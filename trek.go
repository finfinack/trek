/*
Trek is a simple collector and visualization for IOTracker data.

The setup is as follows:
- iotracker is configured via the iotracker console (note the parameters)
- create an account on The Things Network (TTN)
- create an application in TTN and add the device with the previously noted parameters
- create an MQTT API key

Based on the above, the data flows:
- iotracker sends a message via LoRa
- one or more LoRa gateways nearby pick the message up and relay it to TTN
- TTN forwards it to MQTT subscribers
- trek picks up the messages sent to MQTT and stores it in a sqlite DB
- messages are visualized in a web UI
- the web UI can also be used to send messages to the iotracker to reconfigure it

References:
- https://docs.iotracker.eu/devices/iot3/
- https://docs.iotracker.eu/configuration/introduction/
- https://www.thethingsnetwork.org/docs/applications/mqtt/quick-start/
*/
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/finfinack/trek/export"
	"github.com/finfinack/trek/geo"
	"github.com/finfinack/trek/payload"

	// Blind import support for sqlite3 used by sqlite.go.
	_ "github.com/mattn/go-sqlite3"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

var (
	mqttBroker   = flag.String("mqttBroker", "tls://eu1.cloud.thethings.network:8883", "MQTT Broker host to connect to.")
	mqttUsername = flag.String("mqttUsername", "", "MQTT Username.")
	mqttPassword = flag.String("mqttPassword", "", "MQTT Password / API Key.")
	devices      = flag.String("devices", "", "Comma separated list of Device IDs.")

	port    = flag.Int("port", 8080, "Listening port for webserver.")
	tlsCert = flag.String("tlsCert", "", "Path to TLS Certificate. If this and -tlsKey is specified, service runs as TLS server.")
	tlsKey  = flag.String("tlsKey", "", "Path to TLS Key. If this and -tlsCert is specified, service runs as TLS server.")

	sqliteFile = flag.String("sqliteFile", "/tmp/trek.sqlite", "File path of the sqlite DB file to use.")
)

var (

	// https://www.thethingsindustries.com/docs/integrations/mqtt/
	subTopicTmpl = []string{
		"v3/%s/devices/%s/join",
		"v3/%s/devices/%s/up",
		"v3/%s/devices/%s/down/queued",
		"v3/%s/devices/%s/down/sent",
		"v3/%s/devices/%s/down/ack",
		"v3/%s/devices/%s/down/failed",
		"v3/%s/devices/%s/service/data",
		"v3/%s/devices/%s/location/solved",
	}
	pushTopicTmpl = "v3/%s/devices/%s/down/push"
)

const (
	loraTimeFormat = time.RFC3339Nano // "2006-01-02T15:04:05.999999999Z"

	indexEndpoint    = "/"
	deviceEndpoint   = "/trek/v1/device"
	downlinkEndpoint = "/trek/v1/downlink"

	latestDataStartTmpl = `SELECT
			ReceivedAt,
			Gateways,
			HasGPS,
			HasAccesspoints,
			Battery,
			AccessPoints,
			Temperature,
			Luminosity,
			MaxAcceleration,
			GPS,
			RAWMessage
		FROM
			trek
		WHERE
			DeviceID = ?`
	latestDataMustHaveGPS = `
			AND HasGPS = true`
	latestDataEndTmpl = `
		ORDER BY ReceivedAt DESC
		LIMIT 1;`

	historicalDataTmpl = `SELECT
			ReceivedAt,
			Gateways,
			HasGPS,
			HasAccesspoints,
			Battery,
			AccessPoints,
			Temperature,
			Luminosity,
			MaxAcceleration,
			GPS,
			RAWMessage
		FROM
			trek
		WHERE
			DeviceID = ?
			AND ReceivedAt > ?
			AND ReceivedAt < ?
		ORDER BY ReceivedAt DESC;`

	statsTmpl = `SELECT
			COUNT(CASE WHEN HasGPS THEN 1 END) AS HasGPS,
			COUNT(*) AS Total
		FROM
			trek
		WHERE
			DeviceID = ?
			AND ReceivedAt > ?
			AND ReceivedAt < ?;
	`

	// defaultLocationHistoryDuration defines how far back history goes by default.
	defaultLocationHistoryDuration = 24 * time.Hour
	locationHistoryFmt             = "2006-01-02"

	// battMax is the max reading of an iotracker device with fresh batteries.
	// This is used to calculate how full the battery currently is.
	battMax = 254
	battExt = 255 // this is the value set when connected to an external power source
)

type TrekServer struct {
	Server   *http.Server
	DB       *sql.DB
	Trek     *Trek
	MQTTUser string
}

func (t *TrekServer) getDeviceStats(deviceID string, startTime, endTime time.Time) (*payload.Stats, error) {
	statement, err := t.DB.Prepare(statsTmpl)
	if err != nil {
		return nil, err
	}

	var hasGPS, total int
	if err := statement.QueryRow(deviceID, startTime.UnixMilli(), endTime.UnixMilli()).Scan(&hasGPS, &total); err != nil {
		return nil, err
	}

	dur := endTime.Sub(startTime)
	var avg time.Duration
	if total > 0 {
		avg = time.Duration(float64(time.Second) * dur.Seconds() / float64(total))
	}
	return &payload.Stats{
		TotalCount:             total,
		GPSCount:               hasGPS,
		StatsDuration:          dur,
		AverageMessageInterval: avg,
	}, nil
}

func (t *TrekServer) getHistoricalData(deviceID string, startTime, endTime time.Time) ([]*payload.Message, error) {
	statement, err := t.DB.Prepare(historicalDataTmpl)
	if err != nil {
		return nil, err
	}

	var msgs []*payload.Message

	rows, err := statement.Query(deviceID, startTime.UnixMilli(), endTime.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hasGPS, hasAPs bool
		var gateways, aps, gps, raw string
		var received int64
		var battery int
		var temp, lum, acc float32
		if err := rows.Scan(&received, &gateways, &hasGPS, &hasAPs, &battery, &aps, &temp, &lum, &acc, &gps, &raw); err != nil {
			return nil, err
		}

		msgs = append(msgs, payload.CreateMessageFromRaw(deviceID, nil, received, gateways, hasGPS, hasAPs, battery, aps, temp, lum, acc, gps, raw))
	}

	return msgs, nil
}

func (t *TrekServer) getLatestData(deviceID string, mustHaveGPS bool, userLoc *geo.Location) (*payload.Message, error) {
	q := []string{latestDataStartTmpl}
	if mustHaveGPS {
		q = append(q, latestDataMustHaveGPS)
	}
	q = append(q, latestDataEndTmpl)
	statement, err := t.DB.Prepare(strings.Join(q, ""))
	if err != nil {
		return nil, err
	}

	var hasGPS, hasAPs bool
	var gateways, aps, gps, raw string
	var received int64
	var battery int
	var temp, lum, acc float32
	if err := statement.QueryRow(deviceID).Scan(&received, &gateways, &hasGPS, &hasAPs, &battery, &aps, &temp, &lum, &acc, &gps, &raw); err != nil {
		return nil, err
	}

	return payload.CreateMessageFromRaw(deviceID, userLoc, received, gateways, hasGPS, hasAPs, battery, aps, temp, lum, acc, gps, raw), nil
}

func (t *TrekServer) indexHandler(c *gin.Context) {
	type queryParameters struct {
		Device string `form:"device"`
	}

	var parsedQueryParameters queryParameters
	if err := c.ShouldBind(&parsedQueryParameters); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"device":    parsedQueryParameters.Device,
		"startDate": time.Now().Add(-defaultLocationHistoryDuration).Format(locationHistoryFmt),
		"endDate":   time.Now().Format(locationHistoryFmt),
	})
}

func (t *TrekServer) deviceHandler(c *gin.Context) {
	type queryParameters struct {
		Device         string  `form:"device"`
		MustHaveGPS    bool    `form:"mustHaveGPS"`
		Lat            float64 `form:"lat"`
		Lon            float64 `form:"lon"`
		ShowBrowserLoc bool    `form:"showBrowserLoc"`
		StartDate      string  `form:"startDate"`
		EndDate        string  `form:"endDate"`
		Format         string  `form:"format"`
	}

	var parsedQueryParameters queryParameters
	if err := c.ShouldBind(&parsedQueryParameters); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	startDate, err := time.Parse(locationHistoryFmt, parsedQueryParameters.StartDate)
	if err != nil {
		startDate = time.Now().Add(-defaultLocationHistoryDuration)
	}
	endDate, err := time.Parse(locationHistoryFmt, parsedQueryParameters.EndDate)
	if err != nil {
		endDate = time.Now()
	}

	stats, err := t.getDeviceStats(parsedQueryParameters.Device, startDate, endDate)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	var userLoc *geo.Location
	if parsedQueryParameters.Lat != 0 && parsedQueryParameters.Lon != 0 {
		userLoc = &geo.Location{
			Latitude:  parsedQueryParameters.Lat,
			Longitude: parsedQueryParameters.Lon,
		}
	}
	m, err := t.getLatestData(parsedQueryParameters.Device, parsedQueryParameters.MustHaveGPS, userLoc)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	history, err := t.getHistoricalData(parsedQueryParameters.Device, startDate, endDate)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	switch strings.ToLower(parsedQueryParameters.Format) {
	case "json":
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   m,
			"stats":  stats,
		})
	case "html":
		fallthrough
	default:
		c.HTML(http.StatusOK, "device.html", gin.H{
			"device":         m.DeviceID,
			"startDate":      startDate.Format(locationHistoryFmt),
			"endDate":        endDate.Format(locationHistoryFmt),
			"receivedAt":     m.ReceivedAt,
			"receivedAgo":    time.Since(m.ReceivedAt),
			"hasGPS":         m.HasGPS,
			"gps":            m.GPS,
			"lum":            m.Luminosity,
			"temp":           m.Temperature,
			"acc":            m.MaxAcceleration,
			"battLevel":      battLevel(m.Battery),
			"gateways":       m.Gateways,
			"hasAP":          m.HasAccessPoints,
			"aps":            m.AccessPoints,
			"hasUserLoc":     m.HasUserLocation,
			"userLoc":        m.UserLocation,
			"showBrowserLoc": parsedQueryParameters.ShowBrowserLoc,
			"stats":          stats,
			"history":        history,
		})
	}
}

func (t *TrekServer) downlinkHandler(c *gin.Context) {
	type queryParameters struct {
		Device  string `form:"device"`
		Message string `form:"message"`
		Format  string `form:"format"`
	}

	var parsedQueryParameters queryParameters
	if err := c.BindQuery(&parsedQueryParameters); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	if err := t.Trek.Publish(fmt.Sprintf(pushTopicTmpl, t.MQTTUser, parsedQueryParameters.Device), parsedQueryParameters.Message); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	switch strings.ToLower(parsedQueryParameters.Format) {
	case "json":
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
		})
	case "html":
		fallthrough
	default:
		u := url.URL{
			Path: indexEndpoint,
		}
		q := u.Query()
		q.Set("device", parsedQueryParameters.Device)
		u.RawQuery = q.Encode()
		c.Redirect(http.StatusFound, u.String())
	}
}

type Trek struct {
	client mqtt.Client
	topics []string

	Messages chan payload.Message
}

func (i *Trek) Connect(broker, username, password string, topics []string) error {
	if i.client != nil && i.client.IsConnected() {
		return errors.New("MQTT already connected")
	}

	opts := mqtt.NewClientOptions()
	if strings.HasPrefix(broker, "tls") {
		opts.SetTLSConfig(&tls.Config{})
	}
	opts.AddBroker(broker)
	opts.SetClientID("trekker")
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetOrderMatters(false)

	opts.SetDefaultPublishHandler(i.messagePubHandler)
	opts.SetOnConnectHandler(i.connectHandler)
	opts.SetConnectionLostHandler(i.disconnectHandler)

	i.topics = topics // will subscribe in "connected" handler
	i.client = mqtt.NewClient(opts)
	token := i.client.Connect()
	token.Wait()
	return token.Error()
}

func (i *Trek) Disconnect() {
	for _, t := range i.topics {
		if err := i.unsubscribe(t); err != nil {
			glog.Errorf("MQTT error unsubscribing from %q: %s", t, err)
		} else {
			glog.Infof("MQTT unsubscribed from %q", t)
		}
	}
	i.topics = nil
	i.client.Disconnect(250)
	i.client = nil
	time.Sleep(1 * time.Second)
}

func (i *Trek) subscribe(topic string) error {
	token := i.client.Subscribe(topic, 1, i.messagePubHandler)
	token.Wait()
	return token.Error()
}

func (i *Trek) unsubscribe(topic string) error {
	token := i.client.Unsubscribe(topic)
	token.Wait()
	return token.Error()
}

func (i *Trek) encodePayload(msg string) (string, error) {
	data, err := hex.DecodeString(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (i *Trek) Publish(topic string, msg string) error {
	encoded, err := i.encodePayload(msg)
	if err != nil {
		return err
	}
	payload := &payload.DownPush{
		Downlinks: []*payload.Downlink{
			{
				FPort:      1,
				FRMPayload: encoded,
				Priority:   "NORMAL",
			},
		},
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	token := i.client.Publish(topic, 0, false, p)
	token.Wait()
	return token.Error()
}

func (i *Trek) messagePubHandler(client mqtt.Client, msg mqtt.Message) {
	glog.Infof("Received message (%s): %s\n", msg.Topic(), msg.Payload())

	var store *payload.Message
	switch {
	case strings.HasSuffix(msg.Topic(), "/join"):
		glog.Warningf("unknown topic message type (%s): %s", msg.Topic(), msg.Payload())
	case strings.HasSuffix(msg.Topic(), "/up"):
		p := &payload.Up{}
		if err := json.Unmarshal(msg.Payload(), p); err != nil {
			glog.Warningf("unable to unmarshal received message: %s", err)
			return
		}
		t, err := time.Parse(loraTimeFormat, p.ReceivedAt)
		if err != nil {
			glog.Warningf("unable to parse timestamp: %s", err)
		}
		store = &payload.Message{
			Topic:           msg.Topic(),
			ReceivedAt:      t,
			DeviceID:        p.EndDeviceIDs.DeviceID,
			Gateways:        p.UplinkMessage.RXMetadata,
			HasGPS:          p.UplinkMessage.DecodedPayload.ContainsGPS,
			HasAccessPoints: p.UplinkMessage.DecodedPayload.SensorContent.ContainsWifiPositioningData,
			Battery:         p.UplinkMessage.DecodedPayload.BatteryLevel,
			AccessPoints:    p.UplinkMessage.DecodedPayload.WiFiInfo.AccessPoints,
			Temperature:     p.UplinkMessage.DecodedPayload.Temperature,
			Luminosity:      p.UplinkMessage.DecodedPayload.LightIntensity,
			MaxAcceleration: p.UplinkMessage.DecodedPayload.MaxAccelerationNew,
			GPS:             p.UplinkMessage.DecodedPayload.GPS,
			RAWMessage:      string(msg.Payload()),
		}
	case strings.HasSuffix(msg.Topic(), "/down/queued"):
		p := &payload.DownQueued{}
		if err := json.Unmarshal(msg.Payload(), p); err != nil {
			glog.Warningf("unable to unmarshal received message: %s", err)
			return
		}
	case strings.HasSuffix(msg.Topic(), "/down/sent"):
		p := &payload.DownSent{}
		if err := json.Unmarshal(msg.Payload(), p); err != nil {
			glog.Warningf("unable to unmarshal received message: %s", err)
			return
		}
	case strings.HasSuffix(msg.Topic(), "/down/ack"):
		p := &payload.DownAck{}
		if err := json.Unmarshal(msg.Payload(), p); err != nil {
			glog.Warningf("unable to unmarshal received message: %s", err)
			return
		}
	case strings.HasSuffix(msg.Topic(), "/down/nack"):
		glog.Warningf("message type not implemented (%s): %s", msg.Topic(), msg.Payload())
	case strings.HasSuffix(msg.Topic(), "/down/failed"):
		glog.Warningf("message type not implemented (%s): %s", msg.Topic(), msg.Payload())
	case strings.HasSuffix(msg.Topic(), "/service/data"):
		glog.Warningf("message type not implemented (%s): %s", msg.Topic(), msg.Payload())
	case strings.HasSuffix(msg.Topic(), "/location/solved"):
		glog.Warningf("message type not implemented (%s): %s", msg.Topic(), msg.Payload())
	default:
		glog.Warningf("unknown topic (%s): %s", msg.Topic(), msg.Payload())
	}

	if store != nil {
		i.Messages <- *store
	}
}

func (i *Trek) connectHandler(client mqtt.Client) {
	glog.Info("MQTT connected")

	// Ensures when we reconnect, subscriptions are set up again as well.
	for _, t := range i.topics {
		if err := i.subscribe(t); err != nil {
			glog.Errorf("MQTT error subscribing to %q: %s", t, err)
		} else {
			glog.Infof("MQTT subscribed to %q", t)
		}
	}
}

func (i *Trek) disconnectHandler(client mqtt.Client, err error) {
	glog.Errorf("MQTT connection lost: %s", err)
}

func battLevel(b int) int {
	if b == battExt {
		return 100
	}
	return int(float32(b) * 100.0 / battMax)
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", d.Minutes())
	case d < 24*time.Hour:
		hours := math.Floor(d.Hours())
		mins := d.Minutes() - 60*hours
		return fmt.Sprintf("%.0fh %.0fm", hours, mins)
	default:
		days := math.Floor(d.Hours() / 24)
		hours := d.Hours() - 24*days
		return fmt.Sprintf("%.0fd %.0fh", days, hours)
	}
}

func formatTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

func formatDistance(d float64) string {
	switch {
	case d > 10000:
		return fmt.Sprintf("%.0fkm", d/1000)
	case d > 1000:
		return fmt.Sprintf("%.1fkm", d/1000)
	default:
		return fmt.Sprintf("%.0fm", d)
	}
}

func main() {
	ctx := context.Background()
	// Set defaults for glog flags. Can be overridden via cmdline.
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "WARNING")
	flag.Set("v", "1")
	// Parse flags globally.
	flag.Parse()

	devs := strings.Split(*devices, ",")

	db, err := sql.Open("sqlite3", *sqliteFile)
	if err != nil {
		glog.Exitf("unable to open sqlite DB %q: %s", *sqliteFile, err)
	}
	exporter := &export.SQL{
		DB: db,
	}

	// Connect to MQTT broker and subscribe to topics.
	var topics []string
	for _, t := range subTopicTmpl {
		for _, d := range devs {
			topics = append(topics, fmt.Sprintf(t, *mqttUsername, d))
		}
	}
	messages := make(chan payload.Message, 10)
	trekker := &Trek{
		Messages: messages,
	}
	if err := trekker.Connect(*mqttBroker, *mqttUsername, *mqttPassword, topics); err != nil {
		glog.Exit(err)
	}

	// Export samples.
	go func() {
		if err := exporter.Write(ctx, messages); err != nil {
			glog.Fatal(err)
		}
	}()

	// Configure and run webserver.
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetFuncMap(template.FuncMap{
		"battLevel":      battLevel,
		"formatDuration": formatDuration,
		"formatTime":     formatTime,
		"formatDistance": formatDistance,
	})
	router.LoadHTMLGlob("templates/*")
	trekkerServer := TrekServer{
		Server: &http.Server{
			Addr:    fmt.Sprintf(":%d", *port),
			Handler: router, // use `http.DefaultServeMux`
		},
		DB:       db,
		Trek:     trekker,
		MQTTUser: *mqttUsername,
	}
	router.GET(indexEndpoint, trekkerServer.indexHandler)
	router.GET(deviceEndpoint, trekkerServer.deviceHandler)
	router.GET(downlinkEndpoint, trekkerServer.downlinkHandler)

	router.StaticFile("/favicon.ico", "./resources/favicon.ico")
	router.StaticFS("/resources", http.Dir("./resources/"))

	if *tlsCert != "" && *tlsKey != "" {
		router.RunTLS(fmt.Sprintf(":%d", *port), *tlsCert, *tlsKey)
	} else {
		router.Run(fmt.Sprintf(":%d", *port))
	}

	// Wait for abort signal (e.g. CTRL-C pressed).
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		// Unsubscribe and disconnect.
		trekker.Disconnect()
		trekkerServer.Server.Shutdown(ctx)
		glog.Flush()

		os.Exit(1)
	}()
}
