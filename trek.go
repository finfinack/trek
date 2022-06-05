package main

/*
https://docs.iotracker.eu/configuration/downlink-examples/
*/

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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/finfinack/trek/export"
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

	listen     = flag.String("listen", ":8080", "Listening port for webserver.")
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
	renderEndpoint   = "/trek/v1/render"
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

	// latPadding and lonPadding define the size of the OSM box and thus
	// the zoom level. Larger padding equals zooming out further.
	latPadding = 0.001
	lonPadding = 0.002
)

type TrekServer struct {
	Server   *http.Server
	DB       *sql.DB
	Trek     *Trek
	MQTTUser string
}

func (t *TrekServer) indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{})
}

func (t *TrekServer) renderHandler(c *gin.Context) {
	type queryParameters struct {
		Device      string `form:"device"`
		MustHaveGPS string `form:"mustHaveGPS"`
		Format      string `form:"format"`
	}

	var parsedQueryParameters queryParameters
	if err := c.ShouldBind(&parsedQueryParameters); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	q := []string{latestDataStartTmpl}
	if parsedQueryParameters.MustHaveGPS == "1" || parsedQueryParameters.MustHaveGPS == "true" {
		q = append(q, latestDataMustHaveGPS)
	}
	q = append(q, latestDataEndTmpl)
	statement, err := t.DB.Prepare(strings.Join(q, ""))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	var hasGPS, hasAPs bool
	var gateways, aps, gps, raw string
	var received int64
	var battery int
	var temp, lum, acc float32
	if err := statement.QueryRow(parsedQueryParameters.Device).Scan(&received, &gateways, &hasGPS, &hasAPs, &battery, &aps, &temp, &lum, &acc, &gps, &raw); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	p := &payload.Message{
		ReceivedAt:      time.UnixMilli(received),
		DeviceID:        parsedQueryParameters.Device,
		Battery:         battery,
		Temperature:     temp,
		Luminosity:      lum,
		MaxAcceleration: acc,
	}
	json.Unmarshal([]byte(gateways), &p.Gateways)
	if hasGPS {
		if err := json.Unmarshal([]byte(gps), &p.GPS); err != nil {
			glog.Warning(err)
		} else {
			p.HasGPS = true
		}
	}
	if hasAPs {
		if err := json.Unmarshal([]byte(aps), &p.AccessPoints); err != nil {
			glog.Warning(err)
		} else {
			p.HasAccessPoints = true
		}
	}

	switch strings.ToLower(parsedQueryParameters.Format) {
	case "html":
		var bbox string
		if hasGPS {
			bbox = fmt.Sprintf("%f,%f,%f,%f", p.GPS.Longitude-lonPadding, p.GPS.Latitude-latPadding, p.GPS.Longitude+lonPadding, p.GPS.Latitude+latPadding)
		}
		c.HTML(http.StatusOK, "render.html", gin.H{
			"device":      p.DeviceID,
			"receivedAt":  p.ReceivedAt.Format(time.RFC3339),
			"receivedAgo": time.Since(p.ReceivedAt).String(),
			"hasGPS":      hasGPS,
			"gps":         p.GPS,
			"bbox":        bbox,
			"lum":         p.Luminosity,
			"temp":        p.Temperature,
			"acc":         p.MaxAcceleration,
			"batt":        p.Battery,
			"gateways":    p.Gateways,
			"hasAP":       hasAPs,
			"aps":         p.AccessPoints,
		})
	default:
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   p,
		})
	}
}

func (t *TrekServer) downlinkHandler(c *gin.Context) {
	type queryParameters struct {
		Username string `form:"username"`
		Device   string `form:"device"`
		Message  string `form:"message"`
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
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
	})
}

type Trek struct {
	client mqtt.Client

	Messages chan payload.Message
}

func (i *Trek) Connect(broker string, username string, password string) error {
	if i.client != nil {
		return errors.New("already connected")
	}

	opts := mqtt.NewClientOptions()
	if strings.HasPrefix(broker, "tls") {
		opts.SetTLSConfig(&tls.Config{})
	}
	opts.AddBroker(broker)
	opts.SetClientID("trekker")
	opts.SetUsername(username)
	opts.SetPassword(password)

	opts.SetDefaultPublishHandler(i.messagePubHandler)
	opts.OnConnect = i.connectHandler
	opts.OnConnectionLost = i.disconnectHandler

	i.client = mqtt.NewClient(opts)
	token := i.client.Connect()
	token.Wait()
	return token.Error()
}

func (i *Trek) Disconnect() {
	i.client.Disconnect(250)
	time.Sleep(1 * time.Second)
}

func (i *Trek) Subscribe(topic string) error {
	token := i.client.Subscribe(topic, 1, i.messagePubHandler)
	token.Wait()
	return token.Error()
}

func (i *Trek) Unsubscribe(topic string) error {
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
		Downlinks: []payload.Downlink{
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
		// glog.Infof("message decoded: %+v", payload)

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
		// glog.Infof("message decoded: %+v", payload)
	case strings.HasSuffix(msg.Topic(), "/down/sent"):
		p := &payload.DownSent{}
		if err := json.Unmarshal(msg.Payload(), p); err != nil {
			glog.Warningf("unable to unmarshal received message: %s", err)
			return
		}
		// glog.Infof("message decoded: %+v", payload)
	case strings.HasSuffix(msg.Topic(), "/down/ack"):
		p := &payload.DownAck{}
		if err := json.Unmarshal(msg.Payload(), p); err != nil {
			glog.Warningf("unable to unmarshal received message: %s", err)
			return
		}
		// glog.Infof("message decoded: %+v", payload)
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
	glog.Info("connected")
}

func (i *Trek) disconnectHandler(client mqtt.Client, err error) {
	glog.Error(err)
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

	// Connect to MQTT broker.
	messages := make(chan payload.Message, 10)
	trekker := &Trek{
		Messages: messages,
	}
	if err := trekker.Connect(*mqttBroker, *mqttUsername, *mqttPassword); err != nil {
		glog.Exit(err)
	}

	// Subscribe to all topics.
	for _, t := range subTopicTmpl {
		for _, d := range devs {
			topic := fmt.Sprintf(t, *mqttUsername, d)
			if err := trekker.Subscribe(topic); err != nil {
				glog.Error(err)
			}
		}
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
	router.LoadHTMLGlob("templates/*")
	trekkerServer := TrekServer{
		Server: &http.Server{
			Addr:    *listen,
			Handler: router, // use `http.DefaultServeMux`
		},
		DB:       db,
		Trek:     trekker,
		MQTTUser: *mqttUsername,
	}
	router.GET(indexEndpoint, trekkerServer.indexHandler)
	router.GET(renderEndpoint, trekkerServer.renderHandler)
	router.GET(downlinkEndpoint, trekkerServer.downlinkHandler)
	glog.Fatal(trekkerServer.Server.ListenAndServe())

	// Wait for abort signal (e.g. CTRL-C pressed).
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c

		// Unsubscribe and disconnect.
		for _, t := range subTopicTmpl {
			for _, d := range devs {
				topic := fmt.Sprintf(t, *mqttUsername, d)
				if err := trekker.Unsubscribe(topic); err != nil {
					glog.Error(err)
				}
			}
		}
		trekker.Disconnect()
		trekkerServer.Server.Shutdown(ctx)
		glog.Flush()

		os.Exit(1)
	}()
}
