package payload

import (
	"encoding/json"
	"time"

	"github.com/finfinack/trek/geo"
	"github.com/golang/glog"
)

type Message struct {
	// Metadata
	Topic      string        `json:"topic"`
	ReceivedAt time.Time     `json:"received_at"`
	DeviceID   string        `json:"device_id"`
	Gateways   []*RXMetadata `json:"gateways"`

	// Sensors
	HasGPS          bool           `json:"has_gps"`
	HasAccessPoints bool           `json:"has_accesspoints"`
	Battery         int            `json:"battery_level"`
	AccessPoints    []*AccessPoint `json:"accesspoints"`
	Temperature     float32        `json:"temperature"`
	Luminosity      float32        `json:"luminosity"`
	MaxAcceleration float32        `json:"max_acceleration"`
	GPS             *geo.Location  `json:"gps"`

	// Data
	RAWMessage string `json:"raw_message"`

	// Downstream data (i.e. not in DB)
	HasUserLocation bool          `json:"has_user_location"`
	UserLocation    *geo.Location `json:"user_location"`
}

type Stats struct {
	TotalCount int `json:"total_count"`
	GPSCount   int `json:"gps_count"`

	StatsDuration time.Duration `json:"stats_duration"`

	AverageMessageInterval time.Duration `json:"message_interval"`
}

func CreateMessageFromRaw(deviceID string, userLoc *geo.Location, received int64, gateways string, hasGPS, hasAPs bool, battery int, aps string, temp, lum, acc float32, gps, raw string) *Message {
	m := &Message{
		ReceivedAt:      time.UnixMilli(received),
		DeviceID:        deviceID,
		Battery:         battery,
		Temperature:     temp,
		Luminosity:      lum,
		MaxAcceleration: acc,
	}
	json.Unmarshal([]byte(gateways), &m.Gateways)

	if userLoc != nil {
		m.HasUserLocation = true
		m.UserLocation = userLoc
	}

	if hasGPS {
		if err := json.Unmarshal([]byte(gps), &m.GPS); err != nil {
			glog.Warning(err)
		} else {
			m.HasGPS = true
		}
	}

	if hasAPs {
		if err := json.Unmarshal([]byte(aps), &m.AccessPoints); err != nil {
			glog.Warning(err)
		} else {
			m.HasAccessPoints = true
		}
	}

	if m.HasGPS && m.HasUserLocation {
		m.GPS.DistanceFromUser = userLoc.Distance(&geo.Location{
			Longitude: m.GPS.Longitude,
			Latitude:  m.GPS.Latitude,
		})
	}

	for i, rx := range m.Gateways {
		if rx.Location.Latitude == 0 || rx.Location.Longitude == 0 {
			continue
		}

		if m.HasGPS {
			loc := &geo.Location{
				Longitude: m.GPS.Longitude,
				Latitude:  m.GPS.Latitude,
			}
			m.Gateways[i].Location.DistanceFromTracker = loc.Distance(&geo.Location{
				Longitude: rx.Location.Longitude,
				Latitude:  rx.Location.Latitude,
			})
		}

		if m.HasUserLocation {
			m.Gateways[i].Location.DistanceFromUser = userLoc.Distance(&geo.Location{
				Longitude: rx.Location.Longitude,
				Latitude:  rx.Location.Latitude,
			})
		}
	}

	return m
}
