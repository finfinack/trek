package payload

import "time"

type Message struct {
	// Metadata
	Topic      string       `json:"topic"`
	ReceivedAt time.Time    `json:"received_at"`
	DeviceID   string       `json:"device_id"`
	Gateways   []RXMetadata `json:"gateways"`

	// Sensors
	HasGPS          bool          `json:"has_gps"`
	HasAccessPoints bool          `json:"has_accesspoints"`
	Battery         int           `json:"battery_level"`
	AccessPoints    []AccessPoint `json:"accesspoints"`
	Temperature     float32       `json:"temperature"`
	Luminosity      float32       `json:"luminosity"`
	MaxAcceleration float32       `json:"max_acceleration"`
	GPS             GPS           `json:"gps"`

	// Data
	RAWMessage string `json:"raw_message"`
}
