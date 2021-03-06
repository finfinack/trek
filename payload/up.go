package payload

import "github.com/finfinack/trek/geo"

type Up struct {
	EndDeviceIDs   DeviceIDs     `json:"end_device_ids"`
	CorrelationIDs []string      `json:"correlation_ids"`
	ReceivedAt     string        `json:"received_at"`
	UplinkMessage  UplinkMessage `json:"uplink_message"`
}

type Visibility struct {
	Rights []string `json:"rights"`
}

type Context struct {
	TenantID string `json:"tenant-id"`
}

type Identifier struct {
	DeviceIDs DeviceIDs `json:"device_ids"`
}

type SensorContent struct {
	ButtonEventInfo              bool `json:"buttonEventInfo"`
	ContainsAccelerometerCurrent bool `json:"containsAccelerometerCurrent"`
	ContainsAccelerometerMax     bool `json:"containsAccelerometerMax"`
	ContainsBluetoothData        bool `json:"containsBluetoothData"`
	ContainsExternalSensors      bool `json:"containsExternalSensors"`
	ContainsLight                bool `json:"containsLight"`
	ContainsTemperature          bool `json:"containsTemperature"`
	ContainsWifiPositioningData  bool `json:"containsWifiPositioningData"`
}

type AccessPoint struct {
	MACAddress     string `json:"macAddress"`
	SignalStrength int    `json:"signalStrength"`
	Status         string `json:"status"`
	StatusCode     int    `json:"statusCode"`
}

type WiFiInfo struct {
	AccessPoints []AccessPoint `json:"accessPoints"`
}

type DecodedPayload struct {
	BatteryLevel           int           `json:"batteryLevel"`
	ContainsGPS            bool          `json:"containsGps"`
	ContainsOnboardSensors bool          `json:"containsOnboardSensors"`
	ContainsSpecial        bool          `json:"containsSpecial"`
	GPS                    geo.Location  `json:"gps"`
	CRC                    int           `json:"crc"`
	LightIntensity         float32       `json:"lightIntensity"`
	MaxAccelerationHistory float32       `json:"maxAccelerationHistory"`
	MaxAccelerationNew     float32       `json:"maxAccelerationNew"`
	SensorContent          SensorContent `json:"sensorContent"`
	Temperature            float32       `json:"temperature"`
	UplinkReasonButton     bool          `json:"uplinkReasonButton"`
	UplinkReasonGpio       bool          `json:"uplinkReasonGpio"`
	UplinkReasonMovement   bool          `json:"uplinkReasonMovement"`
	WiFiInfo               WiFiInfo      `json:"wifiInfo"`
}

type GatewayIDs struct {
	GatewayID string `json:"gateway_id"`
	EUI       string `json:"eui"`
}

type RXMetadata struct {
	GatewayIDs  GatewayIDs   `json:"gateway_ids"`
	Time        string       `json:"time"`
	Timestamp   uint64       `json:"timestamp"`
	RSSI        int          `json:"rssi"`
	ChannelRSSI int          `json:"channel_rssi"`
	SNR         float32      `json:"snr"`
	Location    geo.Location `json:"location"`
	UplinkToken string       `json:"uplink_token"`
}

type LoRa struct {
	Bandwidth       int `json:"bandwidth"`
	SpreadingFactor int `json:"spreading_factor"`
}

type DataRate struct {
	LoRa LoRa `json:"lora"`
}

type Settings struct {
	DataRate   DataRate `json:"data_rate"`
	CodingRate string   `json:"coding_rate"`
	Frequency  string   `json:"frequency"`
	Timestamp  uint64   `json:"timestamp"`
	Time       string   `json:"time"`
}

type VersionIDs struct {
	BrandID         string `json:"brand_id"`
	ModelID         string `json:"model_id"`
	HardwareVersion string `json:"hardware_version"`
	FirmwareVersion string `json:"firmware_version"`
	BandID          string `json:"band_id"`
}

type NetworkIDs struct {
	NetID          string `json:"net_id"`
	TenantID       string `json:"tenant_id"`
	ClusterID      string `json:"cluster_id"`
	ClusterAddress string `json:"cluster_address"`
}

type UplinkMessage struct {
	SessionKeyID    string         `json:"session_key_id"`
	FPort           int            `json:"f_port"`
	FCnt            int            `json:"f_cnt"`
	FRMPayload      string         `json:"frm_payload"`
	DecodedPayload  DecodedPayload `json:"decoded_payload"`
	RXMetadata      []RXMetadata   `json:"rx_metadata"`
	Settings        Settings       `json:"settings"`
	ReceivedAt      string         `json:"received_at"`
	ConsumedAirTime string         `json:"consumed_airtime"`
	VersionIDs      VersionIDs     `json:"version_ids"`
	NetworkIDs      NetworkIDs     `json:"network_ids"`
}
