package payload

type DownlinkSent struct {
	SessionKeyID   string   `json:"session_key_id"`
	FPort          int      `json:"f_port"`
	FCnt           int      `json:"f_cnt"`
	FRMPayload     string   `json:"frm_payload"`
	Priority       string   `json:"priority"`
	CorrelationIDs []string `json:"correlation_ids"`
}

type DownSent struct {
	EndDeviceIDs   *DeviceIDs    `json:"end_device_ids"`
	CorrelationIDs []string      `json:"correlation_ids"`
	ReceivedAt     string        `json:"received_at"`
	DownlinkSent   *DownlinkSent `json:"downlink_sent"`
}
