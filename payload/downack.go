package payload

type DownlinkAck struct {
	SessionKeyID   string   `json:"session_key_id"`
	FPort          int      `json:"f_port"`
	FCnt           int      `json:"f_cnt"`
	FRMPayload     string   `json:"frm_payload"`
	Confirmed      bool     `json:"confirmed"`
	Priority       string   `json:"priority"`
	CorrelationIDs []string `json:"correlation_ids"`
}

type DownAck struct {
	EndDeviceIDs   *DeviceIDs   `json:"end_device_ids"`
	CorrelationIDs []string     `json:"correlation_ids"`
	DownlinkAck    *DownlinkAck `json:"downlink_ack"`
}
