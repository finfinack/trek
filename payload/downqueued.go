package payload

type DownlinkQueued struct {
	FPort          int      `json:"f_port"`
	FRMPayload     string   `json:"frm_payload"`
	Priority       string   `json:"priority"`
	CorrelationIDs []string `json:"correlation_ids"`
}

type DownQueued struct {
	EndDeviceIDs   DeviceIDs      `json:"end_device_ids"`
	CorrelationIDs []string       `json:"correlation_ids"`
	Confirmed      bool           `json:"confirmed"`
	DownlinkQueued DownlinkQueued `json:"downlink_queued"`
}
