package payload

type Downlink struct {
	FPort      int    `json:"f_port"`
	FRMPayload string `json:"frm_payload"`
	Priority   string `json:"priority"`
	Confirmed  bool   `json:"confirmed"`
}

type DownPush struct {
	Downlinks []Downlink `json:"downlinks"`
}
