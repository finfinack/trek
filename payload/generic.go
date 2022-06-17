package payload

type ApplicationIDs struct {
	ApplicationID string `json:"application_id"`
}

type DeviceIDs struct {
	DeviceID       string          `json:"device_id"`
	ApplicationIDs *ApplicationIDs `json:"application_ids"`
	DevEUI         string          `json:"dev_eui"`
	JoinEUI        string          `json:"join_eui"`
	DevAddr        string          `json:"dev_addr"`
}
