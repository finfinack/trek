package geo

import (
	"math"
)

const (
	earthRadius = 6371000 // meters
)

func deg2rad(deg float64) float64 {
	return deg * math.Pi / 180
}

type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Altitude  int     `json:"altitude"`

	// Location Metadata.
	Source string `json:"source"`

	// GPS Metadata
	AltRef  float32 `json:"altRef"`
	COG     float32 `json:"cog"`
	HAcc    int     `json:"hAcc"`
	HDOP    float32 `json:"hdop"`
	NavStat int     `json:"navStat"`
	NumSvs  int     `json:"numSvs"`
	SOG     float32 `json:"sog"`
	VAcc    int     `json:"vAcc"`

	// Calculated fields.
	DistanceFromTracker float64 `json:"distance_from_tracker"`
	DistanceFromUser    float64 `json:"distance_from_user"`
}

func (l *Location) Distance(loc *Location) float64 {
	lat1 := deg2rad(l.Latitude)
	lat2 := deg2rad(loc.Latitude)
	latDelta := deg2rad(loc.Latitude - l.Latitude)
	lonDelta := deg2rad(loc.Longitude - l.Longitude)

	a := (math.Pow(math.Sin(latDelta/2), 2) +
		math.Cos(lat1)*
			math.Cos(lat2)*
			math.Pow(math.Sin(lonDelta/2), 2))
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}
