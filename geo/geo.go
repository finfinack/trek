package geo

import (
	"math"
)

const (
	earthRadius = 6371000 // meters
)

type Location struct {
	Latitude  float64
	Longitude float64
}

func (l *Location) Distance(loc *Location) float64 {
	lat1 := l.Latitude * math.Pi / 180
	lat2 := loc.Latitude * math.Pi / 180
	latDelta := (loc.Latitude - l.Latitude) * math.Pi / 180
	lonDelta := (loc.Longitude - l.Longitude) * math.Pi / 180

	a := math.Sin(latDelta/2)*math.Sin(latDelta/2) + math.Cos(lat1)*math.Cos(lat2)*math.Sin(lonDelta/2)*math.Sin(lonDelta/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}
