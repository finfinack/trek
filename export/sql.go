package export

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/finfinack/trek/payload"
	"github.com/golang/glog"
)

const (
	sqlCreateTableTmpl = `CREATE TABLE IF NOT EXISTS trek (
		"ID"              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"Topic"           TEXT NOT NULL,
		"ReceivedAt"      INTEGER,
		"DeviceID"        TEXT NOT NULL,
		"Gateways"        TEXT,
		"HasGPS"          BOOL,
		"HasAccesspoints" BOOL,
		"Battery"         INTEGER,
		"AccessPoints"    TEXT,
		"Temperature"     REAL,
		"Luminosity"      REAL,
		"MaxAcceleration" REAL,
		"GPS"             TEXT,
		"RAWMessage"      TEXT NOT NULL
	);`
	sqlInsertMessageTmpl = `INSERT INTO trek (
		Topic,
		ReceivedAt,
		DeviceID,
		Gateways,
		HasGPS,
		HasAccesspoints,
		Battery,
		AccessPoints,
		Temperature,
		Luminosity,
		MaxAcceleration,
		GPS,
		RAWMessage
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
)

type SQL struct {
	DB *sql.DB
}

func (s *SQL) Write(ctx context.Context, messages <-chan payload.Message) error {
	if err := sqlCreateTableIfNotExists(s.DB); err != nil {
		return fmt.Errorf("unable to create table: %s", err)
	}

	counts := map[string]int{
		"error":   0,
		"success": 0,
		"total":   0,
	}
	for message := range messages {
		counts["total"] += 1
		if err := sqlInsertMessage(s.DB, message); err != nil {
			counts["error"] += 1
			glog.Warningf("error storing in sqlite DB: %s", err)
			continue
		}
		counts["success"] += 1
	}

	return nil
}

func sqlCreateTableIfNotExists(db *sql.DB) error {
	statement, err := db.Prepare(sqlCreateTableTmpl)
	if err != nil {
		return err
	}
	if _, err := statement.Exec(); err != nil {
		return err
	}

	return nil
}

func sqlInsertMessage(db *sql.DB, m payload.Message) error {
	statement, err := db.Prepare(sqlInsertMessageTmpl)
	if err != nil {
		return err
	}

	gateways, err := json.Marshal(m.Gateways)
	if err != nil {
		return err
	}
	aps, err := json.Marshal(m.AccessPoints)
	if err != nil {
		return err
	}
	gps, err := json.Marshal(m.GPS)
	if err != nil {
		return err
	}
	if _, err := statement.Exec(m.Topic, m.ReceivedAt.UnixMilli(), m.DeviceID, gateways, m.HasGPS, m.HasAccessPoints, m.Battery, aps, m.Temperature, m.Luminosity, m.MaxAcceleration, gps, m.RAWMessage); err != nil {
		return err
	}

	return nil
}
