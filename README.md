# Trek

Trek is a simple collector and visualization for IOTracker data.

## LoRa Setup

* iotracker is configured via the iotracker console (note the parameters)
* create an account on The Things Network (TTN)
* create an application in TTN and [add the device](https://www.thethingsindustries.com/docs/devices/adding-devices/) with the previously noted parameters
* create an MQTT API key

## Data Flow

* iotracker sends a message via LoRa
* one or more LoRa gateways nearby pick the message up and relay it to TTN
* TTN forwards it to MQTT subscribers
* trek picks up the messages sent to MQTT and stores it in a sqlite DB
* messages are visualized in a web UI
* the web UI can also be used to send messages to the iotracker to reconfigure it

## Run it!

```
go run trek.go -mqttUsername <MQTT_USER> -mqttPassword <MQTT_PWD> -devices <DEVICES> -sqliteFile /tmp/trek.sqlite
```

Note: If you compile it and move the binary elsewhere, keep the `templates` folder next to the binary as the html templates are read from that folder at runtime.

### Flags

* `mqttUsername`: TTN MQTT username consists of the application ID followed by the tenant ID (which should be `@ttn` in this case). This is the Username as displayed under MQTT "Connection credentials" in the application in the TTN console.

* `mqttPassword`: TTN MQTT password (also named API key) generated in TTN conslle under MQTT "Connection credentials".

* `devices`: Comma separated list of iotracker device IDs you'd like to keep track of. The device ID should be as configured in TTN.

* `sqliteFile`: Path to the SQLite file to use. If it doesn't exist, the file will be created (but the folder must exist).

## References

* https://docs.iotracker.eu/devices/iot3/
* https://docs.iotracker.eu/configuration/introduction/
* https://www.thethingsindustries.com/docs/devices/adding-devices/