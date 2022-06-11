# Trek

Trek is a simple collector and visualization for [IOTracker](https://www.iotracker.eu/iotracker) data.

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
go run trek.go \
  -mqttUsername <MQTT_USER> \
  -mqttPassword <MQTT_PWD> \
  -devices <DEVICES> \
  -sqliteFile /tmp/trek.sqlite
```

Note: If you compile it and move the binary elsewhere, keep the `templates` and `resources` folders next to the binary as the HTML templates and static resources are read from those folders at runtime.

### Flags

* `mqttBroker`: MQTT Broker host to connect to. Defaults to `tls://eu1.cloud.thethings.network:8883` which connects to the EU cluster via TLS. Check [TTN Website](https://www.thethingsindustries.com/docs/getting-started/ttn/#clusters) for other available clusters. Note the custom URI handlers...

* `mqttUsername`: TTN MQTT username consists of the application ID followed by the tenant ID (which should be `@ttn` in this case). This is the Username as displayed under MQTT "Connection credentials" in the application in the TTN console.

* `mqttPassword`: TTN MQTT password (also named API key) generated in TTN conslle under MQTT "Connection credentials".

* `devices`: Comma separated list of iotracker device IDs you'd like to keep track of. The device ID should be as configured in TTN.

* `port`: Port the Trek webserver listens on.

* `tlsCert`: Path to TLS Certificate. If this and `-tlsKey` is specified, service runs as TLS server.

* `tlsKey`: Path to TLS Key. If this and `-tlsCert` is specified, service runs as TLS server.

* `sqliteFile`: Path to the SQLite file to use. If it doesn't exist, the file will be created (but the folder must exist).

### Webserver

Currently the webserver exposes the following endpoints:

* `/`: Index page for convenient access to the other endpoints.

    The endpoint accepts the following parameters:

    * `device`: Preset the device ID fields for convience.

* `/trek/v1/device`: Display information for a given device.

    The endpoint accepts the following parameters:

  * `device`: The device ID to search and display information for.

  * `mustHaveGPS`: Set to `1` or `true` to only display messages of the device which have a GPS position.

  * `lat`: Latitude of an optional user location to display.

  * `lon`: Longitude of an optional user location to display.

  * `showBrowserLoc`: Set to `1` or `true` for the website to try to get the device's/browser's location and display it on the map as well.

  * `format`: Accepts either `json` or `html` (default) to render the output differently.

* `/trek/v1/downlink`: Sends messages to a device to reconfigure it.

  The endpoint accepts the following parameters:

  * `device`: The device ID to search and display information for.

  * `message`: Message to send. This is in HEX format and needs to comply with the IOTracker [downlink message format](https://docs.iotracker.eu/configuration/downlinks/). Specifically have a look at their [examples](https://docs.iotracker.eu/configuration/downlink-examples/).

  * `format`: Accepts either `json` or `html` (default) to render the output differently.

## References

* https://www.iotracker.eu/iotracker
* https://docs.iotracker.eu/devices/iot3/
* https://docs.iotracker.eu/configuration/introduction/
* https://www.thethingsindustries.com/docs/devices/adding-devices/