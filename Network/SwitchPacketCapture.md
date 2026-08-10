# Cisco Switch Packet Capture (EPC)

* Embedded Packet Capture (EPC) on Cisco IOS and IOS XE is an onboard tool used to capture, store, and analyze network traffic directly on a router or switch. The key steps to run an EPC are setting up a capture buffer, defining a capture point, and starting the capture.

## Configuration Steps
* Define the capture name and target interface:
```
monitor capture <session_name> interface GigabitEthernet1/0/1 both
```

* Add a match filter
```
monitor capture <session_name> match ipv4 any any
```

* Start the capture: Turn on the monitoring process.
```
monitor capture <session_name> start
```

* Stop the capture: End the data collection once done.
```
monitor capture <session_name> stop
```

* View brief packet summary (timestamps and IPs):text
```
show monitor capture <session_name> buffer brief
```

* Clean up the capture
```
no monitor capture <session_name>
```
