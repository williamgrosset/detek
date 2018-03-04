# detek
:vertical_traffic_light: TCP Traffic Analysis.

## TODO
+ Verify byte send, recv, total
+ Complete results logger (Section A, B, C, and D)
+ Error handling, nit clean-up, and organize repo
+ Finish README and add example gif

## Overview
...

### Usage 
**Prerequisite**: Python 2.7.x.
1. Install [pcapy](https://github.com/CoreSecurity/pcapy) and [impacket](https://github.com/CoreSecurity/impacket).
2. `python main.py <capture-file>`
3. ...

### Strategy
1. Create dictionary for storing state and information for unique connections (duplex support).
2. Parse each packet in capture file.
  + Add unique TCP connection to HashMap.
  + Update connection object information for each TCP connection
3. ...

#### Identifying a TCP connection
+ 4-attribute tuple (IP source address, source port, IP destination address, destination port)
+ Packets can flow in both directions on a connection (duplex)
  + `(123, 0, 456, 1)` is the same as `(456, 1, 123, 0)`

#### Identifying a Complete TCP connection
+ Acknowledged atleast one `SIN` and `FIN`

#### Estimating Round-Trip Time
Strategy here...

#### Verification 
Output for each file can be tested against values found [Wireshark](https://www.wireshark.org/).
