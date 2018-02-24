# detek
:vertical_traffic_light: TCP Traffic Analysis.

## TODO
+ Create a `HashMap<connection_id, connection_obj>` (**AUDIT ALGORITHM**)
  + `connection_id`: 4-attribute tuple (duplex supported)
    + when adding to HashMap, check for inverse of source and destination values
  + `connection_obj`:
    + state of connection 
    + complete bool (atleast 1 `S1F1`), reset bool 
    + start and end time + duration of connection
    + packets sent from source &rightarrow; destination
    + packets sent from destination &rightarrow; source 
    + total packets
    + data bytes sent from source &rightarrow; destination
    + data bytes sent from destination &rightarrow; source 
    + total data bytes 
+ Grab number for all TCP connections and compare to WS (48)
+ Complete results logger
+ Error handling, nit clean-up, and organize repo
+ Finish README and add example gif
+ Review TCP lecture notes

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

#### All Possible TCP States
+ `S0F0` (no SYN and no FIN)
+ `S1F0` (one SYN and no FIN)
+ `S2F0` (two SYN and no FIN)
+ `S1F1` (one SYN and one FIN)
+ `S2F1` (two SYN and one FIN)
+ `S2F2` (two SYN and two FIN)
+ `S0F1` (no SYN and one FIN)
+ `S0F2` (no SYN and two FIN)
+ `R` (connection reset due to protocol error)

### Verification 
Output for each file can be tested against [Wireshark](https://www.wireshark.org/).
