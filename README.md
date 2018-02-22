# detect 
:vertical_traffic_light: TCP Traffic Analysis.

### TODO
+ Review TCP lecture notes
+ Create a `HashMap<connection_id, connection_obj>` (TODO: algorithm needs auditing)
  + `connection_id`: 4-attribute tuple (duplex supported)
    + when adding to HashMap, check for inverse of source and destination values
  + `connection_obj`: state of connection, connection_complete boolean (atleast 1 S1F1), connection_reset boolean
    + if connection_complete:
      + start and end time + duration of connection
      + packets sent from source &rightarrow; destination
      + packets sent from destination &rightarrow; source 
      + total packets
      + data bytes sent from source &rightarrow; destination
      + data bytes sent from destination &rightarrow; source 
      + total data bytes 
+ Parse each packet identifying the TCP connection (keep track of state)
  + focus on a single packet
+ Complete `Section C) and D)`
+ Error handling, nit clean-up, and organize repo
+ Finish README and add example gif

## Overview
...

### Usage 
1. Ensure you are running Python 3.x.
2. Install [pcapy](https://github.com/CoreSecurity/pcapy).
3. `python3 main.py <capture-file>`
4. ...

### Strategy
...

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
