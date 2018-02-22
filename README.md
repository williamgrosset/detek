# detect 
:vertical_traffic_light: TCP Traffic Analysis.

### TODO
+ Review TCP
+ Create a `HashMap<connection_id, connection_obj>`
  + `connection_id`: 4-attribute tuple
  + `connection_obj`: state of connection, connection_complete boolean
    + if connection_complete:
      + packets sent from source &rightarrow; destination
      + packets sent from destination &rightarrow; source 
      + total packets
      + data bytes sent from source %rightarrow; destination
      + data bytes sent from destination %rightarrow; source 
      + total data bytes 
+ Parse each unique TCP connection (keep track of state) identified by a duplex tuple
+ Leave `Section D)` till last

### Setup
1. Ensure you are running Python 3.x.
2. Install [pcapy](https://github.com/CoreSecurity/pcapy).
3. ...

### Identifying a TCP connection
+ 4-tuple (IP source address, source port, IP destination address, destination port)
+ Packets can flow in both directions on a connection (duplex)
  + `(123, 0, 456, 1)` is the same as `(456, 1, 123, 0)`

### Identifying a Complete TCP connection
+ Acknowledged both `SIN` and `FIN`

### All Possible TCP States
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
