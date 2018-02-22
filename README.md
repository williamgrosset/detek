# detect 
:vertical_traffic_light: TCP Traffic Analysis.

### TODO
+ Review TCP
  + Jot down notes on important sections of assignment
+ Add `pcapy` package
+ Parse the `sample_output_file` TCP trace file
+ Parse each unique TCP connection (keep track of state)

### Setup
1. Ensure you are running Python 3.x.
2. Install [pcapy](https://github.com/CoreSecurity/pcapy).
3. ...

### Identifying a TCP connection
+ 4-tuple (IP source address, source port, IP destination address, destination port)
+ Packets can flow in both directions on a connection (duplex)

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
