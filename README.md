# detek
![alt text](https://github.com/williamgrosset/detek/blob/master/example.gif "detek")

## Overview
This project was an assignment for the [Computer Communications and Networks](https://github.com/williamgrosset/detek/blob/master/csc361_p2.pdf) class at the University of Victoria. The purpose of this program is to identify and analyze TCP connections in a capture file. The program will echo output for each connection regarding it's status, duration, total packets and bytes sent/received, average round-trip time, and more.

### Usage 
**Prerequisite**: `Python 2.7.x` (tested with `Python 2.7.10`)
1. Install [pcapy](https://github.com/CoreSecurity/pcapy) and [impacket](https://github.com/CoreSecurity/impacket).
2. Run `python main.py <capture-file>` (see [sample output](https://github.com/williamgrosset/detek/blob/master/sample_output_file.pdf)).
