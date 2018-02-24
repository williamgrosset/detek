import sys
import time
import pcapy
from impacket import ImpactDecoder

connections = {}

class ConnectionId:
    '''
    Class is used as a dictionary key.
    TODO: Define ConnectionId (tuple)
    '''
    def __init__(self, peer1, peer2):
        self.peer1 = peer1
        self.peer2 = peer2

    def __cmp__(self, other):
        if ((self.peer1 == other.peer1 and self.peer2 == other.peer2) or
            (self.peer1 == other.peer2 and self.peer2 == other.peer1)):
            return 0
        else:
            return -1

    def __hash__(self):
        return(hash(self.peer1[0]) ^ hash(self.peer2[1])
                ^ hash(self.peer2[0]) ^ hash(self.peer2[1]))

class ConnectionState:
    '''
    TODO: Class represents the state of the TCP connection.
    '''
    def __init__(self):
        self.SYN = 0
        self.ACK = 0
        self.FIN = 0
        self.RST = 0
        self.is_complete = False
        self.is_reset = False

class ConnectionInfo:
    '''
    TODO: Class is used as the dictionary item.
    '''
    def __init__(self):
        self.state = ConnectionState()
        self.source = ()
        self.start_ms = 0
        self.end_ms = 0
        self.duration_ms = 0
        self.packets_sent = 0
        self.packets_recv = 0
        self.total_packets = 0
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.total_bytes = 0

def packet_parser(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)
    ip_header = ethernet_packet.child()
    tcp_header = ip_header.child()

    source = (ip_header.get_ip_src(), tcp_header.get_th_sport())
    destination = (ip_header.get_ip_dst(), tcp_header.get_th_dport())
    connection_id = ConnectionId(source, destination)

    if not connections.has_key(connection_id):
        connections[connection_id] = ConnectionInfo()
    else:
        connection_info = connections[connection_id]

        # Update state flags
        connection_info.state.SYN += tcp_header.get_SYN()
        connection_info.state.ACK += tcp_header.get_ACK()
        connection_info.state.FIN += tcp_header.get_FIN()
        connection_info.state.RST += tcp_header.get_RST()

        # If state is at least S1F1, connection is complete
        if not connection_info.state.is_complete and connection_info.state.SYN and connection_info.state.FIN:
            connection_info.state.is_complete = True

        # If RST flag is set, connection has been reset
        if not connection_info.state.is_reset and connection_info.state.RST:
            connection_info.state.is_reset = True

        # Identify if source or destination
        if not connection_info.source and connection_info.state.SYN == 1:
            connection_info.source = source

        # TODO: Update timestamp and duration

        # Update packets for source, destination, and total
        if source == connection_info.source:
            connection_info.packets_sent += 1
        else:
            connection_info.packets_recv += 1
        connection_info.total_packets += 1

        # Update bytes for source, destination, and total
        options_size = len(tcp_header.get_padded_options())
        if source == connection_info.source:
            connection_info.bytes_sent += options_size
        else:
            connection_info.bytes_recv += options_size
        connection_info.total_bytes += options_size

        connections[connection_id] = connection_info

def main():
    # TODO: Error handling for file type
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    # TODO: pass additional arg (connections) to callback
    begin_s = time.clock()
    pc.loop(0, packet_parser)

    # TODO: Results logger (loop through connections dictionary)
    # TODO: Print results for Section A, B, C, and D

if __name__ == '__main__':
    main()
