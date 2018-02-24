import sys
import time
import pcapy
from impacket import ImpactDecoder

connections = {}
initial_time_s = time.time()

class ConnectionState:
    '''
    Class represents the state of the connection.
    '''
    def __init__(self):
        self.SYN = 0
        self.ACK = 0
        self.FIN = 0
        self.RST = 0
        self.is_complete = False
        self.is_reset = False

class ConnectionId:
    '''
    Class is used as a dictionary key.
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

class ConnectionInfo:
    '''
    Class is used as the dictionary item.
    '''
    def __init__(self):
        self.state = ConnectionState()
        self.source = ()
        self.destination = ()
        self.start_s = 0
        self.end_s = 0
        self.duration_s = 0
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

        # TODO: Split each ConnectionInfo modifier into own method

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
        if not connection_info.source and not connection_info.destination and connection_info.state.SYN == 1:
            connection_info.source = source
            connection_info.destination = destination

        # Update connection start, end, and duration (seconds)
        if not connection_info.start_s and connection_info.state.SYN == 1:
            connection_info.start_s = time.time() - initial_time_s

        if not connection_info.end_s and connection_info.state.FIN == 1:
            connection_info.end_s = time.time() - initial_time_s

        if not connection_info.duration_s and connection_info.end_s and connection_info.start_s:
            connection_info.duration_s = connection_info.end_s - connection_info.start_s

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

    # TODO: pass additional args (connections, begin_s) to callback
    pc.loop(0, packet_parser)

    # TODO: Results logger (loop through connections dictionary)
    # TODO: Print results for Section A, B, C, and D

if __name__ == '__main__':
    main()
