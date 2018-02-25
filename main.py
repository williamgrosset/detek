import sys
import time
import pcapy
from impacket import ImpactDecoder

connections = {}
initial_time_s = time.time()

class ConnectionState:
    '''
    Class represents the state of the connection.
    TODO: Add explanation for ConnectionState object.
    '''
    def __init__(self, SYN, ACK, FIN, RST):
        self.SYN = SYN
        self.ACK = ACK
        self.FIN = FIN
        self.RST = RST
        self.is_complete = False
        self.is_reset = False

class ConnectionInfo:
    '''
    Class is used as the dictionary item.
    TODO: Add explanation for ConnectionInfo object.
    '''
    def __init__(self, state, source, destination, start_s, packets_sent, bytes_sent):
        self.state = state
        self.source = source
        self.destination = destination
        self.start_s = start_s
        self.end_s = 0
        self.duration_s = 0
        self.packets_sent = packets_sent
        self.packets_recv = 0
        self.total_packets = self.packets_sent + self.packets_recv
        self.bytes_sent = bytes_sent
        self.bytes_recv = 0
        self.total_bytes = self.bytes_sent + self.bytes_recv

class ConnectionId:
    '''
    Class is used as a dictionary key.
    TODO: Add explanation for ConnectionId object.
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
        return (hash(self.peer1[0]) ^ hash(self.peer2[1]) ^ hash(self.peer2[0]) ^ hash(self.peer2[1]))

def packet_parser(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)
    ip_header = ethernet_packet.child()
    tcp_header = ip_header.child()

    source = (ip_header.get_ip_src(), tcp_header.get_th_sport())
    destination = (ip_header.get_ip_dst(), tcp_header.get_th_dport())
    connection_id = ConnectionId(source, destination)
    # TODO: Verify amount for bytes sent/recv
    options_size = len(tcp_header.get_padded_options())
    SYN = tcp_header.get_SYN()
    ACK = tcp_header.get_ACK()
    FIN = tcp_header.get_FIN()
    RST = tcp_header.get_RST()

    if not connections.has_key(connection_id):
        connection_state = ConnectionState(SYN, ACK, FIN, RST)
        connection_info = ConnectionInfo(connection_state, source, destination, time.time() - initial_time_s, 1, options_size)
        connections[connection_id] = connection_info
    else:
        connection_info = connections[connection_id]

        # TODO: Split each ConnectionInfo modifier into own method

        # Update state flags
        connection_info.state.SYN += SYN
        connection_info.state.ACK += ACK
        connection_info.state.FIN += FIN
        connection_info.state.RST += RST

        # If state is at least S1F1, connection is complete
        if not connection_info.state.is_complete and connection_info.state.SYN and connection_info.state.FIN:
            connection_info.state.is_complete = True

        # If RST flag is set, connection has been reset
        if not connection_info.state.is_reset and connection_info.state.RST:
            connection_info.state.is_reset = True

        # TODO: Verify formula - Update connection start, end, and duration (seconds)
        if not connection_info.end_s and connection_info.state.FIN == 1:
            connection_info.end_s = time.time() - initial_time_s

        if not connection_info.duration_s and connection_info.end_s and connection_info.start_s:
            connection_info.duration_s = connection_info.end_s - connection_info.start_s

        # Update packets for source and destination
        if source == connection_info.source:
            connection_info.packets_sent += 1
        else:
            connection_info.packets_recv += 1

        connection_info.total_packets += 1

        # TODO: Verify formula - Update bytes for source and destination
        if source == connection_info.source:
            connection_info.bytes_sent += options_size
        else:
            connection_info.bytes_recv += options_size

        connection_info.total_bytes += 1

        connections[connection_id] = connection_info

def main():
    # TODO: Error handling for file type
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    # TODO: pass additional args (connections, begin_s) to callback
    pc.loop(0, packet_parser)

    for key, value in connections.iteritems():
        if value.state.is_complete:
            print('Source')
            print(value.source)
            print('Destination')
            print(value.destination)
            print('Start time')
            print(value.start_s)
            print('End time')
            print(value.end_s)
            print('Duration')
            print(value.duration_s)

    # TODO: Results logger (loop through connections dictionary)
    # TODO: Print results for Section A, B, C, and D

if __name__ == '__main__':
    main()
