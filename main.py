import sys
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
        # TODO: Create ConnectionState class (SYN: 0; FIN: 0) (?)
        self.SYN = 0
        self.ACK = 0
        self.FIN = 0
        self.is_complete = false
        self.is_reset = false

class ConnectionInfo:
    '''
    TODO: Class is used as the dictionary item.
    '''
    def __init__(self):
        self.state = ConnectionState()
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

    print 'Connection: %s' % (connection_id)

    if not connections.has_key(connection_id):
        connections[connection_id] = 'unique'


def main():
    # TODO: Error handling for file type
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    # TODO: pass additional arg (connections) to callback
    pc.loop(0, packet_parser)

    print(len(connections))

    # TODO: Results logger

if __name__ == '__main__':
    main()
