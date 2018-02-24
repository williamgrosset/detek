import sys
import pcapy
from impacket import ImpactDecoder

connections = {}

class Connection:
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

'''
TODO: Class is used as the dictionary value.
'''

def packet_parser(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)
    ip_header = ethernet_packet.child()
    tcp_header = ip_header.child()

    source = (ip_header.get_ip_src(), tcp_header.get_th_sport())
    destination = (ip_header.get_ip_dst(), tcp_header.get_th_dport())
    connection = Connection(source, destination)

    print 'Connection: %s' % (connection)

    if not connections.has_key(connection):
        connections[connection] = 'unique'


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
