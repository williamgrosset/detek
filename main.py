import sys
import pcapy
from impacket import ImpactDecoder

class Connection:
    '''
    Class is used as a dictionary key.
    '''
    def __init__(self, peer1, peer2):
        self.peer1 = peer1
        self.peer2 = peer2

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


def main():
    # TODO: Error handling for file type
    connections = {}
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')
    pc.loop(0, packet_parser)

    # TODO: Results logger

if __name__ == '__main__':
    main()
