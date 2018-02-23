import sys
import pcapy
from impacket import ImpactDecoder

def callback(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)
    ip_header = ethernet_packet.child()
    source_ip = ip_header.get_ip_src()
    dest_ip = ip_header.get_ip_dst()
    print "Connection: %s -> %s" % (source_ip, dest_ip)


def main():
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    pc.loop(0, callback)

if __name__ == '__main__':
    main()
