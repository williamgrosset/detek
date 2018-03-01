from __future__ import division
from impacket import ImpactDecoder, ImpactPacket
import sys
import pcapy

class ConnectionState:
    '''
    Class represents the state of the connection and contains a counter for the SYN, ACK, FIN, and RST flags.
    Used as part of the ConnectionInfo class.
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
    Class contains information for a connection.
    Used as the connections dictionary item.

    state: ConnectionState class,
    source: (IP addressm, port),
    destination: (IP address, port),
    start_ts: packet timestamp (seconds),
    start_rs: relative start to initial packet (seconds),
    end_ts: packet timestamp (seconds),
    end_rs: relative end to initial packet (seconds),
    duration_s: duration of connection (seconds),
    pckts_sent: packets sent from source to destination (bytes),
    pckts_recv: packets sent from destination to source (bytes),
    total_pckts: total packets in connection (bytes),
    bytes_sent: data bytes sent from source to destination (bytes),
    bytes_recv: data bytes sent from destination to source (bytes),
    total_bytes: total data bytes in connection (bytes)
    '''
    def __init__(self, state, source, destination, start_ts, start_rs, pckts_sent, bytes_sent):
        self.state = state
        self.source = source
        self.destination = destination
        self.start_ts = start_ts
        self.start_rs = start_rs
        self.end_ts = 0
        self.end_rs = 0
        self.duration_s = 0
        self.pckts_sent = pckts_sent
        self.pckts_recv = 0
        self.total_pckts = self.pckts_sent + self.pckts_recv
        self.bytes_sent = bytes_sent
        self.bytes_recv = 0
        self.total_bytes = self.bytes_sent + self.bytes_recv

class ConnectionId:
    '''
    Class uniquely identifies a connection (duplex support: (p1, p2) == (p2, p1)).
    Used as the connections dictionary key.

    peer1: (IP address, port),
    peer2: (IP address, port)
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

def update_state_flags(connection_info, SYN, ACK, FIN, RST):
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

def update_connection_duration(connection_info, pckt_ts, initial_pckt_ts, FIN):
    # Update connection duration for last FIN
    if FIN:
        connection_info.end_ts = pckt_ts
        connection_info.end_rs = pckt_ts % initial_pckt_ts
        connection_info.duration_s = connection_info.end_ts - connection_info.start_ts

def update_total_data_transfer(connection_info, source, options_size):
    # Update packets for source and destination
    if source == connection_info.source:
        connection_info.pckts_sent += 1
    else:
        connection_info.pckts_recv += 1

    connection_info.total_pckts += 1

    # TODO: Update bytes for source and destination
    if source == connection_info.source:
        connection_info.bytes_sent += options_size
    else:
        connection_info.bytes_recv += options_size

    connection_info.total_bytes += options_size

def packet_parser(pc, connections, initial_pckt_ts):
    pckt = pc.next()

    while pckt:
        header = pckt[0]
        data = pckt[1]

        decoder = ImpactDecoder.EthDecoder()
        ethernet_pckt = decoder.decode(data)

        if ethernet_pckt.get_ether_type() != ImpactPacket.IP.ethertype:
            return

        ip_header = ethernet_pckt.child()
        tcp_header = ip_header.child()

        source = (ip_header.get_ip_src(), tcp_header.get_th_sport())
        destination = (ip_header.get_ip_dst(), tcp_header.get_th_dport())
        connection_id = ConnectionId(source, destination)

        options_size = 0
        for option in tcp_header.get_options():
            options_size += option.get_size()

        pckt_ts = header.getts()[0] + (header.getts()[1] / 1000000)

        if not initial_pckt_ts:
            initial_pckt_ts = pckt_ts

        SYN = tcp_header.get_SYN()
        ACK = tcp_header.get_ACK()
        FIN = tcp_header.get_FIN()
        RST = tcp_header.get_RST()

        if not connections.has_key(connection_id):
            connection_state = ConnectionState(SYN, ACK, FIN, RST)
            connection_info = ConnectionInfo(
                                connection_state,
                                source,
                                destination,
                                pckt_ts,
                                pckt_ts % initial_pckt_ts,
                                1,
                                options_size
                              )
            connections[connection_id] = connection_info
        else:
            connection_info = connections[connection_id]

            update_state_flags(connection_info, SYN, ACK, FIN, RST)
            update_connection_duration(connection_info, pckt_ts, initial_pckt_ts, FIN)
            update_total_data_transfer(connection_info, source, options_size)

            connections[connection_id] = connection_info

        pckt = pc.next()

def print_connection_details(connection, count):
    source = connection.source
    destination = connection.destination
    status = 'R' if connection.state.is_reset else 'S%sF%s' % (connection.state.SYN, connection.state.FIN)

    print('Connection %i:' % count)
    print('Source Address: %s' % source[0])
    print('Destination Address: %s' % destination[0])
    print('Source Port: %s' % source[1])
    print('Destination Port: %s' % destination[1])
    print('Status: %s' % status)
    if connection.state.is_complete:
        print('Start Time: %fs' % connection.start_rs)
        print('End Time: %fs' % connection.end_rs)
        print('Duration: %fs' % connection.duration_s)
        print('Number of packets sent from Source to Destination: %i' % connection.pckts_sent)
        print('Number of packets sent from Destination to Source: %i' % connection.pckts_recv)
        print('Total number of packets: %i' % connection.total_pckts)
        print('Number of data bytes sent from Source to Destination: %i' % connection.bytes_sent)
        print('Number of data bytes sent from Destination to Source: %i' % connection.bytes_recv)
        print('Total number of data bytes: %i' % connection.total_bytes)

    print('')


def result_logger(connections):
    i = 1
    for key, value in connections.iteritems():
        print_connection_details(value, i)
        i += 1

def main():
    # TODO: Error handling for file type
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    connections = {}
    initial_pckt_ts = 0
    packet_parser(pc, connections, initial_pckt_ts)

    result_logger(connections)

    # TODO: Results logger (loop through connections dictionary)
    # TODO: Print results for Section A, B, C, and D

if __name__ == '__main__':
    main()
