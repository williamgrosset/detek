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
    source: (IP address, port),
    destination: (IP address, port),
    start_ts: packet timestamp (seconds),
    start_rs: relative start to initial packet (seconds),
    end_ts: packet timestamp (seconds),
    end_rs: relative end to initial packet (seconds),
    duration_s: duration of connection (seconds),
    packets_sent: packets sent from source to destination,
    packets_recv: packets sent from destination to source,
    total_packets: total packets in connection,
    bytes_sent: data bytes sent from source to destination,
    bytes_recv: data bytes sent from destination to source,
    total_bytes: total data bytes in connection,
    rtt_dict: dictionary for SEQ # + data bytes mapping to timestamp (used for rtt_list),
    rtt_list: list of all round-trip times (RTT) (seconds),
    window_size_list: list of all window sizes (bytes)
    '''
    def __init__(self, state, source, destination, start_ts, start_rs, packets_sent, bytes_sent, window_size):
        self.state = state
        self.source = source
        self.destination = destination
        self.start_ts = start_ts
        self.start_rs = start_rs
        self.end_ts = 0
        self.end_rs = 0
        self.duration_s = 0
        self.packets_sent = packets_sent
        self.packets_recv = 0
        self.total_packets = self.packets_sent + self.packets_recv
        self.bytes_sent = bytes_sent
        self.bytes_recv = 0
        self.total_bytes = self.bytes_sent + self.bytes_recv
        self.rtt_dict = {}
        self.rtt_list = []
        self.window_size_list = [window_size]

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

def update_connection_duration(connection_info, packet_ts, initial_packet_ts, FIN):
    # Update connection duration for last FIN
    if FIN:
        connection_info.end_ts = packet_ts
        connection_info.end_rs = packet_ts % initial_packet_ts
        connection_info.duration_s = connection_info.end_ts - connection_info.start_ts

def update_total_data_transfer(connection_info, source, data_bytes):
    # Update packets for source and destination
    if source == connection_info.source:
        connection_info.packets_sent += 1
    else:
        connection_info.packets_recv += 1

    connection_info.total_packets += 1

    # TODO: Update bytes for source and destination
    if source == connection_info.source:
        connection_info.bytes_sent += data_bytes
    else:
        connection_info.bytes_recv += data_bytes

    connection_info.total_bytes += data_bytes

def update_window_size_list(connection_info, window_size):
    connection_info.window_size_list.append(window_size)

def packet_parser(pc, connections, initial_packet_ts):
    packet = pc.next()

    while packet:
        header = packet[0]
        data = packet[1]

        decoder = ImpactDecoder.EthDecoder()
        ethernet_packet = decoder.decode(data)

        if ethernet_packet.get_ether_type() != ImpactPacket.IP.ethertype:
            return

        ip_header = ethernet_packet.child()
        tcp_header = ip_header.child()
        packet_ts = header.getts()[0] + (header.getts()[1] / 1000000)
        data_bytes = (ip_header.get_ip_len() - (ip_header.get_ip_hl() + tcp_header.get_th_off()) * 4)
        window_size = tcp_header.get_th_win()
        source = (ip_header.get_ip_src(), tcp_header.get_th_sport())
        destination = (ip_header.get_ip_dst(), tcp_header.get_th_dport())
        connection_id = ConnectionId(source, destination)

        # Set initial relative timestamp
        if not initial_packet_ts:
            initial_packet_ts = packet_ts

        SYN = tcp_header.get_SYN()
        ACK = tcp_header.get_ACK()
        FIN = tcp_header.get_FIN()
        RST = tcp_header.get_RST()

        connection_info = ()
        if not connections.has_key(connection_id):
            connection_state = ConnectionState(SYN, ACK, FIN, RST)
            connection_info = ConnectionInfo(
                                connection_state,
                                source,
                                destination,
                                packet_ts,
                                packet_ts % initial_packet_ts,
                                1,
                                data_bytes,
                                window_size
                              )
        else:
            connection_info = connections[connection_id]

            update_state_flags(connection_info, SYN, ACK, FIN, RST)
            update_connection_duration(connection_info, packet_ts, initial_packet_ts, FIN)
            update_total_data_transfer(connection_info, source, data_bytes)
            update_window_size_list(connection_info, window_size)

        connection_info.rtt_dict[tcp_header.get_th_seq() + data_bytes] = packet_ts

        if connection_info.rtt_dict.has_key(tcp_header.get_th_ack()):
            ts = connection_info.rtt_dict[tcp_header.get_th_ack()]
            connection_info.rtt_list.append(packet_ts - ts)

        connections[connection_id] = connection_info


        packet = pc.next()

def result_logger(connections):
    complete_connections = 0
    reset_connections = 0
    connections_open = 0
    sum_time_dur = 0
    min_time_dur = sys.maxsize
    max_time_dur = 0
    sum_packets = 0
    min_packets = sys.maxsize
    max_packets = 0
    sum_rtt = 0
    min_rtt = sys.maxsize
    max_rtt = 0
    total_rtts = 0
    sum_window_size = 0
    min_window_size = sys.maxsize
    max_window_size = 0
    total_windows = 0
    count = 1

    print('A) Total number of connections: %i' % len(connections))
    print('')

    print("B) Connections' details:")
    print('')
    for key, connection in sorted(connections.iteritems(), key=lambda
            (connection_id, connection_info): (connection_info.source[1], connection_id)):
        source = connection.source
        destination = connection.destination
        status = 'S%sF%s' % (connection.state.SYN, connection.state.FIN)
        if connection.state.is_reset:
            status += ' + R'

        print('++++++++++++++++++++++++++++++++++++++++++++++++')
        print('Connection %i:' % count)
        print('Source Address: %s' % source[0])
        print('Destination Address: %s' % destination[0])
        print('Source Port: %s' % source[1])
        print('Destination Port: %s' % destination[1])
        print('Status: %s' % status)
        if connection.state.is_complete:
            print('Start Time: %.10fs' % connection.start_rs)
            print('End Time: %.10fs' % connection.end_rs)
            print('Duration: %.10fs' % connection.duration_s)
            print('Number of packets sent from Source to Destination: %i' % connection.packets_sent)
            print('Number of packets sent from Destination to Source: %i' % connection.packets_recv)
            print('Total number of packets: %i' % connection.total_packets)
            print('Number of data bytes sent from Source to Destination: %i' % connection.bytes_sent)
            print('Number of data bytes sent from Destination to Source: %i' % connection.bytes_recv)
            print('Total number of data bytes: %i' % connection.total_bytes)

            sum_time_dur += connection.duration_s
            min_time_dur = min(min_time_dur, connection.duration_s)
            max_time_dur = max(max_time_dur, connection.duration_s)

            sum_packets += connection.total_packets
            min_packets = min(min_packets, connection.total_packets)
            max_packets = max(max_packets, connection.total_packets)

            total_rtts += len(connection.rtt_list)
            for rtt in connection.rtt_list:
                sum_rtt += rtt
                min_rtt = min(min_rtt, rtt)
                max_rtt = max(max_rtt, rtt)

            total_windows += len(connection.window_size_list)
            for window_size in connection.window_size_list:
                sum_window_size += window_size
                min_window_size = min(min_window_size, window_size)
                max_window_size = max(max_window_size, window_size)

        print('++++++++++++++++++++++++++++++++++++++++++++++++')
        print('')

        if connection.state.is_complete:
            complete_connections += 1

        if connection.state.is_reset:
            reset_connections += 1

        if connection.state.SYN and connection.state.FIN == 0:
            connections_open += 1

        count += 1

    print('C) General:')
    print('')
    print('Total number of complete TCP connections: %i' % complete_connections)
    print('Number of reset TCP connections: %i' % reset_connections)
    print('Number of TCP connections that were still open when the trace capture ended: %i'
            % connections_open)
    print('')

    print('D) Complete TCP connections:')
    print('')
    print('Minimum time duration: %.10fs' % min_time_dur)
    print('Mean time duration: %.10fs' % (sum_time_dur / complete_connections))
    print('Maximum time duration: %.10fs' % max_time_dur)
    print('')

    print('Minimum RTT value: %.10fs' % min_rtt)
    print('Mean RTT value: %.10fs' % (sum_rtt / total_rtts))
    print('Maximum RTT value: %.10fs' % max_rtt)
    print('')

    print('Minimum number of packets including both send/received: %i' % min_packets)
    print('Mean number of packets including both send/received: %.10f' % (sum_packets / complete_connections))
    print('Maximum number of packets including both send/received: %i' % max_packets)
    print('')
    
    print('Minimum receive window size including both send/received: %i' % min_window_size)
    print('Mean receive window size including both send/received: %.10f' % (sum_window_size / total_windows))
    print('Maximum receive window size including both send/received: %i' % max_window_size)
    print('')

def main():
    filename = sys.argv[1]
    try:
        pc = pcapy.open_offline(filename)
        pc.setfilter('tcp')
    except Exception as e:
        print('Cannot open capture file: %s' % filename)
        return -1

    connections = {}
    initial_packet_ts = 0

    packet_parser(pc, connections, initial_packet_ts)
    result_logger(connections)

    # TODO: Print results for each Section A, B, C, and D

if __name__ == '__main__':
    main()
