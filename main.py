import sys
import pcapy

def main():
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    data = pc.next()
    total_packets = 0
    while data[0]:
        print(data)
        data = pc.next()
        total_packets += 1

    print('Total number of packets:', total_packets)

if __name__ == '__main__':
    main()
