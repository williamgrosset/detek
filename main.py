import sys
import pcapy

def main():
    pc = pcapy.open_offline(sys.argv[1])
    pc.setfilter('tcp')

    data = pc.next()
    while data[0]:
        print(data)
        data = pc.next()

if __name__ == '__main__':
    main()
