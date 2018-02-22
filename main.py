import sys
import pcapy

def main():
    print('Hello, world')
    pc = pcapy.open_offline(sys.argv[1])
    data = pc.next()
    while data[0]:
        print(data)
        data = pc.next()

if __name__ == '__main__':
    main()
