import sys
import pcapy

def main():
    print('Hello, world')
    pc = pcapy.open_offline(sys.argv[1])

if __name__ == '__main__':
    main()
