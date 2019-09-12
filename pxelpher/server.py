import argparse
import socket

from .protocol.dhcp import DiscoverPacket


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help="Interface to listen on")
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode('utf-8'))

    s.bind(("0.0.0.0", 67))
    while True:
        data, addr = s.recvfrom(1024)
        if data:
            discover = DiscoverPacket.from_network(data)
            print(discover)
