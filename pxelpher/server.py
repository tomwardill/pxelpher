import socket

from .protocol.dhcp import DiscoverPacket


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"enx00e04c3602af")

    s.bind(("0.0.0.0", 67))
    while True:
        data, addr = s.recvfrom(1024)
        if data:
            discover = DiscoverPacket.from_network(data)
            print(discover)
