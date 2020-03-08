import argparse
import socket


def main():

    packet_log = open("tftp-packet.log", "wb")

    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="Interface to listen on")
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(
        socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode("utf-8")
    )
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    s.bind(("0.0.0.0", 69))
    while True:
        data, addr = s.recvfrom(1024)
        print(data)
        print(addr)
