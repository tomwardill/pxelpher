import argparse
import socket

from .protocol.dhcp import DHCPPacket, PacketMode

sample_discover_packet = b"\x01\x01\x06\x00&\xf3\x039\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb8'\xeb\x9b\x08\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x017\x0e+<C\x80\x81\x82\x83\x84\x85\x86\x87B\x01\x03]\x02\x00\x00^\x03\x01\x02\x01a\x11\x00\x88\x08\x9bI\x88\x08\x9bI\x88\x08\x9bI\x88\x08\x9bI< PXEClient:Arch:00000:UNDI:002001\xff"


def send_offer(socket, discover_packet):
    offer_packet = DHCPPacket.make_offer(
        discover_packet
    )
    raw_packet = offer_packet.make_raw()
    socket.sendto(raw_packet, ('255.255.255.255', 68))


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help="Interface to listen on")
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode('utf-8'))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    s.bind(("0.0.0.0", 67))
    while True:
        data, addr = s.recvfrom(1024)
        if data:
            packet = DHCPPacket.from_network(data)
            print(packet)
            if packet.mode == PacketMode.DISCOVER:
                send_offer(s, packet)
