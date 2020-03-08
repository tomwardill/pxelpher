import argparse
import socket

from .protocol.dhcp import DHCPPacket, PacketMode

sample_discover_packet = b"\x01\x01\x06\x00&\xf3\x039\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb8'\xeb\x9b\x08\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x017\x0e+<C\x80\x81\x82\x83\x84\x85\x86\x87B\x01\x03]\x02\x00\x00^\x03\x01\x02\x01a\x11\x00\x88\x08\x9bI\x88\x08\x9bI\x88\x08\x9bI\x88\x08\x9bI< PXEClient:Arch:00000:UNDI:002001\xff"


sample_request_packet = b"\x01\x01\x06\x00\xd5:\xc1z\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00RT\x00\x14\xa3\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x039\x02\x05\xc0]\x02\x00\x00^\x03\x01\x02\x01< PXEClient:Arch:00000:UNDI:002001M\x04iPXE7\x17\x01\x03\x06\x07\x0c\x0f\x11\x1a+<BCw\x80\x81\x82\x83\x84\x85\x86\x87\xaf\xcb\xaf3\xb1\x05\x01\x1a\xf4\x10A\xeb\x03\x01\x00\x00\x17\x01\x01\"\x01\x01\x13\x01\x01\x14\x01\x01\x11\x01\x01'\x01\x01\x19\x01\x01)\x01\x01\x10\x01\x02!\x01\x01\x15\x01\x01\x18\x01\x01\x12\x01\x01=\x07\x01RT\x00\x14\xa3\xf7a\x11\x00\xb3c\x0e\x9bGf\xdeD\xb2\xb9.\xc1\xd4\xed\x16i6\x04\x00\x00\x00\x002\x04\xc0\xa8:\x02\xff"


def send_offer(socket, discover_packet):
    offer_packet = DHCPPacket.make_offer(discover_packet)
    raw_packet = offer_packet.make_raw()
    print("< {}".format(offer_packet))
    socket.sendto(raw_packet, ("255.255.255.255", 68))


def send_acknowledgment(socket, request_packet):
    ack_packet = DHCPPacket.make_acknowledgement(request_packet)
    raw_packet = ack_packet.make_raw()
    print("< {}".format(ack_packet))
    socket.sendto(raw_packet, ("255.255.255.255", 68))


def main():

    packet_log = open("dhcp-packet.log", "wb")

    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="Interface to listen on")
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(
        socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode("utf-8")
    )
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    s.bind(("0.0.0.0", 67))
    while True:
        data, addr = s.recvfrom(1024)
        if data:
            packet = DHCPPacket.from_network(data)
            packet_log.write(packet.RawPacket)
            print("> {}".format(packet))
            if packet.mode == PacketMode.DISCOVER:
                send_offer(s, packet)
            elif packet.mode == PacketMode.REQUEST:
                send_acknowledgment(s, packet)