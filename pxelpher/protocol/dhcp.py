import binascii
from enum import Enum

from dataclasses import dataclass


class PacketMode(Enum):

    DISCOVER = 1
    OFFER = 2
    REQUEST = 3


class DHCPOption:

    def __init__(self, code, length, value):
        self.code = code
        self.length = length
        self.value = value

    def __repr__(self):
        return "DHCP Option {}: {}".format(self.code, self.value)

    def encoded(self):
        return '{}{}{}'.format(
            chr(self.code),
            chr(self.length),
            self.value
        ).encode()


def f_i2h(int_to_format):
    return '0x{:02x}'.format(int_to_format)


def ip_to_hex(ip):
    return bytearray(int(x) for x in ip.split('.'))
    #return (''.join(chr(int(x)) for x in ip.split('.'))).encode()
    #return '0x{}'.format(''.join('{:02x}'.format(int(x)) for x in ip.split('.')).upper())


@dataclass
class DHCPPacket:
    Op: int
    HType: int
    HLen: int
    Hops: int
    XID: str
    Secs: int
    Flags: bytearray
    CiAddr: bytearray
    YiAddr: bytearray
    SiAddr: bytearray
    GiAddr: bytearray
    CHAddr: bytearray
    SName: str
    File: str
    RawOptions: bytearray
    RawPacket: bytearray

    def __repr__(self):
        return "{} from {}".format(self.mode, self.hardware_address)

    @property
    def is_broadcast(self):
        return self.Flags == 1

    @property
    def magic_cookie(self):
        cookie_bytes = self.RawOptions[0:4]
        return '.'.join(str(int(i)) for i in cookie_bytes)

    @property
    def raw_magic_cookie(self):
        return self.RawOptions[0:4]

    @property
    def Options(self):
        available_options = []
        without_magic_cookie = self.RawOptions[4:]
        i = 0
        while without_magic_cookie[i] != 255:
            code = without_magic_cookie[i]
            i = i + 1
            length = without_magic_cookie[i]
            i = i + 1
            value = without_magic_cookie[i:i+length]
            i = i + length
            available_options.append(DHCPOption(
                code, length, value
            ))
        return available_options

    @property
    def mode(self):
        for option in self.Options:
            if option.code == 53:
                return PacketMode(
                    int.from_bytes(option.value, byteorder='big'))
        raise ValueError("No mode Option found")

    @property
    def hardware_address(self):
        bin_representation = binascii.hexlify(self.CHAddr[0:6]).decode()
        string_rep = "{}:{}:{}:{}:{}:{}".format(
            bin_representation[0:2],
            bin_representation[2:4],
            bin_representation[4:6],
            bin_representation[6:8],
            bin_representation[8:10],
            bin_representation[10:12],
        )
        return string_rep

    @staticmethod
    def from_network(packet):
        discover = DHCPPacket(
            Op=packet[0],
            HType=packet[1],
            HLen=packet[2],
            Hops=packet[3],
            XID=binascii.hexlify(packet[4:8]),
            Secs=int.from_bytes(packet[8:10], byteorder='big'),
            Flags=packet[10:12],
            CiAddr=packet[12:16],
            YiAddr=packet[16:20],
            SiAddr=packet[20:24],
            GiAddr=packet[24:28],
            CHAddr=packet[28:44],
            SName=packet[44:108],
            File=packet[108:236],
            RawOptions=packet[236:],
            RawPacket=packet
        )
        return discover

    @staticmethod
    def make_offer(discover_packet):
        raw_options = discover_packet.raw_magic_cookie
        offer_option = DHCPOption(53, 1, chr(2))
        raw_options = raw_options + offer_option.encoded() + b'\xff'
        offer = DHCPPacket(
            Op=chr(2).encode(),
            HType=chr(1).encode(),
            HLen=chr(6).encode(),
            Hops=chr(0).encode(),
            XID=binascii.unhexlify(discover_packet.XID),
            Secs=b'\x00\x00',
            Flags=b'\x00\x00',
            CiAddr=b'\x00\x00\x00\x00',
            YiAddr=ip_to_hex('192.168.58.2'),
            SiAddr=ip_to_hex('192.168.58.1'),
            GiAddr=ip_to_hex('0.0.0.0'),
            CHAddr=discover_packet.CHAddr,
            SName=discover_packet.SName,
            File=discover_packet.File,
            RawOptions=raw_options,
            RawPacket='unknown'
        )
        return offer

    def make_raw(self):
        packet = self.Op + self.HType + self.HLen + self.Hops + self.XID + self.Secs + self.Flags + self.CiAddr + self.YiAddr + self.SiAddr + self.GiAddr + self.CHAddr + self.SName + self.File + self.RawOptions
        return packet
