import binascii

from dataclasses import dataclass


@dataclass
class DiscoverPacket:
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

    @property
    def is_broadcast(self):
        return self.Flags == 1

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
        discover = DiscoverPacket(
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
            CHAddr=packet[28:45]
        )
        return discover
