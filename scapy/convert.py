from scapy.all import *

CONVERT_TLVS = {
    0x1: 'info',
    0xa: 'connect',
    0x14: 'extended',
    0x15: 'supported',
    0x16: 'cookie',
    0x1e: 'error',
}


class _ConvertTLV_HDR(Packet):
    fields_desc = [ByteEnumField(
        "type", 0, CONVERT_TLVS), ByteField("length", 1), ]


class ConvertTLV(Packet):
    name = "Convert TLV"
    fields_desc = [_ConvertTLV_HDR, ShortField("padding", 0)]

    def extract_padding(self, s):
        return '', s


class ConvertTLV_Info(ConvertTLV):
    type = 0x1


class ConvertTLV_Error(ConvertTLV):
    type = 0x1e
    fields_desc = [_ConvertTLV_HDR, ByteField(
        "error_code", 0), ByteField("value", 0), ]


class ConvertTLV_Connect(ConvertTLV):
    type = 0xa
    length = 5
    fields_desc = [_ConvertTLV_HDR, ShortField(
        "remote_port", None), IP6Field("remote_addr", None), ]


class Convert(Packet):
    name = "Convert"
    fields_desc = [ByteField("version", 1),
                   FieldLenField("total_length", None, length_of="tlvs",
                                 fmt="B", adjust=lambda _, l: int(1 + l / 4)),
                   ShortField("reserved", 0),
                   PacketListField("tlvs", None, ConvertTLV)]


if __name__ == '__main__':
    # samples.
    print(str(Convert()))
    hexdump(Convert().build())

    c = Convert(tlvs=[ConvertTLV_Error(), ConvertTLV_Info(),
                      ConvertTLV_Connect(remote_addr="::1", remote_port=80)])
    c.show()
    hexdump(c.build())
