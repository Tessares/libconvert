from scapy.all import *
from convert import *
import time

conf.L3socket = L3RawSocket


class MockConverter:
    actions = None

    def __init__(self, address='127.0.0.1', port=1234):
        self.address = address
        self.port = port

        for a in self.actions:
            a.run(self)


class Action:
    def run(self, converter):
        raise NotImplemented("please implement run()")


class Wait(Action):
    def __init__(self, seconds):
        self.seconds = seconds

    def run(self, converter):
        time.sleep(self.seconds)


class RecvPkt(Action):
    def __init__(self, npkts=1):
        self.number_of_pkts = npkts

    def run(self, converter):
        pkts = sniff(count=self.number_of_pkts, iface="lo", filter="tcp and host {0} and port {1}".format(converter.address,
                                                                                                          converter.port))
        pkt = pkts[0]

        print("received pkt:", pkt.summary())

        tcp = pkt.getlayer(TCP)

        # store info
        converter.caddr = str(pkt.src)
        converter.cport = pkt.sport
        converter.recv_seq = tcp.seq
        converter.recv_end_seq = tcp.seq
        if tcp.flags.S:
            converter.recv_end_seq += 1
        if tcp.flags.F:
            converter.recv_end_seq += 1
        payload = pkt.getlayer(Raw)
        if payload:
            payload = payload.load

            converter.recv_end_seq += len(payload)

            # For the moment, we assume the TLV connect contains the header (4 bytes)
            # and the TLV Connect (4 + 16 bytes). The cookie is then at the offset 24.
            cookie_flag_offset = 24

            # The cookie will only be received in the syn pkt.
            if tcp.flags.S and len(payload) > cookie_flag_offset and bytes(payload)[cookie_flag_offset] == 0x16:

                # The cookie TLV is as follows: 1 byte flag + 1 byte TLV length
                # + 2 byte zeros, then Cookie data
                cookie_size_offset = cookie_flag_offset + 1
                cookie_data_offset = cookie_flag_offset + 4

                # Length is given in 32-bit words, and includes flag byte + length
                # byte and the 2 bytes of zeros.
                cookie_data_size = (bytes(payload)[cookie_size_offset] - 1) * 4

                cookie_data_offset_end = cookie_data_offset + cookie_data_size

                cookie_bytes = bytes(payload)[cookie_data_offset:cookie_data_offset_end]
                converter.cookie = cookie_bytes.decode('utf-8').rstrip('\x00')


class RecvSyn(RecvPkt):
    pass


class RecvHTTPGet(RecvPkt):
    pass


class SendPkt(Action):
    def __init__(self, flags="A", payload=None):
        self.flags = flags
        self.payload = payload

    def run(self, converter):
        seq = converter.seq
        pkt = IP(src=converter.address, dst=converter.address)

        tcp = TCP(sport=converter.port, dport=converter.cport,
                  flags=self.flags, seq=converter.seq, ack=converter.recv_end_seq)
        pkt /= tcp

        if tcp.flags.S:
            converter.seq += 1
        if tcp.flags.F:
            converter.seq += 1
        if self.payload:
            converter.seq += len(self.payload)
            pkt /= self.payload

        send(pkt)


class SendSynAck(SendPkt):
    def __init__(self, payload=None):
        SendPkt.__init__(self, flags="SA", payload=payload)

    def run(self, converter):
        # use the same seq as the one in the SYN.
        converter.seq = converter.recv_seq
        super(SendSynAck, self).run(converter)


class SendSynAckCheckCookie(SendSynAck):
    def __init__(self, payload, cookie):
        SendSynAck.__init__(self, payload=payload)
        self.cookie = cookie

    def run(self, converter):
        # Check cookie value
        if self.cookie != converter.cookie:
            raise Exception("Wrong cookie '{}' instead of '{}'".format(converter.cookie, self.cookie))
        super(SendSynAckCheckCookie, self).run(converter)


class SendHTTPResp(SendPkt):
    def __init__(self, data):
        payload = "HTTP/1.1 200 OK\r\n"
        payload += "Server: exampleServer\r\n"
        payload += "Content-Length: {}\r\n".format(len(data))
        payload += "\r\n"
        payload += data
        SendPkt.__init__(self, flags="A", payload=payload)
