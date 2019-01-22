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
        pkts = sniff(count=self.number_of_pkts, filter="tcp and host {0} and port {1}".format(converter.address,
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
            converter.recv_end_seq += len(payload.load)


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


class SendHTTPResp(SendPkt):
    def __init__(self, data):
        payload = "HTTP/1.1 200 OK\r\n"
        payload += "Server: exampleServer\r\n"
        payload += "Content-Length: {}\r\n".format(len(data))
        payload += "\r\n"
        payload += data
        SendPkt.__init__(self, flags="A", payload=payload)
