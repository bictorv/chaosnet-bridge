## Add dns stuff

import socket, io
import sys, subprocess, threading
import re, string
import functools
from struct import unpack
from datetime import datetime, timedelta
from pprint import pprint, pformat
from enum import IntEnum, auto

from concurrent.futures import TimeoutError, ProcessPoolExecutor
# Pebble works in 3.6, but seems not yet to work in 3.7
from pebble import ProcessPool

import dns.resolver

# server_address = '/tmp/chaos_stream'
packet_address = '/tmp/chaos_packet'

debug = False

  
# Chaos packet opcodes
class Opcode(IntEnum):
    RFC = 1
    OPN = auto()
    CLS = auto()
    FWD = auto()
    ANS = auto()
    SNS = auto()
    STS = auto()
    RUT = auto()
    LOS = auto()
    LSN = auto()
    MNT = auto()
    EOF = auto()                          # with NCP, extended with optional "wait" data part which is never sent on the wire
    UNC = auto()
    BRD = auto()
    ACK = 0o177                           # new opcode to get an acknowledgement from NCP when an EOF+wait has been acked
    DAT = 0o200
    SMARK = 0o201                       # synchronous mark
    AMARK = 0o202                       # asynchronous mark
    DWD = 0o300

#### sockets and simple conns

class Conn:
    sock = None

    def __init__(self):
        self.get_socket()

    # Construct a 4-byte packet header for chaos_packet connections
    def packet_header(self, opc, plen):
        return bytes([opc, 0, plen & 0xff, int(plen/256)])

    def get_socket(self):
        address = '/tmp/chaos_packet'
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            print('Socket errror:',msg, file=sys.stderr)
            sys.exit(1)


    def send_packet(self, opcode, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} {} {}".format(self,Opcode(opcode).name, len(msg)), file=sys.stderr)
        self.sock.sendall(self.packet_header(Opcode(opcode), len(msg)) + msg)

    def get_packet(self):
        # Read header to see how long the pkt is
        hdr = self.sock.recv(4)
        if hdr is None or len(hdr) < 4:
            print("Bad header {!r}".format(hdr), file=sys.stderr)
            return None
        # First is opcode
        opc = hdr[0]
        # then zero
        assert(hdr[1] == 0)
        # then length
        length = hdr[2] + hdr[3]*256
        assert(length <= 488)
        if debug:
            print("< {} {} {}".format(self,Opcode(opc).name, length), file=sys.stderr)
        data = self.sock.recv(length)
        # print("< {} {!s}".format(len(data), str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")))
        return (opc,data)


class Broadcast:
    conn = None
    def __init__(self, subnets, contact, args=[], options=None):
        self.conn = Conn()
        # print("Simple({} {}) t/o {}".format(host,contact, timeout))
        h = ("{} {}"+" {}"*len(args)).format(",".join(map(str,subnets)),contact,*args)
        if options is not None:
            h = "["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] "+h
        dlist = []
        try:
            if debug:
                print("BRD {}".format(h), file=sys.stderr)
            self.conn.send_packet(Opcode.BRD, bytes(h,"ascii"))
        except socket.error:
            return dlist
    def __iter__(self):
        return self
    def __next__(self):
        opc, data = self.conn.get_packet()
        if opc == Opcode.ANS:
            if debug:
                src = data[0] + data[1]*256
                print("Got ANS from {:o} len {}".format(src,len(data)), file=sys.stderr)
            return data
        elif opc == Opcode.LOS:
            raise StopIteration
        else:
            print("Got {} ({})".format(Opcode(opc).name, data), file=sys.stderr)



# The STATUS protocol
class Status:
    def __init__(self,subnets, options=None):
        self.slist = self.get_status(subnets, options)
    def statuses(self):
        return self.slist
    def print_hostat(self,hname,src,sts):
        # Only print the name for the first subnet entry
        if src != 1:
            # ITS sends ANS from address 1!
            first = "{} ({:o})".format(hname, src)
        else:
            first = hname
        if sts is not None:
            for s in sts:
                print(("{:<25s}{:>6o} "+"{:>8} "*len(sts[s])).format(first,s,*sts[s].values()))
                first = ""
        else:
            print("{} not responding".format(first))
    def get_status(self, subnets, options):
        hlist = []
        print(("{:<25s}{:>6s} "+"{:>8} "*8).format("Name","Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected"))
        for data in Broadcast(subnets,"STATUS", options=options):
            src = data[0] + data[1]*256
            data = data[2:]
            dlen = len(data)
            # First is the name of the node
            hname = str(data[:32].rstrip(b'\0x00'),'ascii')
            if hname in hlist:
                continue
            hlist.append(hname)
            fstart = 32
            statuses = dict()
            try:
                while fstart+14 < dlen:
                    # Two 16-bit words of subnet and field length
                    subnet,flen = unpack('H'*2,data[fstart:fstart+4])
                    # But subnet is +0400
                    assert (subnet > 0o400) and (subnet < 0o1000)
                    subnet -= 0o400
                    # Then a number of doublewords of info
                    fields = unpack('{}I'.format(int(flen/2)), data[fstart+4:fstart+4+(flen*2)])
                    statuses[subnet] = dict(zip(('inputs','outputs','aborted','lost','crc_errors','hardware','bad_length','rejected'),
                                                    fields))
                    fstart += 4+flen*2
            except AssertionError:
                print('{} value error at {}: {!r}'.format(hname,fstart,data[fstart:]))
            self.print_hostat(hname, src, statuses)
        return None



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet STATUS broadcast')
    parser.add_argument("subnets", metavar="S", type=int, nargs='+',
                            help="Subnets to broadcast on (must include the local one)")
    parser.add_argument("-t","--timeout", type=int, default=2,
                            help="Timeout in seconds")
    parser.add_argument("-r","--retrans", type=int, default=1000,
                            help="Retransmission interval in milliseconds")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    args = parser.parse_args()
    if args.debug:
        print(args)
        debug = True
    sts = Status(args.subnets,dict(timeout=args.timeout, retrans=args.retrans))
