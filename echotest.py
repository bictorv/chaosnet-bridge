# Copyright © 2021 Björn Victor (bjorn@victor.se)
# A little test program which sends a string of bytes (the one used by
# BABEL) to an ECHO server and checks that the response is right, or
# if bytes go missing. When they do, the program complains and stops.
# (It doesn't check performance, e.g. pkts/second.)
#
# It prints a "." for each n:th response, where n defaults to 10 and
# can be changed by the --chunk option.

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import socket, io
import sys, subprocess, threading, time
import re, string
import functools
from datetime import datetime
from enum import IntEnum, auto

# The directory of this need to match the "socketdir" ncp setting in cbridge.
stream_socket_address = '/tmp/chaos_stream'
packet_socket_address = '/tmp/chaos_packet'
# -d
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

class NCPConn:
    sock = None
    active = False
    contact = None
    remote = None

    def __init__(self):
        self.get_socket()
    def __str__(self):
        return "<{} {} {} {}>".format(type(self).__name__, self.contact,
                                          "active" if self.active else "passive",
                                          self.remote)
    def __del__(self):
        if debug:
            print("{!s} being deleted".format(self))

    def close(self, msg="Thank you"):
        if debug:
            print("Closing {} with msg {}".format(self,msg), file=sys.stderr)
        self.send_cls(msg)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing:',msg)
        self.sock = None

    def get_socket(self):
        address = self.socket_address
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            print('Socket errror:',msg, file=sys.stderr)
            sys.exit(1)

    def send_socket_data(self, data):
        self.sock.sendall(data)

    def get_bytes(self, nbytes):
        return self.sock.recv(nbytes)

    def get_line(self):
        # Read an OPN/CLS in response to our RFC
        rline = b""
        b = self.get_bytes(1)
        while b != b"\r" and b != b"\n":
            rline += b
            b = self.get_bytes(1)
        if b == b"\r":
            b = self.get_bytes(1)
            if b != b"\n":
                print("ERROR: return not followed by newline in get_line from {}: got {}".format(self,b),
                          file=sys.stderr)
                exit(1)
        return rline

class PacketConn(NCPConn):
    def __init__(self):
        self.socket_address = packet_socket_address
        super().__init__()

    # Construct a 4-byte packet header for chaos_packet connections
    def packet_header(self, opc, plen):
        return bytes([opc, 0, plen & 0xff, int(plen/256)])
  
    def send_data(self, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} to {}".format(len(msg), self), file=sys.stderr)
        self.send_socket_data(self.packet_header(Opcode.DAT, len(msg)) + msg)

    def send_packet(self, opc, data):
        self.send_socket_data(self.packet_header(opc, len(data))+data)

    def send_los(self, msg):
        self.send_packet(Opcode.LOS, msg)
    def send_cls(self, msg):
        self.send_packet(Opcode.CLS, msg)

    def get_packet(self):
        hdr = self.get_bytes(4)
        # First is opcode
        opc = hdr[0]
        # then zero
        assert(hdr[1] == 0)
        # then length
        length = hdr[2] + hdr[3]*256
        assert(length <= 488)
        if debug:
            print("< {} {} {}".format(self,Opcode(opc).name, length), file=sys.stderr)
        return opc, self.get_bytes(length)

    def connect(self, host, contact, args=[], options=None):
        h = bytes(("{} {}"+" {}"*len(args)).format(host,contact.upper(),*args),"ascii")
        if options is not None:
            h = bytes("["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] ","ascii")+h
        if debug:
            print("RFC: {}".format(h), file=sys.stderr)
        self.send_packet(Opcode.RFC, h)
        opc, data = self.get_packet()
        if opc == Opcode.OPN:
            return True
        else:
            print("Expected OPN: {}".format(opc), file=sys.stderr)
            return False

    def get_message(self, dlen=488):
        opc, data = self.get_packet()
        if opc != Opcode.DAT:
            print("Unexpected opcode {}".format(opc), file=sys.stderr)
            return None
        elif len(data) >= dlen:
            return data
        else:
            if debug:
                print("read less than expected: {} < {}, going for more".format(len(data),dlen))
            return data + self.get_message(dlen-len(data))
    
class StreamConn(NCPConn):
    def __init__(self):
        self.socket_address = stream_socket_address
        super().__init__()

    def send_data(self, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} to {}".format(len(msg), self), file=sys.stderr)
        self.send_socket_data(msg)

    def send_los(self, msg):
        # Can't do this over stream interface
        pass
    def send_cls(self, msg):
        # Can't do this over stream interface
        pass

    def connect(self, host, contact, args=[], options=None):
        self.contact = contact
        h = ("{} {}"+" {}"*len(args)).format(host,contact.upper(),*args)
        if options is not None:
            h = "["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] "+h
        if debug:
            print("RFC to {} for {}".format(host,h))
        self.send_data("RFC {}".format(h))
        inp = self.get_line()
        op, data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"OPN":
            return True
        else:
            print("Expected OPN: {}".format(inp), file=sys.stderr)
            return False

    def get_message(self, length=488):
        data = self.sock.recv(length)
        if debug:
            print("< {} of {} from {}".format(len(data), length, self), file=sys.stderr)
        if len(data) < length:
            d2 = self.sock.recv(length-len(data))
            if debug:
                print("< {} of {} from {}".format(len(d2), length, self), file=sys.stderr)
            data += d2
        return data

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-c","--chunk", type=int, default=10,
                            help="Chunk length for each '.'")
    parser.add_argument("-R","--retrans", type=int,
                            help="retransmission time in ms")
    parser.add_argument("-W","--winsize", type=int,
                            help="local window size")
    parser.add_argument("-b","--babel", dest='babelp', action='store_true',
                            help="Use BABEL instead of ECHO")
    parser.add_argument("--goon", dest='goon', action='store_true',
                            help="Go on after mismatch")
    parser.add_argument("-p","--packet", dest='packetp', action='store_true',
                            help="Use packet socket")
    parser.add_argument("-r","--rotate", dest='rotatep', action='store_true',
                            help="Rotate string being sent")
    parser.add_argument("host", help='The host to contact')
    args = parser.parse_args()
    if args.debug:
        debug = True
    
    xs = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}"
    dlen = len(xs)

    if args.packetp:
        if args.babelp:
            print("Babel won't work in packet mode", file=sys.stderr)
            exit(1)
        c = PacketConn()
    else:
        c = StreamConn()
    n = 0
    tot = 0
    cargs=dict()
    if args.retrans and args.retrans > 0:
        cargs['retrans'] = args.retrans
    if args.winsize and args.winsize > 0:
        cargs['winsize'] = args.winsize
    if len(cargs) == 0:
        cargs = None
    if c.connect(args.host, "ECHO" if not args.babelp else "BABEL", options=cargs):
        while True:
            if not args.babelp:
                c.send_data(xs)
            d = c.get_message(dlen)
            n += 1
            tot += len(d)
            if d != xs:
                print(("Echo" if not args.babelp else "Babel") + " failed at {} (in {}): {}".format(n, tot, d))
                for i in range(0,len(d)):
                    if xs[i] != d[i]:
                        print("{}: {!r} != {!r}".format(i, d[i], xs[i]))
                if not(args.goon):
                    break
            if n % args.chunk == 0:
                print(".", end='', flush=True, file=sys.stderr)
            if n % (args.chunk*80) == 0:
                print("", file=sys.stderr)
            if args.rotatep:
                xs = xs[2:]+xs[:2]
