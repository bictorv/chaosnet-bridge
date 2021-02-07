# A little test program which sends a string of bytes (the one used by
# BABEL) to an ECHO server and checks that the response is right, or
# if bytes go missing. When they do, the program complains and stops.
# (It doesn't check performance, e.g. pkts/second.)
#
# It prints a "." for each n:th response, where n defaults to 10 and
# can be changed by the --chunk option.

import socket, io
import sys, subprocess, threading, time
import re, string
import functools
from datetime import datetime

# The directory of this need to match the "socketdir" ncp setting in cbridge.
stream_socket_address = '/tmp/chaos_stream'
# -d
debug = False

class StreamConn:
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
        # self.send_packet(Opcode.CLS, msg)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing:',msg)
        self.sock = None

    def get_socket(self):
        address = stream_socket_address
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            print('Socket errror:',msg, file=sys.stderr)
            sys.exit(1)
    
    def send_data(self, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} to {}".format(len(msg), self), file=sys.stderr)
        self.sock.sendall(msg)

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

    def get_line(self):
        rline = b""
        b = self.sock.recv(1)
        while b != b"\r" and b != b"\n":
            rline += b
            b = self.sock.recv(1)
        if b == b"\r":
            b = self.sock.recv(1)
            if b != b"\n":
                print("ERROR: return not followed by newline in get_line from {}: got {}".format(self,b),
                          file=sys.stderr)
                exit(1)
        return rline

    def connect(self, host, contact, args=[]):
        self.contact = contact
        if debug:
            print("RFC to {} for {}".format(host,contact))
        self.send_data(("RFC {} {}"+" {}"*len(args)).format(host,contact,*args))
        inp = self.get_line()
        op, data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"OPN":
            return True
        else:
            print("Expected OPN: {}".format(inp), file=sys.stderr)
            return False

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact))
        self.send_data("LSN {}\r\n".format(contact))
        inp = self.get_line()
        op,data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"RFC":
            self.remote = str(data,"ascii")
            return self.remote
        else:
            print("Expected RFC: {}".format(inp), file=sys.stderr)
            return None


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-c","--chunk", type=int, default=10,
                            help="Chunk length for each '.'")
    parser.add_argument("host", help='The host to contact')
    args = parser.parse_args()
    if args.debug:
        debug = True
    
    xs = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}"
    dlen = len(xs)

    c = StreamConn()
    n = 0
    tot = 0
    if c.connect(args.host, "ECHO"):
        while True:
            c.send_data(xs)
            d = c.get_message(dlen)
            n += 1
            tot += len(d)
            if d != xs:
                print("Echo failed at {} (in {}): {}".format(n, tot, d))
                for i in range(0,len(d)):
                    if xs[i] != d[i]:
                        print("{}: {!r} != {!r}".format(i, d[i], xs[i]))
                break
            if n % args.chunk == 0:
                print(".", end='', flush=True, file=sys.stderr)
            if n % (args.chunk*80) == 0:
                print("", file=sys.stderr)
