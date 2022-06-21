# Copyright © 2020-2021 Björn Victor (bjorn@victor.se)
# Chaosnet server/forwarder for DOMAIN protocol
# Uses the stream API of the NCP of cbridge, the bridge program for various Chaosnet implementations.

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
# pip3 install dnspython
import dns.resolver

from concurrent.futures import ThreadPoolExecutor

# The directory of this need to match the "socketdir" ncp setting in cbridge.
stream_socket_address = '/tmp/chaos_stream'
# This is the default forwarding server
dns_forwarder_name = 'DNS.Chaosnet.NET'
dns_forwarder_addr = None

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
        self.sock.connect(address)
        return self.sock
        # try:
        #     self.sock.connect(address)
        #     return self.sock
        # except socket.error as msg:
        #     print('Socket error for {}: {}'.format(address,msg), file=sys.stderr)
        #     return None
    
    def send_data(self, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} to {}".format(len(msg), self), file=sys.stderr)
        self.sock.sendall(msg)

    def get_message(self):
        # Read header to see how long the pkt is
        hdr = self.sock.recv(2)
        # length
        if len(hdr) != 2:
            if debug:
                print("Got too few bytes for length: {}".format(len(hdr)), file=sys.stderr)
            return None
        length = hdr[0] + hdr[1]*256
        if debug:
            print("< {} from {}".format(length, self), file=sys.stderr)
        data = self.sock.recv(length)
        return data

    def get_line(self):
        rline = b""
        b = self.sock.recv(1)
        if len(b) == 0:
            if debug:
                print("Received empty string", file=sys.stderr)
            return b
        while len(b) > 0 and b != b"\r" and b != b"\n":
            rline += b
            b = self.sock.recv(1)
        if b == b"\r":
            b = self.sock.recv(1)
            if b != b"\n":
                print("ERROR: return not followed by newline in get_line from {}: got {}".format(self,b),
                          file=sys.stderr)
                exit(1)
        return rline

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact))
        self.send_data("LSN {}\r\n".format(contact))
        inp = self.get_line()
        if len(inp) == 0:
            return None
        op,data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"RFC":
            self.remote = str(data,"ascii")
            return self.remote
        else:
            print("Expected RFC: {}".format(inp), file=sys.stderr)
            return None


class Domain_Server:
    conn = None

    def listen(self):
        self.conn = StreamConn()

        rfc = self.conn.listen("DOMAIN")
        if rfc == None:
            return None
        self.conn.send_data("OPN\r\n")
        try:
            while True:
                request = self.conn.get_message()
                if request is None:
                    if debug:
                        print("Got {} message".format(request), file=sys.stderr)
                    break
                if debug:
                    print("Got request len {} from {}".format(len(request),rfc), file=sys.stderr)
                msg = dns.message.from_wire(request)
                if debug:
                    print("Made DNS message, sending to {}".format(dns_forwarder_addr), file=sys.stderr)
                resp = dns.query.tcp(msg, dns_forwarder_addr)
                if debug:
                    print("Got DNS response {}, sending to {}".format(resp,rfc), file=sys.stderr)
                wresp = resp.to_wire()
                wlen = len(wresp)
                # Send length
                self.conn.send_data(bytes([int(wlen/256), wlen & 0xff]))
                # and data
                self.conn.send_data(wresp)
        except dns.exception.FormError as msg:
            if debug:
                print("DNS Error: {}".format(msg), file=sys.stderr)
            # Should send a LOS, or perhaps CLS, but need packet interface for that
            # self.conn.close(msg)
        except socket.error as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
        self.conn.close()
        return None

debug = False
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet DOMAIN server')
    parser.add_argument("-f","--forwarder", default=dns_forwarder_name,
                            help="DNS forwarder")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    args = parser.parse_args()
    if args.forwarder:
        try:
            # Try to parse it as an IPv4 or IPv6 numeric address
            if socket.inet_pton(socket.AF_INET, args.forwarder):
                dns_forwarder_addr = args.forwarder
            if socket.inet_pton(socket.AF_INET6, args.forwarder):
                dns_forwarder_addr = args.forwarder
        except:
            # and then as a name. OK, this misses ipv6, but...
            dns_forwarder_addr = socket.gethostbyname(args.forwarder)
    if args.debug:
        print(args, file=sys.stderr)
        print("DNS forwarder address: {}".format(dns_forwarder_addr), file=sys.stderr)
        debug = True
    # Start e.g. 5 parallel servers and keep them going
    while True:
        if debug:
            print("Starting Domain_Server", file=sys.stderr)
        try:
            ds = Domain_Server()
            ds.listen()
        except socket.error as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            time.sleep(1)
        time.sleep(0.2)
