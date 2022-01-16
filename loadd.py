# Copyright © 2022 Björn Victor (bjorn@victor.se)
# Chaosnet server for LOAD protocol, mainly used by ITS.
# This is a simple protocol with returns a string a'la "Fair Share: X%\r\nUsers: N."
#
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
import datetime
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
            print("{!s} being deleted".format(self), file=sys.stderr)

    def close(self, msg="Thank you"):
        if debug:
            print("Closing {} with msg {}".format(self,msg), file=sys.stderr)
        if msg is not None:
            self.send_cls(bytes(msg,"ascii"))
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing: {}'.format(msg), file=sys.stderr)
        self.sock = None

    def get_socket(self):
        address = self.socket_address
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        self.sock.connect(address)
        return self.sock
        # try:
        #     self.sock.connect(address)
        #     return self.sock
        # except socket.error as msg:
        #     print('Socket errror for {}: {}'.format(address,msg), file=sys.stderr)
        #     sys.exit(1)

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

    def send_packet(self, opc, data=None):
        if data is None:
            self.send_socket_data(self.packet_header(opc, 0))
        else:
            self.send_socket_data(self.packet_header(opc, len(data))+data)

    def send_los(self, msg):
        self.send_packet(Opcode.LOS, msg)
    def send_cls(self, msg):
        self.send_packet(Opcode.CLS, msg)
    def send_ans(self, msg):
        if debug:
            print("Sending ANS pkt with {}".format(msg), file=sys.stderr)
        self.send_packet(Opcode.ANS, msg)

    def get_packet(self):
        hdr = self.get_bytes(4)
        if len(hdr) < 4:
            if debug:
                print("Bad pkt header length {}: {}".format(len(hdr),hdr), file=sys.stderr)
            return None,None
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

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact), file=sys.stderr)
        self.send_packet(Opcode.LSN,bytes(contact,"ascii"))
        op,data = self.get_packet()
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == Opcode.RFC:
            self.remote = str(data,"ascii")
            # self.send_packet(Opcode.OPN)
            return self.remote
        elif op == Opcode.BRD:
            self.remote = str(data,"ascii")
            return self.remote
        else:
            if debug:
                print("Expected RFC: {}".format(op), file=sys.stderr)
            return None

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
        elif opc == Opcode.ANS:
            print("Got ANS len {}: {}".format(len(data),data), file=sys.stderr)
            return False
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
                print("read less than expected: {} < {}, going for more".format(len(data),dlen), file=sys.stderr)
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
    def send_ans(self, msg):
        self.send_data("ANS {}".format(msg))

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact), file=sys.stderr)
        self.send_data("LSN {}\r\n".format(contact))
        inp = self.get_line()
        op,data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"RFC":
            self.remote = str(data,"ascii")
            return self.remote
        elif op == b"BRD":
            self.remote = str(data,"ascii")
            return self.remote
        else:
            if debug:
                print("Expected RFC: {}".format(inp), file=sys.stderr)
            return None

    def connect(self, host, contact, args=[], options=None):
        self.contact = contact
        h = ("{} {}"+" {}"*len(args)).format(host,contact.upper(),*args)
        if options is not None:
            h = "["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] "+h
        if debug:
            print("RFC to {} for {}".format(host,h), file=sys.stderr)
        self.send_data("RFC {}".format(h))
        inp = self.get_line()
        op, data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"OPN":
            return True
        elif op == b"ANS":
            r = data.split(b' ', maxsplit=1)
            dlen = int(r[0])
            print("Got ANS len {}: {}".format(dlen, r[1]), file=sys.stderr)
            return False
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


def get_load():
    # get nusers by "users" rather than "uptime",
    # since uptime counts every window, while users counts logins (I think)
    r = subprocess.run(["/usr/bin/users"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    nusers = len(rout[0].split(b" "))
    if debug:
        print("/usr/bin/users found {} users".format(nusers), file=sys.stderr)
    r = subprocess.run(["/usr/bin/uptime"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    if len(rout) > 0:
        line = str(rout[0],"ascii")
        if debug:
            print("Got line {} and output {}".format(line,rout), file=sys.stderr)
        num = re.search(r'([0-9]+) users', line)
        load = re.search(r'load averages?: ([0-9.]+)', line)
        if num is None or load is None:
            if debug:
                print("Can't find nusers or load: {} {}".format(num,load), file=sys.stderr)
            return None,None
        else:
            # return num[1],float(load[1])
            return nusers,float(load[1])
    elif debug:
        print("No output from uptime?", file=sys.stderr)
    return None,None

# Try to calculate "fair share" given the load and nr of users
def fairshare(load, nusers=1):
    from multiprocessing import cpu_count
    ncpu = cpu_count()
    if debug:
        print("Load {} on {} cores with {} users = {} used up".format(load,ncpu,nusers,load/ncpu/max(nusers,1)), file=sys.stderr)
    return round(100*(1-(load/ncpu/max(1,nusers))))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-c",'--cachetime',type=int, default=60,
                            help="Seconds to cache calculated load")
    args = parser.parse_args()
    if args.debug:
        debug = True
        print(args, file=sys.stderr)

    cont = "LOAD"
    last = 0
    while True:
        try:
            c = PacketConn()
            h = c.listen(cont)
            if debug:
                print("Conn from {}".format(h), file=sys.stderr)
            # get some real data to send
            if time.time() - last > args.cachetime:
                nusers,load = get_load()
                last = time.time()
                if debug:
                    print("Updated n,l: {} {}".format(nusers,load), file=sys.stderr)
            if nusers is not None:
                c.send_ans(bytes("Fair Share: {}%\r\nUsers: {}.".format(max(0,fairshare(load, nusers)), nusers),"ascii"))
        except (BrokenPipeError, socket.error) as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            time.sleep(10)
            continue
        # No need to close, this is a simple protocol
        # try:
        #     c.close(None)
        # except socket.error as msg:
        #     if debug:
        #         print("Socket error: {}".format(msg), file=sys.stderr)
        #     pass

