# Copyright © 2021 Björn Victor (bjorn@victor.se)
# Chaosnet server for FINGER protocol, mainly used by Lisp Machines.
# (NOT what is otherwise known as finger, but a different protocol on Chaosnet.)
# Demonstrates the APIs for the NCP of cbridge: both the simpler stream protocol and the packet protocol.

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

def get_fullname(user):
    import pwd
    try:
        p = pwd.getpwnam(str(user,"ascii"))
        if debug:
            print("user {} = {}".format(user,p), file=sys.stderr)
        return p.pw_gecos.replace("ö","o").replace("å","a").replace("ä","a")
    except KeyError:
        if debug:
            print("user {} not found".format(user), file=sys.stderr)
        return ""

def get_console_user():
    r = subprocess.run(["/usr/bin/w","-h"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    if len(rout) > 0:
        for l in rout:
            u,con,rest = l.split(maxsplit=2)
            if con == b'console':
                return u
        if debug:
            print("Can't find console, using first line for uname: {}".format(rout[0]), file=sys.stderr)
        uname,rest = rout[0].split(maxsplit=1)
        return uname
    return b""

def get_idle_time(user):
    r = subprocess.run(["/usr/bin/w","-h",user], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    idle = 65534
    if len(rout) > 0:
        for l in rout:
            idl = 65534
            u,con,src,login,i,what = l.split(maxsplit=5)
            if i == b'-':
                idl = 0
            elif re.fullmatch(b'[0-9]+', i):
                idl = int(i)*60
            elif b':' in i:
                ids = i.split(b':')
                if len(ids) == 2:
                    if ids[1].endswith(b'm'):
                        ids[1] = ids[1][:-1]
                    idl = int(ids[0])*60 + int(ids[1])
            else:
                ids = str(i,"ascii")
                m = re.match(r'(\d+(\.\d+)?)s',ids)
                if m is not None:
                    idl = float(m[1])
                else:
                    m = re.match(r'(\d+)d(ay)?', ids)
                    if m is not None:
                        idl = int(m[1])*24*60*60
                    else:
                        print("Unknown idle format: {}".format(ids), file=sys.stderr)
            if debug:
                print("Idle time {} parsed to {}".format(i,idl), file=sys.stderr)
            if idl < idle:
                idle = idl
    else:
        print("No lines from w: {}".format(rout), file=sys.stderr)
    return idle

def idlestring_min(sec):
    min = sec//60
    if min == 0:
        return b''
    elif min < 60:
        return bytes("0:{:02}".format(min), "ascii")
    elif min < 24*60:
        return bytes("{}:{:02}".format(min//(60), min % (60)), "ascii")
    elif min < 7*24*60:
        return bytes("{}d".format(min//(60*24)),"ascii")
    else:
        return b"*:**"


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-l","--location", default="Here",
                            help="Set the location of your system")
    args = parser.parse_args()
    if args.debug:
        debug = True
        print(args, file=sys.stderr)

    loc = bytes(args.location,"ascii")
    cont = "FINGER"
    last = 0
    while True:
        try:
            c = PacketConn()
            h = c.listen(cont)
            if debug:
                print("Conn from {}".format(h), file=sys.stderr)
            # get some real data to send
            if time.time() - last > 60:
                uname = get_console_user()
                pname = bytes(get_fullname(uname),"ascii")
                idle = get_idle_time(uname)
                last = time.time()
                if debug:
                    print("Updated u,p,i,is: {} {} {} {}".format(uname,pname,idle,idlestring_min(idle)), file=sys.stderr)
            c.send_ans(b"\215".join([uname,loc,idlestring_min(idle),pname,b"-"])+b"\215")
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

