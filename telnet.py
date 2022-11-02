# Copyright © 2022 Björn Victor (bjorn@victor.se)
# Chaosnet client for TELNET protocol (not SUPDUP, just to keep it simple for now)
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
from datetime import datetime
from enum import IntEnum, auto
import tty, termios

#from concurrent.futures import ThreadPoolExecutor
#import multiprocessing as mp


# The directories of these need to match the "socketdir" ncp setting in cbridge.
# The directory of this need to match the "socketdir" ncp setting in cbridge.
stream_socket_address = '/tmp/chaos_stream'
packet_socket_address = '/tmp/chaos_packet'
# -d
debug = False
packetp = False
broadcastp = False

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

    def close(self, msg=b"Thank you"):
        if debug:
            print("Closing {} with msg {}".format(self,msg), file=sys.stderr)
        self.send_cls(msg)
        time.sleep(0.5)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing:',msg)

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

    def send_packet(self, opc, data=None):
        if debug:
            print(">>> {} len {}".format(Opcode(opc).name, len(data) if data is not None else 0), file=sys.stderr)
        if data is None:
            self.send_socket_data(self.packet_header(opc, 0))
        else:
            self.send_socket_data(self.packet_header(opc, len(data))+data)

    def send_los(self, msg):
        self.send_packet(Opcode.LOS, msg)
    def send_cls(self, msg):
        self.send_packet(Opcode.CLS, msg)

    def get_packet(self):
        hdr = self.get_bytes(4)
        if hdr is None or len(hdr) == 0:
            # This is handled somewhere
            raise OSError("Error: Got no bytes: {}".format(hdr))
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
            print("Listen for {}".format(contact))
        self.send_packet(Opcode.LSN,bytes(contact,"ascii"))
        op,data = self.get_packet()
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == Opcode.RFC:
            self.remote = str(data,"ascii")
            self.send_packet(Opcode.OPN)
            return self.remote
        else:
            print("Expected RFC: {}".format(inp), file=sys.stderr)
            return None

    def connect(self, host, contact, args=[], options=None):
        h = bytes(("{} {}"+" {}"*len(args)).format(host,contact.upper(),*args),"ascii")
        if options is not None:
            h = bytes("["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] ","ascii")+h
        if debug:
            print("Options: {} = {}".format(options, h), file=sys.stderr)
            print("RFC: {}".format(h), file=sys.stderr)
        self.send_packet(Opcode.RFC, h)
        opc, data = self.get_packet()
        if opc == Opcode.OPN:
            self.active = True
            self.remote = str(data,"ascii")
            self.contact = contact
            return True
        else:
            print("Expected OPN: {}".format(opc), file=sys.stderr)
            return False

    def get_message(self, dlen=488):
        opc, data = self.get_packet()
        if opc == Opcode.CLS:
            self.close()
            return None
        elif opc == Opcode.LOS:
            if True or debug:
                print("{} got LOS: {}".format(self,data), file=sys.stderr)
            return None
        elif opc == Opcode.EOF:
            if debug:
                print("{} got EOF: {}".format(self,data), file=sys.stderr)
            return None
        elif opc != Opcode.DAT:
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
            self.active = True
            self.remote = host                  #should parse OPN data
            self.contact = contact
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

t_cmds = {240: "SE", 250: "SB", 241: "NOP", 243: "Break", 244: "INT", 246: "AYT", 249: "GA",
              251: "WILL", 252: "WONT", 253: "DO", 254: "DONT"}
t_willdo_neg = {251: 254, 252: 253, 253: 252, 254: 251}
t_willdo_agree = {251: 253, 252: 254, 253: 251, 254: 252}
t_opts = {1:"ECHO",3:"SUPRGA",21:"Supdup",22:"SupdupOutput",23:"SendLoc",24:"TTYTYPE"}

def descr_willdo(willdo,opt):
    return "{} {}".format(t_cmds[willdo],t_opts[opt] if opt in t_opts else opt)

def input_handler(sock, once=False):
    data = []
    while True:
        try:
            data = sock.get_message(1)
        except OSError as e:
            if debug:
                print("Error getting message: {}".format(e),file=sys.stderr)
            return
        if debug:
            print("<< read {} bytes from remote: {}".format(len(data) if data is not None else 0,data), file=sys.stderr)
        if data is None:
            if debug:
                print("input_handler got None for message, quitting", file=sys.stderr)
            return
        # Handle IAC WILL/WONT
        i = 0
        while i < len(data):
            # if debug:
            #     print("<< byte {}<{}: {}".format(i,len(data),data[i]), file=sys.stderr)
            c = data[i]
            if c == 0xff:            #IAC
                if i+2 < len(data):
                    if data[i+1] in range(251,254):
                        if debug:
                            print("[IAC {}]".format(descr_willdo(data[i+1], data[i+2])), file=sys.stderr)
                        # Just agree
                        if data[i+2] == 21:   #except for Supdup
                            agree = [255,t_willdo_neg[data[i+1]],data[i+2]]
                        else:
                            agree = [255,t_willdo_agree[data[i+1]],data[i+2]]
                        if debug:
                            print("> reply {}".format(descr_willdo(agree[1],agree[2])), file=sys.stderr)
                        sock.send_data(bytes(agree))
                        i = i+3
                        continue
                if i+2 < len(data) and data[i+1] == 250:   #subnegotiation
                    e = data.find(240,i+2)
                    if e > i:
                        if debug:
                            print("[Subnegotiation: {}]".format(data[i+2:e]),file=sys.stderr)
                        i = e
                    if debug:
                        print("[Subnegotiation: no end found!]",file=sys.stderr)
                elif i+1 < len(data):
                    if debug:
                        print("[IAC {}]".format(t_cmds[data[i+1]] if data[i+1] in t_cmds else data[i+1]), file=sys.stderr)
                    i = i+2
                    continue
                elif debug:
                    print("[IAC]",file=sys.stderr)
                i = i+1
            elif c == 0o215:
                if debug:
                    print("[Newline]", file=sys.stderr)
                print("",flush=True)                 #newline
            elif c > 127:
                if debug:
                    print("[8bit]", file=sys.stderr)
                print("{:x}".format(c),end='',flush=True)
            else:
                if debug:
                    print("[normal char {}]".format(c), file=sys.stderr)
                else:
                    print(chr(c),end='',flush=True)
            i = i+1
            # if debug:
            #     print("<< next is {}".format(i), file=sys.stderr)
        # o = str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"ascii")
        # # o = data #str(data,"ascii")
        # if debug:
        #     print("<< after translate: {} {}".format(len(o),o), file=sys.stderr)
        # print("{!s}".format(o), end='')
        if debug:
            print("<< end of data", file=sys.stderr)
        if once:
            break

# This is useful for handling cut-and-paste, with more than 1 char at-a-time
# TOPS-20 beeps when there is too much data, it seems.
def read_a_line(strm, maxlen=20):      #cf T20
    import select
    line = strm.read(1)
    while len(line) < maxlen and select.select([strm], [], [], 0) == ([strm], [], []):
        line = line+strm.read(1)
    return line

def telnet(host,contact="TELNET", options=None):
    sock = StreamConn() if not packetp else PacketConn()
    ctlc = False
    if sock is not None:
        sock.connect(host,contact,options=options)
        try:
            xec = threading.Thread(target=input_handler, args=(sock,))
            xec.start()
            with open("/dev/tty","rb", buffering=0) as tin:
                oldmode = termios.tcgetattr(tin)
                tty.setraw(tin)
                try:
                    while True:
                        try:
                            line = read_a_line(tin) # tin.read(1)
                            if debug:
                                print("Input: {} length {}".format(line,len(line)), file=sys.stderr)
                            if line == b"\x1d" or line == b"\x1e":
                                # ^] or ^^ pressed
                                print("\x0d",file=sys.stderr)
                                print("Telnet escape - press q for quit: ", file=sys.stderr, end='')
                                sys.stderr.flush()
                                ch = tin.read(1)
                                print("\x0d",file=sys.stderr)
                                if ch == b"q":
                                    if debug:
                                        print("Closing socket",file=sys.stderr)
                                    sock.close()
                                    return
                                else:
                                    line = ch
                            ctlc = False
                        # except KeyboardInterrupt:
                        #     if ctlc:
                        #         print("Ouch!", file=sys.stderr)
                        #         sock.close()
                        #         break
                        #     if debug:
                        #         print("Ouch!", file=sys.stderr)
                        #     line = b"\x03"
                        #     ctlc = True
                        except EOFError:
                            line = b"\x04"
                        sock.send_data(line)
                except BrokenPipeError:
                    if debug:
                        print("Broken pipe, setting cbreak again", file=sys.stderr)
                    tty.setcbreak(tin)
                    termios.tcsetattr(tin, termios.TCSANOW, oldmode)
                    return
                finally:
                    if debug:
                        print("finally setting cbreak again", file=sys.stderr)
                    tty.setcbreak(tin)
                    termios.tcsetattr(tin, termios.TCSANOW, oldmode)
        finally:
            pass
    else:
        print("Connection failed")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet telnet')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-p","--packet",dest='packetp',action='store_true',default=True,
                            help='Use packet mode (chaos_seqpacket) instead of plain stream')
    parser.add_argument("-c","--contact",dest='contact', default="TELNET",
                            help="Contact other than TELNET")
    parser.add_argument('-b','--broadcast',action='store_true',
                            help='Use BRD instead of RFC, and host arg is a comma-but-not-space-separated list of subnets, or "all"')
    parser.add_argument("-W","--winsize", type=int,
                            help="local window size")
    parser.add_argument("host", help='The host to connect to')
    args = parser.parse_args()

    cargs=dict()
    # if args.retrans and args.retrans > 0:
    #     cargs['retrans'] = args.retrans
    if args.winsize and args.winsize > 0:
        cargs['winsize'] = args.winsize
    # if args.timeout and args.timeout > 0:
    #     cargs['timeout'] = args.timeout
    if len(cargs) == 0:
        cargs = None

    if args.packetp:
        packetp = True
    if args.broadcast:
        broadcastp = True
    if args.debug:
        debug = True
        print(args, file=sys.stderr)

    telnet(args.host, args.contact, options=cargs)

