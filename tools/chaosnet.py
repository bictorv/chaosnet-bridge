# Copyright © 2023-2024 Björn Victor (bjorn@victor.se)
# Chaosnet support for python.
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

# TODO:
# - let debug be connection-local and initable

import socket, sys, time, re
import functools
from enum import IntEnum, auto
from struct import unpack
from datetime import datetime, timedelta

# The directories of these need to match the "socketdir" ncp setting in cbridge.
stream_socket_address = '/tmp/chaos_stream'
packet_socket_address = '/tmp/chaos_packet'
# -d
debug = False

# Exceptions
class ChaosError(Exception):
    message = "Chaosnet Error"
    def __init__(self,msg):
        self.message=msg
        super().__init__(msg)
class ChaosSocketError(ChaosError):
    pass
class EOFError(ChaosError):
    pass
class LOSError(ChaosError):
    pass
class CLSError(ChaosError):
    pass
# @@@@ add FWD exception?
class UnexpectedOpcode(ChaosError):
    pass

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

def opcode_name(code):
    try:
        return Opcode(code).name
    except ValueError:
        return "{:o}".format(code)

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
                                          "{:o}".format(self.remote) if type(self.remote) is int else self.remote)
    def __del__(self):
        if debug:
            print("{!s} being deleted".format(self), file=sys.stderr)

    def set_debug(self,val):
        global debug
        debug = val

    def abort(self):
        self.sock.close()       # emergency close
    def close(self, msg=b"Thank you"):
        if debug:
            print("Closing {} with msg {}".format(self,msg), file=sys.stderr)
        self.send_cls(msg)
        time.sleep(0.5)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing: {}'.format(msg), file=sys.stderr)
        self.sock = None

    def get_socket(self):
        address = self.socket_address
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if debug:
            print("{} got socket {}".format(self,self.sock), file=sys.stderr)

        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            raise ChaosSocketError("Error opening Chaosnet socket {}: {} - Is the Chaosnet bridge running?".format(address,msg))

    def send_socket_data(self, data):
        try:
            self.sock.sendall(data)
        except OSError as msg:
            raise ChaosSocketError(msg)

    def get_bytes(self, nbytes):
        try:
            return self.sock.recv(nbytes)
        except OSError as msg:
            raise ChaosSocketError(msg)

    def get_line(self):
        # Read an OPN/CLS in response to our RFC
        rline = b""
        havesome = False
        b = self.get_bytes(1)
        while b != b"\r" and b != b"\n" and b != b"\215" and b != b"":
            havesome = True
            rline += b
            b = self.get_bytes(1)
        if rline == b"" and not havesome:
            raise EOFError("got no data in get_line for {}".format(self))
            # raise ChaosError("got no data in get_line for {}".format(self))
        if b == b"\r":
            b = self.get_bytes(1)
            if b != b"\n":
                raise ChaosError("ERROR: return not followed by newline in get_line from {}: got {}".format(self,b))
        return rline

class PacketConn(NCPConn):
    def __init__(self):
        self.socket_address = packet_socket_address
        super().__init__()

    # Construct a 4-byte packet header for chaos_packet connections
    def packet_header(self, opc, plen):
        return bytes([opc, 0, plen & 0xff, int(plen/256)])
  
    def send_data(self, data):
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} bytes to {}".format(len(msg), self), file=sys.stderr)
        n = 0
        for i in range(0, len(msg), 488):
            n = n+1
            chunk = msg[i:i+488]
            clen = len(chunk)
            if debug:
                print("Sending chunk {} len {}".format(n,clen), file=sys.stderr)
            # self.send_socket_data(self.packet_header(Opcode.DAT, clen) + chunk)
            self.send_packet(Opcode.DAT, chunk)
        if debug:
            print("Sent all {} bytes in {} packets".format(len(msg),n), file=sys.stderr)

    def send_packet(self, opc, data=None):
        if debug:
            print(">>> {} len {}".format(opcode_name(opc), len(data) if data is not None else 0), file=sys.stderr)
        if data is None:
            self.send_socket_data(self.packet_header(opc, 0))
        else:
            self.send_socket_data(self.packet_header(opc, len(data))+data)

    def send_los(self, msg):
        self.send_packet(Opcode.LOS, msg)
    def send_cls(self, msg):
        self.send_packet(Opcode.CLS, msg)
    def send_ans(self, msg):
        self.send_packet(Opcode.ANS, msg)
    def send_unc(self, msg):
        self.send_packet(Opcode.UNC, msg)
    def send_opn(self):
        self.send_packet(Opcode.OPN)
    def send_eof(self, wait=False):
        if wait:
            self.send_packet(Opcode.EOF,b"wait")
            # eofwait should also be an RFC option.
            # @@@@ NOTE BUG: when both client and server are using NCP on same host, the EOF isn't ACKed!
            opc,ack = self.get_packet()
            if opc != Opcode.ACK:
                raise UnexpectedOpcode("in {}: Expected ACK after EOF[wait], got {}".format(self,opcode_name(opc)))
        else:
            self.send_packet(Opcode.EOF)

    def get_packet(self):
        hdr = self.get_bytes(4)
        if hdr is None or len(hdr) == 0:
            # This is handled somewhere
            raise ChaosSocketError("Error: {} got no bytes: {}".format(self,hdr))
        # First is opcode
        opc = hdr[0]
        # then zero
        assert(hdr[1] == 0)
        # then length
        length = hdr[2] + hdr[3]*256
        if opc == Opcode.ANS:
            # Includes 2 bytes of source!
            assert length <= 490
        elif opc == Opcode.UNC:
            # Includes 4 bytes (packetno, ackno fields)
            assert length <= 492
        else:
            assert(length <= 488)
        if debug:
            print("< {} {} {}".format(self,opcode_name(opc), length), file=sys.stderr)
        return opc, self.get_bytes(length)

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact), file=sys.stderr)
        self.send_packet(Opcode.LSN,bytes(contact,"ascii"))
        op,data = self.get_packet()
        if debug:
            print("{}: {}".format(opcode_name(op),data), file=sys.stderr)
        if op == Opcode.RFC or op == Opcode.BRD: # BRD is supposed to be translated to RFC!
            hostandargs = str(data,"ascii").split(" ",maxsplit=1)
            self.remote = hostandargs[0]
            self.args = hostandargs[1] if len(hostandargs) > 1 else ""
            return self.remote,self.args
        elif op == Opcode.LOS:
            raise LOSError("LOS: {}".format(str(data,"ascii")))
        else:
            raise UnexpectedOpcode("Expected RFC: {}".format(opcode_name(op)))

    def connect(self, host, contact, args=[], options=None, simple=False):
        h = bytes(("{} {}"+" {}"*len(args)).format("{:o}".format(host) if type(host) is int else host,contact.upper(),*args),"ascii")
        if options is not None:
            h = bytes("["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] ","ascii")+h
        if debug:
            print("Options: {} = {}".format(options, h), file=sys.stderr)
            print("RFC: {}".format(h), file=sys.stderr)
        self.active = True
        self.contact = contact
        self.send_packet(Opcode.RFC, h)
        if simple:
            # Need to return and let caller call get_packet
            return True
        opc, data = self.get_packet()
        if opc == Opcode.OPN:
            self.remote = str(data,"ascii")
            return True
        elif opc == Opcode.CLS:
            raise CLSError(str(data,"ascii"))
        elif opc == Opcode.LOS:
            raise LOSError("LOS: {}".format(str(data,"ascii")))
        else:
            raise UnexpectedOpcode("Expected OPN, got {}".format(opcode_name(opc)))

    def get_message(self, dlen=488, partialOK=False):
        opc, data = self.get_packet()
        if opc == Opcode.CLS:
            self.close()
            return None
        elif opc == Opcode.LOS:
            raise LOSError("LOS: {}".format(str(data,"ascii")))
        elif opc == Opcode.EOF:
            if debug:
                print("{} got EOF: {}".format(self,data), file=sys.stderr)
            raise EOFError("EOF")
        elif opc != Opcode.DAT:
            raise UnexpectedOpcode("Unexpected opcode {}".format(opc))
            return None
        elif len(data) == 0:
            return None
        elif partialOK or len(data) >= dlen:
            return data
        else:
            if debug:
                print("read less than expected: {} < {}, going for more".format(len(data),dlen), file=sys.stderr)
            return data + self.get_message(dlen-len(data))

    def get_string_until_eof(self):
        # Returns the string, translated from LISPM chars
        string = ""
        while True:
            opc,data = self.get_packet()
            if opc == Opcode.CLS:
                self.close()
                return string
            elif opc == Opcode.LOS:
                raise LOSError("LOS: {}".format(str(data,"ascii")))
            elif opc == Opcode.EOF:
                return string
            # @@@@ handle ANS too?
            elif opc != Opcode.DAT:
                raise UnexpectedOpcode("Unexpected opcode {}".format(opc))
            else:
                # Translate to Unix
                out = str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")
                string += out

    def copy_until_eof(self):
        # Returns the number of bytes printed
        nprinted = 0
        while True:
            opc, data = self.get_packet()
            if opc == Opcode.CLS:
                self.close()
                return nprinted
            elif opc == Opcode.LOS:
                raise LOSError("LOS: {}".format(str(data,"ascii")))
            elif opc == Opcode.EOF:
                # raise EOFError("{} got EOF: {}".format(self,data))
                return nprinted
            # @@@@ handle ANS too?
            elif opc != Opcode.DAT:
                raise UnexpectedOpcode("Unexpected opcode {}".format(opc))
                return None
            else:
                nprinted += len(data)
                # Translate to Unix
                out = str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")
                print("{!s}".format(out), end='' if out[-1] not in [0o215,0o212,0o15,0o12] and nprinted>0 else None)

# For simple broadcast protocols
# Iterator gives source address and data for each ANS
class BroadcastConn(PacketConn):
    def __init__(self, subnets, contact, args=[], options=None):
        super().__init__()
        # Allow aliases for "all" and "local" subnets
        if len(subnets) == 1 and subnets[0] == -1:
            subnets = ["all"]
        elif len(subnets) == 1 and subnets[0] == 0:
            subnets = ["local"]
        self.contact = contact
        self.remote = subnets
        h = bytes("{} {}".format(",".join(map(str,subnets)),contact),"ascii")
        for a in args:
            if isinstance(a,str):
                h += b" "+bytes(a,"ascii")
            else:
                h += b" "+a
        if options is not None:
            h = bytes("["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] ","ascii")+h
        self.send_packet(Opcode.BRD, h)
        return None

    def __iter__(self):
        return self
    def __next__(self):
        try:
            opc, data = self.get_packet()
            if opc == None:
                raise StopIteration
        except ChaosSocketError:
            # e.g. reading nothing
            raise StopIteration
        if opc == Opcode.ANS:
            src = data[0] + data[1]*256
            if debug:
                print("Got ANS from {:o} len {} for {}".format(src,len(data),self.contact), file=sys.stderr)
            return src,data[2:]
        elif opc == Opcode.LOS or opc == Opcode.CLS:
            # LOS from cbridge after BRD time-outs, CLS from buggy BSD
            if debug:
                print("Got {}: {}".format(opcode_name(opc), data), file=sys.stderr)
            # just ignore it.
            raise StopIteration
        else:
            raise UnexpectedOpcode("Got unexpected {} len {}: {}".format(opcode_name(opc), len(data) if data is not None else 0, data))

class StreamConn(NCPConn):
    def __init__(self):
        self.socket_address = stream_socket_address
        self.opn_sent = False
        super().__init__()

    def send_data(self, data):
        # print("send pkt {} {} {!r}".format(opcode_name(opcode), type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} to {}".format(len(msg), self), file=sys.stderr)
        self.send_socket_data(msg)

    def send_opn(self):
        self.send_data("OPN\r\n")
        self.opn_sent = True
    def send_los(self, msg):
        # Can't do this over stream interface
        pass
    def send_cls(self, msg):
        # Can only be sent before OPN
        if not self.opn_sent:
            self.send_data("CLS {}\r\n".format(msg))

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
            hostandargs = str(data,"ascii").split(" ",maxsplit=1)
            self.remote = hostandargs[0]
            self.args = hostandargs[1] if len(hostandargs) > 1 else ""
            return self.remote,self.args
        elif op == b"LOS":
            raise LOSError("LOS: {}".format(str(data,"ascii")))
            return None,None
        else:
            raise UnexpectedOpcode("Expected RFC: {}".format(op))

    def connect(self, host, contact, args=[], options=None):
        self.contact = contact
        h = ("{} {}"+" {}"*len(args)).format("{:o}".format(host) if type(host) is int else host,contact.upper(),*args)
        if options is not None:
            h = "["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] "+h
        if debug:
            print("RFC to {} for {!r}".format(host,h), file=sys.stderr)
        self.send_data("RFC {}".format(h))
        inp = self.get_line()
        op, data = inp.split(b' ', maxsplit=1)
        if debug:
            print("{}: {}".format(op,data), file=sys.stderr)
        if op == b"OPN":
            self.active = True
            self.remote = host                  #should we parse OPN data?
            self.contact = contact
            return True
        elif op == b"CLS":
            raise CLSError(str(data,"ascii"))
        elif op == b"LOS":
            raise LOSError("LOS: {}".format(str(data,"ascii")))
        else:
            raise UnexpectedOpcode("Expected OPN: {}".format(op))

    def get_message(self, length=488, partialOK=False):
        data = self.get_bytes(length)
        if debug:
            print("< {} of {} from {}".format(len(data), length, self), file=sys.stderr)
        if len(data) == 0:
            # This is handled somewhere
            raise ChaosSocketError("Error: Got no bytes: {}".format(data))
        elif not partialOK and len(data) < length:
            d2 = self.get_bytes(length-len(data))
            if debug:
                print("< {} of {} from {}".format(len(d2), length, self), file=sys.stderr)
            data += d2
        return data

    def get_string_until_eof(self):
        # Returns the string, translated from LISPM chars
        string = ""
        while True:
            data = self.get_bytes(488)
            if len(data) == 0:
                return string
            else:
                # Translate to Unix
                out = str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")
                string += out

    def copy_until_eof(self):
        # Returns the number of bytes printed
        nprinted = 0
        cmap = { 0o211: 0o11, 0o215: 0o12, 0o212: 0o15 }
        last = None
        while True:
            data = self.get_bytes(488)
            if len(data) == 0:
                if last not in [0o215,0o212,0o15,0o12] and nprinted > 0:
                    # finish with a fresh line
                    print("")
                return nprinted
            nprinted += len(data)
            for c in data:
                last = c
                # translate
                if c in cmap:
                    print(chr(cmap[c]),end='')
                else:
                    print(chr(c),end='')

# Generic simple protocol
class Simple:
    conn = None
    hname = None
    # To support chaining with broadcast
    hdr_printed = False
    printed_sources = []
    def __init__(self, hnames, contact, args=[], options=None, header=None, footer=None, printer=None, nonprinter=None, already_printed=None, header_printed=False):
        self.hdr_printed = header_printed
        if already_printed is not None:
            self.printed_sources = already_printed
        # Accept a list of host names to contact
        if type(hnames) is not list:
            hnames = [hnames]
        nonprinted = []
        for hname in hnames:
            self.conn = PacketConn()
            self.hname = hname
            try:
                if debug:
                    print("Simple connect to {} {} {}".format(hname,contact,args), file=sys.stderr)
                self.conn.connect(hname, contact, args, options, simple=True)
                if printer is not None:
                    src, data = self.result()
                    if src is not None and data is not None and not self.hdr_printed and header is not None:
                        print(header)
                        self.hdr_printed = True
                    if data is not None and not printer(src,data):
                        # Save this if it wasn't printed now (e.g. Free lispm)
                        nonprinted.append([src,data])
                    self.printed_sources.append(src)
                else:
                    return None
            except LOSError as m:
                # handle LOS for timeout etc
                # hard to handle better here?
                if printer is not None:
                    print(m)
                nonprinted.append([src,m])
                if debug:
                    print("<!--") 
                    print(m)
                    print(" -->")
            except socket.error:
                pass
        if footer and self.hdr_printed:
            print(footer)
        if nonprinter is not None and len(nonprinted) > 0:
            # At the end, maybe print those not printed earlier
            nonprinter(nonprinted)
        return None
    def result(self):
        opc, data = self.conn.get_packet()
        if opc == Opcode.ANS:
            src = data[0] + data[1]*256
            if debug:
                print("Simple ANS len {} from {:o}".format(len(data)-2,src), file=sys.stderr)
            return src, data[2:]
        elif opc == Opcode.CLS:
            if debug:
                print("CLS (from {}): {}".format(self.hname, data), file=sys.stderr)
            return None,None
        elif opc == Opcode.LOS:
            if debug:
                print("LOS (from {}): {}".format(self.hname, data), file=sys.stderr)
            raise LOSError("LOS: {}".format(str(data,"ascii")))
            return None, None
        elif opc == Opcode.FWD:
            dest = data[0] + data[1]*256
            if debug:
                print("FWD received: use host {:o} contact {}".format(dest,str(data[2:],"ascii")), file=sys.stderr)
            # @@@@ This should be a separate exception so it can be handled, and FWD should be detected in other places too.
            raise UnexpectedOpcode("Unexpected FWD from {}: use host {:o} contact {}".format(self.hname, dest, str(data[2:],"ascii")))
        else:
            raise UnexpectedOpcode("Unexpected opcode {} from {} ({})".format(opcode_name(opc), self.hname, data))

# Given subnets, contact, options, header, and a printer (taking ANS as arg),
# broadcast and then iterate printer over responses, filtering previously received ones
class BroadcastSimple:
    # To support chaining with unicast
    hdr_printed = False
    printed_sources = []
    def __init__(self, subnets, contact, args=[], options=None, header=None, footer=None, printer=None, nonprinter=None, already_printed=None, header_printed=False):
        nonprinted = []
        self.hdr_printed = header_printed
        if already_printed is not None:
            self.printed_sources = already_printed
        else:
            self.printed_sources = []
        if debug:
            print("{}: already printed {}, printed {}".format(self,already_printed, self.printed_sources), file=sys.stderr)
        for src,data in BroadcastConn(subnets, contact, options=options, args=args):
            if src in self.printed_sources:
                if debug:
                    print("Already printed {:o} for {}".format(src, contact), file=sys.stderr)
                continue                  # already handled
            self.printed_sources.append(src)
            if not self.hdr_printed and header is not None:
                print(header)               # print header
                self.hdr_printed = True
            elif debug:
                print("hdr_printed {} and header {}".format(self.hdr_printed, header), file=sys.stderr)
            if not printer(src,data):
                # Save this if it wasn't printed now (e.g. Free lispm)
                if debug:
                    print("src {:o} wasn't printed".format(src), file=sys.stderr)
                nonprinted.append([src,data])
        if debug:
            print("Done with subnets {} for {}".format(subnets, contact), file=sys.stderr)
        if footer and self.hdr_printed:
            print(footer)
        # At the end, maybe print those not printed earlier
        if nonprinter is not None:
            nonprinter(nonprinted)

################ Protocols giving structured data back

class SimpleDict:
    # Caller handle CLSError, LOSError and socket.error
    def __init__(self, hname, args=[], options=None):
        self.single_run(hname, args, options)
    # Make this callable by BroadcastSimpleDict classes.
    def single_run(self, hname, args=[], options=None):
        self.conn = PacketConn()
        self.hname = hname
        if options is None:
            options = dict()
        if 'timeout' not in options:
            options['timeout'] = 2 # default timeout
        self.conn.connect(hname, self.contact, args, options, simple=True)

    def result_packet(self):
        try:
            opc, data = self.conn.get_packet()
        except ChaosSocketError as m:
            if debug:
                print("Error getting packet from {!r}: {}".format(hname, m), file=sys.stderr)
            return None,None
        if opc == Opcode.ANS:
            src = data[0] + data[1]*256
            return src, data[2:]
        elif opc == Opcode.LOS:
            if debug:
                print("LOS from {!r}: {}".format(hname, data), file=sys.stderr)
            raise LOSError("LOS: {}".format(str(data,"ascii")))
        elif opc == Opcode.CLS:
            if debug:
                print("CLS from {!r}: {}".format(hname, data), file=sys.stderr)
            return None,None
        elif opc == Opcode.FWD:
            dest = data[0] + data[1]*256
            print("FWD from {!r}: use host {:o}, contact {!r}".format(hname, dest, str(data[2:],"ascii")), file=sys.stderr)
            # @@@@ This should be a separate exception so it can be handled, and FWD should be detected in other places too.
            raise UnexpectedOpcode("Unexpected FWD from {}: use host {:o} contact {}".format(self.hname, dest, str(data[2:],"ascii")))
        else:
            raise UnexpectedOpcode("Unexpected opcode {} from {} ({})".format(opcode_name(opc), self.hname, data))

    def dict_result(self):
        src, data = self.result_packet()
        if src is not None and data is not None:
            return self.packet_to_dict(src, data)
        else:
            return None

# Add a "callback" parameter, a fun which is called for each result as they are collected, with the dict as param
class BroadcastSimpleDict(SimpleDict):
    collected = None
    def __init__(self, subnets, args=[], options=None, callback=None):
        self.collected = dict()
        if options is None:
            options = dict()
        if 'timeout' not in options:
            options['timeout'] = 2 # default timeout
        # Allow host names/addresses too
        sn = [s for s in subnets if isinstance(s,int) and s < 0o400]
        hn = [s for s in subnets if not(isinstance(s,int) and s < 0o400)]
        # First broadcast on the subnets
        for src,data in BroadcastConn(sn, self.contact, options=options, args=args):
            if src in self.collected:
                if debug:
                    print("Already collected data from {:o} for {!r}".format(src,self.contact), file=sys.stderr)
                continue
            if callback is not None:
                callback(dict(source=src) | self.packet_to_dict(src,data))     # @@@@ do we need self too?
            self.collected[src] = data
        # Then check individual hosts
        hlist = [ha for ha in hn if isinstance(ha,int)]
        for h in [he for he in hn if not(isinstance(he,int))]:
            ha = dns_addr_of_name_search(h)
            if ha is not None:      # @@@@ how can I do this test in a list comprehension?
                hlist.append(ha[0]) # first address is sufficient
        for h in hlist:
            if h not in self.collected.keys(): # unless we already know
                if debug:
                    print("Individual host {:o} for {!r}".format(h, self.contact), file=sys.stderr)
                self.single_run(h, args, options) # Set it up
                src,data = self.result_packet()   # get the result
                if callback is not None:
                    callback(dict(source=src) | self.packet_to_dict(src,data))     # @@@@ do we need self too?
                self.collected[src] = data        # save it
    def dict_result(self):
        # Return a list of the dict's, with a source field having the source address.
        # Caller gets to use dns_name_of_address(src, timeout=2) if they want.
        vals = []
        for src in self.collected.keys():
            vals.append(dict(source=src) | self.packet_to_dict(src, self.collected[src]))
        return vals

class StatusDict(SimpleDict):
    contact = "STATUS"

    def parse_status_data(self,src,data):
        from struct import unpack
        # First is the name of the node
        # BGDFAX pads with spaces (instead of nulls)
        hname = str(data[:32].rstrip(b'\x00 '),'ascii')
        fstart = 32
        dlen = len(data)
        statuses = dict()
        # Parse the data
        try:
            while fstart+4 < dlen:
                # Two 16-bit words of subnet and field length
                subnet,flen = unpack('H'*2,data[fstart:fstart+4])
                # But subnet is +0400
                assert (subnet > 0o400) and (subnet < 0o1000)
                subnet -= 0o400
                # Then a number of doublewords of info
                if fstart+flen >= dlen:
                    break
                fields = unpack('{}I'.format(int(flen/2)), data[fstart+4:fstart+4+(flen*2)])
                statuses[subnet] = dict(zip(('inputs','outputs','aborted','lost','crc_errors','hardware','bad_length','rejected'),
                                                fields))
                fstart += 4+flen*2
        except AssertionError:
            print('{} value error at {}: {!r}'.format(hname,fstart,data[fstart:]))
        return hname,statuses

    def packet_to_dict(self, src, data):
        hname, statuses = self.parse_status_data(src,data)
        return dict(hname=hname, status=statuses)
class BroadcastStatusDict(BroadcastSimpleDict, StatusDict):
    # The mix is enough
    pass

class UptimeDict(SimpleDict):
    contact = "UPTIME"
    def parse_packet_data(self, data):
        # cf RFC 868
        s = int(unpack("I",data[0:4])[0]/60)
        return timedelta(seconds=s),s
    def packet_to_dict(self, src, data):
        updelta, upsec = self.parse_packet_data(data)
        dname = dns_name_of_address(src, timeout=2)
        return dict(dname=dname, addr=src, delta=updelta, sec=upsec)
class BroadcastUptimeDict(BroadcastSimpleDict, UptimeDict):
    pass

class TimeDict(SimpleDict):
    contact = "TIME"
    def parse_packet_data(self, data):
        # cf RFC 868
        # @@@@ Prepare for 2036 and adjust offset when MSB is not set
        t = unpack("I",data[0:4])[0]-2208988800
        dt = t-time.time()
        return datetime.fromtimestamp(t),t,dt
    def packet_to_dict(self, src, data):
         dt, ts, delta = self.parse_packet_data(data)
         dname = dns_name_of_address(src, timeout=2)
         return dict(dname=dname, addr=src, dt=dt, timestamp=ts, delta=delta)
class BroadcastTimeDict(BroadcastSimpleDict, TimeDict):
    pass

class DumpRoutingTableDict(SimpleDict):
    contact = "DUMP-ROUTING-TABLE"
    def parse_packet_data(self, data):
        rtt = dict()
        # Parse routing table info
        for sub in range(0,int(len(data)/4)):
            sn = unpack('H',data[sub*4:sub*4+2])[0]
            if sn != 0:
                rtt[sub] = dict(zip(('method','cost'),unpack('H'*2,data[sub*4:sub*4+4])))
        return rtt
    def packet_to_dict(self, src, data):
        rtt = self.parse_packet_data(data)
        dname = dns_name_of_address(src, timeout=2)
        return dict(dname=dname, addr=src, routingtable=rtt)
class BroadcastDumpRoutingTableDict(BroadcastSimpleDict, DumpRoutingTableDict):
    pass

class LastSeenDict(SimpleDict):
    # cbridge specific
    contact = "LASTCN"
    def parse_packet_data(self,data):
        cn = dict()
        i = 0
        while i < int(len(data)/2):
            flen = unpack('H',data[i*2:i*2+2])[0]
            assert flen >= 7
            addr = unpack('H',data[i*2+2:i*2+4])[0]
            inp = unpack('I',data[i*2+4:i*2+4+4])[0]
            via = unpack('H',data[i*2+4+4:i*2+4+4+2])[0]
            age = unpack('I',data[i*2+4+4+2:i*2+4+4+2+4])[0]
            if (flen > 7):
                fc = unpack('H',data[i*2+4+4+2+4:i*2+4+4+2+4+2])[0]
                cn[addr] = dict(input=inp,via=via,age=age,fc=fc)
            else:
                cn[addr] = dict(input=inp,via=via,age=age,fc='')
            i += flen
        return cn
    def packet_to_dict(self, src, data):
        cn = self.parse_packet_data(data)
        dname = dns_name_of_address(src, timeout=2)
        return dict(dname=dname, addr=src, lastseen=cn)
class BroadcastLastSeenDict(BroadcastSimpleDict, LastSeenDict):
    pass

class LoadDict(SimpleDict):
    contact = "LOAD"
    def parse_load_data(self, data):
        lines = data.split(b"\r\n")
        umatch = re.match(r"Users: (\d+)", str(lines[1],"ascii"))
        lmatch = re.match(r"Fair Share: (\d+)%", str(lines[0],"ascii"))
        return dict(users=int(umatch.group(1)) if umatch else None,
                    share=int(lmatch.group(1)) if lmatch else None)
    def packet_to_dict(self, src, data):
        return self.parse_load_data(data)
class BroadcastLoadDict(BroadcastSimpleDict, LoadDict):
    pass

class FingerDict(SimpleDict):
    contact = "FINGER"
    def parse_finger_data(self, data):
        flds = list(map(lambda x: str(x,'ascii'),data.split(b"\215")))
        # Let the caller do this or not
        # flds[2] = parse_idle_time_string(flds[2])
        return flds
    def packet_to_dict(self, src, data):
        fields = self.parse_finger_data(data)
        return dict(uname=fields[0], affiliation=fields[4], pname=fields[3], idle=fields[2], location=fields[1])
class BroadcastFingerDict(BroadcastSimpleDict, FingerDict):
    pass

class DNSDict(SimpleDict):
    # Also cbridge specific: "simple" protocol where contact arg is the (binary) query, and the ANS is the (binary) answer.
    contact = "DNS"
    # @@@@ TODO but not really used anywhere (except bhostat.py)
    pass

def parse_idle_time_string(s):
    # try to parse idle to a number (and consider weird representations like *:**)
    # lispm FINGER servers only give HH:MM, while fingerd.py also can give NNd or *:**
    # unix NAME servers also give MM or NNd (for days).
    if isinstance(s,int):
        return s
    if s == "" or s is None:
        return 0
    elif s.startswith("*:**"):  # could be "*:**."
        return 0xffff    # many minutes (@@@@ maybe should figure out where servers put the line)
    # HH:MM?
    imatch = re.match(r"(\d+):(\d+)", s)
    if imatch:
        return int(imatch.group(1))*60+int(imatch.group(2))
    # NNd (days)?
    imatch = re.match(r"(\d+)d", s)
    if imatch:
        return int(imatch.group(1))*7*24*60
    # Plain minutes?
    imatch = re.match(r"(\d+)", s)
    if imatch:
        return int(imatch.group(1))
    # Don't know
    # @@@@ This is likely the ITS/T20 "." next to idle time/tty messing things up
    # print("#### Can't parse idle time {!r} ####".format(s), file=sys.stderr)
    return s

class NamesDict:
    # Takes a list of hosts and returns a list of results
    def __init__(self, hosts, args=[], options=None):
        self.hresults = [NameDict(h, args=args, options=options).dict_result() for h in hosts]
    def dict_result(self):
        return self.hresults
class NameDict:
    # This gives the "finger" output as a list of dicts. It is complete overkill if you only want
    # to know, e.g., who is logged on. But it is quite flexible and could be used to make a unified list
    # of everyone at all hosts (cf bhostat_html).
    # NOTE that since the "finger" output isn't very standardized, there are a few hacks here.

    def __init__(self, hname, args=[], options=None):
        self.conn = StreamConn()
        self.hname = hname
        self.args = args
        if options is not None and 'timeout' in options:
            self.timeout = options['timeout']
        try:
            self.conn.connect(hname, "NAME", args=args, options=options)
        except socket.timeout as m:
            raise ChaosError(m)

    # Translate headers into labels for the resulting dict.
    # You could give the first header special treatment, it *should* always be userid regardless of header(?)
    # @@@@ *Perhaps* you could instead use heuristics, like:
    # First is always userid. If it has "name" it is pname. If it its idle/tty it is that. If it has "location" it is that.
    # Smells like regexps would work.
    headerlabels = dict(userid=["-User-","User","Login"], # ITS, TOPS-20, Unix
                        affiliation=["Affiliation"],      # Meta-header (ITS)
                        pname=["--Full name--","Personal name","Name"], # ITS, TOPS-20, Unix
                        jobname=["Jobnam","Subsys"], # ITS, TOPS-20
                        idle=["Idle"],
                        tty=["TTY"],
                        location=["-Console location-","Console location"]) # ITS, TOPS-20
    def headerlabel(self,h):
        for lab,hdrs in self.headerlabels.items():
            if h in hdrs:
                return lab

    def parse_header_line(self, hline):
        hack_its_uname = False
        hack_unix_headers = False
        headers = []
        indexes = []
        s = 0
        # since regexps can't count, use explicit variants with --Header--, -Header-, and Header
        for m in re.finditer("(--[A-Z]+[a-z]* ?[a-z]*--)|(-[A-Z]+[a-z]* ?[a-z]*-)|([A-Z]+[a-z]* ?[a-z]*)",hline): # "  +"
            # save index of next header start
            indexes.append(m.start() if m.start() != 1 else 0)
            # save this header
            headers.append(hline[m.start():m.end()].strip())
            s = m.end()
        if len(hline[s:].strip()) > 0:
            headers.append(hline[s:].strip())
        # OS specific hacks
        hi = get_dns_host_info(get_canonical_name(self.hname), timeout=2)
        if hi and 'os' in hi:
            if hi['os'].lower() == "its":
                # ITS affiliation hack alert
                if headers[0] == '-User-':
                    # inject an affiliation header
                    headers = headers[0:1]+["Affiliation"]+headers[1:]
                    hack_its_uname = True
            elif hi['os'].lower() in ["unix","linux","macos"]: # @@@@ add as required
                # Need a hack because headers aren't left-adjusted
                hack_unix_headers = True
        return headers, indexes, hack_its_uname, hack_unix_headers

    def parse_data_lines(self, lines, indexes, headers, hack_its_uname=False, hack_unix_headers=False):
        rows = []
        for nl in lines:
            row = []
            hadj = 0            # header adjust...
            for i in range(len(indexes)):
                hdr = headers[i+hadj] # the current header
                s = indexes[i]
                e = indexes[i+1] if i+1 < len(indexes) else len(nl) # the next field start
                fld = nl[s:e].strip()
                if hack_its_uname and hdr == "-User-":
                    # Hack the first element
                    # check for "UNAME FR" where F is affiliation and R is relation, and separate them.
                    # @@@@ Should probably separate F and R, too, but the caller can do that.
                    # Also strip the uniqifying digit on UNAME for multiple logins.
                    m = re.match(r"([A-Z0-9]+|___\d\d\d) +([A-Z]{1,2}|[$@+-]|-->)$",fld)
                    if m:
                        # append them separately
                        if m.group(1).startswith("___"):
                            row.append(m.group(1))
                        else:
                            row.append(m.group(1).rstrip("0123456789"))
                        row.append(m.group(2))
                    else:
                        if fld.startswith("___"):
                            row.append(fld)
                        else:
                            row.append(fld.rstrip("0123456789"))
                        row.append("") # empty affiliation, perhaps
                    hadj = 1           # adjust for affiliation already added
                elif hdr == "Idle" and fld.endswith("."):
                    # Hack ITS/TOPS-20 Idle time "3." (meaning something like "at top level input")
                    # which is immediately next to the TTY, so the row has "3.T11" for idle 3 and TTY T11.
                    row.append(fld[:-1])
                elif hack_unix_headers:
                    # Hack unix output: headers aren't left-aligned, need to "look backwards" from header offset
                    if s > 0 and s < len(nl) and nl[s-1] != " ": # Not a space at the position under the header start
                        s = nl.rfind(" ",0,s)+1
                    # Also adjust the end, since the next column might also be misaligned
                    if e < len(nl) and nl[i-1] != " ":
                        e = nl.rfind(" ",s,e)+1
                    row.append(nl[s:e].strip())
                else:
                    row.append(fld)
            rows.append(row)
        return rows

    def dict_result(self):
        # Parse NAME output to give it structure. Ghastly, I'm sorry.

        # Collect headers and save indexes of starts
        # - Header heuristic: "[A-Z][a-z]+ ?[a-z]*" (with zero, one, or two dashes before+after)
        # then read successive lines, and create rows based on header indexes.
        # A gross hack is applied to detect and handle the affiliation part of ITS output (which doesn't have a header).
        # Another slightly less gross hack is applied for unix output which doesn't have left-aligned headers

        output = self.conn.get_string_until_eof().rstrip()
        if "\t" in output:
            output = output.expandtabs()
        if len(self.args) > 0:  # can't handle /whois-like output
            return dict(source = self.conn.remote, rawlines=output.replace("\r\n","\n"))
        # Break it into lines
        if "\r\n" in output:
            lines = output.split("\r\n")
        else:
            lines = output.split("\n")
            # Nobody there
        if lines[0].startswith("No users") or lines[0] == "":
            return None
        # Parse headers
        headers, indexes, hack_its_uname, hack_unix_headers = self.parse_header_line(lines[0])
        # Now collect the lines of data
        rows = self.parse_data_lines(lines[1:], indexes, headers, hack_its_uname, hack_unix_headers)
        # Now have headers and rows of data; construct a list of dicts
        # where keys are (simplified standardized) headers
        result = []
        for row in rows:
            r = dict()
            for ri in range(len(row)):
                h = self.headerlabel(headers[ri])
                # avoid e.g. overwriting userid by Unix "Login Time". This makes dict comprehension hard though.
                if h and h not in r.keys():
                    r[h] = row[ri]
            # If no userid found by header names, use the first item in the row
            if 'userid' not in r and len(row) > 0:
                r = dict(userid = row[0]) | r # make it appear first in the dict
            # Make sure all the other headers are there
            for h in self.headerlabels:
                if h not in r:
                    r[h] = ""
            result.append(r)
        return dict(source = self.conn.remote, lines=result)

################ Get host name (and addr) using STATUS and/or DNS
@functools.cache
def host_name(addr, timeout=2):
    name,_ = host_name_and_addr(addr, timeout=timeout)
    return name
@functools.cache
def host_name_and_addr(addr, timeout=2):
    if isinstance(addr,int):
        if addr < 0o400:        # invalid address
            return "{:o}".format(addr),addr
    try:
        s = Simple(addr, "STATUS", options=dict(timeout=timeout))
        src, data = s.result()
    except ChaosError as msg:
        if debug:
            print("Error while getting STATUS of {}: {}".format(addr,msg), file=sys.stderr)
        src = None
    if src:
        # BGDFAX (a VAX) pads with spaces (instead of nulls)
        name = str(data[:32].rstrip(b'\x00 '), "ascii")
        return name,src
    elif isinstance(addr,int):
        if debug:
            print("No STATUS from {:s}, trying DNS".format(addr), file=sys.stderr)
        name = dns_name_of_address(addr, timeout=timeout, onlyfirst=True)
        if debug:
            print("Got DNS for {:s}: {}".format(addr,name), file=sys.stderr)
        return name,addr
    else:
        return None,None

################ DNS
# pip3 install dnspython
import dns.resolver

# Default DNS resolver for Chaosnet
dns_resolver_name = 'DNS.Chaosnet.NET'
dns_resolver_address = socket.gethostbyname(dns_resolver_name)
# Default DNS searchlist
default_dns_searchlist=["Chaosnet.NET"]

def set_dns_search_list(nlist):
    global default_dns_searchlist
    default_dns_searchlist = nlist
def local_domain():
    try:
        name,addr = host_name_and_addr("localhost") # requires late 2025 cbridge
    except ChaosError:
        return None
    if addr and isinstance(addr,int):
        name = dns_name_of_address(addr)
    if name is None:
        return None
    if "." in name:
        return name.split(".",maxsplit=1)[1]
    else:
        return name

def set_dns_resolver_address(adorname):
    global dns_resolver_address
    try:
        dns_resolver_address = socket.gethostbyname(adorname)
    except OSError as msg:
        print("Error resolving {!r}: {}".format(adorname, msg), file=sys.stderr)
        return None
    return dns_resolver_address

class DNSRecord:
    result = None
    def __init__(self, rr, namestring, parser, timeout=2, options=None):
        try:
            if debug:
                print("DNS query for {} to resolver address {}".format(namestring, dns_resolver_address), file=sys.stderr)
            h = dns.query.udp(dns.message.make_query(namestring, rr, rdclass=dns.rdataclass.CH),
                                  dns_resolver_address, timeout=timeout)
            result = []
            for t in h.answer:
                if t.rdtype == rr:
                    for d in t:
                        result.append(parser(d, options))
            if len(result) > 0:
                self.result = result
        except AttributeError as e:
            # dnspython not updated with support for Chaos records?
            pass
            # print("Error", e, file=sys.stderr)
        except dns.exception.Timeout as e:
            if debug:
                print("Timeout error:", e, file=sys.stderr)
        except dns.exception.DNSException as e:
            print("Error:", e, file=sys.stderr)

@functools.cache
def dns_name_of_address(addrstring, onlyfirst=False, timeout=5):
    if type(addrstring) is int:
        name = "{:o}.CH-ADDR.NET.".format(addrstring)
        addrstring = "{:o}".format(addrstring)
    else:
        name = "{}.CH-ADDR.NET.".format(addrstring)
    def parse_ptr(d, options=None):
        n = d.target.to_text(omit_final_dot=True)
        if options and 'onlyfirst' in options and options['onlyfirst']:
            return n.split(".",maxsplit=1)[0]
        else:
            return n
    r = DNSRecord(dns.rdatatype.PTR, name, parse_ptr, timeout=timeout, options=dict(onlyfirst=onlyfirst)).result
    return r[0] if r and len(r) > 0 else r
@functools.cache
def get_canonical_name(hname, timeout=5, onlyfirst=False):
    if re.match("^[0-7]+$",hname):
        return dns_name_of_address(hname, onlyfirst=onlyfirst, timeout=timeout)
    else:
        return next((dns_name_of_address(a, onlyfirst=onlyfirst, timeout=timeout) for a in dns_addr_of_name_search(hname, timeout=timeout)),hname)
@functools.cache
def get_dns_host_info(name, timeout=5):
    def parse_hinfo(d, options=None):
        return dict(os=str(d.os.decode()), cpu=str(d.cpu.decode()))
    r = DNSRecord(dns.rdatatype.HINFO, name, parse_hinfo, timeout=timeout).result
    return r[0] if r and len(r) > 0 else r
@functools.cache
def dns_addr_of_name(name, timeout=5):
    def parse_addr(d, options=None):
        return d.address
    def parse_cname(d, options=None):
        return dns_addr_of_name(d.target.to_text(), timeout=timeout)
    r = DNSRecord(dns.rdatatype.A, name, parse_addr, timeout=timeout).result
    if r is None:
        r = DNSRecord(dns.rdatatype.CNAME, name, parse_cname, timeout=timeout).result
        return r[0] if r and len(r) > 0 else r
    else:
        return r
def dns_addr_of_name_search(name, timeout=5, searchlist=None):
    if searchlist is None:
        searchlist = default_dns_searchlist
    if "." in name or searchlist is None:
        return dns_addr_of_name(name, timeout=timeout)
    for s in searchlist:
        r = dns_addr_of_name(name+"."+s, timeout=timeout)
        if r:
            return r
@functools.cache
def dns_responsible(name, timeout=2):
    def parse_rp(d, options=None):
        m = d.mbox
        maddr = str(m.labels[0],"ascii")+"@"+m.parent().to_text(omit_final_dot=True)
        tx = d.txt
        if tx != dns.name.root:
            # texts = DNSRecord(dns.rdatatype.TXT, tx.to_text(), lambda d,o=None: list(map(lambda x: str(x,"ascii"),d.strings))).result
            texts = dns_text(tx.to_text(), timeout=timeout)
        else:
            texts = None
        return dict(mbox=maddr, text=texts)
    return DNSRecord(dns.rdatatype.RP, name, parse_rp, timeout=timeout).result
@functools.cache
def dns_text(name, timeout=2):
    def parse_txt(d, options=None):
        return [str(x,"utf8") for x in d.strings]
    return DNSRecord(dns.rdatatype.TXT, name, parse_txt, timeout=timeout).result
@functools.cache
def dns_netname(subnet, timeout=2):
    def parse_ptr(d, options=None):
        return d.target.to_text(omit_final_dot=True)
    r = DNSRecord(dns.rdatatype.PTR, "{:o}.CH-ADDR.NET.".format(subnet*256), parse_ptr, timeout=timeout).result
    return r[0] if r and len(r) > 0 else r

# Since default_domain can be a list, we can't cache this.
# @functools.cache
def dns_info_for(name, timeout=2, dns_address=dns_resolver_address, default_domain=None):
    if dns_address:
        set_dns_resolver_address(dns_address)
    if isinstance(name, str):
        oname = None
        if "." in name or default_domain is None:
            addrs = dns_addr_of_name(name, timeout=timeout)
        elif "." not in name and default_domain:
            oname = name
            for dd in default_domain:
                name = oname+"."+dd
                addrs = dns_addr_of_name(name, timeout=timeout)
                if addrs:
                    break
        canonical = None
        if addrs and len(addrs) > 0:
            c = dns_name_of_address(addrs[0], timeout=timeout)
            if c != name:
                canonical = c
                name = canonical
        hinfo = get_dns_host_info(name, timeout=timeout)
        rp = dns_responsible(name, timeout=timeout)
        txt = dns_text(name, timeout=timeout)
        d = {}
        if addrs or hinfo or rp or txt:
            d['name'] = [name] if oname is None else [name,oname]
        if addrs:
            d['addrs'] = addrs
            if canonical:
                d['canonical'] = canonical
        if hinfo:
            d['hinfo'] = hinfo
            d['os'] = hinfo['os']
            d['cpu'] = hinfo['cpu']
        if rp:
            d['responsible'] = rp
        if txt:
            d['txt'] = txt
        return d
    elif isinstance(name, int):
        if (name <= 0xff):
            nn = dns_netname(name, timeout=timeout)
            if nn:
                rp = dns_responsible(nn, timeout=timeout)
                if rp:
                    return dict(netname=nn,responsible=rp)
                else:
                    return dict(netname=nn)
        else:
            n = dns_name_of_address(name, timeout=timeout)
            if n:
                d = dns_info_for(n, timeout=timeout)
                if d:
                    return dict(name=n)|d
                else:
                    return dict(name=n)

# You typically want this, so do it
if local_domain() is not None:
    set_dns_search_list([local_domain(),"Chaosnet.NET"])
