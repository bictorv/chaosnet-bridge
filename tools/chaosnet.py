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
        b = self.get_bytes(1)
        while b != b"\r" and b != b"\n" and b != b"\215" and b != b"":
            rline += b
            b = self.get_bytes(1)
        if rline == b"":
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
            raise ChaosError(str(data,"ascii"))
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
                h += b" "+bytes(a)
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
    def send_los(self, msg):
        # Can't do this over stream interface
        pass
    def send_cls(self, msg):
        # Can't do this over stream interface
        pass

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
            raise ChaosError(str(data,"ascii"))
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
            # This should be a separate exception so it can be handled, and FWD should be detected in other places too.
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

################ DNS
# pip3 install dnspython
import dns.resolver

# Default DNS resolver for Chaosnet
dns_resolver_name = 'DNS.Chaosnet.NET'
dns_resolver_address = socket.gethostbyname(dns_resolver_name)

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
