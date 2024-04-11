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

import socket, sys, time
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
            raise ChaosSocketError("Error opening Chaosnet socket: {} - Is the Chaosnet bridge running?".format(msg))

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
        while b != b"\r" and b != b"\n" and b != b"":
            rline += b
            b = self.get_bytes(1)
        if rline == b"":
            raise ChaosError("got no data in get_line for {}".format(self))
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
            print(">>> {} len {}".format(Opcode(opc).name, len(data) if data is not None else 0), file=sys.stderr)
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
                raise UnexpectedOpcode("in {}: Expected ACK after EOF[wait], got {}".format(self,Opcode(opc).name))
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
            print("< {} {} {}".format(self,Opcode(opc).name, length), file=sys.stderr)
        return opc, self.get_bytes(length)

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact), file=sys.stderr)
        self.send_packet(Opcode.LSN,bytes(contact,"ascii"))
        op,data = self.get_packet()
        if debug:
            print("{}: {}".format(Opcode(op).name,data), file=sys.stderr)
        if op == Opcode.RFC or op == Opcode.BRD: # BRD is supposed to be translated to RFC!
            hostandargs = str(data,"ascii").split(" ",maxsplit=1)
            self.remote = hostandargs[0]
            self.args = hostandargs[1] if len(hostandargs) > 1 else ""
            return self.remote,self.args
        elif op == Opcode.LOS:
            raise LOSError("LOS: {}".format(str(data,"ascii")))
        else:
            raise UnexpectedOpcode("Expected RFC: {}".format(Opcode(op).name))

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
            raise UnexpectedOpcode("Expected OPN, got {}".format(Opcode(opc).name))

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

    def copy_until_eof(self, outstream=sys.stdout):
        while True:
            opc, data = self.get_packet()
            if opc == Opcode.CLS:
                self.close()
                return None
            elif opc == Opcode.LOS:
                raise LOSError("LOS: {}".format(str(data,"ascii")))
            elif opc == Opcode.EOF:
                # raise EOFError("{} got EOF: {}".format(self,data))
                return None
            # @@@@ handle ANS too?
            elif opc != Opcode.DAT:
                raise UnexpectedOpcode("Unexpected opcode {}".format(opc))
                return None
            else:
                # Translate to Unix
                out = str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")
                print("{!s}".format(out), file=outstream, end='' if out[-1] not in [0o215,0o212,0o15,0o12] else None)

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
                print("Got ANS from {:o} len {}".format(src,len(data)), file=sys.stderr)
            return src,data[2:]
        elif opc == Opcode.LOS or opc == Opcode.CLS:
            # LOS from cbridge after BRD time-outs, CLS from buggy BSD
            if debug:
                print("Got {}: {}".format(Opcode(opc).name, data), file=sys.stderr)
            # just ignore it.
            raise StopIteration
        else:
            raise UnexpectedOpcode("Got unexpected {} len {}: {}".format(Opcode(opc).name, len(data) if data is not None else 0, data))

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

    def copy_until_eof(self, outstream=sys.stdout):
        cmap = { 0o211: 0o11, 0o215: 0o12, 0o212: 0o15 }
        last = None
        while True:
            data = self.get_bytes(488)
            if len(data) == 0:
                if last not in [0o215,0o212,0o15,0o12]:
                    # finish with a fresh line
                    print("",file=outstream)
                return None
            for c in data:
                last = c
                # translate
                if c in cmap:
                    print(chr(cmap[c]),end='',file=outstream)
                else:
                    print(chr(c),end='',file=outstream)

# Generic simple protocol
class Simple:
    conn = None
    hname = None
    # To support chaining with broadcast
    hdr_printed = False
    printed_sources = []
    def __init__(self, hnames, contact, args=[], options=None, header=None, printer=None, nonprinter=None, already_printed=None):
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
                    if not self.hdr_printed and header is not None:
                        print(header)
                        self.hdr_printed = True
                    if data is not None and not printer(src,data):
                        # Save this if it wasn't printed now (e.g. Free lispm)
                        nonprinted.append([src,data])
                    self.printed_sources.append(src)
                else:
                    return None
            except socket.error:
                pass
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
        elif opc == Opcode.LOS:
            if debug:
                print("LOS (from {}): {}".format(self.hname, data), file=sys.stderr)
            raise LOSError("LOS: {}".format(str(data,"ascii")))
            return None, None
        elif opc == Opcode.FWD:
            dest = data[0] + data[1]*256
            if debug:
                print("FWD received: use host {:o} instead {}".format(dest,data[2:]), file=sys.stderr)
            # This should be a separate exception so it can be handled, and FWD should be detected in other places too.
            raise UnexpectedOpcode("Unexpected FWD from {}: use host {:o} instead".format(self.hname, dest))
        else:
            raise UnexpectedOpcode("Unexpected opcode {} from {} ({})".format(Opcode(opc).name, self.hname, data))

# Given subnets, contact, options, header, and a printer (taking ANS as arg),
# broadcast and then iterate printer over responses, filtering previously received ones
class BroadcastSimple:
    # To support chaining with unicast
    hdr_printed = False
    printed_sources = []
    def __init__(self, subnets, contact, args=[], options=None, header=None, printer=None, nonprinter=None, already_printed=None):
        nonprinted = []
        if already_printed is not None:
            self.printed_sources = already_printed
        for src,data in BroadcastConn(subnets, contact, options=options, args=args):
            if src in self.printed_sources:
                continue                  # already handled
            self.printed_sources.append(src)
            if not self.hdr_printed and header is not None:
                print(header)               # print header
                self.hdr_printed = True
            if not printer(src,data):
                # Save this if it wasn't printed now (e.g. Free lispm)
                nonprinted.append([src,data])
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

def dns_name_of_address(addrstring, onlyfirst=False, timeout=5):
    if type(addrstring) is int:
        name = "{:o}.CH-ADDR.NET.".format(addrstring)
        addrstring = "{:o}".format(addrstring)
    else:
        name = "{}.CH-ADDR.NET.".format(addrstring)
    try:
        if debug:
            print("DNS query for {} to resolver address {}".format(name, dns_resolver_address), file=sys.stderr)
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.PTR, rdclass=dns.rdataclass.CH),
                              dns_resolver_address, timeout=timeout)
        for t in h.answer:
            if t.rdtype == dns.rdatatype.PTR:
                    for d in t:
                        n = d.target.to_text(omit_final_dot=True)
                        if onlyfirst:
                            return n.split('.',maxsplit=1)[0]
                        else:
                            return n
                        # return d.target_to_text()
        return addrstring
    except AttributeError as e:
        # dnspython not updated with support for Chaos records?
        pass
        # print("Error", e, file=sys.stderr)
    except dns.exception.Timeout as e:
        if debug:
            print("Timeout error:", e, file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error:", e, file=sys.stderr)

def get_dns_host_info(name, timeout=5, rclass="CH"):
    # If it's an address given, look up the name first
    if isinstance(name,int):
        name = dns_name_of_address(name, timeout=timeout) or name
    elif isinstance(name,str) and name.isdigit():
        name = dns_name_of_address(int(name,8), timeout=timeout) or name
    try:
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.HINFO, rdclass=dns.rdataclass.from_text(rclass)),
                              dns_resolver_address, timeout=timeout)
        for t in h.answer:
            if t.rdtype == dns.rdatatype.HINFO:
                for d in t:
                    return dict(os= str(d.os.decode()), cpu= str(d.cpu.decode()))
    except AttributeError as e:
        # dnspython not updated with support for Chaos records?
        pass
        # print("Error", e, file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error", e, file=sys.stderr)

def dns_addr_of_name(name, timeout=5, rclass="CH"):
    # If it's an address given, look up the name first, to collect all its addresses
    if isinstance(name,int):
        name = dns_name_of_address(name, timeout=timeout) or name
    elif isinstance(name,str) and name.isdigit():
        name = dns_name_of_address(int(name,8), timeout=timeout) or name
    addrs = []
    try:
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.A, rdclass=dns.rdataclass.from_text(rclass)),
                              dns_resolver_address, timeout=timeout)
        for t in h.answer:
            if t.rdtype == dns.rdatatype.A:
                    for d in t:
                        addrs.append(d.address)
    except AttributeError as e:
        # dnspython not updated with support for Chaos records?
        pass
        # print("Error", e, file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error", e, file=sys.stderr)
    return addrs

# Get all info
def dns_info_for(nameoraddr, timeout=5, dns_address=dns_resolver_address, default_domain=None, rclass="CH"):
    if dns_address:
        set_dns_resolver_address(dns_address)
    isnum = False
    extra = None
    if isinstance(nameoraddr,int):
        name = dns_name_of_address(nameoraddr,timeout=timeout)
        isnum = nameoraddr
    elif isinstance(nameoraddr,str) and nameoraddr.isdigit():
        name = dns_name_of_address(int(nameoraddr,8),timeout=timeout)
        isnum = int(nameoraddr,8)
    else:
        name = nameoraddr.strip()
    if name:
        if "." not in name:
            # Try each domain in the list
            if isinstance(default_domain,list) and len(default_domain) > 0:
                extra = name
                for d in default_domain:
                    n = name+"."+d
                    addrs = dns_addr_of_name(n,timeout=timeout,rclass=rclass)
                    if addrs is not None and len(addrs) > 0:
                        name = n
                        break
            # Try the given domain
            elif isinstance(default_domain,str):
                extra = name
                name = name+"."+default_domain
                addrs = dns_addr_of_name(name,timeout=timeout,rclass=rclass)
            # Well try it anyway
            else:
                addrs = dns_addr_of_name(name,timeout=timeout,rclass=rclass)
        else:
            addrs = dns_addr_of_name(name,timeout=timeout,rclass=rclass)
        if addrs is None or len(addrs) == 0:
            return None
        hinfo = get_dns_host_info(name,timeout=timeout,rclass=rclass)
        names = [name] if not extra else [name,extra]
        if not isnum and rclass == "CH":
            # Got a name for nameoraddr, check its reverse mapping
            if debug:
                print("Trying name of addr {}".format(addrs[0]), file=sys.stderr)
            canonical = dns_name_of_address(addrs[0],timeout=timeout)
            if canonical:
                names = [canonical]+names  if canonical.lower() != name.lower() else [canonical,extra] if extra else [canonical]
        return dict(name=names, addrs=addrs, os=None if hinfo == None else hinfo['os'], cpu=None if hinfo == None else hinfo['cpu'])
