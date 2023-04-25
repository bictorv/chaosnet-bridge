# Copyright © 2023 Björn Victor (bjorn@victor.se)
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

import socket, io, sys
from enum import IntEnum, auto

# The directories of these need to match the "socketdir" ncp setting in cbridge.
stream_socket_address = '/tmp/chaos_stream'
packet_socket_address = '/tmp/chaos_packet'
# -d
debug = False
packetp = False

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

    def set_debug(self,val):
        global debug
        debug = val

    def close(self, msg=b"Thank you"):
        if debug:
            print("\r\nClosing {} with msg {}".format(self,msg), file=sys.stderr)
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
            print('\r\nSocket errror:',msg, file=sys.stderr)
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
                print("\r\nERROR: return not followed by newline in get_line from {}: got {}".format(self,b),
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
            print("\r\n> {} to {}".format(len(msg), self), file=sys.stderr)
        self.send_socket_data(self.packet_header(Opcode.DAT, len(msg)) + msg)

    def send_packet(self, opc, data=None):
        if debug:
            print("\r\n>>> {} len {}".format(Opcode(opc).name, len(data) if data is not None else 0), file=sys.stderr)
        if data is None:
            self.send_socket_data(self.packet_header(opc, 0))
        else:
            self.send_socket_data(self.packet_header(opc, len(data))+data)

    def send_los(self, msg):
        self.send_packet(Opcode.LOS, msg)
    def send_cls(self, msg):
        self.send_packet(Opcode.CLS, msg)
    def send_eof(self, wait=False):
        if wait:
            self.send_packet(Opcode.EOF,b"wait")
            # eofwait should also be an RFC option.
            # @@@@ NOTE BUG: when both client and server are using NCP on same host, the EOF isn't ACKed!
            opc,ack = self.get_packet()
            if opc != Opcode.ACK:
                raise OSError("in {}: Expected ACK after EOF[wait], got {}".format(self,Opcode(opc).name))
        else:
            self.send_packet(Opcode.EOF)

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
            print("\r\n< {} {} {}".format(self,Opcode(opc).name, length), file=sys.stderr)
        return opc, self.get_bytes(length)

    def listen(self, contact):
        self.contact = contact
        if debug:
            print("Listen for {}".format(contact))
        self.send_packet(Opcode.LSN,bytes(contact,"ascii"))
        op,data = self.get_packet()
        if debug:
            print("\r\n{}: {}".format(op,data), file=sys.stderr)
        if op == Opcode.RFC:
            self.remote = str(data,"ascii")
            self.send_packet(Opcode.OPN)
            return self.remote
        else:
            print("\r\nExpected RFC: {}".format(inp), file=sys.stderr)
            return None

    def connect(self, host, contact, args=[], options=None):
        h = bytes(("{} {}"+" {}"*len(args)).format(host,contact.upper(),*args),"ascii")
        if options is not None:
            h = bytes("["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] ","ascii")+h
        if debug:
            print("\r\nOptions: {} = {}".format(options, h), file=sys.stderr)
            print("\r\nRFC: {}".format(h), file=sys.stderr)
        self.send_packet(Opcode.RFC, h)
        opc, data = self.get_packet()
        if opc == Opcode.OPN:
            self.active = True
            self.remote = str(data,"ascii")
            self.contact = contact
            return True
        elif opc == Opcode.LOS:
            print("\r\nGot LOS: {}".format(str(data,"ascii")), file=sys.stderr)
            return False
        else:
            print("\r\nExpected OPN: {}".format(opc), file=sys.stderr)
            return False

    def get_message(self, dlen=488):
        opc, data = self.get_packet()
        if opc == Opcode.CLS:
            self.close()
            return None
        elif opc == Opcode.LOS:
            if True or debug:
                print("\r\nLOS: {}".format(str(data,"ascii")), file=sys.stderr)
            return None
        elif opc == Opcode.EOF:
            if debug:
                print("\r\n{} got EOF: {}".format(self,data), file=sys.stderr)
            return None
        elif opc != Opcode.DAT:
            print("\r\nUnexpected opcode {}".format(opc), file=sys.stderr)
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
            print("> {} to {}\r".format(len(msg), self), file=sys.stderr)
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
            print("{}: {}\r".format(op,data), file=sys.stderr)
        if op == b"RFC":
            self.remote = str(data,"ascii")
            return self.remote
        else:
            print("\r\nExpected RFC: {}\r".format(inp), file=sys.stderr)
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
            print("\r\n{}: {}".format(op,data), file=sys.stderr)
        if op == b"OPN":
            self.active = True
            self.remote = host                  #should parse OPN data
            self.contact = contact
            return True
        else:
            print("\r\nExpected OPN: {}".format(inp), file=sys.stderr)
            return False

    def get_message(self, length=488):
        data = self.sock.recv(length)
        if debug:
            print("\r\n< {} of {} from {}".format(len(data), length, self), file=sys.stderr)
        if len(data) == 0:
            # This is handled somewhere
            raise OSError("Error: Got no bytes: {}".format(data))
        elif len(data) < length:
            d2 = self.sock.recv(length-len(data))
            if debug:
                print("\r\n< {} of {} from {}".format(len(d2), length, self), file=sys.stderr)
            data += d2
        return data

class Simple:
    conn = None
    hname = None
    def __init__(self, hname, contact, args=[], options=None):
        self.hname = hname
        self.conn = Conn()
        h = ("{} {}"+" {}"*len(args)).format(hname,contact,*args)
        if options is not None:
            h = "["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] "+h
        try:
            if debug:
                print("RFC {}".format(h), file=sys.stderr)
            self.conn.send_packet(Opcode.RFC, bytes(h,"ascii"))
        except socket.error:
            return None
    def result(self):
        opc, data = self.conn.get_packet()
        if opc == Opcode.ANS:
            src = data[0] + data[1]*256
            return src, data[2:]
        elif opc == Opcode.LOS:
            if debug:
                print("LOS (from {}): {}".format(self.hname, data), file=sys.stderr)
            return None, None
        else:
            print("Unexpected opcode {} from {} ({})".format(Opcode(opc).name, self.hname, data), file=sys.stderr)
            return None

################ DNS
# pip3 install dnspython
import dns.resolver

# Default DNS resolver for Chaosnet
dns_resolver_name = 'DNS.Chaosnet.NET'
dns_resolver_address = None

def set_dns_resolver_address(adorname):
    global dns_resolver_address
    dns_resolver_address = socket.gethostbyname(adorname)
    return dns_resolver_address

def dns_name_of_address(addrstring, onlyfirst=False, timeout=5):
    if type(addrstring) is int:
        name = "{:o}.CH-ADDR.NET.".format(addrstring)
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
