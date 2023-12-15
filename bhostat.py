# Copyright © 2021 Björn Victor (bjorn@victor.se)
# Tool for exploring Chaosnet broadcast for various (simple) protocols.
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
import sys, subprocess, threading, errno
import re, string
import functools
from struct import unpack
from datetime import datetime, timedelta
from pprint import pprint, pformat
from enum import IntEnum, auto

# pip3 install dnspython
import dns.resolver

# server_address = '/tmp/chaos_stream'
packet_address = '/tmp/chaos_packet'

debug = False

# Default DNS resolver for Chaosnet
dns_resolver = 'DNS.Chaosnet.NET'
dns_resolver_address = None
  
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

#### sockets and simple conns

class Conn:
    sock = None

    def __init__(self):
        self.get_socket()
    def __str__(self):
        return "<{} {}>".format(type(self).__name__, self.sock is not None)
       
    # Construct a 4-byte packet header for chaos_packet connections
    def packet_header(self, opc, plen):
        return bytes([opc, 0, plen & 0xff, int(plen/256)])

    def get_socket(self):
        address = '/tmp/chaos_packet'
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except OSError as msg:
            print("Error opening Chaosnet socket: {} - Is the Chaosnet bridge running?".format(msg), file=sys.stderr)
            sys.exit(1)


    def send_packet(self, opcode, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} {} {}".format(self,Opcode(opcode).name, len(msg)), file=sys.stderr)
        self.sock.sendall(self.packet_header(Opcode(opcode), len(msg)) + msg)

    def get_packet(self):
        # Read header to see how long the pkt is
        hdr = self.sock.recv(4)
        if hdr is None or len(hdr) < 4:
            if debug:
                if len(hdr) == 0:
                    print("No data from recv, assuming closed socket {}".format(self.sock), file=sys.stderr)
                else:
                    print("Bad header {!r}".format(hdr), file=sys.stderr)
            return None, None
        # First is opcode
        opc = hdr[0]
        # then zero
        assert(hdr[1] == 0)
        # then length
        length = hdr[2] + hdr[3]*256
        if debug:
            print("< {} {} {}".format(self,Opcode(opc).name, length), file=sys.stderr)
        if opc == Opcode.ANS:
            # Includes 2 bytes of source!
            assert length <= 490
        else:
            assert length <= 488
        data = self.sock.recv(length)
        # print("< {} {!s}".format(len(data), str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")))
        return (opc,data)


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

def dns_name_of_address(addrstring, onlyfirst=True, timeout=5):
    if type(addrstring) is int:
        name = "{:o}.CH-ADDR.NET.".format(addrstring)
    else:
        name = "{}.CH-ADDR.NET.".format(addrstring)
    try:
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


host_names = dict()
# Prefer not to ask for a host's name
no_host_names = False
def host_name(addr, timeout=2):
    if isinstance(addr,int):
        if addr < 0o400:
            return addr
        addr = "{:o}".format(addr)
    # if no_host_names:
    #     return addr
    if addr in host_names:
        return host_names[addr]
    try:
        s = Simple(addr, "STATUS", options=dict(timeout=timeout))
        src, data = s.result()
    except:
        if debug:
            print("Error while getting STATUS of {}".format(addr), file=sys.stderr)
        host_names[addr] = "????"
        return "????"
    if src:
        name = str(data[:32].rstrip(b'\x00'), "ascii")
        host_names[addr] = name
    else:
        if debug:
            print("No STATUS from {:s}".format(addr), file=sys.stderr)
        name = dns_name_of_address(addr, timeout=timeout)
        if debug:
            print("Got DNS for {:s}: {}".format(addr,name), file=sys.stderr)
        if name is None:
            host_names[addr] = addr
        else:
            host_names[addr] = name
        # name = "{}".format(addr)
    return host_names[addr]

class Broadcast:
    conn = None
    def __init__(self, subnets, contact, args=[], options=None):
        self.conn = Conn()
        # print("Simple({} {}) t/o {}".format(host,contact, timeout))
        if len(subnets) == 1 and subnets[0] == -1:
            subnets = ["all"]
        elif len(subnets) == 1 and subnets[0] == 0:
            subnets = ["local"]
        h = bytes("{} {}".format(",".join(map(str,subnets)),contact),"ascii")
        for a in args:
            if isinstance(a,str):
                h += b" "+bytes(a)
            else:
                h += b" "+a
        if options is not None:
            h = bytes("["+",".join(list(map(lambda o: "{}={}".format(o, options[o]), filter(lambda o: options[o], options))))+"] ","ascii")+h
        try:
            if debug:
                print("BRD {}".format(h), file=sys.stderr)
            self.conn.send_packet(Opcode.BRD, h)
        except socket.error:
            return None
    def __iter__(self):
        return self
    def __next__(self):
        opc, data = self.conn.get_packet()
        if opc == None:
            raise StopIteration
        if opc == Opcode.ANS:
            if debug:
                src = data[0] + data[1]*256
                print("Got ANS from {:o} len {}".format(src,len(data)), file=sys.stderr)
            return data
        elif opc == Opcode.LOS or opc == Opcode.CLS:
            # LOS from cbridge, CLS from buggy BSD
            if debug:
                print("Got {}: {}".format(Opcode(opc).name, data), file=sys.stderr)
            raise StopIteration
        else:
            print("Got unexpected {} len {}: {}".format(Opcode(opc).name, len(data) if data is not None else 0, data),
                      file=sys.stderr)

# The STATUS protocol
class Status:
    def __init__(self,subnets, options=None):
        self.slist = self.get_status(subnets, options)
    def statuses(self):
        return self.slist
    def print_hostat(self,hname,src,sts):
        if " " in hname and not no_host_names:
            # This must be a "pretty name", so find the DNS name if possible
            dname = dns_name_of_address(src,onlyfirst=True,timeout=2)
            if dname is None:
                first = "{} ({:o})".format(hname, src)
            else:
                first = "{} [{}] ({:o})".format(hname, dname, src)
        else:
            first = "{} ({:o})".format(hname, src)
        if sts is not None:
            for s in sts:
                if len(first) >= 26:
                    # Make the numeric columns aligned at the cost of another line of output
                    print("{:s}".format(first))
                    first = ""
                print(("{:<25s}{:>6o}"+" {:>8}"*len(sts[s])).format(first,s,*sts[s].values()))
                # Only print the name for the first subnet entry
                first = ""
        else:
            print("{} not responding".format(first))
    def get_status(self, subnets, options):
        hlist = []
        print(("{:<25s}{:>6s} "+"{:>8} "*8).format("Name","Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected"))
        for data in Broadcast(subnets,"STATUS", options=options):
            src = data[0] + data[1]*256
            data = data[2:]
            dlen = len(data)
            # First is the name of the node
            hname = str(data[:32].rstrip(b'\x00'),'ascii')
            if hname in hlist:
                if debug:
                    print("Extra response from {} ({:o})".format(hname,src), file=sys.stderr)
                continue
            hlist.append(hname)
            fstart = 32
            statuses = dict()
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
            self.print_hostat(hname, src, statuses)
        return None



# The TIME protocol
class ChaosTime:
    def __init__(self,subnets, options=None):
        self.get_time(subnets, options=options)
    def get_time(self, subnets, options):
        hlist = []
        for data in Broadcast(subnets,"TIME",options=options):
            src = data[0] + data[1]*256
            if src in hlist:
                continue
            hlist.append(src)
            data = data[2:]
            hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
            # cf RFC 868
            print("{:16} {}".format(hname,datetime.fromtimestamp(unpack("I",data[0:4])[0]-2208988800)))

# The UPTIME protocol
class ChaosUptime:
    def __init__(self,subnets, options=None):
        self.get_uptime(subnets, options=options)
    def get_uptime(self, subnets, options):
        hlist = []
        for data in Broadcast(subnets,"UPTIME",options=options):
            src = data[0] + data[1]*256
            if src in hlist:
                continue
            hlist.append(src)
            data = data[2:]
            hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
            # cf RFC 868
            print("{:16} {}".format(hname,timedelta(seconds=int(unpack("I",data[0:4])[0]/60))))

# The FINGER protocol (note: not NAME)
class ChaosFinger:
    def __init__(self,subnets, options=None):
        self.get_finger(subnets, options=options)
    def get_finger(self, subnets, options):
        hlist = []
        free = []
        hdr_printed = False
        for data in Broadcast(subnets,"FINGER",options=options):
            src = data[0] + data[1]*256
            if src in hlist:
                continue
            hlist.append(src)
            data = data[2:]
            # hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
            hname = host_name("{:o}".format(src))
            fields = list(map(lambda x: str(x,'ascii'),data.split(b"\215")))
            if debug:
                print(hname, fields)
            if fields[0] == "":
                free.append([hname,fields])
            else:
                if not hdr_printed:
                    print("{:15s} {:1s} {:22s} {:10s} {:5s}    {:s}".format("User","","Name","Host","Idle","Location"))
                    hdr_printed = True
                # uname affiliation pname hname idle loc
                print("{:15s} {:1s} {:22s} {:10s} {:5s}    {:s}".format(fields[0],fields[4],fields[3],hname,fields[2],fields[1]))
        if len(free) > 0:
            print("\nFree (lisp) machines:")
            for f in free:
                print("{:17s} {:s} (idle {:s})".format(f[0],f[1][1],f[1][2]))

# The LOAD protocol
class ChaosLoad:
    def __init__(self,subnets, options=None):
        self.get_load(subnets, options=options)
    def get_load(self, subnets, options):
        hlist = []
        free = []
        for data in Broadcast(subnets,"LOAD",options=options):
            src = data[0] + data[1]*256
            if src in hlist:
                continue
            hlist.append(src)
            data = data[2:]
            hname = host_name("{:o}".format(src))
            fields = ", ".join(list(map(lambda x: str(x,'ascii'),data.split(b"\r\n"))))
            print("{}: {}".format(hname,fields))

# The DUMP-ROUTING-TABLE protocol
class ChaosDumpRoutingTable:
    def __init__(self,subnets, options=None):
        self.get_routing(subnets, options=options)
    def get_routing(self, subnets, options):
        hlist = []
        print("{:<20} {:>6} {:>6} {}".format("Host","Net","Meth","Cost"))
        # @@@@ consider presenting the info based on subnets, and how far hosts are from them
        for data in Broadcast(subnets,"DUMP-ROUTING-TABLE",options=options):
            src = data[0] + data[1]*256
            if src in hlist:
                continue
            hlist.append(src)
            data = data[2:]
            hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
            rtt = dict()
            for sub in range(0,int(len(data)/4)):
                sn = unpack('H',data[sub*4:sub*4+2])[0]
                if sn != 0:
                    rtt[sub] = dict(zip(('method','cost'),unpack('H'*2,data[sub*4:sub*4+4])))
            first = hname
            for sub in rtt:
                print("{:<20} {:>6o} {:>6o} {}".format(first,sub,rtt[sub]['method'],rtt[sub]['cost']))
                first = ""

# The LASTCN protocol
class ChaosLastSeen:
    def __init__(self,subnets, options=None, show_names=False):
        self.get_lastcn(subnets, options=options, show_names=show_names)
    def get_lastcn(self, subnets, options, show_names=False):
        hlist = []
        if show_names:
            print("{:<20} {:20} {:>8} {:10}  {}".format("Host","Seen","#in","Via","FC","Age"))
        else:
            print("{:<20} {:>8} {:>8} {:>8}  {}".format("Host","Seen","#in","Via","FC","Age"))
        # @@@@ consider presenting the info based on seen addresses (when seen at a certain bridge)?
        for data in Broadcast(subnets,"LASTCN",options=options):
            src = data[0] + data[1]*256
            if src in hlist:
                continue
            hlist.append(src)
            if debug:
                print("Got LASTCN input from {:o}".format(src), file=sys.stderr)
            data = data[2:]
            hname = "{} ({:o})".format(host_name("{:o}".format(src)), src) # if not(no_host_names) else "{:o}".format(src)
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
            first = hname
            for addr in cn:
                e = cn[addr]
                a = timedelta(seconds=e['age'])
                if show_names:
                    print("{:<20} {:<20} {:>8} {:<10} {:>4}  {}".format(first,"{} ({:o})".format(host_name(addr),addr),e['input'],host_name(e['via']),e['fc'],a))
                else:
                    print("{:<20} {:>8o} {:>8} {:>8o} {:>4}  {}".format(first,addr,e['input'],e['via'],e['fc'],a))
                first = ""                

class ChaosDNS:
    def __init__(self,subnets, options=None, name=None, qtype=None):
        rts = dict(a=dns.rdatatype.A, ptr=dns.rdatatype.PTR,
                       hinfo=dns.rdatatype.HINFO, loc=dns.rdatatype.LOC,
                       mx=dns.rdatatype.MX, ns=dns.rdatatype.NS, rp=dns.rdatatype.RP,
                       soa=dns.rdatatype.SOA, txt=dns.rdatatype.TXT,
                       any=dns.rdatatype.ANY)
        rtype = rts[qtype]
        self.subnets = subnets
        self.options = options
        self.name = name
        self.qtype = rts[qtype]
        self.qtype = dns.rdatatype.from_text(qtype)
        # self.get_dns(subnets, options=options, name=name, qtype=qtype)
    def get_values(self):
        hlist = []
        values = []
        msg = dns.message.make_query(self.name, self.qtype, rdclass=dns.rdataclass.CH)
        w = msg.to_wire()
        if debug:
            print("> {!r}".format(msg.to_text()))
            print("> {} {!r}".format(len(w), w))
        # print("> {!r}".format(msg.to_wire().from_wire().to_text()))
        for data in Broadcast(self.subnets,"DNS", args=[w], options=self.options):
            src = data[0] + data[1]*256
            resp = data[2:]
            if src not in hlist:
                r = dns.message.from_wire(resp)
                if r.rcode() == dns.rcode.NXDOMAIN:
                    print("Non-existing domain: {}".format(self.name), file=sys.stderr)
                    if not debug:
                        return None
                if debug:
                    print("< {:o} {!r}".format(src,r.to_text()))
                for t in r.answer:
                    print("Answer from {:o}: {}".format(src,t.to_text()))
                    if self.qtype == t.rdtype:
                        v = []
                        if self.qtype == dns.rdatatype.PTR:
                            for d in t:
                                v.append(d.target.to_text())
                        elif self.qtype == dns.rdatatype.A:
                            for d in t:
                                v.append(d.address)
                        elif self.qtype == dns.rdatatype.TXT:
                            for d in t:
                                v.append(d.strings)
                        elif self.qtype == dns.rdatatype.HINFO:
                            for d in t:
                                v.append(d.to_text())
                        if len(v) > 0:
                            if self.qtype == dns.rdatatype.A:
                                # hack hack
                                print(("{}: "+", ".join(["{:o}"]*len(v))).format(dns.rdatatype.to_text(self.qtype), *v))
                            else:
                                print("{}: {}".format(dns.rdatatype.to_text(self.qtype), v))
                        values += v
                if not debug:
                    # first response is sufficient
                    return values
                hlist.append(src)
        return values

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet STATUS broadcast')
    parser.add_argument("subnets", metavar="SUBNET", type=int, nargs='+',
                            help="Subnets to broadcast on, -1 for all subnets, or 0 for the local subnet")
    parser.add_argument("-t","--timeout", type=int, default=5,
                            help="Timeout in seconds")
    parser.add_argument("-r","--retrans", type=int, default=500,
                            help="Retransmission interval in milliseconds")
    parser.add_argument("-s","--service", default="STATUS",
                            help="Service to ask for (STATUS, TIME, UPTIME, FINGER, ROUTING, LOAD, LASTCN, DNS)")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-n",'--no-host-names', dest='no_host_names', action='store_true',
                            help="Prefer not to ask hosts for their names")
    parser.add_argument("-R","--resolver", default=dns_resolver,
                            help="DNS resolver to use (over IP) for Chaosnet data")
    parser.add_argument("--name", help="Name to ask for Chaosnet data of (DNS)", default="Router.Chaosnet.NET")
    parser.add_argument("--rtype", help="Resource to ask for (DNS)", default="a")
    args = parser.parse_args()
    if args.debug:
        print(args)
        debug = True
    if args.no_host_names:
        no_host_names = True
    if args.resolver:
        try:
            dns_resolver_address = socket.gethostbyname(args.resolver)
        except OSError as msg:
            print("Error resolving {!r}: {}".format(args.resolver, msg), file=sys.stderr)
            exit(1);
    if -1 in args.subnets and len(args.subnets) != 1:
        # "all" supersedes all other
        args.subnets = [-1]
    elif 0 in args.subnets and len(args.subnets) != 1:
        # "local" supersedes all other
        args.subnets = [0]
    if args.service.upper() == 'STATUS':
        c = Status
    elif args.service.upper() == 'TIME':
        c = ChaosTime
    elif args.service.upper() == 'UPTIME':
        c = ChaosUptime
    elif args.service.upper() == 'FINGER':
        c = ChaosFinger
    elif args.service.upper() == 'LOAD':
        c = ChaosLoad
    elif args.service.upper() == "LASTCN":
        c = lambda sn,ops: ChaosLastSeen(sn,ops,show_names=not(no_host_names))
    elif args.service.upper() == "ROUTING" or args.service.upper() == "DUMP-ROUTING-TABLE":
        c = ChaosDumpRoutingTable
    elif args.service.upper() == "DNS":
        if args.name.isdigit():
            args.name += ".ch-addr.net"
            args.rtype = "ptr"
        c = ChaosDNS(args.subnets,options=dict(timeout=args.timeout, retrans=args.retrans),
                         name=args.name, qtype=args.rtype)
        print("Values: {}".format(c.get_values()))
        exit(0)
    else:
        print("Bad service arg {}, please use STATUS, TIME, UPTIME, FINGER, (dump-)ROUTING(-table), LOAD, DNS or LASTCN (in any case)".format(args.service))
        exit(1)
    opts = dict(timeout=args.timeout, retrans=args.retrans)
    try:
        c(args.subnets,opts)
    except KeyboardInterrupt:
        pass
