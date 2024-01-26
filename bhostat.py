# Copyright © 2021-2024 Björn Victor (bjorn@victor.se)
# Tool for exploring Chaosnet using various (simple) protocols.
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

# TODO: rename this to "simple.py", semi-ironically

import sys, time, socket
import string, re
import functools
from struct import unpack
from datetime import datetime, timedelta

from chaosnet import BroadcastSimple, Simple, BroadcastConn, StreamConn
from chaosnet import dns_name_of_address, dns_resolver_name, dns_resolver_address, set_dns_resolver_address

# pip3 install dnspython
import dns.resolver

debug = False
verbose = False

# Prefer not to ask for a host's name
no_host_names = False

@functools.cache
def host_name(addr, timeout=2):
    if isinstance(addr,int):
        if addr < 0o400:
            return addr
        addr = "{:o}".format(addr)
    # if no_host_names:
    #     return addr
    # if addr in host_names:
    #     return host_names[addr]
    try:
        s = Simple(addr, "STATUS", options=dict(timeout=timeout))
        src, data = s.result()
    except OSError as msg:
        if debug:
            print("Error while getting STATUS of {}: {}".format(addr,msg), file=sys.stderr)
        # host_names[addr] = "????"
        return "????"
    if src:
        name = str(data[:32].rstrip(b'\x00'), "ascii")
        # host_names[addr] = name
        return name
    else:
        if debug:
            print("No STATUS from {:s}".format(addr), file=sys.stderr)
        name = dns_name_of_address(addr, timeout=timeout, onlyfirst=True)
        if debug:
            print("Got DNS for {:s}: {}".format(addr,name), file=sys.stderr)
        if name is None:
            # host_names[addr] = addr
            return addr
        else:
            # host_names[addr] = name
            return name
        # name = "{}".format(addr)
    # return host_names[addr]

#### Application protocols

# Oxymoron ("simple" means "datagram" in Chaosnet lingo), but here it means:
# given a host and contact, copy its output until EOF
class SimpleStreamProtocol:
    def __init__(self,host,contact,options=None,args=[]):
        self.conn = StreamConn()
        self.conn.connect(host,contact,options=options,args=args)
    def copy_until_eof(self, outstream=sys.stderr):
        self.conn.copy_until_eof(outstream=outstream)

# Implement methods for header, printer (of each ANS received) and nonprinter (to print e.g. free lispms)
# If the printer methods returns False, the data is assumed non-printed and passed to the nonprinter at the end.
class SimpleProtocol:
    contact = None
    options = None
    def __init__(self,subnets,options=None):
        self.options = options
        # Allow mix of subnets (for broadcast) and host/addresses (for unicast)
        snargs = list(filter(lambda x: isinstance(x,int) and x < 0o400,subnets))
        hargs = list(filter(lambda x: not(isinstance(x,int) and x < 0o400),subnets))
        hdr = self.header() if callable(getattr(self.__class__,'header',None)) else None
        prtr = self.printer if callable(getattr(self.__class__,'printer',None)) else None
        nprtr = self.nonprinter if callable(getattr(self.__class__,'nonprinter',None)) else None
        s = None
        # First do unicast, if any
        if len(hargs) > 0:
            s = Simple(hargs,self.contact,options=options,header=hdr,printer=prtr,nonprinter=nprtr)
        # then do broadcast, if any
        if len(snargs) > 0:
            # Avoid printing the header twice and repeating unicast hosts in the broadcast results
            BroadcastSimple(snargs,self.contact,options=options,header=hdr if s is None or s.hdr_printed is False else None,
                                printer=prtr,nonprinter=nprtr,
                                already_printed=None if s is None else s.printed_sources)

# The STATUS protocol
class Status(SimpleProtocol):
    contact = "STATUS"
    def header(self):
        return ("{:<25s}{:>6s} "+"{:>8} "*8).format("Name","Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected")
    def printer(self,src,data):
        # First is the name of the node
        hname = str(data[:32].rstrip(b'\x00'),'ascii')
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
        # Now print it
        if " " in hname and not no_host_names:
            # This must be a "pretty name", so find the DNS name if possible
            dname = dns_name_of_address(src,onlyfirst=True,timeout=2)
            if dname is None:
                first = "{} ({:o})".format(hname, src)
            else:
                first = "{} [{}] ({:o})".format(hname, dname, src)
        else:
            first = "{} ({:o})".format(hname, src)
        if statuses is not None:
            for s in statuses:
                if len(first) >= 26:
                    # Make the numeric columns aligned at the cost of another line of output
                    print("{:s}".format(first))
                    first = ""            #
                print(("{:<25s}{:>6o}"+" {:>8}"*len(statuses[s])).format(first,s,*statuses[s].values()))
                # Only print the name for the first subnet entry
                first = ""
        else:
            print("{} not responding".format(first))

# The TIME protocol
class ChaosTime(SimpleProtocol):
    contact = "TIME"
    def printer(self,src,data):
        hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
        # cf RFC 868
        t = unpack("I",data[0:4])[0]-2208988800
        if verbose:
            dt = t-time.time()
            print("{:16} {} (delta {}{})".format(hname,datetime.fromtimestamp(t),"+" if dt >= 0 else "-",timedelta(milliseconds=abs(1000*dt))))
        else:
            print("{:16} {}".format(hname,datetime.fromtimestamp(t)))

# The UPTIME protocol
class ChaosUptime(SimpleProtocol):
    contact = "UPTIME"
    def printer(self, src, data):
        hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
        # cf RFC 868
        print("{:16} {}".format(hname,timedelta(seconds=int(unpack("I",data[0:4])[0]/60))))

# The FINGER protocol (note: not NAME)
class ChaosFinger(SimpleProtocol):
    contact = "FINGER"
    def header(self):
        return "{:15s} {:1s} {:22s} {:10s} {:5s}    {:s}".format("User","","Name","Host","Idle","Location")
    def printer(self,src,data):
        hname = host_name("{:o}".format(src))
        fields = list(map(lambda x: str(x,'ascii'),data.split(b"\215")))
        if fields[0] == "":
            return False
        # uname affiliation pname hname idle loc
        print("{:15s} {:1s} {:22s} {:10s} {:5s}    {:s}".format(fields[0],fields[4],fields[3],hname,fields[2],fields[1]))
        return True
    def nonprinter(self,freelist):
        if len(freelist) > 0:
            print("\nFree (lisp) machines:")
            for src,data in freelist:
                hname = host_name("{:o}".format(src))
                f = list(map(lambda x: str(x,'ascii'),data.split(b"\215")))
                print("{:17s} {:s}{:s}".format(hname,f[1]," (idle {:s})".format(f[2]) if f[2] != "" else ""))

# The LOAD protocol
class ChaosLoad(SimpleProtocol):
    contact = "LOAD"
    def printer(self, src, data):
        try:
            hname = host_name("{:o}".format(src))
        except:
            hname = src
        fields = ", ".join(list(map(lambda x: str(x,'ascii'),data.split(b"\r\n"))))
        print("{}: {}".format(hname,fields))

# Hack: use LOAD to see if it's worth fingering (with NAME)
class ChaosLoadName(SimpleProtocol):
    contact = "LOAD"
    def printer(self, src, data):
        try:
            # Get full name, for this purpose
            hname = dns_name_of_address(src,onlyfirst=False,timeout=2)
            if hname is None:
                hname = "{:o}".format(src)
        except:
            hname = src
        # Parse the second line
        nmatch = re.match(r"Users: (\d+)", str(data.split(b"\r\n")[1],"ascii"))
        if nmatch:
            n = int(nmatch.group(1))
            if n == 0:
                # No users, just report it's empty
                return False
            # Print a header to show what's about to happen
            print("[{:s}]".format(hname))
            try:
                s = SimpleStreamProtocol(hname,"NAME")
                s.copy_until_eof()
            except OSError as msg:
                if debug:
                    print(msg, file=sys.stderr)
                return False
            return True
    def nonprinter(self,datas):
        if len(datas) > 0:
            hnames = []
            # Collect the host names of empty hosts - use short name here
            for src,d in datas:
                hnames.append(host_name("{:o}".format(src)))
            # Report it.
            print("\nNo users on "+", ".join(hnames)+".")

# The DUMP-ROUTING-TABLE protocol
class ChaosDumpRoutingTable(SimpleProtocol):
    contact = "DUMP-ROUTING-TABLE"
    def header(self):
        return "{:<20} {:>6} {:>6} {}".format("Host","Net","Meth","Cost")
    def printer(self, src, data):
        hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
        rtt = dict()
        # Parse routing table info
        for sub in range(0,int(len(data)/4)):
            sn = unpack('H',data[sub*4:sub*4+2])[0]
            if sn != 0:
                rtt[sub] = dict(zip(('method','cost'),unpack('H'*2,data[sub*4:sub*4+4])))
        first = hname
        for sub in rtt:
            print("{:<20} {:>6o} {:>6o} {}".format(first,sub,rtt[sub]['method'],rtt[sub]['cost']))
            first = ""

# The LASTCN protocol
class ChaosLastSeen(SimpleProtocol):
    contact = "LASTCN"
    def header(self):
        if not no_host_names:
            return("{:<20} {:20} {:>8} {:10}  {}".format("Host","Seen","#in","Via","FC","Age"))
        else:
            return("{:<20} {:>8} {:>8} {:>8}  {}".format("Host","Seen","#in","Via","FC","Age"))
    def printer(self, src, data):
        hname = "{} ({:o})".format(host_name("{:o}".format(src)), src) if not(no_host_names) else "{:o}".format(src)
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
            if not no_host_names:
                print("{:<20} {:<20} {:>8} {:<10} {:>4}  {}".format(first,"{} ({:o})".format(host_name(addr),addr),e['input'],host_name(e['via']),e['fc'],a))
            else:
                print("{:<20} {:>8o} {:>8} {:>8o} {:>4}  {}".format(first,addr,e['input'],e['via'],e['fc'],a))
            first = ""                

# @@@@ rewrite like above
class ChaosDNS:
    def __init__(self,subnets, options=None, name=None, qtype=None):
        self.subnets = subnets
        self.options = options
        self.name = name
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
        for src,resp in BroadcastConn(self.subnets,"DNS", args=[w], options=self.options):
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

contact_handlers = { 'status': Status,
                         'time': ChaosTime,
                         'uptime': ChaosUptime,
                         'finger': ChaosFinger,
                         'load': ChaosLoad,
                         'loadname': ChaosLoadName,
                         'lastcn': ChaosLastSeen,
                         'routing': ChaosDumpRoutingTable,
                         'dump-routing-table': ChaosDumpRoutingTable }
special_contact_handlers = dict(#lastcn=ChaosLastSeen,
                                dns=ChaosDNS)

if __name__ == '__main__':
    import argparse
    service_names = ", ".join(contact_handlers.keys()).upper()+", "+", ".join(special_contact_handlers.keys()).upper()
    parser = argparse.ArgumentParser(description='Chaosnet simple protocol client',
                                         epilog="If the service is unknown and a host is given, "+\
                                         "tries to contact the service at the host and prints its output.")
    parser.add_argument("subnets", metavar="SUBNET/HOST", nargs='+', #type=int, 
                            help="Hosts to contact or Subnets to broadcast on, -1 for all subnets, or 0 for the local subnet")
    parser.add_argument("-t","--timeout", type=int, default=5,
                            help="Timeout in seconds")
    parser.add_argument("-r","--retrans", type=int, default=500,
                            help="Retransmission interval in milliseconds")
    parser.add_argument("-s","--service", default="STATUS",
                            help="Service to ask for ("+service_names+"), default: STATUS")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-v",'--verbose',dest='verbose',action='store_true',
                            help='Turn on verbose printouts')
    parser.add_argument("-n",'--no-host-names', dest='no_host_names', action='store_true',
                            help="Prefer not to ask hosts for their names")
    parser.add_argument("-R","--resolver", default=dns_resolver_name,
                            help="DNS resolver to use (over IP) for Chaosnet data, default "+dns_resolver_name)
    parser.add_argument("--name", help="Name to ask for Chaosnet data of (DNS)", default="Router.Chaosnet.NET")
    parser.add_argument("--rtype", help="Resource to ask for (DNS)", default="A")
    args = parser.parse_args()
    if args.debug:
        print(args)
        debug = True
    if args.verbose:
        verbose = True
    if args.no_host_names:
        no_host_names = True
    if args.resolver:
        dns_resolver_address = set_dns_resolver_address(args.resolver)

    if -1 in args.subnets and len(args.subnets) != 1:
        # "all" supersedes all other
        args.subnets = [-1]
    elif 0 in args.subnets and len(args.subnets) != 1:
        # "local" supersedes all other
        args.subnets = [0]
    # Parse "subnet" args as numbers (if they can be)
    args.subnets = list(map(lambda x: int(x,8) if isinstance(x,str) and (x.isdigit() or x =="-1") else x, args.subnets))

    # @@@@ if no service explicitly given, but first "subnet" is a service (and more given), use that?
    try:
        if args.service.lower() in contact_handlers:
            c = contact_handlers[args.service.lower()]
            opts = dict(timeout=args.timeout, retrans=args.retrans)
            c(args.subnets,opts)
        elif args.service.lower() in special_contact_handlers:
            if args.service.upper() == "DNS":
                # Broadcast a DNS quuery and show the result
                if args.name.isdigit():
                    # Ask for a pointer instead
                    args.name += ".CH-ADDR.NET"
                    args.rtype = "ptr"
                c = ChaosDNS(args.subnets,options=dict(timeout=args.timeout, retrans=args.retrans),
                                name=args.name, qtype=args.rtype)
                print("Values: {}".format(c.get_values()))
                exit(0)
        elif len(args.subnets) == 1 and (isinstance(args.subnets[0],str) or args.subnets[0] > 0xff):
            # Hack: try connecting to the service at the host
            # @@@@ Could parse the service, split at spaces and put things in contact args.
            # (To make it work with broadcast destination (and open the first OPN-sender) requires cbridge work.)
            s = SimpleStreamProtocol(args.subnets[0],args.service)
            s.copy_until_eof()
            exit(0)
        else:
            print("Bad service arg {}, please use {} (in any case)".format(args.service, service_names))
            exit(1)
    except OSError as msg:
        print(msg, file=sys.stderr)
    except KeyboardInterrupt:
        pass
