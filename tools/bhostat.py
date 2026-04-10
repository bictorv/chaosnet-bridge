# Copyright © 2021-2024 Björn Victor (bjorn@victor.se)
# Tool for exploring Chaosnet using various (simple) protocols.
# Demonstrates the high-level python library for Chaosnet.

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

# TODO: rename this to "simple.py", semi-ironically. Or just "hostat.py", less ironic.

import sys, time, socket
import string, re
import functools
from struct import unpack
from datetime import datetime, timedelta

from chaosnet import BroadcastSimple, Simple, BroadcastConn, StreamConn, ChaosError
from chaosnet import (StatusDict, BroadcastStatusDict, UptimeDict, BroadcastUptimeDict,
                      TimeDict, BroadcastTimeDict, DumpRoutingTableDict, BroadcastDumpRoutingTableDict,
                      LastSeenDict, BroadcastLastSeenDict, LoadDict, BroadcastLoadDict,
                      FingerDict, BroadcastFingerDict, DNSDict, NameDict)
from chaosnet import dns_name_of_address, dns_resolver_name, dns_resolver_address, set_dns_resolver_address, dns_addr_of_name, host_name, get_canonical_name

# pip3 install dnspython
import dns.resolver

debug = False
verbose = False

# Prefer not to ask for a host's name
no_host_names = False

#### Application protocols (@@@@ perhaps move to chaosnet.py?)

# Oxymoron ("simple" means "datagram" in Chaosnet lingo), but here it means:
# given a host and contact, copy its output until EOF
class SimpleStreamProtocol:
    timeout = None
    def __init__(self,host,contact,options=None,args=[]):
        if options is not None and 'timeout' in options:
            self.timeout = options['timeout']
        self.conn = StreamConn()
        self.conn.connect(host,contact,options=options,args=args)
    def copy_until_eof(self):
        try:
            if self.timeout is not None:
                self.conn.sock.settimeout(self.timeout)
            return self.conn.copy_until_eof()
        except socket.timeout as m:
            raise ChaosError(m)

# The STATUS protocol
class Status:
    def __init__(self, hnames, args=[], options=None):
        print(("{:<32s}{:>6s} "+"{:>8} "*8).format("Name","Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected"))
        BroadcastStatusDict(hnames, args, options, callback=self.print_status)
    def print_status(self,s):
        hname = s['hname']
        if " " in hname:
            dname = dns_name_of_address(s['source'],onlyfirst=True,timeout=2)
            hname = "{} ({:o})".format(hname, s['source']) if dname is None else "{} [{}] ({:o})".format(hname, dname, s['source'])
        else:
            hname = "{} ({:o})".format(hname, s['source'])
        statuses = s['status']
        for s in statuses.keys():
            print(("{:<32s}{:>6o}"+" {:>8}"*len(statuses[s])).format(hname,s,*statuses[s].values()))
            hname = ""

# Just collect addresses and subnets
class ChaosSimpleStatus:
    def __init__(self, subnets, options=None):
        result = BroadcastStatusDict(subnets, options=options).dict_result()
        self.haddrs = [s['source'] for s in result]
        self.hname_addrs = [(dns_name_of_address(a),a) for a in self.haddrs]
        self.hosts = [ha[0] for ha in self.hname_addrs]
        snset = set()
        for s in result:
            snset |= set(s['status'].keys())
        self.subnets = list(snset)

# The TIME protocol
class ChaosTime:
    def __init__(self, hnames, args=[], options=None):
        BroadcastTimeDict(hnames, args, options, callback=self.print_time)
    def print_time(self, t):
        print("{:24}  {}  (delta {}{})".format("{} ({:o})".format(t['dname'],t['source']),t['dt'],
                                               "+" if t['delta'] >= 0 else "-", timedelta(milliseconds=abs(1000*t['delta']))))

# The UPTIME protocol
class ChaosUptime:
    def __init__(self, hnames, args=[], options=None):
        BroadcastUptimeDict(hnames, args, options, callback=self.print_uptime)
    def print_uptime(self, t):
        print("{:24}  {}".format("{} ({:o})".format(t['dname'],t['source']),t['delta']))

# The FINGER protocol (note: not NAME)
class ChaosFinger:
    def __init__(self, hnames, args=[], options=None):
        # @@@@ move idle before host?
        print("{:15s} {:1s} {:22s} {:10s} {:5s}    {:s}".format("User","","Name","Host","Idle","Location"))
        # @@@@ Doesn't manage "Free LISPMs", yet
        BroadcastFingerDict(hnames, args, options, callback=self.print_finger)
    def print_finger(self, f):
        # uname affiliation pname hname idle loc
        hname = dns_name_of_address(f['source'],onlyfirst=True,timeout=2)
        print("{:15s} {:1s} {:22s} {:10s} {:5s}    {:s}".format(f['uname'],f['affiliation'],f['pname'],
                                                                hname,f['idle'],f['location']))

# The LOAD protocol
class ChaosLoad:
    def __init__(self, hnames, args=[], options=None):
        BroadcastLoadDict(hnames, args, options, callback=self.print_load)
    def print_load(self, l):
        print("{:10s} Users: {}. Fair Share {}%".format(dns_name_of_address(l['source'], onlyfirst=True, timeout=2), l['users'], l['share']))

# Hack: use LOAD to see if it's worth fingering (with NAME)
class ChaosLoadName:
    def __init__(self, hosts, args=[], options=None):
        # This is quite nifty, if you ask me.
        llist = BroadcastLoadDict(hosts, args, options).dict_result()
        # @@@@ doesn't handle "No users on A, B, C"
        ChaosName(["{:o}".format(l['source']) for l in llist if l['users'] > 0], args=args, options=options)
        empty = [l['source'] for l in llist if l['users'] == 0]
        if len(empty) > 0:
            print("\nNo users on {}.".format(", ".join(map(lambda s: host_name(s), empty))))

class ChaosName:
    def __init__(self, hosts, options=None, args=[]):
        r = [NameDict(host, args, options).dict_result() for host in hosts]
        if len(r) > 0 and 'rawlines' not in r[0]:
            self.print_header()
        for hn in r:
            self.print_lines(hn)
    def print_header(self):
        print("{:10s} {:3s} {:20s} {:7s} {:>6s} {:3s}  {:10s} {:s}".format(
            'User','','Personal name','Jobname','Idle','TTY',"Host",'Location'))
    def print_lines(self, hn):
        if hn is not None:
            if isinstance(hn['source'], int):
                hname = dns_name_of_address(hn['source'], onlyfirst=True, timeout=2)
            else:
                hname = get_canonical_name(hn['source'], onlyfirst=True)
            if 'rawlines' in hn:
                print(hn['rawlines'])
            else:
                for n in hn['lines']:
                    print("{:10s} {:3s} {:20s} {:7s} {:>6s} {:3s}  {:10s} {:s}".format(
                        n['userid'], n['affiliation'], n['pname'], n['jobname'], n['idle'], n['tty'], 
                        hname, n['location']))

# The DUMP-ROUTING-TABLE protocol
class ChaosDumpRoutingTable:
    def __init__(self, hnames, args=[], options=None):
        print("{:<20} {:>6} {:>6} {}".format("Host","Net","Meth","Cost"))
        BroadcastDumpRoutingTableDict(hnames, args, options, callback=self.print_rtt)
    def print_rtt(self, rtt):
        hname = "{} ({:o})".format(rtt['dname'][:rtt['dname'].find(".")], rtt['source'])
        for sub in rtt['routingtable']:
            print("{:<20} {:>6o} {:>6o} {}".format(hname,sub,rtt['routingtable'][sub]['method'],rtt['routingtable'][sub]['cost']))
            hname = ""

# The LASTCN protocol
class ChaosLastSeen:
    def __init__(self, hnames, args=[], options=None):
        print("{:<20} {:25} {:>8} {:10} {:>2} {}".format("Host","Seen","#in","Via","FC","Age"))
        BroadcastLastSeenDict(hnames, args, options, callback=self.print_seen)
    def print_seen(self, seen):
        hname = "{} ({:o})".format(seen['dname'][:seen['dname'].find(".")], seen['source'])
        for addr in seen['lastseen']:
            e = seen['lastseen'][addr]
            a = timedelta(seconds=e['age'])
            print("{:<20} {:<25} {:>8} {:<10} {:>2} {}".format(hname,"{} ({:o})".format(host_name(addr),addr),e['input'],host_name(e['via']),e['fc'],a))
            hname = ""

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
                         'name': ChaosName,
                         'load': ChaosLoad,
                         'loadname': ChaosLoadName,
                         'lastcn': ChaosLastSeen,
                         'routing': ChaosDumpRoutingTable,
                         'dump-routing-table': ChaosDumpRoutingTable }
special_contact_handlers = dict(dns=ChaosDNS)

if __name__ == '__main__':
    import argparse
    service_names = ", ".join(contact_handlers.keys()).upper()+", "+", ".join(special_contact_handlers.keys()).upper()
    parser = argparse.ArgumentParser(description='Chaosnet simple protocol client',
                                         epilog="If the service is unknown and a host is given, "+\
                                         "tries to contact the service at the host and prints its output. "+\
                                         "If no service arg is given, but the first subnet arg is the name of a known service, "+\
                                         "and another subnet arg exists, the first subnet arg is used as service arg.")
    parser.add_argument("subnets", metavar="SUBNET/HOST", nargs='+', #type=int, 
                            help="Hosts to contact or Subnets (octal) to broadcast on, -1 for all subnets, or 0 for the local subnet")
    parser.add_argument("-t","--timeout", type=int, default=3,
                            help="Timeout in seconds")
    parser.add_argument("-r","--retrans", type=int, default=500,
                            help="Retransmission interval in milliseconds")
    parser.add_argument("-s","--service", # default="STATUS",
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
    # Parse "subnet" args as octal numbers (if they can be)
    args.subnets = list(map(lambda x: int(x,8) if isinstance(x,str) and (x.isdigit() or x =="-1") else x, args.subnets))

    # if no service explicitly given, but first "subnet" is a service (and more given), use that
    # Example: "bhostat.py finger 0"
    if args.service is None and len(args.subnets) > 1 and (args.subnets[0] in contact_handlers or args.subnets[0].lower() == "hostat"):
        args.service = args.subnets[0] if args.subnets[0].lower() != "hostat" else "status"
        args.subnets = args.subnets[1:]
    # maybe if only a service is given, use "local" as subnet? But just a host name for STATUS is useful.
    elif args.service is None:
        args.service = "STATUS"
    try:
        if args.service.lower() in contact_handlers:
            c = contact_handlers[args.service.lower()]
            opts = dict(timeout=args.timeout, retrans=args.retrans)
            c(args.subnets,options=opts)
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
            # Example: "bhostat.py -s bye up"
            # @@@@ Could parse the service, split at spaces and put things in contact args.
            # (To make it work with broadcast destination (and open the first OPN-sender) requires cbridge work.)
            s = SimpleStreamProtocol(args.subnets[0],args.service)
            s.copy_until_eof()
            exit(0)
        else:
            print("Bad service arg {}, please use {} (in any case)".format(args.service, service_names))
            exit(1)
    except ChaosError as msg:
        print(msg, file=sys.stderr)
    except KeyboardInterrupt:
        pass
