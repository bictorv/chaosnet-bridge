# Copyright © 2023-2024 Björn Victor (bjorn@victor.se)
# Chaosnet server for HOSTAB protocol.
# As an extension, the request can also be a Chaosnet address (octal), which is looked up
# giving the same response as if the corresponding name had been requested.

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

import sys, socket, threading, re, time
from functools import reduce

from chaosnet import PacketConn, ChaosError, dns_info_for, dns_resolver_name, dns_resolver_address, set_dns_resolver_address

# The typical chaosnet end-of-line (#\return)
eol = b"\215"

keynames = dict(os='SYSTEM-TYPE', cpu='MACHINE-TYPE')

# Parse private hosts file. 
# Lines not starting with # should be an initial octal address (on subnet 376)
# followed by whitespace-separated names for that address.
def parse_private_hosts_file(fname):
    with open(fname) as f:
        return reduce(parse_private_hosts_line, f.readlines(), dict())
def parse_private_hosts_line(alist, l):
    if not l.startswith("#"):
        try:
            astring,nstring = l.split(maxsplit=1)
        except ValueError:
            print("Bad line {!r} in private hosts file".format(l.strip()), file=sys.stderr)
            return alist
        if re.match("^[0-7]+$",astring):
            try:
                addr = int(astring,8)
                if (addr & 0xff) == 0 or (addr >> 8) == 0 or addr > 0xffff or addr < 0xff:
                    print("Error: invalid Chaosnet address {:o}, line {!r}".format(addr,l.strip()),
                              file=sys.stderr)
                    return alist
                elif (addr >> 8) != 0o376:
                    print("Warning: address {:o} is not on the globally private subnet 376 but on subnet {:o}".format(addr,addr>>8),
                              file=sys.stderr)
                names = nstring.upper().split()   # traditions
                # @@@@ should check that each of names start with a letter?
                alist[addr] = names
            except ValueError:
                print("Bad address string {!r} in private hosts file, line {!r}".format(astring,l.strip()),
                          file=sys.stderr)
        else:
            print("Bad line {!r} in private hosts file".format(l.strip()), file=sys.stderr)
    return alist

privhosts = dict()
def private_host_lookup(name):
    for addr,names in privhosts.items():
        if name in names:
            return addr,names
def private_addr_lookup(addr):
    if addr in privhosts.keys():
        return privhosts[addr]

def hostab_server_response(name,timeout=2,dns_address=None,default_domain=None):
    gotip = False
    name = name.upper()                   #Traditions
    # First get Chaosnet info - this usually has os and cpu
    info = dns_info_for(name, timeout=2, dns_address=dns_address, default_domain=default_domain)
    if len(privhosts) > 0:
        # Check for private hosts info, and add it after DNS data (if any)
        if re.match("^[0-7]+$",name):
            a = int(name,8)
            names = private_addr_lookup(a)
            if names is not None:
                if info is None:
                    info = dict()
                info['addrs'] = (info['addrs'] if 'addrs' in info.keys() else []) + [a]
                info['name'] = (info['name'] if 'name' in info.keys() else []) + names
        else:
            addrnames = private_host_lookup(name)
            if addrnames is not None:
                addr,names = addrnames
                if info is None:
                    info = dict()
                info['addrs'] = (info['addrs'] if 'addrs' in info.keys() else []) + [addr]
                info['name'] = (info['name'] if 'name' in info.keys() else []) + names
        if info is not None and 'addrs' in info.keys():
            # Remove any duplicate addrs, while keeping order
            info['addrs'] = list(dict.fromkeys(info['addrs']))
    if info is None:
        # Try Internet class
        info = dns_info_for(name, timeout=2, dns_address=dns_address, default_domain=default_domain, rclass="IN")
        if info is not None:
            if info['addrs']:
                gotip = True
        elif not name.isdigit():
            # Last resort: try gethostbyname_ex - the given DNS server might not serve the IN class to us
            try:
                hname,aliases,ips = socket.gethostbyname_ex(name)
                info = dict()
                if ips and '127.0.1.1' in ips:
                    ips.remove('127.0.1.1')
                    if len(ips) == 0:
                        ips = None
                if ips:
                    info['addrs'] = ips
                    gotip = True
                    if hname.upper() != name:
                        info['name'] = [hname,name]
                    else:
                        info['name'] = [hname]
                    info['name'] += aliases
            except socket.error as msg:
                if debug:
                    print("gethostbyname_ex: {}".format(msg), file=sys.stderr)
                return ["ERROR {}".format(msg)]
    if debug:
        print("Got info {}".format(info), file=sys.stderr)
    resp = []
    if info and 'addrs' in info and info['addrs']:
        for n in info['name']:
            resp.append("NAME {}".format(n))
        for k in keynames.keys():
            if k in info and info[k]:
                resp.append("{} {}".format(keynames[k],info[k].upper()))
        if 'addrs' in info and info['addrs']:
            for a in info['addrs']:
                if isinstance(a,int):
                    resp.append("CHAOS {:o}".format(a))
                else:
                    resp.append("INTERNET {}".format(a))
        if not gotip:
            try:
                # If we didn't already get some IP address info, get it now
                hname,aliases,ips = socket.gethostbyname_ex(info['name'][0] if 'name' in info else name)
                if ips and '127.0.1.1' in ips:
                    ips.remove('127.0.1.1')
                    if len(ips) == 0:
                        ips = None
                if ips:
                    for ip in ips:
                        resp.append("INTERNET {}".format(ip))
            except socket.error as msg:
                if debug:
                    print("gethostbyname: {}".format(msg), file=sys.stderr)
    else:
        
        resp = ["ERROR No such host"]
    return resp

def hostab_server(conn, timeout=2,dns_address=None,default_domain=None):
    try:
        data = conn.get_message(1)             #get a packet
        while data:
            if debug:
                print("Got data {}".format(data), file=sys.stderr)
            name = str(re.split(b"[\215\r]",data,maxsplit=1)[0],"ascii").strip() #split("\r",maxsplit=1)[0]
            if debug:
                print("Got data {} => name {}".format(data,name), file=sys.stderr)
            resp = hostab_server_response(name,timeout,dns_address,default_domain)
            if debug:
                print("Sending response {}".format(resp), file=sys.stderr)
            conn.send_data(eol.join(map(lambda s:bytes(s,"ascii"),resp))+eol)
            conn.send_eof(True)
            data = conn.get_message(1)
    except ChaosError as m:
        # for example EOF[wait] didn't get an ack, then we're broken
        if debug:
            print(m, file=sys.stderr)
        try:
            conn.close()
        finally:
            return

debug = False
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Chaosnet HOSTAB server")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-s",'--dns-server',default=dns_resolver_name,
                            help='DNS server to use, default '+dns_resolver_name)
    parser.add_argument("-D",'--default-domain',action='append',
                            help='Default domain if names have none (repeat to have more than one)')
    parser.add_argument("-t",'--timeout',default=2,type=int,
                            help='DNS timeout in seconds, default 2')
    parser.add_argument("-m",'--maxthreads',default=10,type=int,
                            help='Max number of active threads/connections, default 10')
    # Another option would be to parse cbridge.conf and look for it
    parser.add_argument("-p",'--private-hosts',
                            help='File for private hosts (cf subnet 376)')
    
    args = parser.parse_args()

    dns_resolver_address = set_dns_resolver_address(args.dns_server)

    if args.debug:
        debug = True
        print(args, file=sys.stderr)
        print("DNS addr {}".format(dns_resolver_address))
    if args.private_hosts:
        privhosts = parse_private_hosts_file(args.private_hosts)

    while True:
        try:
            c = PacketConn()
            c.set_debug(debug)
            h = c.listen("HOSTAB")
            if debug:
                print("Conn from {}".format(h), file=sys.stderr)
            c.send_opn()
            xec = threading.Thread(target=hostab_server, args=(c,args.timeout,dns_resolver_address,args.default_domain))
            xec.start()
            # hostab_server(c, timeout=args.timeout)
        except (BrokenPipeError, socket.error, ChaosError) as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            # Could be cbridge crashed
            time.sleep(10)
            continue
        finally:
            while threading.active_count() > args.maxthreads:
                # Wait until some terminate and free up
                if debug:
                    print("Active threads now {}, sleeping".format(threading.active_count()), file=sys.stderr)
                time.sleep(3)
