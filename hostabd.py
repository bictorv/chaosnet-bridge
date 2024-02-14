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

from chaosnet import PacketConn, ChaosError, dns_info_for, dns_resolver_name, dns_resolver_address, set_dns_resolver_address

# The typical chaosnet end-of-line (#\return)
eol = b"\215"

keynames = dict(os='SYSTEM-TYPE', cpu='MACHINE-TYPE')

def hostab_server_response(name,timeout=2,dns_address=None,default_domain=None):
    gotip = False
    name = name.upper()                   #Traditions
    # First get Chaosnet info - this usually has os and cpu
    info = dns_info_for(name, timeout=2, dns_address=dns_address, default_domain=default_domain)
    if info is None:
        # Try Internet class
        info = dns_info_for(name, timeout=2, dns_address=dns_address, default_domain=default_domain, rclass="IN")
        if info is not None:
            if info['addrs']:
                gotip = True
        else:
            # Last resort: try gethostbyname_ex - the given DNS server might not serve the IN class to us
            try:
                hname,aliases,ips = socket.gethostbyname_ex(name)
                gotip = True
                info = dict()
                if hname.lower() != name:
                    info['name'] = [hname,name]
                else:
                    info['name'] = [hname]
                info['name'] += aliases
                if ips:
                    info['addrs'] = ips
            except socket.error as msg:
                if debug:
                    print("gethostbyname_ex: {}".format(msg), file=sys.stderr)
                return ["ERROR {}".format(msg)]
    if debug:
        print("Got info {}".format(info), file=sys.stderr)
    resp = []
    if info:
        for n in info['name']:
            resp.append("NAME {}".format(n))
        for k in keynames.keys():
            if k in info and info[k]:
                resp.append("{} {}".format(keynames[k],info[k].upper()))
        if info['addrs']:
            for a in info['addrs']:
                if isinstance(a,int):
                    resp.append("CHAOS {:o}".format(a))
                else:
                    resp.append("INTERNET {}".format(a))
        if not gotip:
            try:
                # If we didn't already get some IP address info, get it now
                hname,aliases,ips = socket.gethostbyname_ex(info['name'][0] if 'name' in info else name)
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
    
    args = parser.parse_args()

    dns_resolver_address = set_dns_resolver_address(args.dns_server)

    debug = False
    if args.debug:
        debug = True
        print(args, file=sys.stderr)
        print("DNS addr {}".format(dns_resolver_address))

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
