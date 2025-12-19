#!/usr/bin/env python3
#
# Copyright © 2025 Björn Victor (bjorn@victor.se)
# Implementation of the SEND protocol.

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

import sys, re
from chaosnet import StreamConn,ChaosError, EOFError, dns_name_of_address, dns_addr_of_name, dns_addr_of_name_search
from datetime import datetime

# Listens to SEND, returns 5 values:
# destuser: the user for whom the message is
# uname, host: the username and host the message is from
# datestamp: the datestamp of the message (might be in a remote timezone, beware)
# text: the text of the message
def get_send_message(searchlist=None):
    from getpass import getuser
    me = getuser()
    ncp = StreamConn()
    uname,host,date,lines = None, None, None, []
    dt = None
    source,destuser = ncp.listen("SEND")
    sourcehost = dns_name_of_address(int(source,8))
    try:
        if destuser.lower() != me.lower():
            # Assume we're the only user logged in. 
            ncp.send_cls("User {!r} is not logged in.".format(destuser))
            return None,None,None,None,None
        ncp.send_opn()      # accept the connection
        pkt = ncp.get_bytes(488)
        first,pkt = pkt.split(b"\215", maxsplit=1)
        first = first.rstrip(b"\215")
        m = re.match(r"^([\w_.-]+)@([\w_.-]+) (.+)$", str(first,"ascii"))
        if m:
            uname,host,date = m[1],m[2],m[3]
            dnshostaddr = dns_addr_of_name_search(host,searchlist=searchlist)
            if dnshostaddr and len(dnshostaddr) > 0:
                dnshost = dns_name_of_address(dnshostaddr[0])
                if sourcehost is not None and dnshost is not None and sourcehost.lower() != dnshost.lower():
                    # @@@@ maybe do something more
                    print("Attention: SEND client addr {:o} has name {!r} != {!r} ({!r})".format(
                        int(source,8), sourcehost, dnshost, host), file=sys.stderr)
                if dnshost is not None and dnshost.lower().startswith(host.lower()+"."):
                    # sender used a shortname, expand it
                    host = dnshost
            else:
                print("Can't find DNS addr of sender name {!r}".format(host), file=sys.stderr)
            # Try parsing ITS, LispM, etc formats
            # @@@@ Use this to show the time offset
            # @@@@ ITS :REPLY uses simply 3:17pm - do we care? Not yet.
            for f in ["%d/%m/%y %H:%M:%S","%d-%b-%y %H:%M:%S","%d-%b-%Y %H:%M:%S"]:
                try:
                    dt = datetime.strptime(date,f)
                    break
                except ValueError as e:
                    dt = None
                    # print("Error parsing date:",e, file=sys.stderr)
            # @@@@ do the below adjustment also for full time specs! Easier with full datetime!
            if dt is None:
                # Try to parse 3:17pm. This could be east or west of here.
                # Heuristics which work with a diff < 12 hours (i.e. not Japan vs California):
                # Subtract local hour from remote hour; if > 12 or < 12, subtract/add 24.
                # This gives the #hours ahead the sender is (so display e.g. "12:24:42 (-9 h)"
                m = re.match(r"([0-9]+):([0-9]+)([ap]m)", date)
                if m:
                    hr,min,ap = m.group(1,2,3)
                    if ap == "pm":
                        h += 12 # use 24-hour time
                    now = datetime.now()
                    if math.abs(now.minute-min) > 10:
                        pass
                    diff = hr-now.hour
                    if diff > 12:
                        diff -= 24
                    elif diff < 12:
                        diff += 24
                    # @@@@ make a datetime adjusted with diff hours
            while len(pkt) > 0:
                ll = str(pkt.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8").split("\n")
                lines += ll
                pkt = ncp.get_bytes(488)
        else:
            print("Can't parse first line:",first, file=sys.stderr)
            uname,host,date = None
            lines = [str(first,"ascii")]
    except ChaosError as m:
        print("Error!",m, file=sys.stderr)
    return destuser,uname,host,dt if dt else date,"\n".join(lines)

# May raise ChaosError
def send_message(user,athost,text,timeout=5):
    from getpass import getuser
    from socket import getfqdn
    me = getuser()
    myhost = getfqdn()
    ncp = StreamConn()
    # Protocol: RFC arg is destination username
    ncp.connect(athost,"SEND",[user],options=dict(timeout=timeout))
    # First line is sender@host date-and-time
    first = "{}@{} {}".format(me,myhost,datetime.now().strftime("%d-%b-%Y %H:%M:%S"))
    ncp.send_data(bytes(first,"ascii")+b"\215")
    # followed by data with LISPM newlines
    bb = bytes(text,"ascii").translate(bytes.maketrans(b'\t\n\f\r',b'\211\215\214\212'))
    ncp.send_data(bb)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description="Send a Chaosnet message")
    p.add_argument("user_at_host",help="Destination (user@host)")
    p.add_argument("message", nargs="*",help="Message to send (or stdin)")
    args = p.parse_args()

    # Parse destination
    m = re.match(r"^([\w_.-]+)@([\w_.-]+)$",args.user_at_host)
    if not m: 
        print("Bad argument {!r}, should be user@host".format(args.user_at_host), file=sys.stderr)
        exit(1)
    # If no message given, read it from stdin
    if not args.message or len(args.message) == 0:
        msg = "".join(sys.stdin.readlines()).rstrip()
        print("input was {!r}".format(msg), file=sys.stderr)
    else:
        msg = " ".join(args.message)

    try:
        send_message(m.group(1),m.group(2),msg)
    except ChaosError as e:
        print("Chaosnet error: {}".format(e), file=sys.stderr)
