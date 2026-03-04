#!/usr/bin/env python3
#
# Copyright © 2025-2026 Björn Victor (bjorn@victor.se)
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
from chaosnet import StreamConn, PacketConn, ChaosError, EOFError, dns_name_of_address, dns_addr_of_name, dns_addr_of_name_search
from datetime import datetime, timezone, timedelta
import time

# Listens to SEND, returns 5 values or None:
# destuser: the user for whom the message is
# uname, host: the username and host the message is from
# datestamp: the datestamp of the message (might be in a remote timezone, beware)
# diffhours: timezone difference (in rounded hours) between the datestamp and local time
# text: the text of the message
def get_send_message(searchlist=None, conn=None):
    from getpass import getuser
    me = getuser()
    ncp = PacketConn() if conn is None else conn
    source,destuser = ncp.listen("SEND")
    sourcehost = dns_name_of_address(int(source,8))
    try:
        if destuser.lower() != me.lower():
            # Assume we're the only user logged in. 
            ncp.send_cls("User {!r} is not logged in.".format(destuser))
            return None
        ncp.send_opn()      # accept the connection
        pkt = ncp.get_string_until_eof().rstrip()
        return parse_send_message(pkt, destuser, sourcehost, searchlist)
    except ChaosError as m:
        print("Error!",m, file=sys.stderr)

def parse_send_message(pkt, destuser=None, sourcehost=None, searchlist=None):
    first,rest = pkt.split("\n", maxsplit=1)
    uname,host,date,lines = None, None, None, []
    dt = None
    diffh = 0
    m = re.match(r"^([\w_.-]+)@([\w_.-]+) (.+)$", first)
    if m:
        uname,host,date = m[1],m[2],m[3]
        dnshostaddr = dns_addr_of_name_search(host,searchlist=searchlist)
        if dnshostaddr and len(dnshostaddr) > 0:
            dnshost = dns_name_of_address(dnshostaddr[0])
            if sourcehost is not None and dnshost is not None and sourcehost.lower() != dnshost.lower():
                # @@@@ maybe do something more
                print("Attention: SEND client addr {:o} has name {!r} != {!r} ({!r})".format(
                    int(source,8), sourcehost, dnshost, host), file=sys.stderr)
            if dnshost is not None: # and dnshost.lower().startswith(host.lower()+"."):
                # sender used a shortname, expand it
                host = dnshost
        else:
            print("Can't find DNS addr of sender name {!r}".format(host), file=sys.stderr)
        # Try parsing ITS, LispM, etc formats. Use this to show the time offset
        # Try to parse also TZ info as +-HHMM, and if it's there, use that to calculate difftime
        tzp = re.match(r"([0-9a-zA-Z:-]+ [0-9:]+) (([-+])(\d\d)(\d\d))", date)
        tz, mytz = None, None
        if tzp:
            tz = (int(tzp[4])*60+int(tzp[5]))*(1 if tzp[3] == "+" else -1)
            date = tzp[1]
        if hasattr(time.localtime(),'tm_gmtoff'):
            mytz = round(time.localtime().tm_gmtoff/60) # minutes
        else:
            mytzp = re.match(r"([-+])(\d\d)(\d\d)", time.strftime("%z"))
            mytz = (int(mytzp[2])*60+int(mytzp[3]))*(1 if mytzp[1] == "+" else -1)
        # ITS, TOPS-20, Multics, ...
        for f in ["%m/%d/%y %H:%M:%S","%d-%b-%Y %I:%M%p","%m/%d/%y %H:%M",
                  "%Y-%m-%d %H:%M:%S","%d-%b-%y %H:%M:%S","%d-%b-%Y %H:%M:%S"]:
            try:
                dt = datetime.strptime(date,f)
                break
            except ValueError as e:
                dt = None
                # print("Error parsing date:",e, file=sys.stderr)
        now = datetime.now()
        if dt is None:
            # Try to parse 3:17pm, produced e.g. by ITS :REPLY. This could be east or west of here.
            # Heuristics which work with a diff < 12 hours (e.g. not Japan vs California):
            # Subtract local hour from remote hour; if > 12 or < 12, subtract/add 24.
            # This gives the #hours ahead the sender is (so display e.g. "12:24:42 (-9 h)"
            try:
                # Note: no seconds in this format, so messages may appear to do time jumps,
                # e.g. when doing :QSEND (which produces seconds) followed by :REPLY (which doesn't).
                pdt = datetime.strptime(date, "%I:%M%p")
                hr,min = pdt.hour, pdt.minute
                diffh = round(((hr-now.hour)*60+min-now.minute)/60)
                if diffh > 12:
                    diffh -= 24
                elif diffh < -12:
                    diffh += 24
                tz = mytz + diffh*60
                dt = now.replace(hour=hr, minute=min)
                # check if too far off
                if now.hour + diffh < 0 or now.hour + diffh > 23:
                    off = datetime.timedelta(days=-1 if now+hour.diffh < 0 else 1)
                    dt = dt + off
            except ValueError as e:
                print("Failed to parse timespec {!r}: {}".format(date,e), file=sys.stderr)
                dt = now
                tz = mytz
        elif tz is not None:
            diffh = round((tz-mytz)/60)
        else:
            diffdt = dt-now # this is a timedelta with only days and seconds
            diffh = round((diffdt.days*24*60*60 + diffdt.seconds)/(60*60))
            if diffh > 23 or diffh < -23:      # sanity check
                diffh = 0
            tz = mytz+diffh*60
        # Include timezone info in datestamp
        dt = dt.replace(tzinfo=timezone(timedelta(hours=round(tz/60))))
    else:
        print("Can't parse first line:",first, file=sys.stderr)
        uname,host,date = None,None,None
        # @@@@ hmm
        rest = pkt
    # print("dt is {!r}, date is {!r}".format(dt, date), file=sys.stderr)
    return destuser,uname,host,dt if dt else date,diffh,rest

def make_send_message(text,uname=None, hostname=None, date=None):
    from getpass import getuser
    from socket import getfqdn
    uname = uname or getuser()
    host = hostname or getfqdn()
    if date is None:
        date = datetime.now()
    # First line is sender@host date-and-time
    # followed by text
    # Include TZ (+-HHMM) if it occurs in datestamp
    return "{}@{} {}\n".format(uname,host, date.strftime("%d-%b-%Y %H:%M:%S" if date.tzinfo is None else "%d-%b-%Y %H:%M:%S %z"))+text

# May raise ChaosError
def send_message(user,athost,text,timeout=5,myhostname=None):
    ncp = StreamConn()
    # Protocol: RFC arg is destination username
    ncp.connect(athost,"SEND",[user],options=dict(timeout=timeout))
    msg = make_send_message(text)
    # data with LISPM newlines etc
    # @@@@ may get UnicodeEncodeError; need validation and/or error handling
    bb = bytes(msg,"ascii").translate(bytes.maketrans(b'\t\n\f\r',b'\211\215\214\212'))
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
        # print("input was {!r}".format(msg), file=sys.stderr)
    else:
        msg = " ".join(args.message)

    try:
        send_message(m.group(1),m.group(2),msg)
    except ChaosError as e:
        print("Chaosnet error: {}".format(e), file=sys.stderr)
