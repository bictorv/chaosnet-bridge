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
from chaosnet import StreamConn,ChaosError, EOFError, dns_name_of_address, dns_addr_of_name
from datetime import datetime

# Listens to SEND, returns 5 values:
# destuser: the user for whom the message is
# uname, host: the username and host the message is from
# datestamp: the datestamp of the message (might be in a remote timezone, beware)
# text: the text of the message
def get_send_message():
    from getpass import getuser
    me = getuser()
    ncp = StreamConn()
    uname,host,date,lines = None, None, None, []
    dt = None
    source,destuser = ncp.listen("SEND")
    sourcehost = dns_name_of_address(source)
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
            dnshostaddr = dns_addr_of_name(host)
            if len(dnshostaddr) > 0:
                dnshost = dns_name_of_address(dnshostaddr[0])
                if (dnshost is not None and dnshost.lower() != host.lower()) or (sourcehost is not None and host.lower() != sourcehost.lower()):
                    # @@@@ maybe do something more
                    print("Attention: SEND client addr {:o} has name {!r} != {!r} ({!r})".format(
                        source, sourcehost, dnshost, host), file=sys.stderr)
            # Try parsing ITS, LispM, etc formats
            # @@@@ ITS :REPLY uses simply 3:17pm - do we care? No.
            for f in ["%d/%m/%y %H:%M:%S","%d-%b-%y %H:%M:%S","%d-%b-%Y %H:%M:%S"]:
                try:
                    dt = datetime.strptime(date,f)
                    break
                except ValueError as e:
                    dt = None
                    # print("Error parsing date:",e, file=sys.stderr)
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
    ncp.connect(athost,"SEND",[user],options=dict(timeout=timeout))
    first = "{}@{} {}".format(me,myhost,datetime.now().strftime("%d-%b-%y %H:%M:%S"))
    ncp.send_data(bytes(first,"ascii")+b"\215")
    bb = bytes(text,"ascii").translate(bytes.maketrans(b'\t\n\f\r',b'\211\215\214\212'))
    ncp.send_data(bb)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description="Send a message")
    # @@@@ or use user@host syntax
    p.add_argument("user",help="Destination user")
    p.add_argument("host",help="Destination host")
    p.add_argument("message", nargs="+",help="Messsage to send")
    args = p.parse_args()
    send_message(args.user,args.host," ".join(args.message))
