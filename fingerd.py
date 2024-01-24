# Copyright © 2021-2024 Björn Victor (bjorn@victor.se)
# Chaosnet server for FINGER protocol, mainly used by Lisp Machines.
# (NOT what is otherwise known as finger, but a different protocol on Chaosnet.)
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

import socket, sys, time, subprocess, re
import functools
import os

from chaosnet import PacketConn

# -d
debug = False

def get_fullname(user):
    import pwd
    try:
        p = pwd.getpwnam(str(user,"ascii"))
        if debug:
            print("user {} = {}".format(user,p), file=sys.stderr)
        return p.pw_gecos.replace("ö","o").replace("å","a").replace("ä","a")
    except KeyError:
        if debug:
            print("user {} not found".format(user), file=sys.stderr)
        return ""

def get_console_user():
    r = subprocess.run(["/usr/bin/w","-h"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    if len(rout) > 0:
        for l in rout:
            u,con,rest = l.split(maxsplit=2)
            if con == b'console':
                return u
        if debug:
            print("Can't find console, using first line for uname: {}".format(rout[0]), file=sys.stderr)
        uname,rest = rout[0].split(maxsplit=1)
        return uname
    return b""

def get_idle_time(user):
    r = subprocess.run(["/usr/bin/w","-h",user], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    idle = 65534
    if len(rout) > 0:
        for l in rout:
            idl = 65534
            u,con,src,login,i,what = l.split(maxsplit=5)
            if i == b'-':
                idl = 0
            elif re.fullmatch(b'[0-9]+', i):
                idl = int(i)*60
            elif b':' in i:
                ids = i.split(b':')
                if len(ids) == 2:
                    if ids[1].endswith(b'm'):
                        ids[1] = ids[1][:-1]
                    idl = int(ids[0])*60 + int(ids[1])
            else:
                ids = str(i,"ascii")
                m = re.match(r'(\d+(\.\d+)?)s',ids)
                if m is not None:
                    idl = float(m[1])
                else:
                    m = re.match(r'(\d+)d(ay)?', ids)
                    if m is not None:
                        idl = int(m[1])*24*60*60
                    else:
                        print("Unknown idle format: {}".format(ids), file=sys.stderr)
            if debug:
                print("Idle time {} parsed to {}".format(i,idl), file=sys.stderr)
            if idl < idle:
                idle = idl
    else:
        print("No lines from w: {}".format(rout), file=sys.stderr)
    return idle

def idlestring_min(sec):
    min = sec//60
    if min == 0:
        return b''
    elif min < 60:
        return bytes("0:{:02}".format(min), "ascii")
    elif min < 24*60:
        return bytes("{}:{:02}".format(min//(60), min % (60)), "ascii")
    elif min < 7*24*60:
        return bytes("{}d".format(min//(60*24)),"ascii")
    else:
        return b"*:**"


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-l","--location", 
                            help="Set the location of your system")
    parser.add_argument("-a","--affiliation", 
                            help="Set the affiliation shown (one char)")
    parser.add_argument("-c",'--cachetime',type=int, default=60,
                            help="Seconds to cache user and idletime data")
    args = parser.parse_args()
    if args.debug:
        debug = True
        print(args, file=sys.stderr)
    if args.location:
        loc = bytes(args.location,"ascii")
    else:
        loc = os.getenvb(b"LOCATION",b"Home")

    if args.affiliation:
        aff = bytes(args.affiliation[0],"ascii")
    else:
        aff = os.getenvb(b"AFFILIATION",b"-")

    # Update data only occasionally (once per minute)
    last = 0
    while True:
        try:
            c = PacketConn()
            h = c.listen("FINGER")
            if debug:
                print("Conn from {}".format(h), file=sys.stderr)
            # get some real data to send
            if time.time() - last > args.cachetime:
                uname = get_console_user()
                pname = bytes(get_fullname(uname),"ascii")
                idle = get_idle_time(uname)
                last = time.time()
                if debug:
                    print("Updated u,p,i,is: {} {} {} {}".format(uname,pname,idle,idlestring_min(idle)), file=sys.stderr)
            c.send_ans(b"\215".join([uname,loc,idlestring_min(idle),pname,aff])+b"\215")
        except (BrokenPipeError, socket.error) as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            time.sleep(10)
            continue
