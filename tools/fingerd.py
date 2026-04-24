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

from chaosnet import PacketConn, ChaosError

cachetime = 30                  # seconds to cache info we're collecting and sending back

class FingerDaemon:
    # -d
    debug = False
    conn = None

    def __init__(self, user=None, pname=None, location=None, affiliation=None):
        self.user = user
        self.pname = pname
        self.location = location
        self.affiliation = affiliation

    def set_location(self, loc):
        self.location = loc
    def set_affiliation(self, aff):
        self.affiliation = aff
    def set_user(self, uname):
        self.user = uname
    def set_pname(self, pn):
        self.pname = pn
    def set_debug(self, dbugp):
        self.debug = dbugp

    def auto_location(self):
        # Get the location reported by ipinfo.io, assuming we're connected to the Internet.
        # Concatenate city, region, countrycode. Skip region if it's the same as the city.
        from urllib.request import urlopen
        from urllib.error import URLError
        import json
        try:
            resp = None
            with urlopen("https://ipinfo.io") as f:
                resp = json.load(f)
            if resp:
                loc = []
                if 'city' in resp:
                    loc.append(resp['city'])
                if 'region' in resp:
                    if 'city' in resp:
                        if resp['region'] != resp['city']:
                            loc.append(resp['region'])
                    else:
                        loc.append(resp['region'])
                if 'country' in resp:
                    loc.append(resp['country'])
                return ", ".join(loc)
        except URLError as m:
            if self.debug:
                print("FingerDaemon: Error checking ipinfo.io: {}".format(m), file=sys.stderr)

    def get_fullname(self, user=None):
        import pwd
        if user is None:
            user = self.get_current_user()
        try:
            p = pwd.getpwnam(user)
            if self.debug:
                print("FingerDaemon: user {} = {}".format(user,p.pw_gecos), file=sys.stderr)
            import unicodedata
            # Make it ascii, if you can, and use only up to first comma
            return unicodedata.normalize("NFKD",p.pw_gecos).encode("ascii","ignore").decode().split(",",maxsplit=1)[0]
        except KeyError:
            if self.debug:
                print("FingerDaemon: user {} not found".format(user), file=sys.stderr)
            return ""

    def get_current_user(self):
        import getpass
        return getpass.getuser()

    def get_console_user(self):
        r = subprocess.run(["/usr/bin/w","-h"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        rout = r.stdout.splitlines()
        if len(rout) > 0:
            for l in rout:
                u,con,rest = l.split(maxsplit=2)
                if con == b'console':
                    return str(u,"ascii")
            if self.debug:
                print("FingerDaemon: Can't find console, using first line for uname: {}".format(rout[0]), file=sys.stderr)
            uname,rest = rout[0].split(maxsplit=1)
            return str(uname,"ascii")

    # Use this on macOS; detects idle time not only in terminal windows
    def get_idle_time_macos(self):
        r = subprocess.run(["/usr/sbin/ioreg","-r","-c","IOHIDSystem"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        rout = r.stdout.splitlines()
        hididletime = next((line for line in rout if b"HIDIdleTime" in line), None)
        if hididletime is None:
            if self.debug:
                print("FingerDaemon: Can't find idle time", file=sys.stderr)
            return 0
        m = re.match(r".*\"HIDIdleTime\" = ([0-9]+)",str(hididletime,"ascii"))
        if m:
            if self.debug:
                print("FingerDaemon: Idle time {} => {} sec".format(m.group(1), round(int(m.group(1))/1000000000)), file=sys.stderr)
            return round(int(m.group(1))/1000000000)
        elif self.debug:
            print("FingerDaemon: Can't parse idle time: {!r}".format(str(hididletime,"ascii")), file=sys.stderr)

    def parse_idle_time(self, i):
        if i == '-':
            return 0
        elif re.fullmatch('[0-9]+', i):
            return int(i)*60
        elif ':' in i:
            ids = i.split(':')
            if len(ids) == 2:
                if ids[1].endswith('m'):
                    ids[1] = ids[1][:-1]
                return int(ids[0])*60 + int(ids[1])
        else:
            m = re.match(r'(\d+(\.\d+)?)s',i)
            if m is not None:
                return float(m[1])
            else:
                m = re.match(r'(\d+)d(ay)?', i)
                if m is not None:
                    return int(m[1])*24*60*60
                else:
                    print("Unknown idle format: {}".format(i), file=sys.stderr)

    def get_idle_time(self, user):
        import platform
        if platform.system() == "Darwin" and user == self.get_current_user():
            idle = self.get_idle_time_macos()
            if idle is not None:    # else failed somehow
                return idle
        r = subprocess.run(["/usr/bin/w","-h",user], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        rout = r.stdout.splitlines()
        idle = 65534
        if len(rout) > 0:
            for l in rout:
                u,con,src,login,i,what = l.split(maxsplit=5)
                idl = parse_idle_time(str(i,"ascii"))
                if idl is not None and idl < idle:
                    idle = idl
        else:
            print("No lines from w: {}".format(rout), file=sys.stderr)
        return idle

    def idlestring_min(self, sec):
        min = sec//60
        if min == 0:
            return ''
        elif min < 60:
            return "0:{:02}".format(min)
        elif min < 24*60:
            return "{}:{:02}".format(min//(60), min % (60))
        elif min < 7*24*60:
            return "{}d".format(min//(60*24))
        else:
            return "*:**"

    def get_and_handle_finger_request(self, conn=None, last=0):
        self.conn = PacketConn() if conn is None else conn
        h = self.conn.listen("FINGER")
        if self.debug:
            print("FingerDaemon: Conn from {}".format(h), file=sys.stderr)
        # get some real data to send
        if time.time() - last > cachetime:
            self.user = self.get_console_user() if self.user is None else self.user
            self.pname = self.get_fullname(self.user) if self.pname is None else self.pname
            self.location = self.auto_location() if self.location is None else self.location
            if self.location is None:
                self.location = "Home"
            self.affiliation = "-" if self.affiliation is None else self.affiliation
            self.idle = self.get_idle_time(self.user)
            if self.debug:
                print("FingerDaemon: Updated u,p,i,is,loc: {} {} {} {} {}".format(self.user,self.pname,self.idle,self.idlestring_min(self.idle), self.location), file=sys.stderr)
        self.conn.send_ans(b"\215".join(map(lambda s: bytes(s,"ascii"),[self.user,self.location,self.idlestring_min(self.idle),self.pname,self.affiliation]))+b"\215")
        


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="FINGER daemon for Chaosnet",
                                     epilog="Uses the LOCATION and AFFILIATION env vars for defaults. Default defaults are \"Home\" and \"-\", respectively.")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-l","--location", 
                            help="Set the location of your system, default based on your public IP")
    parser.add_argument("-a","--affiliation", 
                            help="Set the affiliation shown (one char)")
    parser.add_argument("-c",'--cachetime',type=int, default=60,
                            help="Seconds to cache user and idletime data")
    args = parser.parse_args()

    fd = FingerDaemon()
    if args.debug:
        fd.set_debug(args.debug)
    if args.location:
        fd.set_location(args.location)
    elif os.getenv("LOCATION"):
        fd.set_location(os.getenv("LOCATION"))

    if args.affiliation:
        if len(args.affiliation[0]) > 2:
            print("Error: affiliation can be max 2 characters")
            exit(1)
        fd.set_affiliation(args.affiliation[0])
    elif os.getenv("AFFILIATION"):
        a = os.getenv("AFFILIATION")
        if len(a) > 2:
            print("Error: $AFFILIATION can be max 2 characters")
            exit(1)
        fd.set_affiliation(os.getenv("AFFILIATION"))

    # Update data only occasionally (once per minute)
    last = 0
    while True:
        try:
            fd.get_and_handle_finger_request(last=last)
            last = time.time()
        except (BrokenPipeError, socket.error, ChaosError) as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            time.sleep(10)
            continue
