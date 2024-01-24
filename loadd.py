# Copyright © 2022-2024 Björn Victor (bjorn@victor.se)
# Chaosnet server for LOAD protocol, mainly used by ITS.
# This is a simple protocol with returns a string a'la "Fair Share: X%\r\nUsers: N."
#
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

import socket, sys, subprocess, time, re
import functools

from chaosnet import PacketConn

# -d
debug = False

def get_load():
    # get nusers by "users" rather than "uptime",
    # since uptime counts every window, while users counts logins (I think)
    r = subprocess.run(["/usr/bin/users"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    nusers = len(rout[0].split(b" "))
    if debug:
        print("/usr/bin/users found {} users".format(nusers), file=sys.stderr)
    r = subprocess.run(["/usr/bin/uptime"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    rout = r.stdout.splitlines()
    if len(rout) > 0:
        line = str(rout[0],"ascii")
        if debug:
            print("Got line {} and output {}".format(line,rout), file=sys.stderr)
        num = re.search(r'([0-9]+) users', line)
        load = re.search(r'load averages?: ([0-9.]+)', line)
        if num is None or load is None:
            if debug:
                print("Can't find nusers or load: {} {}".format(num,load), file=sys.stderr)
            return None,None
        else:
            # return num[1],float(load[1])
            return nusers,float(load[1])
    elif debug:
        print("No output from uptime?", file=sys.stderr)
    return None,None

# Try to calculate "fair share" given the load and nr of users
def fairshare(load, nusers=1):
    from multiprocessing import cpu_count
    ncpu = cpu_count()
    if debug:
        print("Load {} on {} cores with {} users = {} used up".format(load,ncpu,nusers,load/ncpu/max(nusers,1)), file=sys.stderr)
    return round(100*(1-(load/ncpu/max(1,nusers))))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-c",'--cachetime',type=int, default=60,
                            help="Seconds to cache calculated load")
    args = parser.parse_args()
    if args.debug:
        debug = True
        print(args, file=sys.stderr)

    last = 0
    while True:
        try:
            c = PacketConn()
            h = c.listen("LOAD")
            if debug:
                print("Conn from {}".format(h), file=sys.stderr)
            # get some real data to send
            if time.time() - last > args.cachetime:
                nusers,load = get_load()
                last = time.time()
                if debug:
                    print("Updated n,l: {} {}".format(nusers,load), file=sys.stderr)
            if nusers is not None:
                c.send_ans(bytes("Fair Share: {}%\r\nUsers: {}.".format(max(0,fairshare(load, nusers)), nusers),"ascii"))
        except (BrokenPipeError, socket.error) as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            time.sleep(10)
            continue
