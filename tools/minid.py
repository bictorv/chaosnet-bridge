# Copyright © 2024 Björn Victor (bjorn@victor.se)
# Chaosnet server for MINI protocol.

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

import sys, socket, threading, re, time, os, glob

from chaosnet import PacketConn, opcode_name, Opcode, ChaosError

debug = False

# Protocol: see DJ:L.NETWORK.CHAOS;CHSAUX.LISP or ams:/sys/network/chaos/mini-server
# or ITS:LMIO;MINISR or chaos/cmd/MINI.c

# get userid from RFC arg ("MINI user pass", typically "MINI LISPM ")
# loop:
#  read DAT pkt: 200 = ascii, 201 = binary; contents = pathname
#  send DAT pkt 202 with
#   - [LISPM] pathname newline OCTAL creation date, or 
#   - [Unix] pathname newline %D %T (mm/dd/yy hh:mm:ss)
#   - [ITS] FN2 (version) space mm/dd/yy space hh:mm:ss
#   - so the format of the date doesn't really matter - it's only used with si:set-file-loaded-id.
#   or 203 for lose (with error message) and loop back for new DAT
#  send contents as DAT pkts (200 if ascii, 300 if binary)
#  send EOF

def mini_server(conn,rfcargs,rootdir):
    host,args = rfcargs
    if debug:
        print("RFC from {}: {}".format(host,args), file=sys.stderr)
    m = args.split(' ', maxsplit=1)
    if len(m) < 1 or len(m[0]) == 0:
        c.send_cls(b"Bad arguments in RFC, sorry: please specify user and password")
        return
    user = m[0]
    passwd = m[1] if len(m) > 1 else ""
    if debug or logging:
        print("MINI: connection from {} with user '{}' and password '{}'".format(host,user,passwd), file=sys.stderr)
    # @@@@ check userid/passwd?
    c.send_opn()
    try:
        while True:
            opc,data = c.get_packet()
            if opc == Opcode.CLS:
                if debug:
                    print("Remote end closed: {}".format(data), file=sys.stderr)
                return
            if opc != 0o200 and opc != 0o201:
                if debug:
                    print("Bad opcode {} in first packet".format(opcode_name(opc)), file=sys.stderr)
                c.send_cls(bytes("Bad opcode {:o} in first packet".format(opc),"ascii"))
                return
            fname = str(data,"ascii")
            if debug or logging:
                print("MINI: Request for file {}, {} mode".format(fname,"ascii" if opc == 0o200 else "binary"),
                          file=sys.stderr)
            if opc == 0o200:
                send_file(c,rootdir,fname,0o200)
            elif opc == 0o201:
                send_file(c,rootdir,fname,0o300)
            if debug:
                print("Waiting for new request", file=sys.stderr)
    except ChaosError as m:
        if debug:
            print(m, file=sys.stderr)
        pass

def send_file(c,rootdir,pathname,dat_opcode):
    # validate pathname
    if ".." in pathname:
        c.send_packet(0o203,bytes("Illegal filename {}".format(pathname),"ascii"))
        return
    realpath = find_file(rootdir+(pathname if pathname[0] != '/' else pathname[1:]))   # find matching file
    if debug:
        print("found {} for {}".format(realpath,pathname), file=sys.stderr)
    if debug:
        print("Opening {}".format(realpath), file=sys.stderr)
    try:
        # note "rb" since we translate bytes ourselves
        with open(realpath,"rb") as f:
            # @@@@ pname or pathname? With/out version?
            c.send_packet(0o202,bytes(realpath[len(rootdir)-1:],"ascii")+bytes([0o215])+bytes(time.strftime("%D %T",time.localtime(os.path.getctime(realpath))),"ascii"))
            send_file_contents(c,f,dat_opcode)
        c.send_eof()
        if debug:
            print("MINI sent file {} successfully".format(realpath), file=sys.stderr)
    except OSError as m:
        if debug:
            print("MINI: open failed - {}".format(m), file=sys.stderr)
        # @@@@ consider not leaking low-level info such as real pathname
        c.send_packet(0o203,bytes("Open failed - {}".format(m),"ascii"))

def send_file_contents(c,f,opc):
    # read 488 bytes at a time, if ascii then translate \t\n\f\r; send the data until eof
    # @@@@ should perhaps use more elaborate decoding, but will basically only be used for binary files
    trans = bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')
    while True:
        data = f.read(488)
        if len(data) == 0:                #eof
            if debug:
                print("EOF detected", file=sys.stderr)
            return
        if opc == 0o200:
            c.send_packet(opc,data.translate(trans))
        else:
            c.send_packet(opc,data)

def find_file(fname):
    # Find a matching file, considering versions (foo.qfasl.N, foo.qfasl.~N~, foo.qfasl.>)
    if os.path.exists(fname):
        # the plain name exists, use it
        if debug:
            print("fname exists: {}".format(fname), file=sys.stderr)
        return fname
    # split it in directory and file
    root,pname = fname.rsplit("/",maxsplit=1)
    if not '.' in pname or '.' == pname[0]:
        # no type, so no chance of a version
        if debug:
            print("no type: {}".format(pname), file=sys.stderr)
        return pname
    # find possible matches
    if pname.endswith(".>"):
        if debug:
            print("removing >: {}".format(pname), file=sys.stderr)
        cname = pname[:-2]
    else:
        cname = pname
    candidates = glob.glob(cname+".*",root_dir=root)
    if debug:
        print("got {} candidates for {} in {}".format(len(candidates),cname+".*",root), file=sys.stderr)
    if len(candidates) == 0:
        return fname
    # match all candidates against pname.[0-9]+, and maximize the version match
    ecname = re.escape(cname+".")
    maxp = None
    maxv = 0
    for c in candidates:
        m = re.match(ecname+r"(~?)([0-9]+)(~?)$", c)
        if m and len(m[1]) == len(m[3]):   # .N or .~N~, not .~N or .N~
            v = int(m[2])
            if v > maxv:
                if debug:
                    print("new max {} for {}: {}".format(v,pname,m[0]), file=sys.stderr)
                maxv = v
                maxp = m[0]               #remember fname
    if maxv > 0:
        # found some
        return root+"/"+maxp
    # didn't, let caller fail
    return fname

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Chaosnet MINI server")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-l",'--logging',dest='logging',action='store_true',
                            help='Turn on logging')
    parser.add_argument("-r",'--root',default="./sys",
                            help='Root of the pathnames served')

    parser.add_argument("-m",'--maxthreads',default=10,type=int,
                            help='Max number of active threads/connections, default 10')
    
    args = parser.parse_args()

    debug = False
    logging = False
    if args.debug:
        debug = True
        print(args, file=sys.stderr)
    if args.logging:
        logging = True

    if not args.root.endswith("/"):
        args.root += "/"

    while True:
        try:
            c = PacketConn()
            c.set_debug(debug)
            h = c.listen("MINI")
            if debug:
                print("Conn from {}".format(h), file=sys.stderr)
            if False:
                xec = threading.Thread(target=mini_server, args=(c,h,args.root,))
                xec.start()
            else:
                mini_server(c,h,args.root)
        except (BrokenPipeError, socket.error, OSError) as msg:
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
