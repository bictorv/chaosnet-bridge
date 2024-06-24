# Copyright © 2022-2024 Björn Victor (bjorn@victor.se)
# Chaosnet client for TELNET protocol (not SUPDUP, just to keep it simple for now)
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

import socket, sys, threading
from datetime import datetime
import tty, termios

from chaosnet import StreamConn, PacketConn, ChaosError

# -d
debug = False
iacdebug = False
packetp = False


# Just for fun
class TCPconn:
    sock = None
    active = False
    port = None
    remote = None

    def __init__(self):
        self.get_socket()
    def __str__(self):
        return "<{} {} {} {}>".format(type(self).__name__, self.port,
                                          "active" if self.active else "passive",
                                          self.remote)
    def __del__(self):
        if debug:
            print("{!s} being deleted".format(self))

    def close(self, msg=b"Thank you"):
        if debug:
            print("\r\nClosing {} with msg {}".format(self,msg), file=sys.stderr)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing:',msg)

    def get_socket(self):
        # Create a TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_socket_data(self, data):
        ts = 0
        while ts < len(data):
            s = self.sock.send(data[ts:])
            if s == 0:
                raise ChaosError("Error: Sent no bytes: (total sent {})".format(ts))
            ts = ts+s
        # self.sock.sendall(data)

    def get_bytes(self, nbytes):
        return self.sock.recv(nbytes)

    def send_data(self, data):
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("\r\n> {} to {}".format(len(msg), self), file=sys.stderr)
        self.send_socket_data(msg)

    def connect(self, host, port, args=[], options=None):
        self.port = port.lower()
        self.remote = host
        self.active = True
        if debug:
            print("Trying to connect to {} on port {}".format(self.remote,self.port), file=sys.stderr)
        ainfo = socket.getaddrinfo(self.remote, self.port, proto=socket.IPPROTO_TCP)
        _,_,_,_,address=ainfo[0]
        if debug:
            print("Parsed as {}".format(address), file=sys.stderr)
        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            print('\r\nSocket errror:',msg, file=sys.stderr)
            sys.exit(1)

    def get_message(self, length=488):
        data = self.sock.recv(length)
        if debug:
            print("\r\n< {} of {} from {}".format(len(data), length, self), file=sys.stderr)
        if len(data) == 0:
            # This is handled somewhere
            self.sock.close()
            raise ChaosError("Error: Got no bytes: {}".format(data))
        elif len(data) < length:
            d2 = self.sock.recv(length-len(data))
            if debug:
                print("\r\n< {} of {} from {}".format(len(d2), length, self), file=sys.stderr)
            data += d2
        return data


#### Start of Telnet
# @@@@ class TelnetOption
# - vilken ände är initiator
# - vill vi om den andre vill
# - vill vi föreslå
# - hur ser SB ut

## make enums

t_cmds = {240: "SE", 241: "NOP", 242: "Mark", 243: "Break", 244: "INT", 245: "AO", 246: "AYT",
              247: "EC", 248: "EL", 249: "GA",
              250: "SB", 251: "WILL", 252: "WONT", 253: "DO", 254: "DONT", 255: "IAC"}
# will->dont, wont->do, do->wont, dont->will
t_willdo_neg = {251: 254, 252: 253, 253: 252, 254: 251}
# will->do, wont->dont, do->will, dont->wont
t_willdo_agree = {251: 253, 252: 254, 253: 251, 254: 252}
# see https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
t_opts = {1:"Echo",3:"SUPRGA",5:"Status",21:"Supdup",22:"SupdupOutput",23:"SendLoc",24:"TTYTYPE",
              31:"WinSize",32:"TSpeed",33:"RemFlow",35:"XLocation",36:"Env",39:"NewEnv"}
# Well this is option-specific, it turns out
t_subn_codes = {0:"IS", 1:"SEND"}

# Options we agree to: echo, suprga.  Ttytype and SendLoc are handled if we have values for them
t_agree_opts = {1,3}

def descr_cmd(cmd):
    return "{}".format(t_cmds[cmd] if cmd in t_cmds else cmd)

def descr_willdo(willdo,opt):
    return "{} {}".format(t_cmds[willdo],t_opts[opt] if opt in t_opts else opt)

def descr_subneg(seq):
    if len(seq) > 1:
        # Telnet Option
        opt = seq[0]
        oname = opt if opt not in t_opts else t_opts[opt]
        # Code, if any (e.g. IS, SEND)
        code = seq[1]
        cname = code if code not in t_subn_codes else t_subn_codes[code]
        if len(seq) > 4:
            # Options that take a code
            if opt in {24} and code == 0:                         # "IS" ... "IAC SE"
                val = seq[2:-2]
                return "{} {} \"{}\" {} {}".format(oname,cname,"".join(map(chr,val)),descr_cmd(seq[-2]),descr_cmd(seq[-1]))
            # Options that don't
            elif opt in {23}:
                val = seq[1:-2]
                return "{} \"{}\" {} {}".format(oname,"".join(map(chr,val)),descr_cmd(seq[-2]),descr_cmd(seq[-1]))
        return "{} {}".format(oname,cname)
    return "[Bad format: {}]".format(seq)

ttytype = None
location = None

def handle_iac(sock,data,i):
    consumed = 2                # Assume we consume the IAC and cmd at least
    doloc = False
    while len(data)-i < 2: # Make sure we have enough to parse it
        data = data + sock.get_message(1)
    cmd = data[i+1]
    if cmd in range(251,254+1):              # WILL/WONT/DO/DONT
        while len(data)-i < 3: # Make sure we have enough to parse it
            data = data + sock.get_message(1)
        opt = data[i+2]                            # option
        if debug or iacdebug:
            print("[IAC {}]\r".format(descr_willdo(cmd, opt)), file=sys.stderr)
        # @@@@ note here who is the active/initiating party, don't double to infinity
        if ttytype is not None and opt == 24 and cmd == 253:       #do ttytype
            agree = [255,t_willdo_agree[cmd],opt]
        elif location is not None and opt == 23 and cmd == 253:
            # Because we initiated by saying WILL, we don't reply to the agreement DO with another WILL
            doloc = True
            agree = bytes()
        elif cmd in {253,251} and opt not in t_agree_opts:   # They say DO or WILL, but we don't agree to what we can't handle
            agree = [255,t_willdo_neg[cmd],opt]
        else:
            # Else just agree to do or don't
            agree = [255,t_willdo_agree[cmd],opt]
        if len(agree) > 1:
            if debug or iacdebug:
                print("> reply {}\r".format(descr_willdo(agree[1],agree[2])), file=sys.stderr)
            sock.send_data(bytes(agree))
        if doloc:   #got agreement (DO) sendloc
            reply = [255,250,23]+list(map(ord,location))+[255,240]
            if iacdebug or debug:
                print("> sendloc {} {} {}\r".format(descr_cmd(reply[0]),descr_cmd(reply[1]),descr_subneg(reply[2:])),
                          file=sys.stderr)
            sock.send_data(bytes(reply))
        if debug:
            print("[End of WILL/WONT/DO/DONT]\r", file=sys.stderr)
        consumed = 3
    elif cmd == 250:   #subnegotiation
        # Look for IAC SE
        e = data.find(bytes([255,240]),i+2)
        while e < 0:
            data = data + sock.get_message(1)
            e = data.find(bytes([255,240]),i+2)
        opt = data[i+2]                            # option
        if debug or iacdebug:
            print("[IAC SubNeg {}]\r".format(descr_subneg(data[i+2:e])),file=sys.stderr)
        if opt == 24:   #Asking for TTYTYPE
            # IAC SB TTYTYPE IS VT100 IAC SE
            # but find it from environment of course
            reply = [255,250,24,0]+list(map(ord,ttytype if ttytype else "UNKNOWN"))+[255,240]
            if iacdebug and not debug:
                print("> reply {} {} {}\r".format(descr_cmd(reply[0]),descr_cmd(reply[1]),descr_subneg(reply[2:])),
                          file=sys.stderr)
            sock.send_data(bytes(reply))
        consumed = e+2-i
    elif cmd == 255:     #IAC IAC
        if debug or iacdebug:
            print("[IAC IAC]\r", file=sys.stderr)
        print(chr(cmd),end='',flush=True)
    elif debug or iacdebug:
        print("[IAC {}]\r".format(descr_cmd(cmd)),file=sys.stderr)
    return (data,consumed)

def input_handler(sock, once=False):
    data = []
    while True:
        try:
            data = sock.get_message(1)
        except ChaosError as e:
            if debug:
                print("\r\nError getting message: {}".format(e),file=sys.stderr)
            print("\r",file=sys.stdout,end='')
            return
        if debug:
            print("\r\n<< read {} bytes from remote: {}\r".format(len(data) if data is not None else 0,data), file=sys.stderr)
        if data is None:
            if debug:
                print("\r\ninput_handler got None for message, quitting", file=sys.stderr)
            print("\r",file=sys.stdout,end='')
            return
        # Handle IAC 
        i = 0
        while i < len(data):
            # if debug:
            #     print("<< byte {}<{}: {}".format(i,len(data),data[i]), file=sys.stderr)
            c = data[i]
            if c == 0xff:            #IAC
                (data,consumed) = handle_iac(sock,data,i)
                i = i+consumed-1
            elif c == 0o215:
                if debug and False:
                    print("[Newline]\r", file=sys.stderr)
                print("",flush=True)                 #newline
            elif c > 127:
                if debug:
                    print("[8bit]\r", file=sys.stderr)
                print("{:x}".format(c),end='',flush=True)
            else:
                if debug and False:
                    print("[normal char {}]\r".format(c), file=sys.stderr)
                else:
                    print(chr(c),end='',flush=True)
            i = i+1
            # if debug:
            #     print("<< next is {}".format(i), file=sys.stderr)
        # o = str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"ascii")
        # # o = data #str(data,"ascii")
        # if debug:
        #     print("<< after translate: {} {}".format(len(o),o), file=sys.stderr)
        # print("{!s}".format(o), end='')
        if debug:
            print("<< end of data\r", file=sys.stderr)
        if once:
            break

# This is useful for handling cut-and-paste, with more than 1 char at-a-time
# TOPS-20 beeps when there is too much data, it seems.
def read_a_line(strm, maxlen=20):      #cf T20
    import select
    line = strm.read(1)
    while len(line) < maxlen and select.select([strm], [], [], 0) == ([strm], [], []):
        line = line+strm.read(1)
    return line

def send_command(sock,cmd):
    # cmd without the IAC
    sock.send_data(bytes([255])+bytes(cmd))
    if debug or iacdebug:
        if cmd[0] in range(251,254+1):
            print("> send IAC {}\r".format(descr_willdo(cmd[0],cmd[1])), file=sys.stderr)
        else:
            print("> send IAC {}\r".format(descr_cmd(cmd[0])), file=sys.stderr)
    

def telnet(host,contact="TELNET", options=None, tcp=False):
    global debug
    if tcp:
        sock = TCPconn()
    else:
        sock = StreamConn() if not packetp else PacketConn()
    if sock is not None:
        sock.connect(host,contact,options=options)
        try:
            xec = threading.Thread(target=input_handler, args=(sock,))
            xec.start()
            with open("/dev/tty","rb", buffering=0) as tin:
                oldmode = termios.tcgetattr(tin)
                tty.setraw(tin)
                try:
                    if contact.upper() == "TELNET":
                        # Send IAC DO Suppress-go-ahead
                        send_command(sock,[253,3])
                        if ttytype:
                            # Send IAC WILL TTYTYPE
                            send_command(sock,[251,24])
                        if location is not None:
                            send_command(sock,[251,23])   # WILL SEND-LOCATION
                    while True:
                        try:
                            line = read_a_line(tin) # tin.read(1)
                            if debug:
                                print("Input: {} length {}".format(line,len(line)), file=sys.stderr)
                            if line == b"\x1d" or line == b"\x1e":
                                # ^] or ^^ pressed
                                print("\x0d",file=sys.stderr)
                                print("Telnet escape - press q or l for quit, d to toggle debug: ", file=sys.stderr, end='')
                                sys.stderr.flush()
                                ch = tin.read(1)
                                print("\x0d",file=sys.stderr)
                                if ch == b"q" or ch == b"l":
                                    if debug:
                                        print("Closing socket",file=sys.stderr)
                                    sock.close()
                                    return
                                elif ch == b"d":
                                    debug = not debug
                                    print("Debug now {}\r".format(debug),file=sys.stderr)
                                    continue
                                else:
                                    line = ch
                        except EOFError:
                            line = b"\x04"
                        sock.send_data(line)
                except ChaosError as e:
                    if debug:
                        print("\r\nChaosError: {}\r".format(e), file=sys.stderr)
                except (BrokenPipeError,AttributeError) as e:
                    if debug:
                        print("\r\nBroken pipe: {}\r".format(e), file=sys.stderr)
                finally:
                    if debug:
                        print("finally setting cbreak again\r", file=sys.stderr)
                    tty.setcbreak(tin)
                    termios.tcsetattr(tin, termios.TCSANOW, oldmode)
        finally:
            pass
    else:
        print("Connection failed")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet telnet')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-i",'--iacdebug',dest='iacdebug',action='store_true',
                            help='Turn on IAC debug printouts')
    parser.add_argument("-p","--packet",dest='packetp',action='store_true',default=True,
                            help='Use packet mode (chaos_packet) instead of plain stream')
    parser.add_argument("-c","--contact",dest='contact', default="TELNET",
                            help="Contact other than TELNET")
    parser.add_argument("-t","--ttytype",dest='ttytype', default=None,
                            help="Terminal type to try to convey to the server")
    parser.add_argument("-l","--location",dest='location', default=None,
                            help="Location to try to convey to the server")
    parser.add_argument("-W","--winsize", type=int,
                            help="local window size")
    parser.add_argument("-T","--tcp",action='store_true',
                            help="Use TCP rather than Chaosnet(!)")
    parser.add_argument("host", help='The host to connect to')
    args = parser.parse_args()

    cargs=dict()
    if args.winsize and args.winsize > 0:
        cargs['winsize'] = args.winsize
    if len(cargs) == 0:
        cargs = None

    if args.packetp:
        packetp = True
    if args.ttytype:
        ttytype = args.ttytype
    if args.location:
        location = args.location
    if args.iacdebug:
        iacdebug = True
    if args.debug:
        debug = True
        print(args, file=sys.stderr)

    try:
        telnet(args.host, args.contact, options=cargs, tcp=args.tcp)
    except ChaosError as m:
        print("Chaosnet error: {}".format(m), file=sys.stderr)
        sys.exit(1)
