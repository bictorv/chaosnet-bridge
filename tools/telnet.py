# Copyright © 2022-2026 Björn Victor (bjorn@victor.se)
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
import shutil
from enum import IntEnum, auto

from chaosnet import StreamConn, PacketConn, ChaosError
from TCPconn import TCPconn     # for fun and debug

# TODO:
# - WILL ECHO seems hard to convince both ITS and T20 of.
# - WILL SUPRGA is similar: TOPS-20 doesn't understand that client initiated WILL, but responds DO expecting a WILL I suppose.
#   DO SUPRGA works though.
# Todo for TOPS-20:
# - implement WINSIZE using MTOPR% .MOSLW (width) .MOSLL (length). https://datatracker.ietf.org/doc/html/rfc1073
#   However there are only 18 bits of options "in the air", see MAXOPT, NVTOPF, so need to extend to 36.
#   See also NVTWID, (NVTDND). Use different lengths of tables?
# - implement TTYTYPE in the simplest possible way (TBLUK, or simply check for VT100) https://datatracker.ietf.org/doc/html/rfc1091
#   -- see NVTWID/NVTDOD/NVTDND (much longer tables needed), wider NVTOPF (MAXOPT)
#   -- see NVTDTB (need to implement SB)
# - lower prio: implement location - https://datatracker.ietf.org/doc/html/rfc779
#   -- additionally, need to save it somewhere

# -d
debug = False
iacdebug = False
packetp = False

#### Start of Telnet

## make enums
class TelnetCommand(IntEnum):
    SE = 240
    NOP = auto()
    MARK = auto()
    BRK = auto()                # break
    INT = auto()
    AO = auto()
    AYT = auto()
    EC = auto()
    EL = auto()
    GA = auto()
    SB = auto()
    WILL = auto()
    WONT = auto()
    DO = auto()
    DONT = auto()
    IAC = auto()

# see https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
class TelnetOption(IntEnum):
    ECHO = 1
    SUPRGA = 3
    STATUS = 5
    SUPDUP = 21
    SUPDUP_OUTPUT = 22
    SEND_LOC = 23
    TTYTYPE = 24
    WINSIZE = 31
    TSPEED = 32
    REMOTE_FLOW = 33
    XLOCATION = 35
    ENV = 36
    NEW_ENV = 39

ttytype = None
location = None
# Hard to get to work?
local_echo = False

# IAC handling:
# If we have said "will", remote says "do", then do the option
# If we have said "will", remote says "dont", then accept that (and do nothing)
# If remote says "do", we respond with "will/wont" if we can+want to or not, and then maybe do the option
# If remote says "dont", we respond with "wont" (and then do not do the option)

# Things we can do
acceptable_options = [TelnetOption.ECHO, TelnetOption.SUPRGA]

outstanding_will = []   # The options we asked for permission to do (using WILL)
outstanding_do = []   # The options we asked for permission to do (using DO)
outstanding_accepted = []       # Things we accepted the remote to do

# We got an IAC; handle the continuation: IAC, WILL/WONT/DO/DONT, SB
# return any data remaining after handling the continuation
def handle_iac(sock, data):
    while len(data) < 1:      # We need at least one byte
        data = data + sock.get_message(1)
    cmd = TelnetCommand(data[0])
    if cmd == TelnetCommand.IAC:
        if debug or iacdebug:
            print("< [IAC IAC]\r", file=sys.stderr)
        print(chr(data[0]),end='',flush=True)
        return data[1:]
    elif cmd in [TelnetCommand.WILL, TelnetCommand.WONT, TelnetCommand.DO, TelnetCommand.DONT]:
        while len(data) < 2:      # We need at least two bytes
            data = data + sock.get_message(1)
        opt = TelnetOption(data[1])
        if debug or iacdebug:
            print("< [IAC {} {}]\r".format(cmd.name, opt.name), file=sys.stderr)
        if opt in outstanding_will:
            if iacdebug:
                print("[Outstanding will {} - removing it]\r".format(opt.name), file=sys.stderr)
            outstanding_will.remove(opt)
            if cmd == TelnetCommand.DO:
                return handle_do(opt, sock, data)
            elif cmd == TelnetCommand.DONT:
                handle_dont(opt, sock, data)
                if debug or iacdebug:
                    print("[Accepting DONT {}]\r".format(opt.name), file=sys.stderr) # Just accept it
            else:
                print("[Bad response to our WILL {}]\r".format(opt.name), file=sys.stderr)
                # see if this helps
                outstanding_will.append(opt)
            return data[2:]
        elif opt in acceptable_options:
            if iacdebug:
                print("[Acceptable {}]\r".format(opt.name), file=sys.stderr)
            if cmd == TelnetCommand.DO:
                send_will(sock, opt)
                return handle_do(opt, sock, data)
            elif cmd == TelnetCommand.WILL:
                if not opt in outstanding_do:
                    send_do(sock, opt)
                if opt in outstanding_do:
                    outstanding_do.remove(opt)
            elif cmd == TelnetCommand.DONT:
                handle_dont(opt, sock, data)
                send_wont(sock, opt)
            else:
                print("[Weird sequence: expected DO/WILL/DONT, got {}\r".format(cmd.name), file=sys.stderr)
            return data[2:]
        else:
            if iacdebug:
                print("[Unacceptable {} - responding DONT]\r".format(opt.name), file=sys.stderr)
            send_dont(sock, opt)
            return data[2:]
    elif cmd == TelnetCommand.SB: # Subnegotiation: collect data until IAC SE
        return handle_subnegotiation(sock, data[1:])
    elif cmd in [TelnetCommand.NOP, TelnetCommand.MARK, TelnetCommand.GA]:
        # ITS sends NOP early on, TOPS-20 sends MARK when logging out.
        if debug or iacdebug:
            print("< [IAC {}]\r".format(cmd.name), file=sys.stderr)
        return data[1:]
    else:
        if debug or iacdebug:
            print("[Unhandled Telnet command {}]\r".format(cmd.name), file=sys.stderr)
        return data[1:]

def send_will(sock, opt):
    send_command(sock,[TelnetCommand.WILL, opt])
def send_wont(sock, opt):
    send_command(sock,[TelnetCommand.WONT, opt])
def send_do(sock, opt):
    send_command(sock,[TelnetCommand.DO, opt])
def send_dont(sock, opt):
    send_command(sock,[TelnetCommand.DONT, opt])

def send_will_command(sock,opt):
    outstanding_will.append(opt)
    if opt not in acceptable_options:
        acceptable_options.append(opt)
    send_command(sock,[TelnetCommand.WILL,opt])
def send_do_command(sock,opt):
    outstanding_do.append(opt)
    send_command(sock,[TelnetCommand.DO,opt])

def send_command(sock,cmd):
    # cmd without the IAC
    sock.send_data(bytes([TelnetCommand.IAC])+bytes(cmd))
    if debug or iacdebug:
        if cmd[0] in range(251,254+1):
            print("> send IAC {} {}\r".format(cmd[0].name, cmd[1].name), file=sys.stderr)
        else:
            print("> send IAC {}\r".format(cmd[0].name), file=sys.stderr)
def send_subneg(sock, vals):
    if debug or iacdebug:
        print("> [Send Subneg {}]\r".format(vals), file=sys.stderr)
    sock.send_data(bytes([TelnetCommand.IAC, TelnetCommand.SB])+vals+bytes([TelnetCommand.IAC, TelnetCommand.SE]))

def handle_do(opt, sock, data):
    # Do whatever acceptable thing we were asked to (caller responds with WILL)
    match opt:
        case TelnetOption.SEND_LOC:
            send_subneg(sock,bytes([opt])+bytes(location or "Here","ascii"))
        case TelnetOption.TTYTYPE:
            # TTYTYPE IS whatever
            send_subneg(sock,bytes([opt, 0])+bytes(ttytype or "VT100","ascii"))
        case TelnetOption.WINSIZE:
            size = shutil.get_terminal_size()
            send_subneg(sock,bytes([opt, size.columns>>8,size.column&0xff,size.lines>>8,size.lines&0xff]))
        case TelnetOption.SUPRGA:
            pass                # easy
        case TelnetOption.ECHO:
            local_echo = True
        case _:
            print("[Unimplemented DO {}]\r".format(opt.name), file=sys.stderr)
    return data[1:]

def handle_dont(opt, sock, data):
    # Asked to DONT do opt
    match opt:
        case TelnetOption.ECHO:
            if iacdebug:
                print("[Local echo OFF]\r", file=sys.stderr)
            global local_echo
            local_echo = False
        case _:
            if not opt in outstanding_will and not opt in outstanding_do:
                if iacdebug:
                    print("[Unimplemented DONT {}]\r".format(opt.name), file=sys.stderr)

def handle_subnegotiation(sock, data):
    # collect data until IAC SE, do things with it
    # Look for IAC SE
    e = data.find(bytes([255,240]))
    while e < 0:
        data = data + sock.get_message(1)
        e = data.find(bytes([255,240]))
    opt = TelnetOption(data[0])
    if debug or iacdebug:
        print("[Subneg {}]\r".format(opt.name), file=sys.stderr)
    if opt == TelnetOption.TTYTYPE:
        if data[1] == 1:        # Remote wants the next TTY type
            handle_do(opt, sock, data)
        else:
            print("[Bad TTYTYPE sequence: got IAC SB TTYTYPE {}, expected 1 (SEND)]\r".format(data[1]), file=sys.stderr)
    else:
        print("[Unimplemented subneg]\r", file=sys.stderr)
    return data[e:]

# Handle input from remote
def input_handler(sock, once=False):
    data = []
    while True:
        try:
            data = sock.get_message(1) # Read a byte (or more, up to 488 bytes for Chaos PacketConn)
        except (OSError, ChaosError) as e:
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
        # Handle input starting at the beginning
        while len(data) > 0:
            # if debug:
            #     print("<< byte {}<{}: {}".format(i,len(data),data[i]), file=sys.stderr)
            c = data[0]
            if c == 0xff:            # IAC
                if debug or iacdebug:
                    print("< [IAC, data len {}]\r".format(len(data)), file=sys.stderr)
                data = handle_iac(sock,data[1:]) # handle the IAC, get back data following the command
            else:
                data = data[1:] # consume just one byte
                if c == 0o215:    # LISPM/Chaosnet newline
                    if debug and False:
                        print("[Newline]\r", file=sys.stderr)
                    print("",flush=True) # newline
                elif c > 127:
                    if debug:       # @@@@ This really shouldn't happen, should it?
                        print("[8bit]\r", file=sys.stderr)
                    print("{:x}".format(c),end='',flush=True) # @@@@ Print it in hex? Or as an 8-bit byte?
                else:
                    if debug and False:
                        print("[normal char {}]\r".format(c), file=sys.stderr)
                    else:
                        print(chr(c),end='',flush=True)
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
    if local_echo:
        for c in line:
            print(chr(c), end='')
    return line

def telnet(host,contact="TELNET", options=None, tcp=False):
    global debug
    if tcp:
        sock = TCPconn()
    else:
        sock = StreamConn() if not packetp else PacketConn()
    sock.set_debug(debug)
    if sock is not None:
        sock.connect(host,contact,options=options)
        try:
            xec = threading.Thread(target=input_handler, args=(sock,))
            xec.start()
            with open("/dev/tty","rb", buffering=0) as tin:
                oldmode = termios.tcgetattr(tin)
                size = shutil.get_terminal_size()
                tty.setraw(tin)
                try:
                    if contact.upper() == "TELNET":
                        # Send IAC DO Suppress-go-ahead (using WILL causes looping)
                        send_do_command(sock,TelnetOption.SUPRGA)
                        if local_echo:
                            send_will_command(sock, TelnetOption.ECHO)
                        if ttytype:
                            # Send IAC WILL TTYTYPE
                            send_will_command(sock,TelnetOption.TTYTYPE)
                        if location is not None:
                            send_will_command(sock,TelnetOption.SEND_LOC)   # WILL SEND-LOCATION
                        send_will_command(sock,TelnetOption.WINSIZE)       # WILL WINSIZE
                    while True:
                        try:
                            line = read_a_line(tin) # tin.read(1)
                            if debug:
                                print("Input: {} length {}".format(line,len(line)), file=sys.stderr)
                            if line == b"\x1d" or line == b"\x1e":
                                # ^] or ^^ pressed
                                print("\x0d",file=sys.stderr)
                                print("Telnet escape - press q or l for quit, d to toggle debug, ^T for AYT: ", file=sys.stderr, end='')
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
                                elif ch == b"\x14":
                                    send_command(sock,[TelnetCommand.AYT])
                                    continue
                                else:
                                    line = ch
                        except EOFError:
                            line = b"\x04"
                        sock.send_data(line)
                except ChaosError as e:
                    if debug:
                        print("\r\nChaosError: {}\r".format(e), file=sys.stderr)
                except OSError as e:
                    if debug:
                        print("\r\n{}\r".format(e), file=sys.stderr)
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
    # This doesn't seem to play nicely?
    parser.add_argument("-L","--localecho",action='store_true',
                            help="Use local echo")
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
    if args.localecho:
        local_echo = True
    if args.debug:
        debug = True
        print(args, file=sys.stderr)

    try:
        telnet(args.host, args.contact, options=cargs, tcp=args.tcp)
    except ChaosError as m:
        print("Chaosnet error: {}".format(m), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
