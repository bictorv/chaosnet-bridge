# Chaosnet client for NAME protocol (what is otherwise known as finger, which is a different protocol on Chaosnet)
# Demonstrates the APIs for the NCP of cbridge: both the simpler stream protocol and the packet protocol.

import socket, io
import sys, subprocess, threading
import re, string
from datetime import datetime
from enum import IntEnum, auto

# The directories of these need to match the "socketdir" ncp setting in cbridge.
stream_address = '/tmp/chaos_stream'
packet_address = '/tmp/chaos_packet'
# -d
debug = False
packetp = False

# Chaos packet opcodes
class Opcode(IntEnum):
    RFC = 1
    OPN = auto()
    CLS = auto()
    FWD = auto()
    ANS = auto()
    SNS = auto()
    STS = auto()
    RUT = auto()
    LOS = auto()
    LSN = auto()
    MNT = auto()
    EOF = auto()
    UNC = auto()
    BRD = auto()
    DAT = 0o200
    DWD = 0o300

# Construct a 4-byte packet header for chaos_packet connections
def packet_header(opc, plen):
    return bytes([opc, 0, plen & 0xff, int(plen/256)])

def get_socket(address):
    # Create a Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    try:
        sock.connect(address)
        return sock
    except socket.error as msg:
        print(msg)
        sys.exit(1)

def stream_conn(addr, host, contact, args=[], timeout=None):
    if debug:
        print('stream_conn',addr,host,contact,args,timeout)
    sock = get_socket(addr)
    if isinstance(host, int):
        host = "{:o}".format(host)

    if timeout is not None:
        d = bytes(("[timeout={:d}] {} {}"+" {}"*len(args)).format(timeout,host,contact,*args),"ascii")
    else:
        # Play with this option.
        # d = bytes(("[follow_forward=yes] {} {}"+" {}"*len(args)).format(host,contact,*args),"ascii")
        d = bytes(("{} {}"+" {}"*len(args)).format(host,contact,*args),"ascii")
    if packetp:
        if debug:
            print('packet',packet_header(Opcode.RFC, len(d))+d)
        sock.sendall(packet_header(Opcode.RFC, len(d))+d)
    else:
        if debug:
            print(b"stream: RFC "+d)
        sock.sendall(b"RFC "+d)
    try:
        # Receive max 488 data bytes, 16 to fit "ANS 488\r\n" (so 9 would be enough)
        data = sock.recv(488+16)
        if packetp:
            dlen = data[2] + data[3]*256
            if data[0] == Opcode.ANS:
                return data[4:dlen+4]
            elif data[0] == Opcode.OPN:
                return sock
            elif timeout is not None and data[0] == Opcode.LOS and data[4:].startswith(b"Connection timed out"):
                return None
            elif data[0] == Opcode.LOS or data[0] == Opcode.CLS:
                print("{} {}".format(Opcode(data[0]).name, data[4:dlen+4]))
            elif data[0] == Opcode.FWD:
                print("Please connect to {:o} instead".format(data[4] + data[5]*256))
            else:
                print("Unexpected response {} len {} ({})".format(Opcode(data[0]).name, data[2] + data[3]*256, data[4:]))
        else:
            eol = data.find(b'\n')
            resp = data[:eol].split(b' ')
            if resp[0] == b"ANS":
                dstart = eol+1
                dlen = int(resp[1])
                return data[dstart:dstart+dlen]
            elif resp[0] == b"OPN":
                return sock
            elif timeout is not None and resp[0] == b"LOS" and data[eol+1:].startswith(b"Connection timed out"):
                return None
            elif resp[0] == b"LOS" or resp[0] == b"CLS":
                print("{}".format(str(data[4:],"ascii").rstrip('\r\n ')))
            else:
                print("Unexpected response {} len {} ({})".format(resp[0],len(data), data))
    except socket.error:
        return None

def finger(host,user=None):
    sock = stream_conn(packet_address if packetp else stream_address,host,"NAME",args=(['/W',user] if user is not None else []))
    if sock is not None:
        data = []
        while True:
            if len(data) == 0:
                data = sock.recv(488+4)
            if len(data) == 0:
                break
            if packetp:
                opc = data[0]
                if data[1] != 0:
                    print("Bad header - should be zero:",data[1])
                lenth = data[2] + (data[3]*256)
                if debug:
                    print("@@@@ opc {} len {}".format(Opcode(opc).name, lenth))
                    if opc == Opcode.DAT and lenth == 4:
                        print("{!r}".format(data[4:lenth+4]))
                if len(data) < lenth+4:
                    if debug:
                        print("@@@@ reading {} more data".format(lenth+4-len(data)))
                    more = sock.recv(lenth+4-len(data))
                    data = data+more
                if debug and opc != Opcode.DAT:
                    print("{}".format(Opcode(opc).name),end=' ')
                if debug or opc == Opcode.DAT:
                    print("{!s}".format(str(data[4:lenth+4].translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")),end='')
                if opc != Opcode.DAT and debug and lenth > 0:
                    print()
                data = data[lenth+4:]
            else:
                print("{!s}".format(str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")), end='')
                data = []
    else:
        print("Connection failed")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet finger/name')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("--packet",dest='packetp',action='store_true',
                            help='Use packet mode (chaos_seqpacket) instead of plain stream')
    parser.add_argument("host", help='The host to check')
    parser.add_argument("user", nargs="?", help='User to check')
    args = parser.parse_args()

    if args.packetp:
        packetp = True
    if args.debug:
        debug = True

    finger(args.host, args.user)

