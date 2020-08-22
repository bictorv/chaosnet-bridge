# Chaosnet server for NAME protocol (what is otherwise known as finger, which is a different protocol on Chaosnet)
# Demonstrates the APIs for the NCP of cbridge: both the simpler stream protocol and the packet protocol.

import socket, io, time
import sys, subprocess, threading
import re, string
from datetime import datetime
from enum import IntEnum, auto

# Default finger program. Should accept '-s' and '-l' as switches, for best effect.
# Can be set with the --program switch.
finger_program = "/usr/bin/finger"
# The directories of these need to match the "socketdir" ncp setting in cbridge.
server_address = '/tmp/chaos_stream'
packet_address = '/tmp/chaos_packet'
# -d
debug = False
# --packet
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

def give_finger_response(sock, args):
    # Run finger and capture the output
    pargs = [finger_program,'-s']+\
        list(filter(lambda x: x is not None,
                        map(lambda a: b'-l' if a == b'/W' else a if not a.startswith(b'/') else None,
                                args)))
    if debug:
        print("Running {!s}".format(pargs),file=sys.stderr)
    r = subprocess.run(pargs, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

    # Translate to lispm characters, kind of - should also handle Unicode de-translation?
    rout = r.stdout.translate(bytes.maketrans(b'\t\n\f\r',b'\211\215\214\212'))
    # Send the response, and close the socket
    if packetp:
        # Send it in packet chunks
        for i in range(0, len(rout), 488):
            chunk = rout[i : i+488]
            clen = len(chunk)
            hdr = packet_header(Opcode.DAT, clen)
            if debug:
                print("sending chunk len {} header {!r}".format(clen,hdr))
            sock.sendall(bytes(hdr)+chunk)
        # Finish with an EOF, to make sure everything is read before closing
        if debug:
            print("sending EOF")
        sock.sendall(packet_header(Opcode.EOF, 0))
    else:
        if debug:
            print("sending data len {}".format(len(rout)))
        # Nothing special is needed, just write the data. EOF is automatic in this case.
        sock.sendall(rout)
    if debug:
        print("closing socket")
    sock.close()

def name_server():
    # Create a Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    try:
        if packetp:
            sock.connect(packet_address)
        else:
            sock.connect(server_address)
    except ConnectionRefusedError as m:
        # cbridge down, try again in a while
        if debug:
            print("Error {}, sleeping and retrying".format(m))
        time.sleep(15)
        return
    except socket.error as msg:
        print(msg)
        sys.exit(1)

    # Set up a listener for NAME
    if packetp:
        sock.sendall(packet_header(Opcode.LSN, 4) + b"NAME")
    else:
        sock.sendall(b'LSN NAME')

    try:
        # Get a request from the socket
        data = sock.recv(488+16)
        if packetp:
            if data[0] == Opcode.RFC:
                args = data[4:].rstrip().split(b' ')
                if debug:
                    print(datetime.now(),'got RFC from {!s} with args {!r}'.format(args[0],args[1:]))
                # Play with this if you like
                if False and debug:
                    sock.sendall(packet_header(Opcode.FWD, 2)+bytes([0o3143 & 0xff, int(0o3143/256)]))
                    sock.close()
                    return
                sock.sendall(packet_header(Opcode.OPN, 0))
                t = threading.Thread(target=give_finger_response,args=(sock, args[1:])).start()
            else:
                sock.sendall(packet_header(Opcode.CLS, len("Bad request"))+b"Bad request")
                sock.close()
        else:
            # Strip newlines, split at blanks
            args = data.rstrip().split(b' ')
            if args[0] == b"RFC":
                if debug:
                    print(datetime.now(),'got RFC from {!s} with args {!r}'.format(args[1],args[2:]))
                # Accept the request
                sock.sendall(b"OPN\r\n")
                t = threading.Thread(target=give_finger_response,args=(sock, args[2:])).start()
            else:
                sock.sendall(b'CLS Bad request\r\n')
                sock.close()
    except socket.error as msg:
        print(msg)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet NAME server')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-p",'--program',nargs=1,dest='program',
                            help='The program to run to get finger information')
    parser.add_argument("--packet",dest='packetp',action='store_true',
                            help='Use packet mode (chaos_seqpacket) instead of plain stream')
    args = parser.parse_args()
    if args.program:
        finger_program = args.program[0]
        print("Using {!s} for getting finger information".format(finger_program))
    if args.debug:
        print("Turning debug on")
        debug = True
    if args.packetp:
        packetp = True

    # Handle many requests
    while True:
        name_server()
