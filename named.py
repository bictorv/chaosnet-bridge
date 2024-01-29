# Copyright © 2021-2024 Björn Victor (bjorn@victor.se)
# Chaosnet server for NAME protocol (what is otherwise known as finger, which is a different protocol on Chaosnet)
# Demonstrates the APIs for the NCP of cbridge: both the simpler stream protocol and the packet protocol.

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

import socket, time
import sys, subprocess, threading
from datetime import datetime

from chaosnet import StreamConn, PacketConn

# Default finger program. Should accept '-s' and '-l' as switches, for best effect.
# Can be set with the --program switch.
finger_program = "/usr/bin/finger"
# -d
debug = False
# --packet
packetp = False

def give_finger_response(conn, args):
    # Run finger and capture the output
    pargs = [finger_program,'-s']+\
        list(filter(lambda x: x is not None,
                        map(lambda a: b'-l' if a == b'/W' else a if not a.startswith(b'/') else None,
                                args)))
    if debug:
        print("Running {!s}".format(pargs),file=sys.stderr)
    r = subprocess.run(pargs, stdout=subprocess.PIPE,stderr=subprocess.STDOUT, text=True)
    # Translate to lispm characters, kind of partially de-utf-ing
    rout = bytes(r.stdout.translate(str.maketrans("ÅÄÖåäöé","AAOaaoe")),"utf-8").translate(bytes.maketrans(b'\t\n\f\r',b'\211\215\214\212'))
    # Send the response, and close the conn
    if debug:
        print("sending data len {}".format(len(rout)))
    try:
        conn.send_data(rout)
        if packetp:
            # Finish with an EOF, to make sure everything is read before closing
            if debug:
                print("sending EOF")
            conn.send_eof(True)
        else:
            # Nothing special is needed, just write the data. EOF is automatic in this case.
            pass
    except (socket.error,BrokenPipeError) as msg:
        if debug:
            print("Error sending reply: {}".format(msg), file=sys.stderr)
    if debug:
        print("closing {}".format(conn))
    conn.close()

def name_server():
    # Connect 
    try:
        if packetp:
            conn = PacketConn()
        else:
            conn = StreamConn()
    except OSError as m:
        # cbridge down, try again in a while
        if debug:
            print("Error {}, sleeping and retrying".format(m), file=sys.stderr)
        time.sleep(15)
        return
    except socket.error as msg:
        print(msg, file=sys.stderr)
        sys.exit(1)

    # Set up a listener for NAME
    try:
        if debug:
            print("Listening for NAME", file=sys.stderr)
        host,args = conn.listen("NAME")
        conn.send_opn()
        if debug:
            print(datetime.now(),'got RFC from {!s} with args {!r}'.format(host,args))
        # Send the response in a separate thread
        t = threading.Thread(target=give_finger_response,args=(conn, args)).start()
    except ConnectionRefusedError as m:
        # cbridge down, try again in a while
        if debug:
            print("Conn refused: {}".format(msg), file=sys.stderr)
        time.sleep(15)
        pass
    except (socket.error,BrokenPipeError) as msg:
        if debug:
            print("Error: {}".format(msg), file=sys.stderr)
        time.sleep(10)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet NAME server')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-p",'--program',nargs=1,dest='program',
                            help='The program to run to get finger information')
    parser.add_argument("--packet",dest='packetp',action='store_true',
                            help='Use packet mode (chaos_packet) instead of plain stream')
    args = parser.parse_args()

    if args.debug:
        print("Turning debug on")
        debug = True
    if args.program:
        finger_program = args.program[0]
        if debug:
            print("Using {!s} for getting finger information".format(finger_program))
    if args.packetp:
        packetp = True

    # Handle many requests
    while True:
        name_server()
