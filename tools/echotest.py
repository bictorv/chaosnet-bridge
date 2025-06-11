# Copyright © 2021-2024 Björn Victor (bjorn@victor.se)
# A little test program which sends a string of bytes (the one used by
# BABEL) to an ECHO server and checks that the response is right, or
# if bytes go missing. When they do, the program complains and stops.
# (It doesn't check performance, e.g. pkts/second.)
#
# It prints a "." for each n:th response, where n defaults to 10 and
# can be changed by the --chunk option.

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

import socket, sys, threading, time
import functools
from datetime import datetime

from chaosnet import StreamConn, PacketConn, ChaosError

# -d
debug = False

def echo_sender(conn, data):
    try:
        while True:
            conn.send_data(data)
    except ChaosError as e:
        if debug:
            print("ECHO sender: {}".format(e), file=sys.stderr)
        return

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-c","--chunk", type=int, default=10,
                            help="Chunk length for each '.'")
    parser.add_argument("-R","--retrans", type=int,
                            help="retransmission time in ms")
    parser.add_argument("-W","--winsize", type=int,
                            help="local window size")
    parser.add_argument("-b","--babel", dest='babelp', action='store_true',
                            help="Use BABEL instead of ECHO")
    parser.add_argument("-s","--server", dest='serverp', action='store_true',
                            help="Be a server instead of a client")
    parser.add_argument("--goon", dest='goon', action='store_true',
                            help="Go on after mismatch")
    parser.add_argument("-p","--packet", dest='packetp', action='store_true',
                            help="Use packet socket")
    parser.add_argument("-P","--parallel", dest='parallelp', action='store_true',
                            help="Send data in parallel to receiving it")
    parser.add_argument("-r","--rotate", dest='rotatep', action='store_true',
                            help="Rotate string being sent")
    parser.add_argument("host", help='The host to contact')
    args = parser.parse_args()
    if args.debug:
        debug = True
    
    xs = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}"
    dlen = len(xs)

    if args.packetp:
        if args.babelp:
            print("Babel won't work in packet mode", file=sys.stderr)
            exit(1)
        c = PacketConn()
    else:
        c = StreamConn()
    n = 0
    tot = 0
    cargs=dict()
    if args.retrans and args.retrans > 0:
        cargs['retrans'] = args.retrans
    if args.winsize and args.winsize > 0:
        cargs['winsize'] = args.winsize
    if len(cargs) == 0:
        cargs = None
    cont = "ECHO" if not args.babelp else "BABEL"
    if args.serverp:
        print("Conn from {}".format(c.listen(cont)))
    elif not c.connect(args.host, cont, options=cargs):
        print("Failed to connect to {} on {}".format(args.host, cont), file=sys.stderr)
        exit(1)
    if args.parallelp and not args.babelp:
        # Start ECHO client sender in parallel
        xec = threading.Thread(target=echo_sender, args=(c,xs,))
        xec.start()
    while True:
        if args.serverp:
            if not args.babelp:
                # ECHO server: get a message, send it back
                d = c.get_message(dlen)
                c.send_data(d)
            else:
                # BABEL server: just send data
                d = xs
                c.send_data(d)
        else:
            if not args.babelp and not args.parallelp:
                # ECHO client: send data
                c.send_data(xs)
            # ECHO client: get data back; BABEL client: just get data
            d = c.get_message(dlen)
        n += 1
        tot += len(d)
        if d != xs or dlen != len(d):
            print(cont + " failed at {} (in {}): len(d) = {} expected {}\n".format(n, tot, len(d), dlen))
            print("received {!r}\n".format(d))
            print("expected {!r}\n".format(xs))
            for i in range(0,len(d)):
                if xs[i] != d[i]:
                    print("{}: {!r} != {!r}".format(i, d[i], xs[i]))
            if not(args.goon):
                c.sock.close()
                break
        if n % args.chunk == 0:
            print(".", end='', flush=True, file=sys.stderr)
        if n % (args.chunk*80) == 0:
            print(" {}", n, file=sys.stderr)
        if args.rotatep:
            xs = xs[2:]+xs[:2]
