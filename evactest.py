#!/bin/env python3
# A little test program.
#

import socket, sys
import functools
from datetime import datetime

from chaosnet import StreamConn, PacketConn

# -d
debug = False


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
    parser.add_argument("-p","--packet", dest='packetp', action='store_true',
                            help="Use packet socket")
    parser.add_argument("host", help='The host to contact')
    parser.add_argument("file", help='The filename to get')
    args = parser.parse_args()
    if args.debug:
        debug = True

    if args.packetp:
        c = PacketConn()
    else:
        c = StreamConn()
    cargs=dict()
    if args.retrans and args.retrans > 0:
        cargs['retrans'] = args.retrans
    if args.winsize and args.winsize > 0:
        cargs['winsize'] = args.winsize
    if len(cargs) == 0:
        cargs = None

    # \010 for mode bits (see SYSTEM;BITS >) means don't set reference date
    if not c.connect(args.host, "EVACUATE", args=["\000"+args.file], options=cargs):
        print("Failed to connect to {} on {}".format(args.host, "EVACUATE"), file=sys.stderr)
        exit(1)
    while True:
        d = c.get_message(488, partialOK=True)
        if d != None:
            print("{:s}".format(str(d,"ascii")), end='')
        else:
            break
