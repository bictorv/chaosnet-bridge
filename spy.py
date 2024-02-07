# Copyright © 2024 Björn Victor (bjorn@victor.se)
# Chaosnet client for SPY protocol, to see the screen of a LISPM.
# Demonstrates the high-level python library for Chaosnet,
# and use of UNC packets.

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

# The SPY protocol is defined by the sources of the LISPM function:
# - screen segments are packaged in UNC packets
#   where the pktnum and ackno fields hold the width and height of the screen,
#   and the first 16b word is the index for this packet into the screen.
#
# It is rather inefficient: it sends every part of the screen, whether it
# has changed or not. It would be better to send only parts which have changed,
# keeping track of that either by a screen copy or by hashing screen segments.
# This would only require fixes on the server side (for CADR there are 191 segments).

# TODO:
# - Make pixelarray updates more efficient.
# - Try pygame.transform.smoothscale_by() to scale the window up/down?
#   Cf https://github.com/mitrefireline/simfire/blob/94dc737c4a2bf2eb62e244fae6ad4680bb17a800/simfire/game/game.py#L382

import sys, time, functools, math

# see https://www.pygame.org/docs/
import os
# Hide the greeting from "import pygame"
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = "hide"
import pygame

from chaosnet import PacketConn, ChaosError, Opcode, dns_name_of_address

# pygame.PixelArray
# https://www.pygame.org/docs/ref/pixelarray.html#pygame.PixelArray

debug = False

# How many words fit in a packet where 2 bytes are index?
number_of_16b_words = int((488-2)/2)

# Get a packet, handle it.
# If width is not given, get it from the packet.
# If pixelarray is not given, create a window and get it from there.
def spy_process_packet(c, width=None, height=None, pix=None):
    opc,data = c.get_packet()
    if opc != Opcode.UNC:
        raise UnexpectedOpcode("Bad opcode {}, expected UNC".format(Opcode(opc).name))
    if width == None:
        # Each packet contains this
        width = data[0] | (data[1]<<8)
        height = data[2] | (data[3]<<8)
        if debug:
            print("width {} height {}".format(width,height))
    if pix == None:
        # Create a window, and get a handle into it
        if c.remote:
            ttl = "SPY on {}".format(dns_name_of_address(int(c.remote,8), onlyfirst=True, timeout=2) or c.remote)
        else:
            ttl = "SPY"
        # Do this before set_mode
        pygame.display.set_caption(ttl)
        pix = pygame.PixelArray(pygame.display.set_mode(size=(width,height)))
    # The index into the screen for this packet
    idx = data[4] | (data[5]<<8)
    if debug:
        print("idx {}".format(idx))
    # number_of_16b_words in each pkt, 16 pixels in each word
    spix = idx*number_of_16b_words*16 
    epix = spix+number_of_16b_words*16
    # convert b/w pixels to 0/255 values
    pvals = []                            # use an array of 243 instead?
    for b in data[6:]:
        for i in range(8):
            pvals.append(0xFFFFFF if b&(1<<i)==0 else 0)
    if debug:
        print("start row {}, start col {}".format(spix % width, math.floor((spix / width)%height)))
    # @@@@ Do this more efficently, assign slices.
    for p in range(len(pvals)):
        try:
            pix[(spix + p) % width, math.floor((spix + p)/width)%height] = pvals[p]
        except IndexError as m:
            print("{} at {},{}, pos {}".format(m,(spix + p) % width, math.floor((spix + p)/width)%height,p), file=sys.stderr)
            raise
    # Now update the window
    pygame.display.flip()
    return pix,width,height

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Spy on a LISPM screen using Chaosnet (if it allows you).")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-n",'--numpkts',type=int,
                            help='Only process the first N packets')
    parser.add_argument("host", help='The host to spy on')
    args = parser.parse_args()
    if args.debug:
       debug = True
       print(args, file=sys.stderr)

    try:
        pygame.init()
        c = PacketConn()
        c.set_debug(debug)
        c.connect(args.host, "SPY")
        w,h,pa = None, None, None
        n = 0
        while args.numpkts is None or n < args.numpkts:
            pa,w,h = spy_process_packet(c, width=w, height=h, pix=pa)
            n = n+1
    except ChaosError as m:
        print(m, file=sys.stderr)
    except KeyboardInterrupt:
        pass
    c.close()
    print("Closed connection, waiting to let you see the window.")
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        pass
