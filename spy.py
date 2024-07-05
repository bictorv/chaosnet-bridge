#!/bin/env python3
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
# But since UNC pkts are sometimes lost, we need to sometimes send un-updated
# segments anyway, say 25% of the time or something like that. Experiment!

# TODO:
# - Fix the LISPM code to do as above. But it's probably slow anyway - see this as a demo.
# - Try pygame.transform.smoothscale_by() to scale the window up/down?
#   Cf https://github.com/mitrefireline/simfire/blob/94dc737c4a2bf2eb62e244fae6ad4680bb17a800/simfire/game/game.py#L382

import sys, time, functools, array

# see https://www.pygame.org/docs/
import os
# Hide the greeting from "import pygame"
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = "hide"
import pygame

from chaosnet import PacketConn, ChaosError, UnexpectedOpcode, Opcode, dns_name_of_address

# pygame.PixelArray
# https://www.pygame.org/docs/ref/pixelarray.html#pygame.PixelArray

# Parameters
debug = False
atatime = 'row'

# How many words fit in a packet where 2 bytes are index?
number_of_16b_words = int((488-2)/2)

# Use an array (though it's not faster than using lists and .append).
# The size of the element is needed here, from .itemsize
pvals = array.array('L',(number_of_16b_words*16*array.array('L').itemsize)*bytes([0]))

# Get a packet, handle it.
# If width is not given, get it from the packet.
# If pixelarray is not given, create a window and get it from there.
def spy_process_packet(c, width=None, height=None, pix=None):
    opc,data = c.get_packet()
    if opc == Opcode.CLS:
        raise ChaosError(str(data,"ascii"))
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
    for b in range(len(data[6:])):
        for i in range(8):
            pvals[b*8+i] = (0xFFFFFF if data[b+6]&(1<<i)==0 else 0)
    if debug:
        print("start row {}, start col {}".format(spix % width, int((spix / width)%height)))
    # Put them in the pixelarray. This experiment seems rather useless, it's all slow
    if atatime == 'row':
        # A screen row at a time
        firstrowend = width-(spix%width)   # first pixel might be in the middle of a row
        plen = len(pvals)
        if firstrowend > 0:
            pix[spix%width : spix%width+firstrowend, int(spix/width)%height] = pvals[:firstrowend]
        for p in range(firstrowend,plen,width):
            rowlen = min(width,plen-p)    # last row might not have full width (because first pixel...)
            pix[(spix + p)%width : (spix + p)%width+rowlen, int((spix + p)/width)%height] = pvals[p:p+rowlen]
    elif atatime == 16:
        # 16b at a time (safe, since we have n 16b words)
        for p in range(0,len(pvals),16):
            pix[(spix + p)%width : (spix+p)%width+16, int((spix + p)/width)%height] = pvals[p:p+16]
    elif atatime == 1:
        # Pixel at a time (slower, but not much?)
        for p in range(len(pvals)):
            pix[(spix + p) % width, int((spix + p)/width)%height] = pvals[p]
    else:
        print("Don't know how to do {} pixels at a time?".format(atatime), file=sys.stderr)
        exit(1)
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
    parser.add_argument("-a",'--atatime', default="row",
                            help='Number of pixels to update at a time: "row", 16 or 1')
    parser.add_argument("host", help='The host to spy on')
    args = parser.parse_args()
    if args.debug:
       debug = True
       print(args, file=sys.stderr)
    atatime = args.atatime if args.atatime == 'row' else int(args.atatime)

    start = None
    n = 0
    try:
        pygame.init()
        c = PacketConn()
        c.set_debug(debug)
        c.connect(args.host, "SPY")
        w,h,pa = None, None, None
        while args.numpkts is None or n < args.numpkts:
            pa,w,h = spy_process_packet(c, width=w, height=h, pix=pa)
            n = n+1
            if start is None:
                start = time.time()
    except ChaosError as m:
        print(m, file=sys.stderr)
    except KeyboardInterrupt:
        pass
    end = time.time()
    try:
        c.close()
    except:
        # Ignore errors
        pass
    if n > 0:
        print("Closed connection. {} pkts received in {:.1f} s, {:.1f} pkts/s. Waiting to let you see the window.".format(n, end-start, n/(end-start)))
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            pass
