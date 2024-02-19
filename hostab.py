# Copyright © 2024 Björn Victor (bjorn@victor.se)
# A client program for the HOSTAB protocol.

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

import sys

from chaosnet import PacketConn, ChaosError

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("host", help='The host to connect to')
    parser.add_argument("lookup", help="What host or address to look up")
    args = parser.parse_args()
    if args.debug:
        debug = True

    c = PacketConn()
    if args.debug:
        c.set_debug(args.debug)

    try:
        c.connect(args.host, "HOSTAB")
        c.send_data(args.lookup+"\r\n")
        c.copy_until_eof()
    except ChaosError as m:
        print(m, file=sys.stderr)
        exit(1)
