#!/bin/env python3
# Copyright © 2021-2024 Björn Victor (bjorn@victor.se)
# Chaosnet client for NAME protocol (what is otherwise known as finger, which is a different protocol on Chaosnet)
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

from chaosnet import StreamConn

# -d
debug = False

def finger(host,user=None,contact="NAME"):
    sock = StreamConn()
    if sock is not None:
        sock.connect(host,contact,args=(['/W',user] if user is not None else []))
        sock.copy_until_eof()
    else:
        print("Connection failed", file=sys.stderr)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet finger/name')
    parser.add_argument("-c","--contact",dest='contact', default="NAME",
                            help="Contact other than NAME (e.g. BYE or LIMERICK)")
    parser.add_argument("host", help='The host to check')
    parser.add_argument("user", nargs="?", help='User to check')
    args = parser.parse_args()

    finger(args.host, args.user, args.contact)

