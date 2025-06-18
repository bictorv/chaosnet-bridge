# Copyright © 2020-2024 Björn Victor (bjorn@victor.se)
# Chaosnet server/forwarder for DOMAIN protocol
# Uses the stream API of the NCP of cbridge, the bridge program for various Chaosnet implementations.

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

import socket, sys, time
import functools
# pip3 install dnspython
import dns.resolver

from chaosnet import StreamConn

# This is the default forwarding server
dns_forwarder_name = 'DNS.Chaosnet.NET'
dns_forwarder_addr = None

# -d
debug = False

class DomainStream(StreamConn):
    # The DOMAIN message, that is, which starts with a length word
    def get_domain_message(self):
        # Read header to see how long the pkt is
        hdr = self.get_bytes(2)
        # length
        if len(hdr) != 2:
            if debug:
                print("Got too few bytes for length: {}".format(len(hdr)), file=sys.stderr)
            return None
        length = hdr[0] + hdr[1]*256
        if debug:
            print("< {} from {}".format(length, self), file=sys.stderr)
        data = self.get_bytes(length)
        return data
    def send_domain_messsage(self,data):
        dlen = len(data)
        # Send length
        self.send_data(bytes([int(dlen/256), dlen & 0xff])+data)        

class Domain_Server:
    conn = None

    def listen(self):
        self.conn = DomainStream()

        rfc = self.conn.listen("DOMAIN")
        if rfc == None:
            return None
        self.conn.send_opn()
        try:
            while True:
                request = self.conn.get_domain_message()
                if request is None:
                    if debug:
                        print("Got {} message".format(request), file=sys.stderr)
                    break
                if debug:
                    print("Got request len {} from {}".format(len(request),rfc), file=sys.stderr)
                msg = dns.message.from_wire(request)
                if debug:
                    print("Made DNS message, sending to {}".format(dns_forwarder_addr), file=sys.stderr)
                resp = dns.query.tcp(msg, dns_forwarder_addr)
                if debug:
                    print("Got DNS response {}, sending to {}".format(resp,rfc), file=sys.stderr)
                wresp = resp.to_wire()
                self.conn.send_domain_messsage(wresp)
        except dns.exception.FormError as msg:
            if debug:
                print("DNS Error: {}".format(msg), file=sys.stderr)
            # Should send a LOS, or perhaps CLS, but need packet interface for that
            # self.conn.close(msg)
        except socket.error as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
        self.conn.close()
        return None

debug = False
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet DOMAIN server')
    parser.add_argument("-f","--forwarder", default=dns_forwarder_name,
                            help="DNS forwarder")
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    args = parser.parse_args()
    if args.forwarder:
        try:
            # Try to parse it as an IPv4 or IPv6 numeric address
            if socket.inet_pton(socket.AF_INET, args.forwarder):
                dns_forwarder_addr = args.forwarder
            elif socket.inet_pton(socket.AF_INET6, args.forwarder):
                dns_forwarder_addr = args.forwarder
        except:
            # and then as a name. OK, this misses ipv6, but...
            try:
                dns_forwarder_addr = socket.gethostbyname(args.forwarder)
            except OSError as msg:
                print("Error resolving {!r}: {}".format(args.forwarder, msg), file=sys.stderr)
                exit(1)
    if args.debug:
        print(args, file=sys.stderr)
        print("DNS forwarder address: {}".format(dns_forwarder_addr), file=sys.stderr)
        debug = True
    # Start e.g. 5 parallel servers and keep them going
    while True:
        if debug:
            print("Starting Domain_Server", file=sys.stderr)
        try:
            ds = Domain_Server()
            ds.listen()
        except socket.error as msg:
            if debug:
                print("Error: {}".format(msg), file=sys.stderr)
            time.sleep(1)
        time.sleep(0.2)
