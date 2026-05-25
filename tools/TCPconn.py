# Copyright © 2026 Björn Victor (bjorn@victor.se)
# Just for fun: a class corresponding to NCPconn, but for TCP.

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

import socket, sys
from chaosnet import ChaosError

debug = False

class TCPconn:
    sock = None
    active = False
    port = None
    remote = None

    def __init__(self):
        self.get_socket()
    def __str__(self):
        return "<{} {} {} {}>".format(type(self).__name__, self.port,
                                          "active" if self.active else "passive",
                                          self.remote)
    def __del__(self):
        if debug:
            print("{!s} being deleted".format(self))

    def set_debug(self,val):
        global debug
        debug = val

    def close(self, msg=b"Thank you"):
        if debug:
            print("\r\nClosing {} with msg {}".format(self,msg), file=sys.stderr)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing:',msg)

    def get_socket(self):
        # Create a TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_socket_data(self, data):
        ts = 0
        while ts < len(data):
            s = self.sock.send(data[ts:])
            if s == 0:
                raise ChaosError("Error: Sent no bytes: (total sent {})".format(ts))
            ts = ts+s

    def get_bytes(self, nbytes):
        return self.sock.recv(nbytes)

    def send_data(self, data):
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("\r\n> {} to {}".format(len(msg), self), file=sys.stderr)
        self.send_socket_data(msg)

    def connect(self, host, port, args=[], options=None):
        self.port = port.lower()
        self.remote = host
        self.active = True
        if debug:
            print("Trying to connect to {} on port {}".format(self.remote,self.port), file=sys.stderr)
        try:
            ainfo = socket.getaddrinfo(self.remote, self.port, proto=socket.IPPROTO_TCP)
            _,_,_,_,address=ainfo[0]
        except socket.gaierror as m:
            print("Error parsing {}: {}".format(self.remote, m), file=sys.stderr)
            exit(1)
        if debug:
            print("Parsed as {}".format(address), file=sys.stderr)
        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            print('\r\nSocket errror:',msg, file=sys.stderr)
            sys.exit(1)

    def get_message(self, length=488):
        data = self.sock.recv(length)
        if debug:
            print("\r\n< {} of {} from {}".format(len(data), length, self), file=sys.stderr)
        if len(data) == 0:
            # This is handled somewhere
            self.sock.close()
            raise ChaosError("Error: Got no bytes: {}".format(data))
        elif len(data) < length:
            d2 = self.sock.recv(length-len(data))
            if debug:
                print("\r\n< {} of {} from {}".format(len(d2), length, self), file=sys.stderr)
            data += d2
        return data
