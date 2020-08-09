# Copyright © 2020 Björn Victor (bjorn@victor.se)
# Chaosnet client for FILE protocol
# Demonstrates the Packet API for the NCP of cbridge, the bridge program for various Chaosnet implementations.

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

# Based on https://github.com/PDP-10/its/blob/master/doc/sysdoc/chaos.file and LMI's SYS:FILE;SERVER.LISP#202
# and its/src/syseng/file.591, its/src/sysen2/cftp.475

# TODO
# Complain if ostype unknown, implement command to set it
# Split better in classes/modules/files
# Improve exception handling
# Handle binary file transfers (needs NCP hacking, DWD)
# abstract "packets" to make TCP port easy
# make completing (with Tab) and abbreviating parser - https://python-prompt-toolkit.readthedocs.io ?
# add pathname interpretation based on DNS HINFO
# - and handle Symbolics syntax, not only ITS and (MIT) LISPM

import socket, io
import sys, subprocess, threading, time
import re, string
import functools
import codecs
# MacOS readline isn't always the GNU version, so no completion, but at least command history and basic line editing
import readline
from datetime import datetime
from enum import IntEnum, auto
from random import randint
from pprint import pprint, pformat
# pip3 install dnspython
import dns.resolver

from concurrent.futures import ThreadPoolExecutor

# The directory of this need to match the "socketdir" ncp setting in cbridge.
packet_address = '/tmp/chaos_packet'
# -d
debug = False
  
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
    EOF = auto()                          # @@@@ with NCP, extended with optional "wait" data part which is never sent on the wire
    UNC = auto()
    BRD = auto()
    ACK = 0o177                           # @@@@ new opcode to get an acknowledgement from NCP when an EOF+wait has been acked
    DAT = 0o200
    SMARK = 0o201                       # synchronous mark
    AMARK = 0o202                       # asynchronous mark
    DWD = 0o300

# Lispm character set
class LMchar:
    RUBOUT = bytes([0o207])
    BACKSPACE = bytes([0o210])
    TAB = bytes([0o211])
    LF = bytes([0o212])
    PAGE = bytes([0o214])
    RETURN = bytes([0o215])
    def toascii(strng):
        return LMcodec().decode(strng,tostring=False)[0]
        # if isinstance(strng, str):
        #     return strng.translate(str.maketrans('\211\215\214\212','\t\n\f\r'))
        # else:
        #     return strng.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r'))


# See CHAOS FILE https://github.com/PDP-10/its/blob/master/doc/sysdoc/chaos.file
# and SYSENG;FILE > (label CHR2LM etc)
# and! https://www.rfc-editor.org/rfc/rfc1037.html Tables 1 and 2.
# and https://docs.python.org/3/library/codecs.html
# https://stackoverflow.com/questions/38777818/how-do-i-properly-create-custom-text-codecs
# https://github.com/pyserial/pyserial/blob/master/serial/tools/hexlify_codec.py
# Consider UTF8 translation of funny chars, like in Supdup?
class LMcodec(codecs.Codec):
    def __init__(self, errors='strict'):
        # See Tables 1 and 2 in https://www.rfc-editor.org/rfc/rfc1037.html
        if False and debug:
            print("LMcodec({!r})".format(errors), file=sys.stderr)
        # LISPM to Unix
        self.decoding_map = codecs.make_identity_dict(range(256))
        for i in range(0o10, 0o15):
            self.decoding_map[i] = i+0o200
        self.decoding_map[0o177] = 0o377
        for i in range(0o210,0o214):
            self.decoding_map[i] = i-0o200
        self.decoding_map[0o212] = 0o15
        self.decoding_map[0o215] = 0o12
        self.decoding_map[0o377] = 0o177
        # self.decoding_map.update(zip([ ord(c) for c in '\211\215\214\212' ],
        #                              [ ord(c) for c in '\t\n\f\r']))
        #self.encoding_map = codecs.make_encoding_map(self.decoding_map)
        # Unix to LISPM
        self.encoding_map = codecs.make_identity_dict(range(256))
        for i in range(0o10, 0o14):
            self.encoding_map[i] = i+0o200
        self.encoding_map[0o12] = 0o215
        self.encoding_map[0o15] = 0o212
        self.encoding_map[0o177] = 0o377
        for i in range(0o210, 0o215):
            self.encoding_map[i] = i-0o200
        self.encoding_map[0o377] = 0o177
        # self.encoding_map.update(zip([ ord(c) for c in '\t\n\f\r'],
        #                              [ ord(c) for c in '\211\215\214\212' ]))

    def decode(self, data, errors='strict', tostring=True):
        if tostring:
            # This always renders a string
            return codecs.charmap_decode(data, errors, self.decoding_map)
        if isinstance(data,str):
            tr = str.maketrans(self.decoding_map)
            r = data.translate(tr)
        else:
            tr = bytes.maketrans(bytes(self.decoding_map.keys()), bytes(self.decoding_map.values()))
            data = bytes(data)
            r = data.translate(tr)
        if False and debug:
            print("LMcodec.decode {!r} (len {}) errors {!r}: {!r}".format(type(data), len(data), errors, data), file=sys.stderr)
            print("LMcodec.decode result {!r}".format(r))
        return (r,len(r))
        
        # return (LMdecode(data), len(data))
    def encode(self, data, errors='strict', tostring=True):
        if tostring:
            # This always renders a string
            return codecs.charmap_encode(data, errors, self.encoding_map)
        if isinstance(data,str):
            tr = str.maketrans(self.encoding_map)
            r = data.translate(tr)
        else:
            tr = bytes.maketrans(bytes(self.encoding_map.keys()), bytes(self.encoding_map.values()))
            data = bytes(data)
            r = data.translate(tr)
        if False and debug:
            print("LMcodec.encode {!r} (len {}) errors {!r}: {!r}".format(type(data), len(data), errors, data), file=sys.stderr)
        return (r,len(r))
        # return (LMencode(data), len(data))
class LMinc_decoder(LMcodec, codecs.IncrementalDecoder):
    def decode(self, data, final=False):
        return super().decode(data)[0]
class LMinc_encoder(LMcodec, codecs.IncrementalEncoder):
    def encode(self, data, final=False):
        return super().encode(data)[0]
class LMstream_writer(LMcodec, codecs.StreamWriter):
    pass
class LMstream_reader(LMcodec, codecs.StreamReader):
    pass
def LMregentry(encoding_name):
    if False and debug:
        print("LMregentry({})".format(encoding_name))
    if (encoding_name == 'lispm'):
        return codecs.CodecInfo(name='lispm', encode=LMcodec().encode, decode=LMcodec().decode,
                                    incrementalencoder=LMinc_encoder, incrementaldecoder=LMinc_decoder,
                                    streamwriter=LMstream_writer, streamreader=LMstream_reader)
    return None

def LMdecode(data):
    # LISPM to Unix
    return LMcodec().decode(data,tostring=False)[0]
    # if isinstance(data, str):
    #     tr = str.maketrans('\211\215\214\212','\t\n\f\r')
    # else:
    #     data = bytes(data)
    #     tr = bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')
    # if False and debug:
    #     print("LMdecode {!r} (len {}) tr {!r}".format(type(data), len(data), tr), file=sys.stderr)
    # o = data.translate(tr)
    # return o
def LMencode(data):
    # Unix to LISPM
    return LMcodec().encode(data,tostring=False)[0]


# Basic error class
class FileError(Exception):
    typestring = "FILE Error"
    def __init__(self,code,msg):
        self.code = code
        self.message = msg
        super().__init__(msg)
    def __str__(self):
        return "{} {!s}: {!s}".format(self.typestring, str(self.code,"ascii"), str(self.message,"ascii"))

# The three types of errors
class CommandError(FileError):
    typestring = "Command error"
class RestartableError(FileError):
    typestring = "Restartable error"
class FatalError(FileError):
    typestring = "Fatal error"

# Some specific errors we want to handle
class FNFError(FatalError):
    pass
class DNFError(FatalError):
    pass
class NLIError(FatalError):
    pass


class NCPConn:
    sock = None
    active = False
    contact = None

    def __init__(self):
        self.get_socket()
    def __str__(self):
        return "<{} {} {}>".format(type(self).__name__, self.contact, "active" if self.active else "passive")

    def close(self, msg="Thank you"):
        if debug:
            print("Closing {} with msg {}".format(self,msg), file=sys.stderr)
        self.send_packet(Opcode.CLS, msg)
        try:
            self.sock.close()
        except socket.error as msg:
            print('Socket error closing:',msg)
        self.sock = None

    # Construct a 4-byte packet header for chaos_packet connections
    def packet_header(self, opc, plen):
        return bytes([opc, 0, plen & 0xff, int(plen/256)])

    def get_socket(self):
        address = '/tmp/chaos_packet'
        # Create a Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        try:
            self.sock.connect(address)
            return self.sock
        except socket.error as msg:
            print('Socket errror:',msg, file=sys.stderr)
            sys.exit(1)


    def send_packet(self, opcode, data):
        # print("send pkt {} {} {!r}".format(Opcode(opcode).name, type(data), data))
        if isinstance(data, str):
            msg = bytes(data,"ascii")
        else:
            msg = data
        if debug:
            print("> {} {} {}".format(self,Opcode(opcode).name, len(msg)), file=sys.stderr)
        self.sock.sendall(self.packet_header(Opcode(opcode), len(msg)) + msg)

    def get_packet(self):
        # Read header to see how long the pkt is
        hdr = self.sock.recv(4)
        # First is opcode
        opc = hdr[0]
        # then zero
        assert(hdr[1] == 0)
        # then length
        length = hdr[2] + hdr[3]*256
        assert(length <= 488)
        if debug:
            print("< {} {} {}".format(self,Opcode(opc).name, length), file=sys.stderr)
        data = self.sock.recv(length)
        # print("< {} {!s}".format(len(data), str(data.translate(bytes.maketrans(b'\211\215\214\212',b'\t\n\f\r')),"utf8")))
        return (opc,data)

    def rfc(self, contact,host,args=[]):
        h = bytes(("{} {}"+" {}"*len(args)).format(host,contact.upper(),*args),"ascii")
        if debug:
            print("RFC: {}".format(h), file=sys.stderr)
        self.send_packet(Opcode.RFC, h)
        opc, data = self.get_packet()
        if opc == Opcode.CLS:
            raise FileError(b'CLS',data)
        elif opc != Opcode.OPN:
            print("Unexpected RFC response for {} from {}: {} {} (wanted OPN)".format(contact,host, Opcode(opc).name, data), file=sys.stderr)
            return False
        if debug:
            print("OPN {!r}".format(data), file=sys.stderr)
        if self.ostype == None and host != str(data,'ascii'):
            if debug:
                print("Checking DNS info for {}".format(str(data,'ascii')), file=sys.stderr)
            self.dnsinfo = dns_info_for(str(data,'ascii'))
            self.host = self.dnsinfo['name'] if self.dnsinfo and 'name' in self.dnsinfo else str(data,'ascii')
            self.ostype = self.dnsinfo['os'] if self.dnsinfo and 'os' in self.dnsinfo else None
        self.active = True
        self.contact = contact
        return True

    def listen(self, contact, expected_host=None):
        if debug:
            print("Listen for {} (expected {})".format(contact,expected_host))
        self.send_packet(Opcode.LSN,contact)
        self.active = False
        self.contact = contact
        opc, data = self.get_packet()
        rh = str(data,"ascii")
        if opc != Opcode.RFC:
            # Raise exception
            print("Unexpected response {} ({}) in input handler for {} (wanted RFC)".format(Opcode(opc).name, data, ofh), file=sys.stderr)
            return None
        elif expected_host != None and expected_host != rh:
            print("Unexpected host sent RFC: {} (expected {})".format(rh, expected_host))
            self.send_packet(Opcode.CLS,"You are the wrong host to RFC this contact")
            # Raise exception
            return None
        else:
            if debug:
                print("RFC {!r}".format(data), file=sys.stderr)
            self.send_packet(Opcode.OPN,"")
            return rh
        
    def read_until_smark(self):
        if debug:
            print("attempting to read until SMARK from {}".format(self))
        opc, d = self.get_packet()
        # @@@@ cf SmrKin, but there it might read duplicates/ooo pkts?
        while opc != Opcode.SMARK:
            if opc not in (Opcode.SMARK, Opcode.AMARK, Opcode.EOF, Opcode.DAT, Opcode.DWD):
                raise FileError(b'UNC', bytes("read_until_smark: Unexpected opcode {}".format(Opcode(opc).name),"ascii"))
            if debug:
                print("read_until_smark: read {} data len {} ({:15})".format(Opcode(opc).name, len(d), d), file=sys.stderr)
            opc, d = self.get_packet()

class File(NCPConn):
    ncp = None
    curr_tid = 1
    dnsinfo = None

    def __init__(self, host, version=1):
        self.dnsinfo = dns_info_for(host)
        self.host = self.dnsinfo['name'] if self.dnsinfo and 'name' in self.dnsinfo else host
        self.ostype = self.dnsinfo['os'] if self.dnsinfo and 'os' in self.dnsinfo else None
        self.homedir = ""
        self.dataconn = None
        self.get_socket()
        self.rfc("FILE", host, [version])
        self.xecutor = ThreadPoolExecutor()


    def next_tid(self):
        self.curr_tid = self.curr_tid+1
        return bytes(format("T{:04}".format(self.curr_tid)),"ascii")

    def make_fh(self,direction):
        if direction == 'input':
            return b"I"+bytes("{:04}".format(randint(1,9999)), "ascii")
        else:
            return b"O"+bytes("{:04}".format(randint(1,9999)), "ascii")

    def data_conn_maker(self, tid):
        # Returns response to DATA-CONNECTION
        # Caller is expected to get the result from self.data before proceeding to read/write (using read/write_handler)
        self.ifh = self.make_fh('input')
        self.ofh = self.make_fh('output')
        # Submit a listener, returning a conn as result
        self.data = self.xecutor.submit(self.dataconn_listener, self.ofh, self.ifh)
        # Tell the other end to connect back
        self.send_command(tid, b"", b"DATA-CONNECTION", options=[self.ifh,self.ofh])
        resp = self.get_response()
        # Return the response (@@@@ maybe parse it first?)
        return resp

    def dataconn_listener(self, ofh, ifh):
        # Just make a conn for the ofh, and return when there is an RFC
        conn = NCPConn()
        self.dataconn = conn
        rh = conn.listen(str(ofh,'ascii'))
        return conn

    def undata_connection(self, tid, ifh):
        self.send_command(tid, ifh, b"UNDATA-CONNECTION")
        resp = self.get_response()
        if debug:
            print("undata-conn response {}".format(resp), file=sys.stderr)
        return resp

    def read_handler(self, outstream, conn):
        # if outstream is None, returns the input read as bytes
        # the caller is expected to CLOSE the FH, read the reply, and then read_until_smark from the dataconn
        idata = []
        while True:
            opc, d = conn.get_packet()
            if opc == Opcode.EOF:
                if outstream == None:
                    return b''.join(idata)
                else:
                    return None
            elif opc == Opcode.DAT:
                if outstream == None:
                    idata.append(d)
                else:
                    if isinstance(outstream, io.TextIOBase):
                        d = str(d,'lispm')
                    outstream.write(d)
            elif opc == Opcode.AMARK:
                # @@@@ parse it and make more specific exception
                raise FileError(b'AMARK', d)
            elif opc == Opcode.CLS:
                raise FileError(b'CLS', d)
            else:
                raise FileError(b'UNC', bytes("Unexpected response {} ({}) in data handler for {} (wanted DAT or EOF)".format(Opcode(opc).name, d, stream),"ascii"))


    def write_handler(self, instream, ncp):
        # returns the number of bytes written
        # caller is supposed to CLOSE the FH (but we already wrote EOF and SMARK)
        nbytes = 0
        if debug:
            print("WH for {} and {} starting".format(instream,ncp), file=sys.stderr)
        while True:
            d = instream.read(488)
            if len(d) == 0:
                if debug:
                    print("WH for {} and {} done, sending EOF and closing, returning {}".format(instream,ncp,nbytes), file=sys.stderr)
                # Need to wait for EOF to be acked - extend NCP protocol by data in EOF pkt, which is normally not there
                ncp.send_packet(Opcode.EOF,"wait")
                print("!", file=sys.stderr, end='', flush=True)
                # @@@@ but we notice the waiting only by delaying the next pkt!
                # @@@@ so, invent an ACK pkt as response to EOF+wait
                opc, d = ncp.get_packet()
                if opc != Opcode.ACK:
                    raise FileError(b'BUG', bytes("unexpected opcode in response to EOF+wait: {} ({})".format(Opcode(opc).name, d), "ascii"))
                print("\n", end='', file=sys.stderr, flush=True)
                ncp.send_packet(Opcode.SMARK,"")
                return nbytes
            d = codecs.encode(d,'lispm')
            nbytes += len(d)
            ncp.send_packet(Opcode.DAT, d)
            print(".", file=sys.stderr, end='', flush=True)

    # send_command(tid, fh, cmd, options = on same line as cmd, args = on consecutive lines)
    def send_command(self, tid, fh, cmd, options=[], args=[]):
        # ar = list(functools.reduce(lambda a,b: a+b, map(lambda x: [x,bytes([LMchar.RETURN])], args)))
        # m = bytes(("{} {} {}"+" {}{}"*len(args)).format(tid,fh,cmd,*ar),"utf8")
        m = tid+b" "+fh+b" "+cmd
        if debug:
            print("send_command: tid {} fh {} cmd {} opts {} args {}".format(tid,fh,cmd, options, args))
        if len(options) > 0:
            m = m+b" "+b" ".join(options)
        if len(args) > 0:
            m = m+LMchar.RETURN+LMchar.RETURN.join(args)+LMchar.RETURN
        self.send_packet(Opcode.DAT, m)

    # get_response => (tid, fh, cmd, array-of-results)
    def get_response(self):
        opc,data = self.get_packet()
        if opc == Opcode.DAT:
            dlines = data.split(LMchar.RETURN)
            # return list(map(lambda x: LMdecode(x), dlines))
            return list(map(lambda x: LMcodec().decode(x,tostring=False)[0], dlines))
        elif opc == Opcode.EOF:
            return []
        elif opc == Opcode.AMARK:
            # @@@@ better more specific condition, parse data
            raise FileError(b'AMARK', data)
        elif opc == Opcode.CLS:
            # raise FileError(b'CLS',data)
            if debug:
                print("CLS {!s}".format(data))
            return []
        else:
            # raise exception
            raise FileError(b"UNC",bytes("Unexpected opcode {} ({}) (wanted DAT or EOF)".format(Opcode(opc).name, data), "ascii"))

    # parse_response(first line of reply) => rest of line after "tid fh cmd", split at spaces
    def parse_response(self, rsp, expected_tid=None):
        if debug:
            print("Parsing {}".format(rsp), file=sys.stderr)
        if rsp.count(b' ') > 2:
            tid,fh,cmd,res = rsp.split(b' ',maxsplit=3)
        else:
            tid,fh,cmd = rsp.split(b' ',maxsplit=2)
            res = b""
        if expected_tid is not None and expected_tid != tid:
            if True or debug:
                print("Response for wrong TID: expected {}, got {}".format(expected_tid,tid))
            return None
        if cmd == b'ERROR':
            erc,flag,msg = res.split(b' ',maxsplit=2)
            # @@@@ make exceptions
            if flag == b'F':
                # fatal error
                if erc == b'FNF':
                    raise FNFError(erc,msg)
                if erc == b'DNF':
                    raise DNFError(erc,msg)
                elif erc == b'NLI':
                    raise NLIError(erc,msg)
                else:
                    raise FatalError(erc,msg)
            elif flag == b'R':
                raise RestartableError(erc,msg)
            elif flag == b'C':
                raise CommandError(erc,msg)
        else:
            if debug:
                print("{}: {}".format(cmd,res), file=sys.stderr)
        return res.split(b' ')

    def execute_operation(self, operation, is_write=False, options=[], args=[], dataconn=True, outstream=None, instream=None):
        tid = self.next_tid()
        if dataconn and self.dataconn == None:
            if debug:
                print("creating dataconn for {}".format(operation), file=sys.stderr)
            resp = self.data_conn_maker(tid)
            r = self.parse_response(resp[0])
            if debug:
                print("data-conn response {!r} ({!r})".format(r, resp), file=sys.stderr)
            if r == None:
                raise FileError(b'BUG',b'Bad response from data_conn_maker')
        if dataconn:
            ifh = self.ifh
            ofh = self.ofh
        else:
            ifh = b""
            ofh = b""
        args = list(map(lambda x: bytes(x.upper(), 'ascii'), args))
        options = list(map(lambda x: bytes(x.upper(), 'ascii'), options))
        self.send_command(tid, ofh if is_write else ifh, bytes(operation.upper(), 'ascii'), options=options, args=args)
        msg = self.get_response()
        resp = self.parse_response(msg[0], tid)
        while resp is None:
            if debug:
                print("Bad response or mismatching TID (expected {}) for {!r}".format(tid, msg))
            msg = self.get_response()
            resp = self.parse_response(msg[0], tid)
        if dataconn:
            # Get the conn (waiting here for RFC)
            c = self.data.result()
            if is_write:
                hand = self.xecutor.submit(self.write_handler, instream, c)
                fh = ofh
            else:
                hand = self.xecutor.submit(self.read_handler, outstream, c)
                fh = ifh
            # Wait for the work to be done
            r = hand.result()
            # Close the FH, get the response
            self.send_command(tid, fh, b"CLOSE")
            cr = self.get_response()
            crr = self.parse_response(cr[0], tid)
            if debug:
                print("response to CLOSE: {!r} ({!r})".format(crr,cr), file=sys.stderr)
            # Post-process response
            iolen = 0
            if len(crr) > 2:
                iolen = int(crr[2])
            if is_write:
                if iolen == 0:
                    iolen = r
                return resp, msg[1:], iolen
            else:
                # read until SMARK
                c.read_until_smark()
                return resp,msg[1:],r
        else:
            return resp,msg[1:]

    #### Here are the commands.

    def login(self, uname):
        resp, msg = self.execute_operation("LOGIN", options=[uname], dataconn=False)
        if debug:
            print('Login',resp,msg, file=sys.stderr)
        # Lambda: b'bv ' [b'LX: BV;', b'']
        # uname RETURN homedir
        # ITS: b'BV USERS1' [b'Victor, Bjorn', b'@']
        # uname hsname RETURN persname affiliation
        homedir = ""
        if self.ostype == 'ITS':
            homedir = str(resp[1],"ascii")+";"
        elif self.ostype == 'LISPM':
            homedir = str(msg[0],"ascii") if len(msg) > 0 else ""
        self.homedir = homedir
        return str(resp[0],"ascii")

    def delete_file(self, fname):
        resp,msg = self.execute_operation("delete", args=[fname], dataconn=False)
        if debug:
            print('Delete:',resp,msg)

    def expunge_file(self, fname):
        resp,msg = self.execute_operation("expunge", args=[fname], dataconn=False)
        if debug:
            print('Expunge:',resp,msg)

    def rename_file(self, fromfile, tofile):
        resp,msg = self.execute_operation("rename", args=[fromfile,tofile], dataconn=False)
        if debug:
            print('Rename:',resp,msg)

    def complete_file(self, fname, options=[]):
        dflt = self.homedir + "*"
        if self.ostype == 'ITS' and options == []:
            # ITS requires some option, so use these?
            options = ["READ","NEW-OK"]
        resp, new = self.execute_operation("complete", options=options, args=[dflt, fname], dataconn=False)
        if debug:
            print("Complete {} with {} => {} {}".format(fname, dflt, resp, new))
        return str(new[0].lstrip(),"ascii"), str(resp[0],"ascii")

    def probe_file(self, fname):
        try:
            resp,msg = self.execute_operation("OPEN", options=["PROBE"], args=[fname], dataconn=False)
        except FNFError:
            print("File not found: {}".format(fname), file=sys.stderr)
            return None
        except DNFError:
            print("Directory not found: {}".format(fname), file=sys.stderr)
            return None
        truename = str(msg[0],"ascii")
        cdate,ctime,length,binp,x = resp[:5]
        if debug:
            print('response',cdate,ctime,length,binp, file=sys.stderr)
        length = int(length)
        crdt = datetime.strptime(str(cdate+b' '+ctime,"ascii"), '%m/%d/%y %H:%M:%S')
        binp = False if binp == b'NIL' else True
        if debug:
            print(resp,msg, file=sys.stderr)
            print("= {} created {} len {}{}".format(truename,crdt,length," (binary)" if binp else " (not binary)"),
                    file=sys.stderr)
        return dict(truename=truename, creationdate=crdt, length=length, binary=binp)

    def read_file(self, fname, output, raw=False):
        try:
            resp, msg, content = self.execute_operation("OPEN", outstream=output, options=["READ"]+(["RAW"] if raw else []), args=[fname])
        except DNFError as e:
            print(e, file=sys.stderr)
            return None
        except FNFError as e:
            print(e, file=sys.stderr)
            return None
        truename = str(msg[0],"ascii")
        cdate,ctime,length,binp,x = resp[:5]
        if debug:
            print('response',cdate,ctime,length,binp, file=sys.stderr)
        # But length often doesn't match for text files, since CR LF => #\Return
        length = int(length)
        crdt = datetime.strptime(str(cdate+b' '+ctime,"ascii"), '%m/%d/%y %H:%M:%S')
        binp = False if binp == b'NIL' else True
        if debug:
            print("= Here comes {} created {} len {}{}".format(truename,crdt,length," (binary)" if binp else " (not binary)"),
                    file=sys.stderr)
        if output == 'return':
            if raw or binp:
                return content
            else:
                return str(content,'lispm')
        elif not output:
            if raw or binp:
                print(content)
            else:
                print(str(content,'lispm'))

    def write_file(self, fname, instream, raw=False):
        if debug:
            print("Writing {} from stream {}".format(fname,instream))
        if instream is None:
            raise FileError(b'BUG',b'You called write_file without an input stream')
        resp, msg, content = self.execute_operation("OPEN", is_write=True, instream=instream, options=["WRITE"]+(["RAW"] if raw else []), args=[fname])
        truename = str(msg[0],"ascii")
        cdate,ctime,length,binp,x = resp[:5]
        if debug:
            print('open write response',cdate,ctime,length,binp, file=sys.stderr)
        # But length often doesn't match for text files, since CR LF => #\Return
        length = int(length)
        crdt = datetime.strptime(str(cdate+b' '+ctime,"ascii"), '%m/%d/%y %H:%M:%S')
        binp = False if binp == b'NIL' else True
        if debug:
            print("= Here was {} created {} len {}{}".format(truename,crdt,length," (binary)" if binp else " (not binary)"),
                    file=sys.stderr)
        return dict(truename=truename, created=crdt, length=max(length,content), binary=binp)

    # See directory option DIRECTORIES-ONLY instead
    def all_directories(self, fname=None):
        if self.dnsinfo and self.dnsinfo['os'] == 'ITS':
            # ITS: space dirname-using-six-positions-with-space-filler RETURN
            dirlist = list(filter(lambda x: len(x) > 0, map(lambda x: x.strip(), self.read_file("dsk:m.f.d. (file)", 'return').split('\n'))))
            dirlist.sort()
            return dirlist
        elif self.dnsinfo and self.dnsinfo['os'] == 'LISPM':
            # LISPM
            # ('', [b'(((#\x10FS::LM-PATHNAME "LX: BACKUP-LOGS; .#"\x11) (#\x10FS::LM-PATHNAME "LX: RELEASE-5; .#"\x11) (#\x10FS::LM-PATHNAME "LX: VICTOR; .#"\x11)))'])
            resp,dlist = self.execute_operation("extended-command", options=["all-directories"], args=[fname,"((:noerror))"], dataconn=False)
            if len(dlist) != 1 or not dlist[0].startswith(b'(((') or not dlist[0].endswith(b')))'):
                print('Bad result from LISPM',dlist, file=sys.stderr)
                return None
            dlist = dlist[0]
            dirlist = []
            # This skips device/host name, and file part of pathname - only directory names remain
            rgx = br'#\x10FS::LM-PATHNAME "[^:]+: *([^;]+);[^"]*"\x11'
            x = re.search(rgx, dlist)
            while x:
                dirlist = dirlist + [str(x.group(1),"ascii")]
                dlist = dlist[x.end():]
                x = re.search(rgx, dlist)
            dirlist.sort()
            return dirlist
        else:
            print('unsupported OS',self.dnsinfo['os'] if self.dnsinfo else None, file=sys.stderr)
        return None

    def change_props(self, fname, propvaldict):
        pv = [fname]
        for k in propvaldict:
            pv = pv+["{} {}".format(k,propvaldict[k])]
        resp, msg = self.execute_operation("change-properties", args=pv, dataconn=False)
        if debug:
            print('change_props result',resp,msg, file=sys.stderr)

    def parse_properties(self, lines):
        props = dict()
        if debug:
            print('parsing',lines, file=sys.stderr)
        for l in lines:
            if l == b'':
                break
            try:
                prop,val = l.split(b' ', maxsplit=1)
            except ValueError:
                # Binary property, true when mentioned
                prop = l
                val = b"T"
            prop = str(prop,"ascii")
            # Hack values
            if val.isdigit():
                val = int(val)
            elif prop.endswith('-DATE'):
                # except ITS seems to represent "never" as 01/31/27 00:00:00
                if val == b'01/31/27 00:00:00':
                    val = '--'
                else:
                    val = datetime.strptime(str(val,"ascii"),'%m/%d/%y %H:%M:%S')
            elif prop == 'SETTABLE-PROPERTIES':
                val = str(val,"ascii").split(' ')
            elif prop == 'PHYSICAL-VOLUME-FREE-BLOCKS':
                # e.g. '0:9357,1:11724,2:36499'
                volumes = dict()
                diskl = str(val,"ascii").split(',')
                for d in diskl:
                    unit,free = d.split(':')
                    volumes[int(unit)] = int(free)
                val = volumes
            elif val == b'T':
                val = True
            elif val == b'NIL':
                val = False
            else:
                val = str(val,"ascii")
            if False and debug:
                print('prop {} = {}'.format(prop,val), file=sys.stderr)
            props[prop] = val
        if debug:
            print('found',props, file=sys.stderr)
        return props

    def list_files(self, path, deleted=False, directories=False, fast=False):
        opts = ["DELETED"] if deleted else []
        # Unfortunately Lambdas only give top-level directories (and ITS only has such, of course)
        opts += ["DIRECTORIES-ONLY"] if directories else []
        opts += ["FAST"] if fast else []
        try:
            resp, msg, res = self.execute_operation("DIRECTORY", args=[path], options=opts)
        except DNFError as e:
            print(e, file=sys.stderr)
            return [],[]
        if len(res) > 0 and res.startswith(LMchar.RETURN):
            res = res[1:]
        if debug:
            print("{!s}".format(str(LMchar.toascii(res),"ascii")), file=sys.stderr)
        # Break at double RETURN
        if res.startswith(LMchar.RETURN):   #special case
            resparts = [b""]+res[1:].split(LMchar.RETURN * 2)
        else:
            resparts = res.split(LMchar.RETURN * 2)
        if len(resparts) == 0:
            return None
        # Parse headers into a dictionary
        if debug:
            print("Headers {!r}".format(resparts[0]), file=sys.stderr)
        hdrs = self.parse_properties(resparts[0].split(LMchar.RETURN))
        # Parse files
        files = dict()
        if len(resparts) > 1:
            for p in resparts[1:]:
                if debug:
                    print("Part {!r}".format(p), file=sys.stderr)
                if p == b'':
                    continue
                # Parse lines
                reslines = p.split(LMchar.RETURN)
                # First is filename
                fname = str(reslines[0],"ascii")
                # Get its properties
                fps = self.parse_properties(reslines[1:])
                files[fname] = fps
        return hdrs,files

#### some DNS support

# Get all info
def dns_info_for(nameoraddr):
    if isinstance(nameoraddr,int):
        name = dns_name_of_addr(nameoraddr)
    elif isinstance(nameoraddr,str) and nameoraddr.isdigit():
        name = dns_name_of_addr(int(nameoraddr,8))
    else:
        name = nameoraddr
    addrs = dns_addr_of_name(name)
    hinfo = get_dns_host_info(name)
    return dict(name=name, addrs=addrs, os=None if hinfo == None else hinfo['os'], cpu=None if hinfo == None else hinfo['cpu'])

def get_dns_host_info(name):
    # If it's an address given, look up the name first
    if isinstance(name,int):
        name = dns_name_of_addr(name) or name
    elif isinstance(name,str) and name.isdigit():
        name = dns_name_of_addr(int(name,8)) or name
    try:
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.HINFO, rdclass=dns.rdataclass.CH), '130.238.19.25')
        for t in h.answer:
            if t.rdtype == dns.rdatatype.HINFO:
                for d in t:
                    return dict(os= str(d.os.decode()), cpu= str(d.cpu.decode()))
    except AttributeError as e:
        # dnspython not updated with support for Chaos records?
        pass
        # print("Error", e, file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error", e, file=sys.stderr)

def dns_addr_of_name(name):
    # If it's an address given, look up the name first, to collect all its addresses
    if isinstance(name,int):
        name = dns_name_of_addr(name) or name
    elif isinstance(name,str) and name.isdigit():
        name = dns_name_of_addr(int(name,8)) or name
    addrs = []
    try:
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.A, rdclass=dns.rdataclass.CH), '130.238.19.25')
        for t in h.answer:
            if t.rdtype == dns.rdatatype.A:
                    for d in t:
                        addrs.append(d.address)
    except AttributeError as e:
        # dnspython not updated with support for Chaos records?
        pass
        # print("Error", e, file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error", e, file=sys.stderr)
    return addrs

def dns_name_of_addr(addr):
    if isinstance(addr, str) and not addr.isdigit():
        # already a name, so get the canonical name by looking up its first address
        addrs = dns_addr_of_name(addr)
        if len(addrs) > 0:
            addr = addrs[0]
    try:
        if (isinstance(addr,int)):
            name = "{:o}.CH-ADDR.NET.".format(addr)
        else:
            name = "{}.CH-ADDR.NET.".format(addr)
        h = dns.query.udp(dns.message.make_query(name, dns.rdatatype.PTR, rdclass=dns.rdataclass.CH), '130.238.19.25')
        for t in h.answer:
            if t.rdtype == dns.rdatatype.PTR:
                    for d in t:
                        return d.target.to_text(omit_final_dot=True)
                        # return d.target_to_text()
    except AttributeError as e:
        # dnspython not updated with support for Chaos records?
        pass
        # print("Error", e, file=sys.stderr)
    except dns.exception.DNSException as e:
        print("Error", e, file=sys.stderr)

## Handling directory listings

def print_directory_list(hd,fs):
    # Format this nicely instead
    pprint(hd,width=100)
    if debug:
        pprint(fs,width=100)
    if fs:
        # Get max pathname length
        mxlen = len(max(fs, key=len))
        fmt = string.Template("{:<2} {:$mxlen} {:>7} {:<4} {:<4} {:<19}  {}").substitute(mxlen=mxlen)
        # Handle links (in ITS)
        lks = list(filter(lambda x: 'LINK-TO' in fs[x], fs))
        if len(lks) > 0:
            lklen = len(max(lks, key=len))
            lfmt = string.Template("{:<2} {:$mxlen} => {:$lklen} {:<4} {:<19}  {}").substitute(mxlen=mxlen, lklen=lklen)
        else:
            lfmt = None
        print(fmt.format("","Name","Length","Bs","Flg","Creation","Author"))
        def ftype(f,fs):
            if 'DELETED' in fs[f] and fs[f]['DELETED']:
                return "d"
            elif 'LINK-TO' in fs[f] and len(fs[f]['LINK-TO']) > 0:
                return "L"
            else:
                return ''
        def flags(f,fs):
            return ("!" if 'NOT-BACKED-UP' in fs[f] and fs[f]['NOT-BACKED-UP'] else "")+\
              ("@" if 'DONT-DELETE' in fs[f] and fs[f]['DONT-DELETE'] else "")+\
              ("$" if 'DONT-REAP' in fs[f] and fs[f]['DONT-REAP'] else "")+\
              ("#" if 'DONT-SUPERSEDE' in fs[f] and fs[f]['DONT-SUPERSEDE'] else "")
        def fieldp(f,fs, fld):
            if fld in fs[f]:
                return fs[f][fld]
            else:
                return ''
        for f in fs:
            if 'DIRECTORY' in fs[f]:
                print(fmt.format(ftype(f,fs),
                                 f, fieldp(f,fs,'LENGTH-IN-BYTES') if not fs[f]['DIRECTORY'] else "(dir)", 
                                 "({})".format(fieldp(f,fs,'BYTE-SIZE')) if not fs[f]['DIRECTORY'] else "",
                                 flags(f,fs),
                                 str(fieldp(f,fs,'CREATION-DATE')), fieldp(f,fs,'AUTHOR')))
            elif 'LINK-TO' in fs[f]:
                print(lfmt.format(ftype(f,fs),
                                  f, fs[f]['LINK-TO'], 
                                 flags(f,fs),
                                 # Is creation-date really wanted/valid for links?
                                 str(fieldp(f,fs,'CREATION-DATE')), fieldp(f,fs,'AUTHOR')))
            else:
                print(fmt.format(ftype(f,fs),
                                 f, fieldp(f,fs,'LENGTH-IN-BYTES'), "({})".format(fieldp(f,fs,'BYTE-SIZE')),
                                 flags(f,fs),
                                 str(fieldp(f,fs,'CREATION-DATE')), fieldp(f,fs,'AUTHOR')))

# Make a command interpreter out of this.
if __name__ == '__main__':
    codecs.register(LMregentry)

    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet FILE protocol client')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    # parser.add_argument('user', help='User to login as')
    parser.add_argument("host", help='The host to connect to')
    args = parser.parse_args()

    if args.debug:
        debug = True

    uid = ""
    cwd = ""
    ncp = None
    def wdparse(f):
        if f.count(';') > 0:
            return f
        else:
            return cwd + f

    try:
        ncp = File(args.host)
        if ncp == None:
            exit(1)

        while True:
            # Wish: a completing/abbreviating command reader
            cline = input("FILE {}@{}{}> ".format(uid,args.host, " [debug]" if debug else ""))

            parts = cline.split(' ', maxsplit=1)
            if len(parts) == 0:
                continue

            op = parts[0]
            arg = parts[1:]
            if debug:
                print("op {!r} args {!r}".format(op,arg))

            try:
                if op == '':
                    continue
                elif op == '?':
                    print('Commands:',["debug","bye","cwd","login","probe","complete",
                                           "delete","undelete","expunge",
                                           "nodelete","supersede","nosupersede",
                                           "read","readraw","write",
                                           "alldirs", "directory", "ddirectory","fdirectory"])
                elif op == "bye" or op == "quit":
                    print("Bye bye.", file=sys.stderr)
                    try:
                        ncp.send_packet(Opcode.EOF,"")
                    except BrokenPipeError as e:
                        print("[Connection already down: {}]".format(e))
                    break
                elif op == "debug":
                    debug = not debug
                elif op == "dns":
                    print('DNS info:', ncp.dnsinfo)
                elif op == "login":
                    uid = ncp.login(arg[0])
                    if ncp.homedir.count(':') > 0:
                        cwd = ncp.homedir[ncp.homedir.index(':')+1:].strip()
                    else:
                        cwd = ncp.homedir
                    print("Logged in as {!r} (homedir {!r})".format(uid,ncp.homedir))
                elif op == "cd" or op == "cwd":
                    if len(arg) > 0:
                        if arg[0].endswith(';'):
                            cwd = arg[0].strip()
                        else:
                            print("Directory should end with ;", file=sys.stderr)
                    print("CWD = {}".format(cwd))
                elif op == "probe":
                    pb = ncp.probe_file(wdparse(arg[0]))
                    if pb is not None:
                        print("{} created {} length {}{}".format(pb['truename'],pb['creationdate'],pb['length']," (binary)" if pb['binary'] else " (not binary)"),
                            file=sys.stderr)
                elif op == "delete":
                    ncp.delete_file(wdparse(arg[0]))
                elif op == "undelete":
                    ncp.change_props(wdparse(arg[0]),dict(deleted='NIL'))
                elif op == "rename":
                    ffil,tofil = arg[0].split(' ', maxsplit=1)
                    ncp.rename_file(wdparse(ffil),wdparse(tofil))
                elif op == "complete":
                    fname, stat = ncp.complete_file(wdparse(arg[0]))
                    print("{!s} ({!s})".format(fname, stat))
                    if ncp.ostype != 'ITS' and (stat == 'NEW' or stat == 'NIL'):
                        # Look for ambiguousity (but ITS doesn't handle partial wildcards)
                        if stat == 'NIL':
                            fname += "*"
                        hd,fs = ncp.list_files(fname if stat != 'NIL' else fname+"*", fast=True)
                        if fs:
                            print(list(fs))
                elif op == "expunge":
                    ncp.expunge_file(wdparse(arg[0]))
                # @@@@ make a generic proprty-change command, e.g. a "toggle"?
                elif op == "nodelete":
                    ncp.change_props(wdparse(arg[0]),{'dont-delete':'T'})
                elif op == "supersede":
                    ncp.change_props(wdparse(arg[0]),{'dont-supersede':'NIL'})
                elif op == "nosupersede":
                    ncp.change_props(wdparse(arg[0]),{'dont-supersede':'T'})
                # @@@@ read into output file, read binary files...
                elif op == "read":
                    # s = io.StringIO()
                    s = sys.stdout
                    ncp.read_file(wdparse(arg[0]), s)
                    # print(s.getvalue(), end='')
                elif op == "readraw":
                    ncp.read_file(wdparse(arg[0]), None, raw=True)
                # @@@@ write binary files...
                elif op == "write":
                    inf,outf = arg[0].split(' ', maxsplit=1)
                    try:
                        ins = open(inf,"r")
                    except FileNotFoundError as e:
                        print(e, file=sys.stderr)
                        continue
                    r = ncp.write_file(wdparse(outf), ins)
                    ins.close()
                    print("Wrote {}, length {} ({}), created {}".format(r['truename'], r['length'],
                                                                            "binary" if r['binary'] else "character",
                                                                            r['created']))
                elif op == "alldirs":
                    # print(ncp.all_directories())
                    hd,fs = ncp.list_files(wdparse(arg[0]) if len(arg) > 0 else "*;", directories=True)
                    for f in fs:
                        fs[f]['DIRECTORY'] = True
                    print_directory_list(hd,fs)
                elif op == "directory" or op == "ddirectory" or op == "fdirectory" or op == "dir" or op == "ddir" or op == "fdir":
                    dflt = cwd + "*"
                    if len(arg) > 0:
                        a = wdparse(arg[0])
                        if a.endswith(";"):
                            a += "*"
                    else:
                        a = dflt
                    hd,fs = ncp.list_files(a, deleted=True if op.startswith("ddir") else False,
                                               fast=True if op.startswith("fdir") else False)
                    print_directory_list(hd,fs)
                else:
                    print("NYI operation {} not yet implemented".format(op), file=sys.stderr)
            except NLIError as e:
                print(e)
            except RestartableError as e:
                print(e)
            except CommandError as e:
                print(e)
            except FatalError as e:
                print(e)
            except IndexError as e:
                print(e)
                print("Maybe you forgot an argument to the command?")
            except ValueError as e:
                print(e)
                print("Maybe you forgot an argument to the command?")
    except FileError as e:
        print(e)
    except EOFError:
        print("EOF", file=sys.stderr)
        try:
            ncp.send_packet(Opcode.EOF,"")
        except BrokenPipeError as e:
            print("[Connection already down: {}]".format(e))
    if ncp:
        if ncp.dataconn:
            try:
                ncp.dataconn.close()
            except BrokenPipeError:
                pass
        try:
            ncp.close()
        except BrokenPipeError:
            pass
    exit(0)
