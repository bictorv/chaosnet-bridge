# Copyright © 2023 Björn Victor (bjorn@victor.se)
# Tool to make it easier to use CHaosnet class DNS servers.
# Vaguely based on the example in https://pypi.org/project/NetfilterQueue/

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

# Motivation:
# A standard DNS server has no real clue about Chaosnet class data,
# while the few servers that do, will not (want to) forward queries about INternet data.
# Before this script+netfilterqueue, the workaround was to create your own forwarding
# DNS server, which would ask a central DNS Chaosnet server for that data, and the standard
# forwarder (e.g. 1.1.1.1 or your ISP) for Internet data.
#
# This helps:
# In nftables, outgoing DNS packets to the default DNS server/forwarder are queued to this script.
# The script checks if it is a CHaosnet class query, then marks it, and "repeats" the packet
# In nftables, check for marked DNS packets, and DNAT them to a Chaosnet-capable DNS server/forwarder.
#
# It should also work with "iptables ... -j NFQUEUE --queue-num 53".

# Check /proc/net/netfilter/nfnetlink_queue for presence and some statistics for the queue.
# For description of columns, e.g. see https://pypi.org/project/NetfilterQueue/.

# To set up nftables, do this:
# Make sure you have a tabe for ip to use (check with "nft list tables" for a "table ip nnnn")
# or make one e.g. with
#  sudo nft "add table ip nat"
# (or use an existing nnnn below in place of "nat").
# Then
#  sudo nft "add chain ip nat dnsoutput { type nat hook output priority mangle; policy accept; }"
# Then two rules needed:
#  sudo nft "add nat dnsoutput ip daddr $DEFAULT_DNS_SERVER udp dport 53 meta mark != 53053 queue num 53 bypass"
#  sudo nft "add nat dnsoutput udp dport 53 meta mark 53053 dnat to $CHAOS_DNS_SERVER"

# The result of "nft list chain ip nat dnsoutput" should be something like:
# table ip nat {
# 	chain dnsoutput {
# 		type nat hook output priority mangle; policy accept;
# 		ip daddr 10.0.1.2 udp dport 53 meta mark != 0x0000cf3d queue num 53 bypass
# 		udp dport 53 meta mark 0x0000cf3d dnat to 10.1.1.72
# 	}
# }


#### @@@@ TOPS-20 reuses its local port, meaning the NAT entry of the first packet remains in use,
#### which means this queue isn't called again for the next packet.
#### To fix, make TOPS-20 reinitialize its UDP port at the end of a successful answer,
#### when it has gotten the/a reply. Patch available!

# @@@@ TODO:
# - run with least privileges (CAP_NET_ADMIN, any more?) rather than root
# - generalise from IPv4 to also IPv6 - urk, but doable
# - generalise from UDP to also TCP - cannot, since it requires inspecting data in packets after the first SYN


# netfilterqueue: https://pypi.org/project/NetfilterQueue/
#  requires apt-get install build-essential python3-dev libnetfilter-queue-dev
# dnspython: https://pypi.org/project/dnspython/

import netfilterqueue
import dns.message, dns.opcode, dns.rdataclass
# Standard modules
import sys, socket, subprocess
from struct import unpack

# Also settable by command-line options
debug = False
# This is the mark we're setting on pkts, which MUST match the netfilter rule
markval = 53053

# This is where to "redirect" CHaosnet class queries
DEFAULT_CHAOS_DNS_SERVER = "dns.chaosnet.net"
CHAOS_DNS_SERVER = None
# This is what to "masquerade" the responses to
DEFAULT_DNS_SERVER = str(subprocess.check_output("grep ^nameserver /etc/resolv.conf | head -1 | sed -e 's/nameserver //'",shell=True),"ascii").strip()

# Just the IHL field of an IPv4 pkt
def ip_pkt_header_length(pkt):
    version = (pkt[0] >> 4) & 0x0f
    ihl = pkt[0] & 0xf
    if version != 4:
        print("Wrong IP version: {}".format(version), file=sys.stderr)
        # Should perhaps raise exception and try the next packet instead,
        # but nft only passes IP packets to us so this is overkill.
        exit(1)
    if debug:
        print("IP version {}, IHL {}".format(version,ihl), file=sys.stderr)
    return ihl

# iplen is in bytes here
def udp_pkt_data(pkt, iplen=20):
    if debug:
        sport,dport,dlen,cksum = unpack("HHHH",pkt[iplen:iplen+4*2])
        print("UDP src {} dst {} len {} cksum {:x}".format(socket.ntohs(sport),socket.ntohs(dport),socket.ntohs(dlen),socket.ntohs(cksum)), file=sys.stderr)
    # Could return pkt[iplen+8:iplen+dlen] but don't care
    return pkt[iplen+8:]

def dns_data(pkt):
    return udp_pkt_data(pkt, 4*ip_pkt_header_length(pkt))

def get_dns_message(pkt):
    # Get a high-level data structure for the DNS message in the pkt
    return dns.message.from_wire(dns_data(pkt))

def has_chaos_question(msg):
    # Finding the class requires either parsing the DNS message,
    # or assuming the class is always the last two bytes are always the payload.
    # Note: regardless of query or answer
    return (msg.question is not None and len(msg.question) > 0
                and msg.question[0].rdclass == dns.rdataclass.CH)
def question_name(msg):
    if msg.question is not None and len(msg.question) > 0:
        return msg.question[0].to_text()
def is_query(msg):
    # This can be checked in nftables I guess
    return (msg.opcode() == dns.opcode.QUERY and (msg.flags & dns.flags.QR) == 0)

def mark_and_repeat(nfpkt):
    if debug:
        print("mangle_and_accept({})".format(nfpkt), file=sys.stderr)
    pkt = nfpkt.get_payload()
    msg = get_dns_message(pkt)
    if has_chaos_question(msg) and is_query(msg):
        if debug:
            print("Chaos query for {}, marking {} (old mark {}) and repeating".
                      format(question_name(msg),markval,nfpkt.get_mark()), file=sys.stderr)
        nfpkt.set_mark(markval)
        nfpkt.repeat()
    else:
        if debug:
            print("not Chaos query {} (mark {})".format(question_name(msg),nfpkt.get_mark()), file=sys.stderr)
        #nfpkt.accept()
        nfpkt.set_mark(markval+1)         #don't try again
        nfpkt.repeat()
    print()

def make_queue(qnum, callback):
    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(qnum, callback)
    return nfqueue

def run_queue(nfq):
    while True:
        nfq.run()


# Note: "hook output" is only for local traffic.
# So should introduce a switch for setting up prerouting too.
def setup_rules(tablename,chainname,defdns,chadns,mark,queue):
    # Check if the table exists
    if 0 != subprocess.call("nft list tables ip | grep {}".format(tablename),
                                shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
        # else add it
        if 0 != subprocess.call("nft add table ip {}".format(tablename),
                                  shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
            print("Failed to add new table {}".format(tablename), file=sys.stderr)
            return False
    # Check if the chain exists
    if 0 != subprocess.call("nft list chain ip {} {} | grep {}".format(tablename,chainname,chainname),
                              shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
        # Else add it
        if 0 != subprocess.call('nft "add chain ip {} {} {}"'.
                                          format(tablename,chainname,"{ type nat hook output priority mangle; policy accept; }"),
                                  shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
            print("Failed to add new chain {}".format(chainname), file=sys.stderr)
            return False
    else:
        # if it did exist, flush all rules in it
        if 0 != subprocess.call("nft flush chain ip {} {}".format(tablename,chainname),
                                 shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
            print("Failed to flush chain {}".format(chainname), file=sys.stderr)
            return False
    # Now add the rules to the chain
    if 0 != subprocess.call('nft "add {} {} ip daddr {} udp dport 53 meta mark 0 meta nftrace set 1 queue num {} bypass"'.
                                     format(tablename,chainname,defdns,queue),
                             shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
        print("Failed to add first rule to chain {}".format(chainname), file=sys.stderr)
        return False
    if 0 != subprocess.call('nft "add {} {} udp dport 53 meta mark {} meta nftrace set 1 dnat to {}"'.
                                     format(tablename,chainname,mark,chadns),
                             shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
        print("Failed to add second rule to chain {}".format(chainname), file=sys.stderr)
        return False
    if debug:
        subprocess.call("nft list chain ip {} {}".format(tablename,chainname), shell=True)
    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet DNS mangling/marking tool')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-m","--mark", type=int, default=53053,
                            help="mark value for Chaos-class queries")
    parser.add_argument("-q","--queue", type=int, default=53,
                            help="id for netfilter queue to use")
    parser.add_argument("--tablename",dest="tbname",help="nftables Table name",default="nat")
    parser.add_argument("--chainname",dest="chname",help="nftables Chain name",default="dnsoutput")
    parser.add_argument("-n","--no-nftable-setup",action="store_true",
                            help="Do not set up nftables automatically, only run the queue process")
    parser.add_argument("-c","--chaos-dns-server", 
                            help="DNS server to send Chaosnet class queries to - default DNS.Chaosnet.NET")
    parser.add_argument("-i","--default-dns-server",
                            help="Default DNS server for non-Chaosnet queries - default from /etc/resolv.conf")
    args = parser.parse_args()
    if args.debug:
        print(args)
        debug = True
    if (args.chaos_dns_server or args.default_dns_server) and args.no_nftable_setup:
            print("Note: dns server parameters only needed for setting up nftable", file=sys.stderr)
    while CHAOS_DNS_SERVER is None:
        try:
            CHAOS_DNS_SERVER = socket.gethostbyname(args.chaos_dns_server if args.chaos_dns_server else DEFAULT_CHAOS_DNS_SERVER)
        except socket.error as msg:
            # This indicates the net might not be up yet, so retry
            print("Can't find Chaos DNS server {} - retrying".format(msg), file=sys.stderr)
            sleep(3)
    if args.default_dns_server:
        try:
            DEFAULT_DNS_SERVER = socket.gethostbyname(args.default_dns_server)
        except socket.error as msg:
            # This is either from /etc/resolv.conf or a parameter, should work?
            print("Can't find default DNS server {}".format(msg), file=sys.stderr)
            exit(1)
    if args.mark:
        markval = args.mark
    if not args.no_nftable_setup:
        if not setup_rules(args.tbname, args.chname, DEFAULT_DNS_SERVER, CHAOS_DNS_SERVER, args.mark, args.queue):
            print("Failed setting up nftable rules", file=sys.stderr)
            exit(1)
    run_queue(make_queue(args.queue, mark_and_repeat))
