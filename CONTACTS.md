# Supported Chaosnet protocols

The following Chaosnet contacts (protocol names) have built-in support in the bridge program. Additional protocols may be supported through the [NCP](NCP.md).

### `DUMP-ROUTING-TABLE`
The bridge responds to the `DUMP-ROUTING-TABLE` contact, which sends the
routing table (for subnets up to nr 122). This is used by e.g. the
functions `CHAOS:SHOW-ROUTING-PATH` and `CHAOS:SHOW-ROUTING-TABLE` on LMI
systems, the `CHAOS:PRINT-ROUTING-TABLE` function on Symbolics systems,
and if you're lucky, the `DUMP-ROUTING-TABLE` command of the `CHATST`
program in ITS. 

### `STATUS`

It also responds to the `STATUS` protocol (see AI Memo 628), using the
host name from the "myname" configuration parameter (defaults to the
DNS name of the configured Chaosnet address (the "chaddr" parameter), or the
"real" host name, up to first period).

### `TIME` and `UPTIME`
It also responds to `TIME` and `UPTIME` contacts. Note that `UPTIME` is wrt
the start of the bridge program, which is more interesting than the
host uptime (e.g. wrt the `STATUS` statistics).

### `LASTCN`
A non-standard contact `LASTCN` is also supported, which reponds with
info about which hosts the bridge has received packets from, from what
other host (e.g. another router) and how long ago. Each entry consists of
the following 16-bit words:

 0. length of entry in 16-bit words (8)
 1. host addr which was seen
 2. \# input pkts from that (least significant 16 bits)
 3.   (most significant 16 bits)
 4. address the host was last seen from (e.g. a bridge)
 5. how many seconds ago was the host seen (LSB 16 bits)
 6.   (MSB 16 bits)
 7. the forwarding count field of the last seen packet

### `DNS`
A non-standard contact `DNS` is also supported, which responds to a
"simple" protocol. The contact string is "DNS" followed by a space and
then the DNS query packet. The cbridge process, if configured for it,
forwards the query to a DNS server (over IP/UDP) and sends the
response as an ANS packet to the (Chaosnet) requester.  Because of the
packet size limit, queries and responses are also limited in size.

There is also a (separate) [server](domain.py) for the `DOMAIN`
contact which allows DNS queries over a stream connection, lifting the
size limit. This is more standard, used by Symbolics lisp machines,
and (soon) by the Bogodyne lisp system. 

A client implementation (for both protocols) for the
[LambdaDelta lisp machine](https://github.com/dseagrav/ld) exists,
which could prossibly be ported to the CADR system (which doesn't have
IP).

See also https://chaosnet.net for info about DNS for Chaosnet data.
