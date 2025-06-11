# The Chaosnet Bridge

This program is a bridge between Chaosnet implementations. It supports different link layer implementations:
- Chaos-over-Ethernet (protocol nr 0x0804, cf https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
- Chaos-over-UDP (encapsulation used by e.g. the klh10/its pdp10 emulator, see https://its.victor.se/wiki/ch11)
- Chaos-over-Unix-sockets (used by the usim CADR emulator, see http://www.unlambda.com/cadr/) 
- Chaos-over-TLS (see below)
- Chaos-over-IP (using IP protocol 16, cf https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

It also implements the transport layer of Chaosnet (using any of the above link layers), see [NCP](NCP.md).

## See also
- [INSTALLATION](doc/INSTALLATION.md) for info about how to get cbridge running.
- [CONTACTS](doc/CONTACTS.md) for info about which Chaosnet application protocols are supported - see also NCP (below) for how to add your own.
- [CONFIGURATION](doc/CONFIGURATION.md) for how to configure the bridge program.
- [EXAMPLES](doc/EXAMPLES.md) for some example configurations.
- [TLS](doc/TLS.md) for how to get a certificate for Chaosnet-over-TLS.
- [NCP](doc/NCP.md) for how to connect a user program to Chaosnet.
- [FIREWALL](doc/FIREWALL.md) for how to configure the built-in firewall. 
- [HISTORY](doc/HISTORY.md) for some historic notes.
- [COPYRIGHT](COPYRIGHT.md) for copyright notice and acknowledgements.

## Use cases

You can configure the bridge to connect subnets and/or individual hosts. 

Use cases could be
- connecting ITSes running on klh10 or simh, or [the usim CADR emulator](https://tumbleweed.nu/lm-3/).
  Rather than configuring your
  klh10 to handle all other chudp hosts and iptables to forward chudp
  pkts over the tun interface, you can keep routing in the bridge
  program. Adding new chudp hosts now doesn't require klh10
  configuration. 
- connecting remote Chaosnet-over-Ethernets, e.g. to communicate with
  others using LambdaDelta (use a Chaos-over-UDP or -over-TLS or -over-IP
  link between them). 
- connecting remote Chaosnet-over-Unix-sockets, e.g. to communicate
  with others using usim (use a Chaos-over-UDP or -over-TLS or
  -over-IP link between them). 
- connecting remote Chaosnet-over-IP networks, e.g. in case you run [TOPS-20 with Chaosnet](https://github.com/bictorv/tops20-chaos), or a
  [PDP-10/X](http://www.fpgaretrocomputing.org/pdp10x/).
- and interconnecting these, of course!

There is also support for connecting user programs such as Supdup (in some Unix-like environment) to Chaosnet - [read more](#network-control-program).

For more info on the Global Chaosnet, see https://chaosnet.net.

## Requirements

Note: This list might not be complete. Let me know your findings.

For Linux:
- `linux-libc-dev`, of course
- `libpcap-dev`, `libnet1-dev`, `libssl-dev`

For macOS:
- xcode command line tools, of course
- `libpcap`, `openssl`, sometimes `libbind` (which needs `groff`)

## Features

### Chaos-over-UDP

Chaosnet packets are encapsulated in UDP packets, using a four-byte
header (version=1, function=1, 0, 0), and with a "hardware
trailer" (cf [Section 2.5 of MIT AI Memo 628](https://chaosnet.net/amber.html#Hardware-Protocols))
containing the destination and source addresses and an [Internet
Checksum](https://tools.ietf.org/html/rfc1071). Packets are sent in
["little-endian"
order](https://en.wikipedia.org/wiki/Endianness#Mapping_multi-byte_binary_values_to_memory),
i.e. with the least significant byte of a 16-bit word before the most
significant byte. (I'm really sorry about this, and might develop
version 2 of the protocol with the only change being big-endian byte
order.)

When configured to use Chaos-over-UDP ("chudp", see the [configuration](doc/CONFIGURATION.md) section)
- the `dynamic` keyword can be used to allow new hosts to be added to
  the configuration by simply sending a chudp packet to us.
  This feature is not as useful here as in klh10, since it's easy
  to configure new links and fast to restart the bridge, as opposed to
  a whole ITS system.
- host names given in chudp links (see [configuration](doc/CONFIGURATION.md)) are re-parsed every five
  minutes or so, to support dynamic DNS entries (hosts changing
  addresses). (Maybe this should be configurable.)

For tracing traffic, you might want to use [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) (or Wireshark) with the provided [dissector script](support/chaos.lua).

### Chaos-over-Unix-sockets

Chaosnet packets are sent over a named Unix socket, with a 4-byte
header (length MSB, length LSB, 1, 0). Packets are sent in
"big-endian" order, with a ["hardware
trailer"](https://chaosnet.net/amber.html#Hardware-Protocols).

When configured to use Chaos-over-unix-sockets, you need to also run
the "chaosd" server (found with the usim CADR emulator, see
http://www.unlambda.com/cadr/, or at https://tumbleweed.nu/lm-3/).
There can be only one such server per host system (on the same host as
the bridge) since the named socket of the server is constant.

(Note that the modern usim at https://tumbleweed.nu/lm-3/ does not
need the "chaosd" server, but can connect directly to cbridge using
Chaos-over-UDP.)

### Chaos-over-Ethernet

Chaosnet packets are sent using the standard Ethernet protocol
[0x0804](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
No "hardware trailer" is used (cf [Section 2.5 of MIT AI Memo
628](https://chaosnet.net/amber.html#Hardware-Protocols)), since the
Ethernet header does the corresponding job. Packets are sent in
"big-endian" order.

When configured to use Ethernet, ARP for Chaosnet is used: 
- ARP packets are sent and received in a standard manner to find ethernet-chaos mappings
- Proxy ARP is used to inform the Ether hosts about non-Ethernet hosts (e.g chudp or unix-socket hosts)

For tracing traffic, you might want to use [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) (or Wireshark) with the provided [dissector script](support/chaos.lua).

### Chaos-over-IP

Chaosnet packets are sent in IP/IPv6 packets, using the standard
[IP protocol 16](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
Packets are sent in "big-endian" order, most often (but **not always**) with a ["hardware
trailer"](https://chaosnet.net/amber.html#Hardware-Protocols).

Chaosnet addresses are mapped to IP/IPv6 addresses either
individually, or for a whole subnet (see
[configuration](doc/CONFIGURATION.md)).

Chaosnet addresses where the host byte is 0xFF cannot be used with
subnet mappings on IPv4, since they map to the broadcast address. 
Broadcast on IPv6 (e.g for sending routing packets on a subnet) is Not
Yet Implemented.

Requires `libpcap-dev` and `libnet1-dev` (on Linux) or `libpcap` (on macOS, using `port`).

For tracing traffic, you might want to use [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) (or Wireshark) with the provided [dissector script](support/chaos.lua).

### Chaos-over-TLS

Chaosnet packets are sent over TLS, with a 2-byte header (length MSB,
length LSB). Packets are sent in "big-endian" order, with a ["hardware
trailer"](https://chaosnet.net/amber.html#Hardware-Protocols).

There are different reasons to want to use TLS:
- one is for improved security (confidentiality, authenticity), and
- another is for clients which don't have externally reachable and
  stable IP addresses and thus are not reachable by UDP. TCP would
  suffice, but since clients don't have stable IPs, it would be hard to
  firewall - instead you need an open server which is not so
  nice/secure. TLS helps with the authentication. 

When configured to use Chaos-over-TLS, it needs some certificate
infrastructure. There is one for the Global Chaosnet, see [TLS](doc/TLS.md) 

TLS is asymmetric, in the sense that one end is the server which the
clients connect to.

Requires `libssl-dev` to compile on Linux; on macOS with `port`, install `openssl`.

### Network Control Program

A simple unix sockets interface ("API") for connecting "any old program" to Chaosnet, e.g. Supdup. See [the docs](doc/NCP.md) and [Supdup for Chaosnet](https://github.com/PDP-10/supdup). There is also a higher-level Python library.

For convenient Chaosnet DNS use on macOS 15.4 (and perhaps higher), some people need to install `libbind` (which needs `tbl` which comes with `groff`).

## Routing basics

When configuring your Chaosnets, you should really think about routing
and subnets properly. Trying to interconnect two "segments" of the
same subnet on different media is harder to get right than
interconnecting two different subnets. Attaching single hosts to a
subnet through this bridge is more doable.

A bridge between two subnets needs an address on each one of them. In
the [configuration](doc/CONFIGURATION.md), see the `myaddr` parameter for
links.

### Private non-routed subnet
In order to minimise address collisions and routing problems, the
subnet 0376 octal, is reserved for private non-routed use, such as
experiments. 
No routing information about that subnet should be sent
outside that subnet, no packets from that subnet should be sent to
other subnets, and any packets received from that subnet on another
subnet should be dropped. This is similar to the IP private networks
such as 10.x.y.z or 192.168.x.y.

Additional private non-routed subnets can be defined using the
`private` keyword in the [configuration](doc/CONFIGURATION.md), which can
also define a file for hostname-address mappings for private
networks. (Such networks typically do not have DNS entries.)

## Other features

If the process receives a SIGUSR1 signal, it prints things about its
configuration, routing and statistics. If SIGINFO is defined (e.g. on
macOS, using ctrl-T in bash), that signal does the same.

## Thoughts - let me know what you think

Should BRD packets be forwarded towards subnets in the bitmask which we know a route to? 
This would make it possible to do a "remote broadcast" on a net we're not directly connected to.
(Currently they are only forwarded on subnets we are directly connected to, which means they can still reach remote subnets, but only by being broadcast on every net along the way.)

## Future work (let me know if you do it!):

- [ ] validate configuration (at least warn about crazy things, subnet-specific address on each link, multiple links/routes to same dest))
- [ ] improve logging (avoid mixing output from different threads, improve granularity e.g. to only log "significant" events, "levels" and "facilities" a'la LambdaDelta)
- [ ] rewrite BPF part (Chaos-over-Ethernet) using libpcap (for portability and simplicity)
- [ ] invent version 2 of CHUDP to send packets in network order, like all the others, and thus avoid swapping/copying data all over (except for version 1 of CHUDP)
- [ ] detect unexpected traffic (e.g. traffic from a known subnet coming on a different link)
- [ ] make Open Genera use tap instead of tun, to allow Chaosnet (quite different project, but for Chaos interoperability)


---

## Notes

When looking for a route, first a route for the individual host is
searched for, then the subnet. The bridge sends RUT routing packets
about subnets (but not about individual host routes, since that can't
be done with RUT).

Separate threads are started to handle input from different link types
(several for TLS). Each thread is only started if the configuration
needs it (e.g. if you configure an ether link, the ethernet thread is
started).

Often the Ethernet link can NOT send and receive to the host system
running the bridge program, or other programs using the same
mechanism, such as klh10 using Chaos-over-Ether. 
(With the latest version of LambdaDelta, the bridge program plays nicely though.)
If you have problems, run the bridge on another system on your network.
