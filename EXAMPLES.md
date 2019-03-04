# Examples

Some examples of configurations.

## Basic example

Assuming you run an ITS system (e.g. on klh10), and a local Chaosnet network over Ethernet, and you use subnet 11 (octal). In the example, you connect to the Global Chaosnet over chudp, and you have been assigned address 3171 for connecting to it (cf Routing Basics).

    ; My default Chaosnet address
    chaddr 4401
    ; Define a chaos-over-udp link to the Global Chaosnet router, which has address 3040
    link chudp router.aosnet.ch host 3040 myaddr 3171
    ; Define a local Chaos-over-Ether subnet nr 11 (hosts 4400-4777)
    link ether subnet 11
    ; A chaos-over-udp link to the ITS configured below
    link chudp localhost:42043 host 4411

For a ITS/klh10 running on the same host as cbridge, you can use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=4411 chudpport=42043 chip=4401/localhost:42042

If you let ITS/klh10 use Chaos-over-Ethernet, you do not need the last
"link chudp" line in the cbridge config, and in klh10.ini you can use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=4411 ifmeth=pcap

The ITS will pick up routing info from cbridge. (Of course you also
need to configure ITS to use address 4411.)

If you only run the ITS system, over chudp, and do not use Chaosnet over Ethernet for other purposes, just skip the "link ether" line.


## Example: MX-11

A different example is the config for MX-11 (aka router.aosnet.ch).

The MX-11 serves as a hub for a number of hosts connecting through
CHUDP (mostly ITS systems, but also BSD and MINITS). They have
individual addresses on net 6. 

    ; The name of MX-11 (used e.g. in STATUS replies):
    myname MX-11
    ; The "main" Chaosnet address of MX-11 (on net 6) is
    chaddr 3040
    ; Listen to CHUDP on the standard port, also over IPv6
    chudp 42042 ipv6
    ; Also act as a TLS server for Chaos-over-TLS
    tls key private/router.aosnet.ch.key.pem cert certs/router.aosnet.ch.cert.pem ca-chain ca-chain.cert.pem ipv6 server
    ; Use the standard name for the ethernet interface
    ether eth0

The config for the CHUDP hosts consists of lines

    link chudp hostN host addrN

where `hostN` is the host name or IP of a host, and `addrN` is its
Chaosnet addess. 

Additionally, MX-11 connects to the local ethernet (where an old
Symbolics lisp machine might be running). NOTE the declaration of
"myaddr" for net 1 below, which means that packets cbridge sends on this net
are sent from address 440. A router/bridge should always have (and
use) an address specific to each net.

    link ether subnet 1 myaddr 440

To tell cbridge to send routing info about net 6, which only has
individual host links, a route declaration is necessary.

    route subnet 6 bridge 3040 cost asynch

## Example: Chaos-over-IP

To set up an individual link to another host (a chaosnet bridge, or perhaps a PDP-10/X) using Chaos-over-IP, use

    link chip host.name.com host NNNN

where `host.name.com` is the host name, and `NNNN` is its Chaosnet address. If the host is on a different subnet, add your address on that subnet using the `myaddr` parameter (see [configuration](CONFIGURATION.md)). A specific example, assuming you have an address on Chaos subnet 6:

    link chip router.aosnet.ch host 3040

To set up a whole Chaosnet subnet mapped to an IP subnet, use

    link chip a.b.c.0 subnet NN

where `a.b.c.0` is the IP address of the IP subnet, with the last octet being zero, and `NN` is the (octal) subnet. If this is not your default subnet, i.e. your `chaddr` setting is not on that subnet, add your address on subnet `NN` using the `myaddr` parameter.

The effect is that any Chaosnet packets sent to an address on subnet NN is forwarded to the corresponding IP address on net `a.b.c.0`. For example, suppose you map Chaos subnet 2 to the IP net 10.11.12.0. 

    link chip 10.11.12.0 subnet 2

Addresses on Chaos subnet 2 range from 1001 to 1377 octal. The address 1066 has host byte 66 (octal) = 54 (decimal), and is mapped to 10.11.12.54. Note that address 1377, which has host byte 255, can not be mapped to the IPv4 address 10.11.12.255, since that is the broadcast address on net 10.11.12.0.

For IPv6 addresses, the same mapping is used: the last byte of the IPv6 address is set to the host byte. Note that IPv6 subnet mappings are unfortunately less useful, since the chaosnet bridge doesn't support IPv6 broadcast yet.
