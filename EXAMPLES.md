# Examples

Some examples of configurations.

## Example: klh10

A slightly complex, but general, example. See the next example for a simpler setup with a single klh10.

The example assumes you run an ITS system (e.g. on klh10), and a local Chaosnet network over Ethernet, and you use subnet 14 (octal). 
In this example, you connect to the Global Chaosnet over chudp, and you have been assigned address 3171 for connecting to it (cf Routing Basics).

    ; My default Chaosnet address
    chaddr 6001
    ; Define a chaos-over-udp link to the Global Chaosnet router, which has address 3040
    link chudp router.chaosnet.net host 3040 myaddr 3171
    ; Define a local Chaos-over-Ether on the eth0 interface, for subnet nr 14 (hosts 6001-6376)
    link ether eth0 subnet 14
    ; A chaos-over-udp link to the ITS configured below
    link chudp localhost:42043 host 6002

For a ITS/klh10 running on the same host as cbridge, you can use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=6002 chudpport=42043 chip=6001/localhost:42042

If you let ITS/klh10 use Chaos-over-Ethernet, you do not need the last
"link chudp" line in the cbridge config, and in klh10.ini you can use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=6002 ifmeth=pcap

The ITS will pick up routing info from cbridge. (Of course you also
need to configure ITS to use address 6002, see [here](https://github.com/PDP-10/klh10/blob/master/run/ksits/pubits/doc/distrib.its) for instructions.)

If you only run the ITS system, over chudp, and do not use Chaosnet over Ethernet for other purposes, just skip the `link ether` line.

## Example: A single klh10 behind a TLS-connected cbridge

If you run a single klh10 but want to connect to the global Chaosnet using TLS, you can get away without allocating a whole subnet for your local hosts, by using the `mux` parameter. In this example, the local klh10 has been given address 3172, and the cbridge has been given address 3171 on subnet 6.

For a ITS/klh10 running on the same host as cbridge, you can (similar to the above example) use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=3172 chudpport=42043 chip=3171/localhost:42042

For cbridge, you can use the following:

    ; FIRST define the link to my KLH10
    link chudp localhost:42043 host 3172 myaddr 3171
    ; THEN define the link to the central, with the mux parameter
    link tls router.chaosnet.net host 3040 myaddr 3171 mux 3072

(The "mux" setup works not only for a single klh10, but also up to four local hosts.)

## Example: linux/macOS

If you just want to connect your linux or macOS system to the global Chaosnet, something like this cwould work. 

First, [create a certificate request](TLS.md) and get a certificate back. Then, assuming the address you got was 3077, use the following configuration.

	; My Chaosnet address
	chaddr 3077
	; Enable the NCP, so you can connect using linux/macOS programs
	ncp enabled yes
	; Configure my TLS key and cert (see TLS.md)
	tls key private/my.key.pem cert certs/my.cert.pem
	; Define a TLS link to the main router over IPv6
	link tls router.chaosnet.net host 3040 myaddr 3077

This should enable you to use e.g. [supdup](https://github.com/PDP-10/supdup) to connect to ITS systems,  [hostat](hostat.c) to check the status of systems, or [finger](finger.py) to check who is logged in.

## Example: MX-11

A different example is the config for MX-11 (aka router.chaosnet.net).

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
    tls key private/router.chaosnet.net.key.pem cert certs/router.chaosnet.net.cert.pem ca-chain ca-chain.cert.pem ipv6 server

The config for the CHUDP hosts consists of lines

    link chudp hostN host addrN

where `hostN` is the host name or IP of a host, and `addrN` is its
Chaosnet addess. 

Additionally, MX-11 connects to the local ethernet (where an old
Symbolics lisp machine might be running). NOTE the declaration of
"myaddr" for net 1 below, which means that packets cbridge sends on this net
are sent from address 440. A router/bridge should always have (and
use) an address specific to each net.

    link ether eth0 subnet 1 myaddr 440

To tell cbridge to send routing info about net 6, which only has
individual host links, a route declaration is necessary.

    route subnet 6 bridge 3040 cost asynch

## Example: Chaos-over-IP

To set up an individual link to another host (a chaosnet bridge, or perhaps a PDP-10/X) using Chaos-over-IP, use

    link chip host.name.com host NNNN

where `host.name.com` is the host name, and `NNNN` is its Chaosnet address. If the host is on a different subnet, add your address on that subnet using the `myaddr` parameter (see [configuration](CONFIGURATION.md)). A specific example, assuming you have an address on Chaos subnet 6:

    link chip router.chaosnet.net host 3040

To set up a whole Chaosnet subnet mapped to an IP subnet, use

    link chip a.b.c.0 subnet NN

where `a.b.c.0` is the IP address of the IP subnet, with the last octet being zero, and `NN` is the (octal) subnet. If this is not your default subnet, i.e. your `chaddr` setting is not on that subnet, add your address on subnet `NN` using the `myaddr` parameter.

The effect is that any Chaosnet packets sent to an address on subnet NN is forwarded to the corresponding IP address on net `a.b.c.0`. For example, suppose you map Chaos subnet 2 to the IP net 10.11.12.0. 

    link chip 10.11.12.0 subnet 2

Addresses on Chaos subnet 2 range from 1001 to 1377 octal. The address 1066 has host byte 66 (octal) = 54 (decimal), and is mapped to 10.11.12.54. Note that address 1377, which has host byte 255, can not be mapped to the IPv4 address 10.11.12.255, since that is the broadcast address on net 10.11.12.0.

For IPv6 addresses, the same mapping is used: the last byte of the IPv6 address is set to the host byte. Note that IPv6 subnet mappings are unfortunately less useful, since the chaosnet bridge doesn't support IPv6 broadcast yet.
