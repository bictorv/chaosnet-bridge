# Examples

Some examples of configurations.

## Example: klh10

A slightly complex, but general, example. See the next example for a simpler setup with a single klh10.

The example assumes you run an ITS system (e.g. on klh10), and a local Chaosnet network over Ethernet, and you use subnet 14 (octal). 
In this example, you connect to the Global Chaosnet [over TLS](TLS.md), and you have been assigned address 3171 for connecting to it (cf Routing Basics).

    ; My default Chaosnet address
    chaddr 6001
	; Configure my TLS key and cert (see TLS.md)
	tls key private/my.key.pem cert certs/my.cert.pem
    ; Define a Chaos-over-TLS link to the Global Chaosnet router. Its address might occasionally change, so keep it unspecified.
    link tls router.chaosnet.net host unknown myaddr 3171
    ; Define a local Chaos-over-Ether on the eth0 interface, for subnet nr 14 (hosts 6001-6376)
    link ether eth0 subnet 14
    ; A chaos-over-udp link to the ITS configured below
    link chudp localhost:42043 host 6002

(If you don't use Ethernet, skip that line. If you run more than one klh10, repeat the last line with other ports/addresses.)

For a ITS/klh10 running on the same host as cbridge, you can use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=6002 chudpport=42043 chip=6001/localhost:42042

If you let ITS/klh10 use Chaos-over-Ethernet, you do not need the last
"link chudp" line in the cbridge config, and in klh10.ini you can use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=6002 ifmeth=pcap

The ITS will pick up routing info from cbridge. If you run a recent version of ITS from https://github.com/PDP-10/its, it will also use the address from the `myaddr` parameter automatically. You still need to make sure `SYSHST;H3TEXT` is up-to-date.
(If you run an older version of ITS, you need to configure it to use address 6002, see [here](https://github.com/PDP-10/klh10/blob/master/run/ksits/pubits/doc/distrib.its) for instructions.)

If you only run the ITS system, over chudp, and do not use Chaosnet over Ethernet for other purposes, just skip the `link ether` line.

(If you use a [simh](https://github.com/simh/simh)-based system, see its [KL10](https://github.com/simh/simh/blob/master/doc/kl10_doc.doc) or [KS10](https://github.com/simh/simh/blob/master/doc/ks10_doc.doc) documentation for how to set it up.)

## Example: A single klh10 behind a TLS-connected cbridge

If you run a single klh10 but want to connect to the global Chaosnet using TLS, you can get away without allocating a whole subnet for your local hosts, by using the `mux` parameter. In this example, the local klh10 has been given address 3172, and the cbridge has been given address 3171 on subnet 6.

For a ITS/klh10 running on the same host as cbridge, you can (similar to the above example) use

    devdef chaos ub3 ch11 addr=764140 br=6 vec=270 myaddr=3172 chudpport=42043 chip=3171/localhost:42042

For cbridge, you can use the following (after [getting yourself a cerificate](TLS.md)):

	; Configure my TLS key and cert (see TLS.md)
	tls key private/my.key.pem cert certs/my.cert.pem
    ; FIRST define the link to my KLH10
    link chudp localhost:42043 host 3172 myaddr 3171
    ; THEN define the link to the central, with the mux parameter
    link tls router.chaosnet.net host unknown myaddr 3171 mux 3072

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
	; Define a TLS link to the main router over IP
	link tls router.chaosnet.net host unknown myaddr 3077

This should enable you to use e.g. [supdup](https://github.com/PDP-10/supdup) to connect to ITS systems,  [hostat](hostat.c) to check the status of systems, or [finger](finger.py) to check who is logged in.


### On your local subnet
If you already have a cbridge running on some local server, e.g. to connect a bunch of emulators to the global Chaosnet, and want to connect your personal (e.g. laptop) linux/macOS over a local network, you can do without TLS and certificates.
You can instead use UDP or IP or Ethernet, e.g. like this (for the UDP case, assuming the local main cbridge has Chaos address 7701 and has hostname `local-main-cbridge`):

	; My Chaosnet address
	chaddr 7077
	; Enable the NCP, so you can connect using linux/macOS programs
	ncp enabled yes
    ; Listen to CHUDP on the standard port
    chudp 42042
	; Define a CHUDP link to the main local cbridge
	link chudp local-main-cbridge host 7701

On the local main cbridge, you need to add (assuming your personal laptop is named `laptop`):

     link chudp laptop host 7077

Also make sure the local main cbridge has enabled the chudp server (which is likely, if it was serving a bunch of emulators):

    chudp 42042

**Please note** that you should only use UDP or IP links for local non-routed networks (like 10.x.y.z, 192.168.x.y etc). (To avoid making you paranoid, I won't mention the [zero trust](https://en.wikipedia.org/wiki/Zero_trust_security_model) model. If I did, you'd need TLS and certificates.)

## Example: CADR/usim

To connect your [usim](https://tumbleweed.nu/r/usim/doc/trunk/README.md) emulator to cbridge, you need to do the following. These are not always full examples and not fully explained, so please note that you also need to read the documentation of usim and cbridge and quite possibly also [the Lisp Machine Manual](https://tumbleweed.nu/r/lm-3/uv/chinual.html).

If you are not connected to the Global Chaosnet, you should use addresses on the private non-routed network 376 (octal), i.e. addresses 177001-177377.

### hosts.text

You need a Chaosnet host table (in a file named e.g. `hosts.text`). An example file for a local network could be this.

	HOST LOCAL-BRIDGE,	CHAOS 177001,SERVER,UNIX,VAX,[BRIDGE]
	HOST LOCAL-CADR,	CHAOS 177041,USER,LISPM,LISPM,[CADR,LISPM]

You can of course change LOCAL-BRIDGE and LOCAL-CADR to something more personal. The last bracket contains aliases, which are typically shorter.

Such a file is used by both usim (the emulator) and the Lisp Machine system on the emulated CADR, where it lives in `SYS:SITE;HOSTS.TEXT`.

### In usim.ini

  - `hosts=hosts.text` where `hosts.text` is a Chaosnet host table which has entries for at least your usim/CADR machine and the cbridge (see above).
  - `myname=`*myname* where *myname* is your host name in the hosts file, such as `LOCAL-CADR`.
  - `backend=udp` (or `backend=hybrid`) to be able to connect to cbridge.
  - `bridgeip=`*ipaddr* where *ipaddr* is the IP address of your cbridge (e.g. 127.0.0.1 if you are running usim and cbridge on the same machine).
  - `bridgechaos=`*chaosaddr* where *chaosaddr* is the Chaosnet address of your cbridge, e.g. 177001.
  - `bridgeport=`*portnr* where *portnr* is the UDP port used on your cbridge. This is needed only if you use a port other than 42042, the default.
  - `bridgeport_local`=*portnr* where *portnr* is the UDP port to be used by usim. This is needed only if you need to use a port other than 42042, the default, e.g. if usim and cbridge are running on the same machine. A popular choice is 42043.
  
### In cbridge.conf

This example is for running a local network, with the usim on the same machine. If you are running usim on another machine, change the address 127.0.0.1 appropriately.

	; The name of your cbridge on Chaosnet
	myname MyGW
	; The chaosnet address of your cbridge
	chaddr 177001
	; Listen to Chaos-over-UDP on the standard port
	chudp 42042
	; Set up a firewall to protect the CADR
	firewall enabled yes log on rules cbridge-rules.conf
	; Set up the chaos-over-udp link to the CADR
	link chudp 127.0.0.1:42043 host 177041 myaddr 177001

For the firewall rules, I recommend something like this as a start. It protects the most sensitive servers from remote access outside your local network. I **strongly recommend** that you add the firewall setting even if you are only using a local network for now, since it's easy to forget if you at some point would join the Global Chaosnet. See [the firewall doc](FIREWALL.md) for more info.

	; Allow these protocols only on the local network.
	; Allow use of the EVAL server from local nets. This allows the remote end to do absolutely anything.
	"EVAL" from localnet allow
	; Protect the FILE server on your CADR (if you start one) so others can't change/delete your local files
	"FILE" from localnet allow
	; Protect the REMOTE-DISK and BAND-TRANSFER servers, so others can't change your disk
	"REMOTE-DISK" from localnet allow
	"BAND-TRANSFER" from localnet allow
	; Reject them from anyone else
	"EVAL" from any reject
	"FILE" from any reject
	"REMOTE-DISK" from any reject
	"BAND-TRANSFER" from any reject

## Example: MX-11

A different example is the (historical) config for MX-11 (aka router.chaosnet.net). (It has long been superseded by MX12, with a more complex config.)

The MX-11 served as a hub for a number of hosts connecting through
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

## Example: Chaos-over-IP

To set up an individual link to another host (a chaosnet bridge, or perhaps a PDP-10/X) using Chaos-over-IP, use

    link chip host.name.com host NNNN

where `host.name.com` is the host name, and `NNNN` is its Chaosnet address. If the host is on a different subnet, add your address on that subnet using the `myaddr` parameter (see [configuration](CONFIGURATION.md)). A specific example, assuming you have an address on Chaos subnet 6:

    link chip mx12.victor.se host 3040

To set up a whole Chaosnet subnet mapped to an IP subnet, use

    link chip a.b.c.0 subnet NN

where `a.b.c.0` is the IP address of the IP subnet, with the last octet being zero, and `NN` is the (octal) subnet. If this is not your default subnet, i.e. your `chaddr` setting is not on that subnet, add your address on subnet `NN` using the `myaddr` parameter.

The effect is that any Chaosnet packets sent to an address on subnet NN is forwarded to the corresponding IP address on net `a.b.c.0`. For example, suppose you map Chaos subnet 2 to the IP net 10.11.12.0. 

    link chip 10.11.12.0 subnet 2

Addresses on Chaos subnet 2 range from 1001 to 1377 octal. The address 1066 has host byte 66 (octal) = 54 (decimal), and is mapped to 10.11.12.54. Note that address 1377, which has host byte 255, can not be mapped to the IPv4 address 10.11.12.255, since that is the broadcast address on net 10.11.12.0.

For IPv6 addresses, the same mapping is used: the last byte of the IPv6 address is set to the host byte. Note that IPv6 subnet mappings are unfortunately less useful, since the chaosnet bridge doesn't support IPv6 broadcast yet.

## Example: PiDP-10 with extension

The [PiDP-10](https://github.com/obsolescence/pidp10/) system comes with a cbridge setup for an ITS system (under simh/pdp10), using the [private non-routed subnet](README.md#private-non-routed-subnet) for addresses. It looks something like this:

- The ITS system is at address 177002, using CHUDP on port 44042 to communicate with the cbridge at localhost:44041
- The cbridge is at address 177001, using CHUDP on port 44041 to communicate with the ITS system at localhost:44042

So both the ITS (emulator) and the cbridge run on the same system (a raspberry pi).

The typical cbridge.conf file on your PiDP-10 looks like this:

	chaddr 177001
	chudp 44041
	ncp enabled yes
	private hosts /opt/pidp10/bin/chaos-hosts
	link chudp localhost:44042 host 177002 myaddr 177001

Suppose you have another  system, like a desktop, you want to connect to the ITS system (for using `supdup`, `mlftp` or other fancy tools). 

The easiest way would be to configure a cbridge on your desktop with the following configuration:

    ; Desktop system Chaosnet address
    chaddr 177003
    ; Standard port for CHUDP
    chudp 42042
    ; Enable NCP so you can use the nice tools
    ncp enabled yes
    ; Use a copy of the same hosts file for local hosts
    private hosts chaos-hosts
    ; Here is the link to the PiDP cbridge
    link chudp pidp:44041 host 177001 myaddr 177003
    ; And here is an explicit route to the ITS system
    route host 177002 bridge 177001 myaddr 177003
	
Note that `pidp` is assumed to be the host name of your PiDP-10 system - update as appopriate. Note that the `route` line must be after all `link` lines.

You also need to add the following to the cbridge.conf on the PiDP-10, where `desktop` is assumed to be the host name of your desktop. (Nothing needs to be added for the ITS system/emulator):

	; Here is the link to the desktop cbridge
	link chudp desktop:42042 host 177003 myaddr 177001

And finally, you most likely want to add a line to your `chaos-hosts` file on both the PiDP-10 and your desktop:

    177003 desktop

(Many thanks to [Steven Falco](https://gitlab.com/stevenfalco/incompatible-timesharing-system-notes) for figuring out and testing the details!)
