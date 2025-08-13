# Configuration

See also the [example configurations](EXAMPLES.md), and the separate configuration docs for [the NCP](NCP.md).

## Command line options:

| Option | Description |
| --- | --- |
| -d  | turns on debug (lots of it) |
| -v  | turns on verbose (less detail) |
| -s | print stats every 15 seconds, including routing tables, link states, ARP tables...|
| -t  | turns on TLS debug (lots). Same effect as enabling the `debug` option to `tls`, see below. |
| -c *cf* | reads config from file *cf*, default cbridge.conf |

## Configuration file syntax

`;` or `#` at the **start** of a line begins a comment. Below, *%o* stands for "an octal number", typically 16-bit.

It is strongly suggested to begin with Global settings, followed by Link definitions, followed by Route definitions.

### Global settings

Use max one of each of these. Collect all arguments on one command, rather than repeating the command with different options.

Below, *%o* means an octal number, and square brackets [ ] are around optional parameters.

- `chaddr` *%o*

    set my default chaos address - but it might be better to use explicit `myaddr` parameters for each link (except for CHUDP servers, below, which use the `chaddr` parameter, oddly)
- `myname` *name*

	set my Chaosnet host name, max 32 bytes, for STATUS. If DNS is supported, the main/first/default chaos address (e.g. the `chaddr` parameter) is looked up and used for *name* (up to the first period), if available, otherwise defaults to "real" local host name up to first period, prettified a little.
- `chudp` *portnr* [`dynamic` \| `static` \| `ipv6` \| `debug` off/on ]

	set my chudp portnr (default 42042). If `dynamic`, add new chudp links [dynamically](#dynamic-links-and-routes) when receiving pkts from unknown sources. With ipv6 option, listens to both v4 and v6 (enabled also by defining a chudp link where the host has an ipv6 addr). With debug on, prints some debug stuff. 
- `tls` [ `key` *keyfile* ] [ `cert` *certfile* ] [ `ca-chain` *ca-chain-cert-file* ] [ `myaddrs` *list* ] [ `server` *portnr* ] [ `debug` off/on ] [ `expirywarn `*days* ] [ `crl` *crlfile* ] [ `accept_timeout` *%d* ]

	set up for TLS using the private key in *keyfile*, the cert in *certfile*, and the CA trust chain in *ca-chain-cert-file*. If `server` is specified, a TLS server is started listening to *portnr* (default 42042, if at EOL). This requires a server certificate. TLS servers are always "dynamic" in that they listen to connections from anywhere, but accept only those using certificates trusted by the CA trust chain. Server-end connections are added dynamically at runtime, and can not be pre-declared. 

	The `myaddrs` *list* parameter (octal, comma-separated, no space around the commas) specifies which local addresses are to be used by the server. Connections are accepted only from clients on subnets matching those addresses.

	With debug on, prints some debug stuff.  `expirywarn` defaults to 90, the number of days before certificate expiry to start whining about it.
	
	The `crl` parameter specifies a Certificate Revocation List file, supplied by the CA you use. This is encouraged, in particular if you are running a TLS server. You will need to update it regularly (a warning is printed about this). See the [TLS documentation](TLS.md#certificate-revocation-list-crl) for more info.
	
	The `accept_timeout` setting specifies the number of seconds to wait for an incoming TCP connection to complete an initial SSL negotiation (by means of `SSL_accept`). The timeout value should be small but not too small (default 5). This setting is only meaningful when setting up a TLS server. The timeout stops robots that connect to the server port from using up valuable resources in cbridge.
- `ether` [ `debug` off/on ]

	With debug on, prints some debug stuff. (Note that interface names are now on link definitions.) 
- `chip` [ `dynamic` off/on \| `debug` off/on ]

	Allow [dynamically](#dynamic-links-and-routes) added destinations (cf `chudp` above). With debug on, prints some debug stuff. 
- `unix` [ `debug` off/on ]

	With debug on, prints some debug stuff.
- `dns` [ `servers` dns.chaosnet.net ] [ `addrdomain` CH-ADDR.NET ] [ `forwarder` off/on ] [ `trace` off/on ]

	set the DNS IP servers (which should handle CH records, default above; comma-separated list without whitespace around commas), the domain of "local" CH class addresses (default above, no ending dot), enable/disable forwarding of pkts received on the "DNS" contact name (default off), and enable trace printouts (default off). DNS is used internally by the TLS server/client to look up the certificate CN (of server and client) as Chaos hosts, looking for their addresses, and also by the [NCP](NCP.md) to look up addresses.
	
	For redundancy, more than one DNS server should be listed. A useful set of servers are the nameservers of the root CH domain, currently `dns.chaosnet.net,ns1.dfupdate.se,ns2.dfupdate.se`, which you can find e.g. by `host -c ch -t ns . dns.chaosnet.net` (note the separate period meaning "root").

- `private` [ `subnet` *list* ] [ `hosts` *hostsfile* ]

	Provide a list of private, non-routed subnets, where *list* is a list of comma-separated octal subnets, and *hostsfile* an optional hosts file defining hostname-address mapping for private subnets (including the standard private subnet 376).  The hosts file format is similar to a standard `/etc/hosts` file: lines beginning with `#` are ignored, other lines start with an octal address followed by whitespace and a list of whitespace-separated host names.

- `firewall ` [ `enabled` no/yes ] [ `debug` off/on ] [ `log` off/on ] [ `rules` *filename* ]

	Configures the firewall - see [FIREWALL](FIREWALL.md) for more info.

### LINKDEF:
You can define links of two types: for whole subnets, and for individual hosts. Here, *LINKTYPE* is one of several possible link types, see [below](#linktype).

- `link` *LINKTYPE* `subnet` *%o* *ROUTEARGS*

    configures a subnet (one octal byte) 
- `link` *LINKTYPE* `host` *%o* *ROUTEARGS*

	configures an individual host (octal 16-bit address). 
	For TLS links, the address can be the string `unknown` (but only if cbridge is configured to use DNS). 
	In this case, the address is discovered dynamically from the DNS addresses of the server CN, which is found in its TLS certificate. 
	This is mainly useful when the server might occasionally change addresses, like the central hub for [the Global Chaosnet](https://chaosnet.net/global).
	For `unknown` to work, the server must have an address on a subnet which matches the `myaddr` link parameter (or the `chaddr` global parameter).

### ROUTEDEF:

You can define routes, separately from links. This is very rarely needed. All route defs should be **after** all link defs.

- `route host` *%o1* `bridge` *%o2* *ROUTEARGS*

    configures a route to host *%o1* through the host *%o2* (there had better be a way to reach *%o2* , though a route or link) 
- `route subnet` *%o1* `bridge` *%o2* *ROUTEARGS*

	configures a route to subnet *%o1* through the host *%o2* 

### ROUTEARGS (optional):

Link and route defs take optional arguments. 

- `myaddr` *%o*

    defines the address of this bridge on this link (e.g. its address on that subnet). Not useful for route defs, but very often **necessary** for link defs to subnets other than the one used in `chaddr` (above).
- `cost` *c*

	sets the cost of the route: `direct`, `ether`, `asynch`. (Should support actual numbers too?)

- `mux` *%o-list*

    For TLS links *only*, an additional parameter `mux` can be used to multiplex more hosts (e.g. a KLH10) over a single TLS connection, without requiring a separate subnet to be allocated. See [an example config](EXAMPLES.md). The argument *%o-list* is a comma-separated list of octal Chaosnet addresses (note: no spaces allowed, only commas). A maximum limit for the number of multiplexed addresses exists (currently 16, see `CHTLS_MAXMUX`).
    **NOTE** that the "muxed" addresses *must* be on the same subnet as the TLS link, and *each* must be directly reachable through (individual) links, defined *before* the TLS link. *Note*: If the link to the muxed address is a `subnet` link (rather than a `host` link), routing might break.

- `link` *LINKTYPE*

  Sets the link type of the route. This is useful when the bridge of the route might not always be connected/available.
  If unspecified, the link type is taken from the currently available link to the bridge, or is left as "no link", making it useless.

### LINKTYPE:

For links, you need to specify what link layer implementation is used for it.

- `ether` *ifname*

    this is a Chaos-over-Ethernet link using the interface *ifname*. Default cost: `direct`. 
- `unix`

	this is a Chaos-over-unix-sockets link. Default cost: `direct`. 
- `chudp` *host*:*port* (or *host*|*port*)

	this is a Chaos-over-UDP link to *host* (IPv4, IPv6, or hostname) on *port* (default 42042). Default cost: `asynch`. 
	The *host*:*port* syntax is invalid for numeric IPv6 *host* parts - use *host*|*port* if you want to specify a port.
- `tls` *host*:*port* (or *host*|*port*)

	this is a Chaos-over-TLS link, client end, connecting to *host* (IPv4, IPv6, or hostname) at *port* (default 42042). Default cost: `asynch`. 
	The *host*:*port* syntax is invalid for numeric IPv6 *host* parts - use *host*|*port* if you want to specify a port.
- `chip` *addr*

	this is a Chaos-over-IP link to *addr* (IPv4, IPv6, or hostname). See below about subnet links. Default cost: `asynch`. 

Note that while links implicitly define a (static) route to the subnet/host,
you can only have a CHUDP link to a host, not directly to a subnet;
you may need an additional route definition for the subnet.
(See the MX-11 [example config](EXAMPLES.md#example-mx-11).)

Some link types can only be to hosts (CHUDP, TLS client) and some can only be to subnets (Ether).

#### Chaos-over-IP for subnets

Note that when configuring a CHIP subnet link, you should use an
explicit IP/IPv6 address (not a host name), and the last octet should
be zero (0). For subnets, the host byte of the Chaos address is copied
to the last octet of the configured IP/IPv6 address. 
See [an example config](EXAMPLES.md#example-chaos-over-ip).

For IPv4, the Chaosnet address host byte can not be 0xFF (which is
otherwise OK for Chaosnet), since that would map to the IP subnet
broadcast address.

(IPv6-mapped subnets will not receive routing info until broadcast/multicast for IPv6 is implemented.)
(The name `chip` coincides with a parameter to the `chudp` implementation in klh10, which is a tiny bit unfortunate.)

## Dynamic links and routes

A `link` definition is automatically created when a chudp (or chip)
pkt arrives from a new source and chudp (or chip) have been configured
with the `dynamic` option.

A dynamic `route` definition is automatically created when a Chaosnet
routing (RUT) pkt is received, describing a new or better route to a
subnet. 

Dynamic routes are also defined automatically by incoming TLS
connections (to the server) and when using `dynamic` chudp/chip,
unless there is an existing static route.

## Using a TLS "hub" network

Until August 2025, the Global Chaosnet used a central hub for subnet 6 which is a TLS server, and clients with a proper certificate can connect to it, adding connectivity to their local subnets.
The use of a central hub made the network structure contradictory to the Chaosnet principle of "[no central control](https://chaosnet.net/amber.html#Introduction)", and sensitive to crashes or errors at the central hub.

For increased redundancy, the dependence on a central hub can be removed. Two (or more) TLS servers for a subnet can cooperate, all of them accepting clients. If a packet arrives at one of them, but the server does not have a direct TLS link to the destination, it can send it to another of the subnet servers. The next server might have a direct link to the destination, or pass the packet along to another server. If none have a direct link to the destination, the [forwarding count](https://chaosnet.net/amber.html#Routing) for the packet will eventually reach its maximum and the packet is dropped.

### Client configuration
**Normal (non-server) TLS clients** connecting to any of the servers will dynamically/automatically configure their routes (so no manual `route` config is needed).

If the host name used in a `link tls` configuration has more than one IPv4/IPv6 address, they will be tried in a round-robin manner when connecting. This e.g. means that if/when `router.chaosnet.net` has the addresses of all the subnet servers for net 6, a client needs only use

    link tls router.chaosnet.net host unknown myaddr NNNN

(where *NNNN* is the client's Chaosnet address) and will be connected to the first of the subnet servers that is available (in case they are not all available).

### Server configuration (hub servers)

For servers with **only incoming** TLS links for the particular subnet, and have "secondary" servers for the subnet (see "Other servers" below), the route to the "next" subnet server needs to be configured manually using e.g.

    route subnet 6 bridge NNNN link tls

(where *NNNN* is the Chaosnet address of the "next" subnet server). Note that `link tls` is necessary for the route to be used also before/when the TLS link to *NNNN* is not up (yet). Note also that if the server is the only TLS server for a subnet, no such manual `route` configuration is necessary or desired.

**Other servers**, with active/client TLS links to its "next" server, e.g. with

    link tls next.chaosnet.net host MMMM myaddr NNNN

will dynamically/automatically configure their routes when (a) the TLS connection is up, and (b) the other server sends routing info about the net.

### If you find this confusing
Please let me know so I can explain better! :-)
