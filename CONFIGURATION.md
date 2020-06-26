# Configuration

See also the [example configurations](EXAMPLES.md).

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

Below, *%o%* means an octal number, and square brackets [ ] are around optional parameters.

- `chaddr` *%o*

    set my default chaos address - must be set 
- `myname` *name*

	set my Chaosnet host name, max 32 bytes, for STATUS. Defaults to "real" host name up to first period, first based on Chaosnet DNS name for `chaddr`, then on local host name. 
- `chudp` *portnr* [`dynamic` \| `static` \| `ipv6` \| `debug` off/on ]

	set my chudp portnr (default 42042). If `dynamic`, add new chudp links [dynamically](#dynamic-links-and-routes) when receiving pkts from unknown sources. With ipv6 option, listens to both v4 and v6 (enabled also by defining a chudp link where the host has an ipv6 addr). With debug on, prints some debug stuff. 
- `tls` [ `key` *keyfile* ] [ `cert` *certfile* ] [ `ca-chain` *ca-chain-cert-file* ] [ `myaddr` *%o* ] [ `server` *portnr* ] [ `debug` off/on ]

	set up for TLS using the private key in *keyfile*, the cert in *certfile*, and the CA trust chain in *ca-chain-cert-file*. If `server` is specified, a TLS server is started listening to *portnr* (default 42042, if at EOL). TLS servers are always "dynamic" in that they listen to connections from anywhere, but accept only those using certificates trusted by the CA trust chain. Server-end connections are added dynamically at runtime, and can not be pre-declared. The local address is set to the `myaddr` parameter, or the global `chaddr`. With debug on, prints some debug stuff. 
- `ether` [ `debug` off/on ]

	With debug on, prints some debug stuff. (Note that interface names are now on link definitions.) |
- `chip` [ `dynamic` off/on \| `debug` off/on ]

	Allow [dynamically](#dynamic-links-and-routes) added destinations (cf `chudp` above). With debug on, prints some debug stuff. 
- `dns` [ `server` 130.238.19.25 ] [ `addrdomain` CH-ADDR.NET ] [ `forwarder` off/on ] [ `trace` off/on ]

	set the DNS IP server (which should handle CH records, default above), the domain of "local" CH class addresses (default above, no ending dot), enable/disable forwarding of pkts received on the "DNS" contact name (default off), and enable trace printouts (default off). DNS is used internally by the TLS server/client to look up the certificate CN (of server and client) as Chaos hosts, looking for their addresses. 

### LINKDEF:
You can define links of two types: for whole subnets, and for individual hosts.

- `link` *LINKTYPE* `subnet` *%o* *ROUTEARGS*

    configures a subnet (one octal byte) 
- `link` *LINKTYPE* `host` *%o* *ROUTEARGS*

	configures an individual host (octal 16-bit address)

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

### LINKTYPE:

For links, you need to specify what link layer implementation is used for it.

- `ether` *ifname*

    this is a Chaos-over-Ethernet link using the interface *ifname*. Default cost: `direct`. 
- `unix`

	this is a Chaos-over-unix-sockets link. Default cost: `direct`. 
- `chudp` *host:port*

	this is a Chaos-over-UDP link to *host* (IPv4, IPv6, or hostname) on *port* (default 42042). Default cost: `asynch`. 
- `tls` *host:port*

	this is a Chaos-over-TLS link, client end, connecting to *host* (IP or name) at *port* (default 42042). Default cost: `asynch`. 
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

(IPv6-mapped subnets will not receive routing info until broadcast for IPv6 is implemented.)
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
