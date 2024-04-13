# Firewall for Chaosnet

A simple firewall is implemented in cbridge, where you can define how to handle connection requests (RFC and BRD packets).

It can be used e.g. to restrict access to services running on your cbridge using [the NCP interface](NCP.md), or if your cbridge is in a "gateway position", to filter packets passing through it (i.e. not necessarily with the cbridge as final destination).

## Motivation

The Chaosnet application protocols were mostly developed in a time when network users were all trustworthy, and since Chaosnet was a local area network it was easier to keep track of who had access. There was probably a bit of social control, [hacker ethics](https://en.wikipedia.org/wiki/Hacker_ethic) etc, in play.

With the [Global Chaosnet](https://chaosnet.net) this doesn't necessarily hold anymore, but retrofitting access control in many ancient programs would be a daunting task.

## Use cases

The firewall could be useful e.g. if
  - you run local `FILE` or `RTAPE` servers but don't want to give the whole Chaosnet read&write access to their contents
  - you run Lisp Machines on your network, which e.g may have servers for `EVAL`, `BAND-TRANSFER`, `REMOTE-DISK` etc which you want to protect
  - you run a `TCP` [gateway server](https://github.com/Chaosnet/chaosnet-tools) but want to avoid opening up the Chaosnet to *Evil Automated Internet Hackers*
  - you at the same time have servers for less sensitive protocols such as `NAME`, `SUPDUP`, `TELNET`, `TIME`, `UPTIME` etc, which you want to keep open and public

(See the [Computer History Wiki](https://gunkies.org/wiki/List_of_Chaos_application_protocols) or the [Chaosnet wiki](https://chaosnet.net/protocol#application_layer) for descriptions of the application protocols.)

## Configuration

`firewall ` [ `enabled` no/yes ] [ `debug` off/on ] [ `log` off/on ] [ `rules` *filename* ]

| setting | description |
| --- | --- |
|`enabled`| used to enable/disable the firewall - default is `no` (disabled).|
|`debug`| if on, writes about each packet processed and maybe more.|
|`log` | if on, writes the verdict of packets handled (but not those not matched by some rule).|
|`rules` | specifies a file containing the firewall rules (see below for description).|

## Firewall rules

The syntax for firewall rules is the following:

<*contact*|`all`> [`from` *addrspec* (default `any`)] [`to` *addrspec* (default `myself`)] *action*

where *contact* is a contact name in doublequotes, e.g. `"FILE"`, and `all` matches all contact names.
*addrspec* can be any of the below, where the address/subnet lists are lists of octal numbers separated by commas (but no space around the commas).

| *addrspec* | description |
| --- | --- |
|`any` | matches any address (including broadcast)  |
|`host` *addrlist* | matches those addresses in the list |
|`subnet` *subnetlist* | matches addresses on those subnets in the list |
|`myself`| matches any of the cbridge's own addresses (cf. `myaddr` in [the configuration documentation](CONFIGURATION.md). Use this rather than listing them explicitly in a `host` spec. |
|`localnet` | matches any of the subnets of the cbridge's own addresses **EXCEPT** subnet 6, which is the "hub network" of the Global Chaosnet, thus never local. |
|`broadcast`| matches the broadcast address (0). Only makes sense as a "to" address, and only applies to BRD packets.|

The *action* can be
| action | description |
| --- | --- |
|`allow`| Allow the packet to be processed. This is the default.|
|`drop`|Drop the packet without further processing.|
|`reject` [*reason*]| Responds to the sender with a `CLS` packet with the optional *reason* (a double-quoted string) as data (default: "Connection rejected by firewall"). Note that there is no way of escaping " in the string. |
|`forward` *dest* [*contact*]| Responds to the sender with a `FWD` packet, where *dest* is the octal address to refer to, and *contact* is the (optional) new contact name. (Default: the original contact name used.) |

### Note:
  - Explicit responses (`CLS` and `FWD`) are not sent for `BRD` attempts, since it would be pointless.
  - Responses are sent using the destination addr and index as the source, so "on behalf of" the destination even though it might not be the cbridge itself.
  - The rules are processed in the order given, until a match is found.

#### Broadcast matching

Broadcast (BRD) packets are delivered to all hosts (on the subnets in the BRD mask, see [MIT AIM 628 Section 4.5](https://chaosnet.net/amber.html#Broadcast)), and could therefore be considered to match (basically) all `to` specifications in firewall rules. This would, however, make it difficult to be precise in filtering them: the `to` specification wouldn't matter. So in the general case of cbridge forwarding packets, BRD packets only match rules with `to broadcast` and `to any` specifications, except for packets which are delivered to cbridge itself. For those,  BRD packets are considered to match `myself` specifications.

On the other hand, most of the protocols which are useful with BRD are so-called "simple" protocols, which are mostly harmless.

**Give an example, perhaps a table, to make this more understandable?**

#### Optimization
To optimize processing a little, rules are collected by contact name, so 

    "RTAPE" from subnet 7 allow
	"RTAPE" to subnet 7 to any reject
	"EVAL" from subnet 7,11 to any allow
	"EVAL" to subnet 7 reject "Please don't disturb"
	
is parsed into something like

| contact | address rules |
| --- | --- |
| "RTAPE" | |
|| from subnet 7 *to myself* allow |
|| *from any* to subnet 7 reject *"Connection rejected by firewall"*|
| "EVAL" ||
|| from subnet 7,11 to any allow |
|| *from any* to subnet 7 reject "Please don't disturb"

(where the italics are defaults spelled out). So the contact name in an incoming packet need only be matched once against the ruleset. This also means that as soon as the address rules for a contact name run out without matches, no more processing is needed since the contact name can't match another rule. That is, *unless* you also have a firewall rule for the `all` contact name token, which means processing will need to go on in case another rule matches. So if speed is important, try to avoid `all`. [Yes, there is a way to keep that equally efficient by injecting the address rule for `all` in all contact name address rules, but preserving the order and handling explicit contacts appearing after `all` seems a bit of a hassle. Maybe one day.]

(This also means the ruleset example above is equivalent and parsed to the same structure as the following reordering:)

    "RTAPE" from subnet 7 to myself allow
	"EVAL" from subnet 7,11 to any allow
	"RTAPE" from any to subnet 7 reject
	"EVAL" to subnet 7 reject "Please don't disturb"

## Examples

In `cbridge.conf`, specify

`firewall enabled yes debug off log on rules cbridge-rules.conf`

and then in `cbridge-rules.conf`, use

	; Allow access to the remote tape server from my local subnet
	"RTAPE" from localnet allow
	; Reject all other connection attempts
	"RTAPE" to localnet reject
	; For the EVAL servers on my LISPMs, allow local but also AMS and EJS subnets
	"EVAL" from localnet to any allow
	"EVAL" from subnet 11,13 to any allow
	"EVAL" to localnet reject
	; Allow friendly ITSes to use MLDEV on my ITS
	"MLDEV" from host 5460,3443,3150 to host 3405 allow
	; Reject others
	"MLDEV" to host 3405 reject "Who are you?"
	; Subnet 47 is full of evil hackers - drop their connection attempts!
	all from subnet 47 drop

## Discussion

  - Is the default `to myself` useful, or should it be `to any`?
  - `"NOTIFY" to myself drop` is now protected against broadcasts to `NOTIFY`, but to protect other destinations you need to use `to broadcast` which would filter *all* other destinations. How bad is this?
  - In "modern systems", firewalls are/can often be configured per network interface, but not here. How desirable would that be?
