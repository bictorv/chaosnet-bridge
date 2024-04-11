# Firewall for Chaosnet

A simple firewall is implemented, where you can define how to handle RFC and BRD packets.

It can be used e.g. to restrict access to services running on your cbridge using [the NCP interface](NCP.md), or if your cbridge is in a "gateway position", to filter packets passing through it (i.e. not necessarily with the cbridge as destination).

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
|`broadcast`| matches the broadcast address (0). Only makes sense as a "to" address, and only applies to BRD packets.|

The *action* can be
| action | description |
| --- | --- |
|`allow`| Allow the packet to be processed. This is the default.|
|`drop`|Drop the packet without further processing.|
|`reject` [*reason*]| Responds to the sender with a `CLS` packet with the optional *reason* (a double-quoted string) as data (default: "Connection rejected by firewall").|
|`forward` *dest* [*contact*]| Responds to the sender with a `FWD` packet, where *dest* is the octal address to refer to, and *contact* is the (optional) new contact name. (Default: the original contact name used.) **Note** that supplying a new contact name is not yet handled by cbridge (that's a bug). |

### Note:
  - Explicit responses (`CLS` and `FWD`) are not sent for `BRD` attempts, since it would be pointless.
  - Responses are sent using the destination addr and index as the source, so "on behalf of" the destination even though it might not be the cbridge itself.
  - The rules are processed in the order given, until a match is found. (*Explain efficiency*)

Broadcast (BRD) packets are delivered to all hosts (on the subnets in the BRD mask, see [MIT AIM 628 Section 4.5](https://chaosnet.net/amber.html#Broadcast)), and could therefore be considered to match (basically) all `to` specifications in firewall rules. This would, however, make it difficult to be precise in filtering them: the `to` specification wouldn't matter. So in the general case of forwarding packets, BRD packets only match rules with `to broadcast` and `to any` specifications, exceptwhile for packets to `myself`, BRD packets are considered to match `myself` specifications. (Similar handling should be done in other "endpoint delivery" cases.)

**Give an example, perhaps a table, to make this more understandable?**


## Examples

In `cbridge.conf`, specify

`firewall enabled on debug off log on rules cbridge-rules.conf`

and then in `cbridge-rules.conf`, use

	; Allow access to the remote tape servers from my local subnet
	"RTAPE" from subnet 7 allow
	; Reject all other connection attempts
	"RTAPE" to subnet 7 reject
	; Allow friendly ITSes to use MLDEV on my ITS
	"MLDEV" from host 5460,3443,3150 to host 3405 allow
	; Reject others
	"MLDEV" to host 3405 reject "Who are you?"
	; Subnet 47 is full of evil hackers - drop their connection attempts!
	all from subnet 47 drop
