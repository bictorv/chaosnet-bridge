# Firewall for Chaosnet

A simple firewall is implemented, where you can define how to handle RFC and BRD packets.

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

| thing | description |
| --- | --- |
|*contact* | a contact name in doublequotes, e.g. `"FILE"` |
|`all`| matches all contact names. |
|*addrspec*| can be `any`, `host` *addrlist*, `subnet` *subnetlist*, or `myself`. The address/subnet lists are lists of octal numbers separated by commas but no space around the commas. `myself` matches any of the cbridge's own addresses (cf. `myaddr` in [the configuration documentation](CONFIGURATION.md).|

The *action* can be
| action | description |
| --- | --- |
|`allow`| Allow the packet to be processed. This is the default.|
|`drop`|Drop the packet without further processing.|
|`reject` [*reason*]| Responds to the sender with a `CLS` packet with the optional *reason* (a double-quoted string) as data (default: "Connection rejected by firewall").|
|`forward` *dest* [*contact*]| Responds to the sender with a `FWD` packet, where *dest* | is the octal address to refer to, and *contact* is the (optional) new contact name. (Default: the original contact name used.)|

### Note:
  - Explicit responses (`CLS` and `FWD`) are not sent for `BRD` attempts, since it would be against the spec.
  - Responses are sent using the destination addr and index as the source, so "on behalf of" the destination even though it might not be the cbridge itself.
  - The rules are processed in the order given, until a match is found.

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
