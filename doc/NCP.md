# Network Control Program

The NCP implements the "transport layer" of Chaosnet, and lets a regular user program easily make use of the Chaosnet routing and infrastructure built by the rest of cbridge.

You can also use it to make your "unix-like" host a Chaosnet node, by using and adding applications connected to the Chaosnet, such as file transfer, interactive terminal sessions, etc.

For convenient Chaosnet DNS use on macOS 15.4 (and perhaps higher), install `libbind` (which needs `tbl` which comes with `groff`).

# Configuration

`ncp ` [ `enabled` no/yes ] [ `debug` off/on ] [ `trace` off/on ]  ...

| setting | description |
| --- | --- |
|`enabled`| used to enable/disable the NCP - default is `no` (disabled).|
|`domain`| used for specifying the default DNS domains for RFC arg parsing, as a comma-separated list. **NOTE** that there must be no spaces around the comma! Default (if none are specified) is `chaosnet.net`. Example: `domain update.uu.se,chaosnet.net`|
|`retrans`| specifies the retransmission time interval - default 500 ms.|
|`window`| specifies window size - default 13 packets (maximally 6344 bytes). Max window size is 128. (ITS uses only 5, and a max of 64, while CADR and Lambda Lisp machine systems use 013, and max 128. Symbolics uses a max of 50.)|
|`eofwait` | specifies time to wait for ACK of final EOF pkt when closing conn - default 3 `retrans` intervals, i.e. 1500.|
|`finishwait`| specifies the time to wait for a half-open conn (OPN Sent) to become Open (thus allowing final retransmissions) while finishing it. Default 5000 ms. (You probably don't want to mess with this.)|
|`follow_forward`| specifies whether FWD responses should be transparently followed, i.e., result in the RFC being resent to the target host. Default `no`, can also be specified as an option to individual RFCs (see below).|
|`socketdir`| specifies the directory where to put the socket files, `chaos_stream` and `chaos_packet` - default is `/tmp`.|
|`trace`| if on, writes a line when a connection is opened or closed.|
|`debug`| if on, writes a lot.|

# Usage

The NCP opens a named local ("unix") socket for letting user programs interact with Chaosnet.  To try it out, use `nc -U /tmp/chaos_stream`. There is also [a special verion of supdup.c](https://github.com/PDP-10/supdup) to try a "real" protocol,  [a simple demo program for connectionless protocols](hostat.c), and [a finger program](finger.c) (also [in python](../tools/finger.py)) to try a simple stream protocol, and [an example server program](../tools/named.py). Additionally there is also [a little demonstration program](../tools/bhostat.py) for the broadcast packet API (see below).

There is also [a simple client program for the FILE protocol](../tools/file.py), which can list directories, read and write files etc, to and from LISPM and ITS systems, and a server for the [DOMAIN](../tools/domain.py) contact name, which responds to DNS queries over a stream connection (cbridge already handles queries on a simple protocol, but response sizes are limited by the Chaosnet packet size.) A [Telnet](../tools/telnet.py) client is also available, and a [HOSTAB](../tools/hostabd.py) server.


Example:
```
$ nc -c -U /tmp/chaos_stream
RFC up.update.uu.se BYE
OPN Connection to host 03143 opened

I am not a number!
I am a free man!
```

Using `hostat`:
```
$ hostat up.update.uu.se
Hostat for host UP
Net 	In       Out      Abort    Lost     crcerr   ram      Badlen   Rejected
06 	1005504  316751   0        33373    0        0        2800     0
$ hostat up.update.uu.se time
2020-06-02 17:48:21
```

Using `finger`:
```
$ finger -w bv@up.update.uu.se
BV     @  Bjorn Victor           Last logout 06/02/20 21:50:32  No plan.
   [UP]

   Alias for VICTOR

```

## chaos_stream

This is a socket of type `SOCK_STREAM`.

This socket is for "stream protocols" (see [Section 4.1 in Chaosnet](https://chaosnet.net/amber.html#Connection-Establishment), where an RFC starts a stream connection with flow control - this is similar to TCP. It can also be used for Simple protocols (similar to UDP).

### Client opening

If the user program acts as a client, it opens the socket and writes

`RFC `[*options*] *host* *contactname* *args*

(followed by LF or CRLF), where
- [*options*] (including the square brackets!) is optional, and specifies (a comma-separated list of) options for the connection. 
- *host* is either the name or the (octal!) address of the host to be contacted,
- *contactname* is the contact name, such as `NAME`, `UPTIME`, `TIME` or `STATUS`, and
- *args* are optional arguments, such as a user name for `NAME`. The *args* are separated from *contactname* with a single space. (Note that the *args* are treated as a string and can not contain null or CR or LF. If you need such args, use [the packet interface](#chaos_packet), below.)

The NCP sends a corresponding RFC packet to the destination host.

#### Options:
Options are
- `timeout=`*%d* to specify a (positive, decimal) timeout value (in seconds) for the connection to open (i.e. a response to be received). The default is 30 seconds. In case of a timeout, a `LOS Connection timed out` response is given to the user program.
- `retrans=`*%d* to specify a (positive, decimal) retransmission value (in milliseconds) for this connection, see the configuration options above.
- `winsize=`*%d* to specify a (positive, decimal) local window size for this connection, see the configuration options above.
- `follow_forward`=*yes/no* to specify whether a FWD response packet should be transparently followed, i.e., result in the RFC being redirected to the target host.

#### Examples:
- `RFC time.chaosnet.net TIME`
    - basic example: returns an ANS with the (binary) current time (try `hostat time.chaosnet.net time` to get it legibly)
- `RFC up.update.uu.se NAME /W bv`
    - args example: gets "whois" info about bv@up
- `RFC [timeout=3] 3402 STATUS`
    - options example: tries to get the status of host 3402 (octal) but with a timeout of 3 seconds. Note the explicit square brackets.
- `rfc 3040 dump-routing-table`
    - it's all case-insensitive (contact names are made uppercase). (Try `hostat 3040 dump-routing-table` for legible output.)

#### Broadcast:

To send a controlled [broadcast packet](https://chaosnet.net/amber.html#Broadcast), write

`BRD `[*options*] *CSL* *contactname* *args*

where *options*, *contactname* and *args* are as above, and *CSL* is a comma-separated list of (octal) subnet numbers (no spaces around commas) to broadcast to. 

The *CSL* can also be `all` to broadcast on all (reachable) subnets, or `local` to broadcast only on the local subnet (as defined by the `chaddr` [global config](CONFIGURATION.md#global-settings) parameter). In these cases, no other subnet can be listed.

For a simple protocol, you can read multiple `ANS` responses.
When the timeout expires, a `LOS Connection timed out` response is given to the user program (as described above for `RFC`).

Example: `BRD [timeout=3] 6,7,11 STATUS` sends a STATUS broadcast (BRD) packet to subnets 6, 7 and 11, with a timeout of 3 seconds. Please read [the spec](https://chaosnet.net/amber.html#Broadcast) for how this works. There is also [a little demonstration program](../tools/bhostat.py) for the packet API (see below).

#### Responses

Any errors in parsing the RFC line (etc) result in a
`LOS `*reason*
line given to the user program, and the socket is closed.

When a response is received from the destination host, it is either an ANS, OPN or CLS packet. The NCP informs the user program by writing on its socket:

`ANS `*%o* *len*
*data*

where *%o* is the (octal) source address of the ANS packet, and *len* is the length of the following *data*.

`OPN Connection to host `*%o*` opened`

or

`CLS `*reason*

In the case of OPN, the NCP sets up a stream connection , handles flow control etc, and forwards data between the remote host and the user program. 

Writes from the user program are packaged into DAT packets which are sent to the remote host (when the window allows), and DAT packets from the remote host are written to the user program. No character translation is done in the NCP, so the client needs to handle e.g. translation between "ascii newline" (012) and "lispm newline" (0212).

When the user program closes the socket, the NCP sends an EOF, waits for it to be acked (see `eofwait` setting), and then sends a CLS to close the connection in a controlled way (not quite as in [Section 4.4 in Chaosnet](https://chaosnet.net/amber.html#End_002dof_002dData), see below).

When the NCP receives a CLS, the user socket is closed. When the NCP receives an EOF, it is immediately acked.

The NCP attempts to remove the user socket file after it is closed, to keep the place tidy.

### Server opening

If the user program acts as a server, it opens the socket and writes

`LSN `[*options*] *contactname*

where *options* (including the brackets) are optional, and are limited to `retrans=`*%d* and `winsize=`*%d*.
The NCP then notes that the user program is listening for connections to *contactname*, and when a matching RFC packet appears, it writes

`RFC `*rhost* *args*

to the user program, where *rhost* is the remote host (octal address), and *args* are the arguments given in the RFC packet, if any.

The user program is then supposed to handle the RFC and respond to it by either an OPN, ANS or CLS, as follows:

#### `OPN` (or `OPN `*whatever*)
causes the NCP to send an OPN packet to the remote host, and when it reponds with an STS packet, the connection is established as above.

#### `CLS `*reason*
where *reason* is a single line of text, which results in the NCP sending a corresponding CLS packet to the remote host, and the connection is then closed - including the user socket.

#### `ANS `*len*
*data*

where *len* is the length in bytes (max 488) of the following *data* (which may include any bytes). This results in the NCP sending an ANS packet to the remote host, with the supplied data, and then closing the socket.

#### `FWD `*addr* *newcontact*
where *addr* is an octal address and *newcontact* is the new contact to refer to, results in a FWD packet to the remote host, indicating it should instead send its RFC to that address and contact.

To handle new RFCs (while handling one, or after) your user program needs to open the `chaos_stream` socket again. See [an example server program](../tools/named.py).

## chaos_packet

This is also a socket of type `SOCK_STREAM`.

As above, but the NCP and the user program exchange packets rather than just a stream of data. The packets have a 4-byte header (no need for the full Chaosnet header at the transport layer).

Packets are sent and received with a 4-byte binary header:

| byte 0 | b 1 | b 2 | b 3|
| --- | --- | --- | --- |
| opcode | 0 | lenLSB | lenMSB |

followed by the *n* bytes of data of the packet, where *n* is the length indicated by the len bytes.  Data lengths can not be more than 488 bytes. Note that `LSN` packets can be used, where the data is the contact name to listen to. Note also that RFC and FWD packets have slightly different data from the actual Chaosnet packets (see below).

| Opcode | Data | Type |
| --- | --- | --- |
| RFC (sent) | [*options*] *rhost* *contact* *args* | text - the "[*options*]" and "*args*" parts are optional (but note the explicit brackets around the options). (Note that *args* can be any bytes, since the length is given in the header.) |
| RFC (rcvd) | *rhost* *args* | text - *rhost* is in octal digits, the *args* part is optional. (Note that *args* can be any bytes, since the length is given in the header.)|
| BRD (sent) | [*options*] *CSL* *contact* *args* | ascii. The *CSL* is a comma-separated list of subnet numbers (in octal, no spaces around commas) for which subnets to broadcast to (or `all` or `local`, cf above). As for RFC, the "[*options*]" and "*args*" parts are optional (but note the explicit brackets around the options) |
| BRD (rcvd) | - | is translated to an RFC (see above) |
| OPN (sent) | none | |
| OPN (rcvd) | *rhost* | ascii, an octal address |
| LSN |  [*options*] *contact* | ascii (only interpreted by NCP, not sent on Chaosnet). The "[*options*]" are optional and limited to `retrans` and `winsize`. |
| ANS (rcvd) | *src* *data* | *src* is the source address (two bytes: LSB, MSB), followed by *data* which is the original binary data (not interpreted by NCP) |
| ANS (sent) | *data* | binary data (not interpreted by NCP) |
| LOS, CLS | *reason* | ascii (but not interpreted by NCP) |
| UNC | *data* | binary, where the first 4 bytes are stored in the packetno and ackno fields of the header (each 2 bytes) |
| DAT, DWD | *data*  | binary (not interpreted by NCP) |
| EOF | none | or when sending, optionally the ascii string "wait" (four bytes) |
| FWD | *addr* *contact* | where *addr* is 2 bytes (LSB, MSB) of forwarding address immediately followed by the new contact name to refer to |
| ACK | none | received from NCP as response to "EOF wait", when th EOF is acked or an eofwait timeout happens |


Setting up the connection is similar to `chaos_stream`:
1. Set up: either
    - send `RFC` with data being [*options*] *rhost* *contact* *args* (as for the RFC for `chaos_stream`)
    - send `LSN` with data being *contact*
1. Response: either
    - receive `RFC` with data being *rhost* *args* (as for the RFC for `chaos_stream`)
        - as response to `LSN`
	- receive `ANS` with data being the source address (LSB, MSB) followed by answer data
        - as response for RFC for Simple protocol
	- receive `OPN` with data being the remote host (name or address)
        - as response to RFC for Stream protocol
	- receive `FWD` with new host address and contact
	- receive `LOS` or `CLS` with data being *reason*
1. If you received an `RFC`:
	- send an `OPN` (without data) or an `ANS` (with data)
1. If you sent or received an `OPN`:
	- send and receive `DAT`, `DWD`, `UNC` packets
1. If you received a `FWD`: send a new `RFC` to the host address using the new contact name, starting at the top here
1. To be sure all data is acked before closing (for non-Simple conns)
	- send an `EOF` packet last

When the Chaosnet connection is  closed by the other end, the user socket is also closed, and vice versa, so you only need to use CLS as negative response to RFC.

The user program will never see any STS, SNS, MNT, BRD, or RUT packets (so only sees RFC, OPN, EOF, DAT, DWD, CLS, LOS, FWD, UNC).

The user program can never send any such packets (so only LSN, RFC, OPN, EOF, DAT, DWD, CLS, LOS, FWD, UNC).

The NCP handles duplicates and flow control, and DAT and DWD packets are delivered individually in order to the user program. (LOS and UNC are uncontrolled.)

By the way, the description of the bidirectional "safe EOF protocol" in [Section 4.4 of Chaosnet](https://chaosnet.net/amber.html#index-EOF) is not what is implemented in Lisp Machines or, it seems, in ITS.

#### NOTE
The data part of `RFC`, `OPN`, `ANS`, `FWD`, and `UNC` packets are non-standard:
- for RFC, it includes the remote host and (optional) options (see above).
- for OPN (received), it includes the remote host (see above)
- for ANS (received), it includes the remote host (see above)
- for FWD, it is two bytes of host address [lsb, msb] (which gets put in the ack field of the actual packet) immediately followed by the new contact name (ascii).
- for UNC, it includes the packetno (2 bytes) and ackno (2 bytes) fields, which are not used for their normal purposes, but by the protocol using UNC. See [Using Foreign Protocols in Chaosnet](https://chaosnet.net/amber.html#Using-Foreign-Protocols-in-Chaosnet), and for example the "screen SPY" protocol for LispM (cf [spy.py](../tools/spy.py) in this repo).

#### NOTE further
If an `EOF` packet sent from the user program to the NCP has the data "wait" (four bytes), the NCP will send the EOF packet (without data) on the Chaosnet, await the packet to be acked, and send a special `ACK` packet (opcode 0177) to the user program when either the EOF packet is acked, or the `eofwait` timeout occurs. 

This is sometimes necessary for complex protocols, such as [FILE](https://github.com/PDP-10/its/blob/master/doc/sysdoc/chaos.file).

Note, again, that the data part of EOF is always empty when sent over Chaosnet, and that the ACK packet is never sent over Chaosnet - only between the NCP and the user program.

Note also that `UNC` packets may be lost or out-of-order.

# Internals

There is one thread handling user processes opening the socket, starting new connections.

Each connection uses three threads:
1. one to handle data from the connection to the user socket,
1. one to handle data from the socket to the connection, and
1. one to handle data from the connection to the network

Tons of locking, but possibly not enough.

## Caveats

The foreign protocol type (see [Section 6 in Chaosnet](https://chaosnet.net/amber.html#Using-Foreign-Protocols-in-Chaosnet)) is not even tried, but should be tested (using `chaos_packet`). Note: UNC packets are now used by the [SPY](tools/spy.py) protocol client, but that isn't really the same as Foreign Protocols.

There are remains of code for a `chaos_simple` socket type, an early idea which is not needed with how `chaos_stream` now works.

## TODO

### Internals:
- [ ] Add a bit of statistics counters for conns
- [ ] Make a few more things configurable, such as (long) probe intervals, and the "host down" interval.

### Applications:
- [ ] Implement a PEEK protocol to show the state of conns and cbridge (including the things reported by the `-s` command line option). (This needs to be done in cbridge itself, to have access the internal data structures. Having only 488 bytes for a Simple protocol is limiting, but implementing a "shortcut" Stream protocol directly is a nice challenge.)
- [ ] Implement a new CONFIG stream command for interacting with the configuration and state. Avoids the 488 byte problem, and would not allow remote access meaning a more limited security issue (only local).
- [x] Implement a fabulous web-based Chaosnet display using STATUS, LASTCN, DUMP-ROUTING-TABLE, UPTIME, TIME... Done, see [here](https://up.dfupdate.se/cha/hinfo.py).
- [x] Implement a proper DOMAIN server (same as the non-standard simple DNS but over a Stream connection). Done, see [here](../tools/domain.py).
- [x] Implement a [HOSTAB server](https://chaosnet.net/amber.html#Host-Table). This is useful for CADR systems (using the `:CHAOS-HOST-TABLE-SERVER-HOSTS` site option). (There is a HOSTAB server in ITS, but it only uses the local host table, not DNS.)
- [x] Port the old FILE server from MIT to use this (see https://tumbleweed.nu/r/chaos/dir?ci=tip&name=chcbridge).
- [ ] Implement a new [FILE](https://github.com/PDP-10/its/blob/master/doc/sysdoc/chaos.file) (or [NFILE](https://tools.ietf.org/html/rfc1037)) server (and client) in a modern programming language.  A sketch of [a client for FILE](../tools/file.py) is now done, in Python.
- [ ] Implement UDP over Foreign/UNC, then CHUDP over that. :-) Using `chaos_packet` it should be straight-forward.
