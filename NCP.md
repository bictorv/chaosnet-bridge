# Network Control Program

The NCP implements the "transport layer" of Chaosnet, and lets a regular user program easily make use of the Chaosnet routing and infrastructure built by the rest of cbridge.

# Configuration

`ncp ` [ `enabled` no/yes ] [ `debug` off/on ] [ `trace` off/on ]  ...

| setting | description |
| --- | --- |
|`enabled`| used to enable/disable the NCP - default is `no` (disabled).|
|`domain`| used for specifying the default DNS domains for RFC arg parsing, as a comma-separated list. **NOTE** that there must be no spaces around the comma! Default (if none are specified) is `chaosnet.net`.|
|`retrans`| specifies the retransmission time interval - default 500 ms.|
|`window`| specifies window size - default 13 packets (maximally 6344 bytes). Max window size is 128. (ITS uses only 5, and a max of 64, while CADR and Lambda Lisp machine systems use 013, and max 128. Symbolics uses a max of 50.)|
|`eofwait` | specifies time to wait for ACK of final EOF pkt when closing conn - default 1000 ms.|
|`finishwait`| specifies the time to wait for a half-open conn (OPN Sent) to become Open (thus allowing final retransmissions) while finishing it. Default 5000 ms. (You probably don't want to mess with this.)|
|`socketdir`| specifies the directory where to put the socket file(s), `chaos_stream` - default is `/tmp`.|
|`trace`| if on, writes a line when a connection is opened or closed.|
|`debug`| if on, writes a lot.|

# Usage

The NCP opens a named local ("unix") socket for letting user programs interact with Chaosnet.  To try it out, use `nc -U /tmp/chaos_stream`. There is also [a special verion of supdup.c](https://github.com/Chaosnet/supdup) to try a "real" protocol,  [a simple demo program for connectionless protocols](hostat.c), and [a finger program](finger.c) to try a simple stream protocol, and [an example server program](named.py).

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

This socket is for "stream protocols" (see Section 4.1 in [Chaosnet](https://tumbleweed.nu/r/lm-3/uv/amber.html#Connection-Establishment), where an RFC starts a stream connection with flow control - this is similar to TCP. It can also be used for Simple protocols (similar to UDP).

### Client opening

If the user program acts as a client, it opens the socket and writes

`RFC `[*options*] *host* *contactname* *args*

(followed by LF or CRLF), where
- [*options*] (including the square brackets!) is optional, and specifies (a comma-separated list of) options for the connection. 
- *host* is either the name or the (octal!) address of the host to be contacted,
- *contactname* is the contact name, such as `NAME`, `UPTIME`, `TIME` or `STATUS`, and
- *args* are optional arguments, such as a user name for `NAME`. The *args* are separated from *contactname* with a single space.

The NCP sends a corresponding RFC packet to the destination host.

#### Options:
So far there is only one:
- `timeout=`*%d* to specify a (positive, decimal) timeout value (in seconds) for the connection to open (i.e. a response to be received). The default is 30 seconds. In case of a time out, a `LOS Connection timed out` response is given to the user program.

#### Examples:
- `RFC time.chaosnet.net TIME`
    - basic example: returns an ANS with the (binary) current time (try `hostat time.chaosnet.net time` to get it legibly)
- `RFC up.update.uu.se NAME /W bv`
    - args example: gets "whois" info about bv@up
- `RFC [timeout=3] 3402 STATUS`
    - options example: tries to get the status of host 3402 (octal) but with a timeout of 3 seconds. Note the explicit square brackets.
- `rfc 3040 dump-routing-table`
    - it's all case-insensitive (contact names are made uppercase). (Try `hostat 3040 dump-routing-table` for legible output.)

#### Responses

Any errors in parsing the RFC line (etc) result in a
`LOS `*reason*
line given to the user program, and the socket is closed.

When a response is received from the destination host, it is either an OPN or CLS packet. The NCP informs the user program by writing on its socket:

`OPN Connection to host `*%o*` opened`

or

`CLS `*reason*

In the case of OPN, the NCP sets up a stream connection , handles flow control etc, and forwards data between the remote host and the user program. 

Writes from the user program are packaged into DAT packets which are sent to the remote host (when the window allows), and DAT packets from the remote host are written to the user program. No character translation is done in the NCP, so the client needs to handle e.g. translation between "ascii newline" (012) and "lispm newline" (0212).

When the user program closes the socket, the NCP sends an EOF, waits for it to be acked (see `eofwait` setting), and then sends a CLS to close the connection in a controlled way (not quite as in Section 4.4 in [Chaosnet](https://tumbleweed.nu/r/lm-3/uv/amber.html#End_002dof_002dData)..

When the NCP receives an EOF or CLS, the user socket is closed.

The NCP attempts to remove the user socket file after it is closed, to keep the place tidy.

### Server opening

If the user program acts as a server, it opens the socket and writes

`LSN `*contactname*

The NCP then notes that the user program is listening for connections to *contactname*, and when a matching RFC packet appears, it writes

`RFC `*rhost* *args*

to the user program, where *rhost* is the remote host (name or octal address), and *args* are the arguments given in the RFC packet, if any.

The user program is then supposed to handle the RFC and respond to it by either an OPN, ANS or CLS, as follows:

`OPN` (or `OPN `*whatever*)
causes the NCP to send an OPN packet to the remote host, and when it reponds with an STS packet, the connection is established as above.

`CLS `*reason*
where *reason* is a single line of text, which results in the NCP sending a corresponding CLS packet to the remote host, and the connection is then closed - including the user socket.

`ANS `*len*
*data*

where *len* is the length in bytes (max 488) of the following *data* (which may include any bytes). This results in the NCP sending an ANS packet to the remote host, with the supplied data, and then closing the socket.


To handle new RFCs (while handling one, or after) your user program needs to open the `chaos_stream` socket again. See [an example server program](named.py).


# Internals

There is one thread handling user processes opening the socket, starting new connections.

Each connection uses three threads:
1. one to handle data from the connection to the user socket,
1. one to handle data from the socket to the connection, and
1. one to handle data from the connection to the network

Tons of locking, but possibly not enough.

## Caveats

The foreign protocol type (see [Section 6](https://tumbleweed.nu/r/lm-3/uv/amber.html#Using-Foreign-Protocols-in-Chaosnet) in Chaosnet) is not even tried, but since foreign data in UNC packets are uncontrolled (not in order) it doesn't make sense - however in `chaos_seqpacket` below it would.

There are remains of code for a `chaos_simple` socket type, an early idea which is not needed with how `chaos_stream` now works.

## TODO

### Internals:
- [ ] Add a bit of statistics counters for conns
- [ ] Make a few more things configurable, such as the default connection timeout, retransmission and (long) probe intervals, and the "host down" interval.
- [ ] Implement FWD (redirect the connection invisibly? See `RECEIVE-FWD` in Lambda code.).
- [ ] Implement broadcast (both address-zero and BRD).

### Applications:
- [ ] Implement a PEEK protocol to show the state of conns and cbridge (including the things reported by the `-s` command line option)
- [ ] Implement a fabulous web-based Chaosnet display using HOSTAT, LASTCN, DUMP-ROUTING-TABLE, UPTIME, TIME...
- [ ] Implement a proper DOMAIN server (same as the non-standard simple DNS but over a Stream connection).
- [ ] Implement a [HOSTAB server](https://tumbleweed.nu/r/lm-3/uv/amber.html#Host-Table).
- [ ] Implement UDP over Foreign/UNC, then CHUDP over that. :-) Would need `chaos_seqpacket` though (below).
- [ ] Port the old FILE server from MIT to use this (see http://www.unlambda.com/cadr/) (also needs chaos_seqpacket).
- [ ] Instead, implement a new FILE (or [NFILE](https://tools.ietf.org/html/rfc1037)) server in a modern programming language (also needs chaos_seqpacket).


## Future idea? chaos_seqpacket

This is a socket of type `SOCK_SEQPACKET`.

As above, but the NCP and the user program exchange packets rather than just a stream of data. The packets have a 4-byte header (no need for the full Chaosnet header at the transport layer).

Setting up the connection is as for `chaos_stream`:
1. `RFC `*rhost* *args*
    - or `LSN `*contact*
1. Response:
	- `LOS `*reason*
	- `CLS `*reason*
	- `ANS `*length*
	- `OPN Connection to host `%o` opened`

After that, packets are sent and received with a 4-byte binary header:

| opcode | 0 | lenMSB | lenLSB |

followed by the data of the packet, with the length indicated by the len bytes.  Data lengths can not be more than 488 bytes.

The user program will never see any STS, SNS, EOF, MNT, BRD, or RUT packets.

The user program can never send any such packets, and also no RFC, OPN, or BRD packets.

The NCP handles flow control, but DAT packets (and other controlled packets) are delivered individually in order to the user program.

Implementation should be fairly easy given the flow control is already in place, it's just a new flavor of `conn_to_sock` and `conn_from_sock` handlers (how to read and package input from the socket, and how to present the packets to the socket). The `conn_to_net` just works.
