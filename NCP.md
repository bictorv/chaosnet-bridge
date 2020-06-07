# Network Control Program

The NCP lets a regular user program easily make use of the Chaosnet routing and infrastructure built by the rest of cbridge.

# Configuration

`ncp ` [ `enabled` no/yes ] [ `debug` off/on ] [ `trace` off/on ]  [ `domain` *default* ] [ `socketdir` /tmp ] [ `retrans` 500 ]

| setting | description |
| --- | --- |
|`enabled`| used to enable/disable the NCP - default is `no` (disabled).|
|`domain`| used for specifying the default DNS domain for RFC arg parsing - default is `chaosnet.net`. |
|`retrans`| specifies the retransmission time interval - default 500 ms.|
|`window`| specifies window size - default 13 packets (maximally 6344 bytes). Max window size is 128.|
|`socketdir`| specifies the directory where to put the socket file(s), `chaos_stream` - default is `/tmp`.|
|`trace`| if on, writes a line when a connection is opened or closed.|
|`debug`| if on, writes a lot.|

# Usage

The NCP opens a named local ("unix") socket for letting user programs interact with Chaosnet.  To try it out, use `nc -U /tmp/chaos_stream`. There is also [a special verion of supdup.c](supdup-patch.tar) to try a "real" protocol,  [a simple demo program for connectionless protocols](hostat.c), and [a finger program](finger.c) to try a simple stream protocol.

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

This socket is for "stream protocols" (see Section 4.1 in [Chaosnet](https://tumbleweed.nu/r/lm-3/uv/amber.html#Connection-Establishment), where an RFC starts a stream connection with flow control - this is similar to TCP. It can/will also be used for Simple protocols.

### Client opening

If the user program acts as a client, it opens the socket and writes

`RFC `*host* *contactname* *args*

(followed by LF or CRLF), where *host* is either the name or the (octal) address of the host to be contacted, *contactname* is the contact name, such as `FINGER`, `TIME` or `STATUS`, and *args* are optional arguments, such as a user name for `FINGER`. The *args* are separated from *contactname* with a single space.

The NCP sends a corresponding RFC packet to the destination host.

When a response is received from the destination host, it is either an OPN or CLS packet. The NCP informs the user program by writing on its socket:

`OPN Connection to host `*%o*` opened`

or

`CLS `*reason*

In the case of OPN, the NCP sets up a stream connection , handles flow control etc, and forwards data between the remote host and the user program. 

Writes from the user program are packaged into DAT packets which are sent to the remote host (when the window allows), and DAT packets from the remote host are written to the user program.

When the user program closes the socket, the NCP sends an EOF, waits for it to be acked, and then sends a CLS to close the connection in a controlled way (not quite as in Section 4.4 in [Chaosnet](https://tumbleweed.nu/r/lm-3/uv/amber.html#End_002dof_002dData)..

When the NCP receives an EOF or CLS, the user socket is closed.

The NCP attempts to remove the user socket file after it is closed, to keep the place tidy.

### Server opening

If the user program acts as a server, it opens the socket and write

`LSN `*contactname*

The NCP then notes that the user program is listening for connections to *contactname*, and when a matching RFC packet appears, it writes

`RFC `*rhost* *args*

to the user program, where *rhost* is the remote host (name or octal address), and *args* are the arguments given in the RFC packet, if any.

The user program is then supposed to handle the RFC and respond to it by either an OPN, ANS or CLS, as follows:

`OPN` (or `OPN `*whatever*)
causes the NCP to send an OPN packet to the remote host, and when it reponds with an STS packet, the connection is established as above.

`CLS `*reason*
where *reason* is a single line of text, which results in the NCP sending a corresponding CLS packet to the remote host, and the connection is then closed - including the user socket.

`ANS `*len*\r\n*data*
where *len* is the length in bytes of the following *data* (which may include any bytes). This results in the NCP sending an ANS packet to the remote host, with the supplied data, and then closing the connection.


To handle new RFCs (while handling one, or after) your user program needs to open the `chaos_stream` socket again.


# Internals

Each connection uses three threads:
1. one to handle data from the connection to the user socket,
1. one to handle data from the socket to the connection, and
1. one to handle data from the connection to the network

Tons of locking, but probably not enough.

## Caveats

Currently (2020-06-03), the server side (LSN) is not very debugged.

The foreign protocol type (see [Section 6](https://tumbleweed.nu/r/lm-3/uv/amber.html#Using-Foreign-Protocols-in-Chaosnet) in Chaosnet) is not even tried.

There are remains of code for a `chaos_simple` socket type, an early idea which is not needed with how `chaos_stream` now works.

## TODO

Write simple server programs to validate LSN stuff (NAME, SEND, HOSTAB... and DOMAIN).

Implement fabulous web-based Chaosnet display using HOSTAT, LASTCN, DUMP-ROUTING-TABLE, UPTIME, TIME...

Implement UDP over Foreign/UNC, then CHUDP over that. :-) Would need chaos_seqpacket though (below).

## Future? chaos_seqpacket

This is a socket of type `SOCK_SEQPACKET`.

As above, but the NCP and the user program exchanges packets with a four-byte text header (rather than a binary Chaosnet header) consisting of the three-letter opcode followed by a space.

The exceptions are
`RFC `*rhost* *args*
`LOS `*reason*
`CLS `*reason*

The user program will never see any STS, SNS, MNT or RUT packets, and any such packets from the user program are ignored.

The NCP handles flow control, but DAT packets are delivered individually to the user program, and such DAT packets from the user program are not allowed to be more than 488 (decimal) bytes.
