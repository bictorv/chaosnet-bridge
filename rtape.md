# RTAPE server

`rtape` is a Unix program that implements a server for the RTAPE
protocol, which provides remote access to a tape drive.

This program was implemented primarily by reading and testing against
the ITS **DUMP** tape backup program, which can optionally use RTAPE.
The Unix **rtape** server from MIT/Symbolics was used as a secondary
reference.

### Tape data format

When a client connects, it must specify which tape drive to use.  This
server uses the drive name to open a file.  Data read from or written
to this file will be stored in the SIMH tape image format.

### Options

```
  -a  Allow slashes in mount drive name.
  -d  Run as daemon.
  -q  Quiet operation - no logging, just errors.
  -r  Only allow read-only mounts.
  -v  Verbose operation - detailed logging.
```

The `-a` option is dangerous.  The default is to not allow slashes, to
avoid people poking around the host by sending a drive name like
`/etc/password` or `../foobar`.

The default is to allow writing tapes, but `-r` is available for
cautious people.

### Example

For example, if the rtape server is running on the host 177001, the
ITS **DUMP** backup program can mount a remote tape like this:

```
*dump^K
DUMP  .448

_remote
TAPE SERVER HOST=177001
DRIVE=backup.tap
READ ONLY? n
REMOTE TAPE UNWOND
_
```
