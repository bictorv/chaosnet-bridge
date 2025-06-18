# Tools

This directory contains various tools to use with cbridge.

C language programs:
- finger.c - a client for the NAME protocol (note: not the FINGER protocol, see below). Try ```finger @up``` etc.
- hostat.c - a client for the STATUS protocol. Try ```hostat -1``` or ```hostat -1 time``` etc.

Servers, written in Python using the NCP "API" of cbridge:
- domain.py - a server for the DOMAIN protocol (i.e. the DNS system).
- fingerd.py - a server for the FINGER protocol (originally used on Lisp Machines, intended for single-user machines).
- hostabd.py - a server for the HOSTAB protocol ("host tables").
- loadd.py - a server for the LOAD protocol (mainly for timesharing machines).
- minid.py - a server for the MINI file transfer protocol (not well tested).
- named.py - a server for the NAME protocol (used by finger.c, or :NAME or :F in ITS)

Clients, written in Python using the NCP "API" of cbridge:
- echotest.py - a client for the ECHO and BABEL protocols, for testing/debugging purposes.
- evactest.py - a client for the EVACUATE protocol (a very simple file transfer protocol)
- file.py - a client for the FILE protocol (a nontrivial file transfer protocol). This is a gross hack.
- finger.py - a client for the NAME protocol (no, not the FINGER protocol...)
- hostab.py - a client for the HOSTAB protocol ("host table").
- spy.py - a client for the SPY protocol (which shows the screen of a Lisp Machine that allows it).
- telnet.py - a client for the TELNET protocol (not SUPDUP, yet).
- bhostat.py - a program which can use broadcast packets to quickly get information about the hosts on Chaosnet.

The Python servers and clients use support libraries:
- chaosnet.py - basic Chaosnet access. See the classes PacketConn, BroadcastConn, StreamConn, and Simple for "simple" protocols. It also has some DNS support functions.
- dnspython - library for low-level DNS, see [documentation](https://dnspython.readthedocs.io/en/latest/). Install by e.g. `pip3 install dnspython`.
