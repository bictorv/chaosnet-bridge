OS_NAME = $(shell uname)
MACH_NAME = $(shell uname -m)

ifeq ($(OS_NAME), Darwin)
OS = OSX
endif

ifeq ($(OS_NAME), Linux)
OS = LINUX
endif

# Mac OSX
ifeq ($(OS), OSX)
CFLAGS = -I/opt/local/include -g
LDFLAGS = -L/opt/local/lib
endif

all: cbridge hostat

OBJS = cbridge.o contacts.o usockets.o chtls.o chudp.o debug.o chether.o dns.o chip.o ncp.o pkqueue.o

# YMMV, but sometimes openssl etc are in /opt/local.
# -lssl and -lcrypto are needed only for TLS.
# -lresolv needed only for dns.o
cbridge: $(OBJS) chaosd.h cbridge-chaos.h chudp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o cbridge $(OBJS) -lpthread -lssl -lcrypto -lresolv

cbridge.o: cbridge.c cbridge.h cbridge-chaos.h 
	$(CC) -c $(CFLAGS) -o $@ $<

contacts.o: contacts.c cbridge.h cbridge-chaos.h 
	$(CC) -c $(CFLAGS) -o $@ $<

usockets.o: usockets.c cbridge.h cbridge-chaos.h chaosd.h
	$(CC) -c $(CFLAGS) -o $@ $<

chtls.o: chtls.c cbridge.h cbridge-chaos.h
	$(CC) -c $(CFLAGS) -o $@ $<

chudp.o: chudp.c cbridge.h cbridge-chaos.h chudp.h
	$(CC) -c $(CFLAGS) -o $@ $<

chip.o: chip.c cbridge.h cbridge-chaos.h chudp.h
	$(CC) -c $(CFLAGS) -o $@ $<

debug.o: debug.c cbridge.h cbridge-chaos.h
	$(CC) -c $(CFLAGS) -o $@ $<

chether.o: chether.c cbridge.h cbridge-chaos.h
	$(CC) -c $(CFLAGS) -o $@ $<

dns.o: dns.c cbridge.h cbridge-chaos.h
	$(CC) -c $(CFLAGS) -o $@ $<

ncp.o: ncp.c ncp.h cbridge.h pkqueue.h
	$(CC) -c $(CFLAGS) -o $@ $<

pkqueue.o: pkqueue.c pkqueue.h cbridge-chaos.h
	$(CC) -c $(CFLAGS) -o $@ $<

hostat: hostat.c cbridge-chaos.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f cbridge $(OBJS)

