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
CFLAGS = -I/opt/local/include
LDFLAGS = -L/opt/local/include
endif

all: cbridge

OBJS = contacts.o usockets.o chtls.o chudp.o debug.o chether.o

# YMMV, but sometimes openssl etc are in /opt/local. -lssl and -lcrypto are needed only for TLS
cbridge: cbridge.c $(OBJS) chaosd.h cbridge-chaos.h chudp.h contacts.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o cbridge cbridge.c $(OBJS) -lpthread -lssl -lcrypto

contacts.o: contacts.c cbridge-chaos.h cbridge.h
	$(CC) -c $(CFLAGS) -o $@ $<

usockets.o: usockets.c cbridge.h
	$(CC) -c $(CFLAGS) -o $@ $<

chtls.o: chtls.c cbridge.h
	$(CC) -c $(CFLAGS) -o $@ $<

chudp.o: chudp.c cbridge.h chudp.h
	$(CC) -c $(CFLAGS) -o $@ $<

debug.o: debug.c cbridge.h
	$(CC) -c $(CFLAGS) -o $@ $<

chether.o: chether.c cbridge.h
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f cbridge $(OBJS)

