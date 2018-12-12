all: cbridge

# YMMV, but sometimes openssl etc are in /opt/local. -lssl and -lcrypto are needed only for TLS
cbridge: cbridge.c chaosd.h cbridge-chaos.h chudp.h
	$(CC) -I/opt/local/include -L/opt/local/lib $(CFLAGS) -o cbridge cbridge.c -lpthread -lssl -lcrypto

# Just a PoC
uttun: uttun.c
	$(CC) -I/opt/local/include -L/opt/local/lib $(CFLAGS) -o uttun uttun.c -lpthread -lssl -lcrypto

clean:
	rm -f cbridge cbridge.o
