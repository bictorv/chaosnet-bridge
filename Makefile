all: cbridge

cbridge: cbridge.c chaosd.h cbridge-chaos.h chudp.h
	$(CC) $(CFLAGS) -o cbridge cbridge.c -lpthread

uttun: uttun.c
	$(CC) -I/opt/local/include -L/opt/local/lib $(CFLAGS) -o uttun uttun.c -lpthread -lssl -lcrypto

clean:
	rm -f cbridge cbridge.o
