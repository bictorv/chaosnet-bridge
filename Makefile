all: cbridge

cbridge: cbridge.c chaosd.h chaos.h chudp.h
	$(CC) $(CFLAGS) -o cbridge cbridge.c -lpthread

clean:
	rm -f cbridge cbridge.o
