all: cbridge

cbridge: cbridge.c chaosd.h cbridge-chaos.h chudp.h
	$(CC) $(CFLAGS) -o cbridge cbridge.c -lpthread

clean:
	rm -f cbridge cbridge.o
