CFLAGS=-I../src

all: hostat finger

hostat: hostat.c ../src/cbridge-chaos.h
	$(CC) $(CFLAGS) -o $@ $<

finger: finger.c ../src/cbridge-chaos.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f hostat finger
