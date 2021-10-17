#!/bin/sh
# Starter script for Chaosnet services not already built-in in cbridge (typically stream services).

# Start DOMAIN server (the stream protocol; cbridge has the simple DNS protocol built-in)
DOMAINP=1
# The NAME protocol (corresponding to TCP finger, port 79)
NAMEDP=0
# The FINGER protocol (for lisp machines and other single-user machines)
FINGERDP=0

# first allow cbridge to start
sleep 3
i=0
while [ ! -S /tmp/chaos_stream ]; do
    i=$((i+1));
    if [ $i -gt 5 ]; then
	echo "No socket at /tmp/chaos_stream - is cbridge running?";
	exit 1;
    fi;
    sleep 2;
done
# Run anyway, but notify user
./hostat -q -t 3 3040 || echo FYI: No route to MX-11?

if [ $DOMAINP -gt 0 ]; then
    python3 ./domain.py &;
fi
if [ $NAMEDP -gt 0 ]; then
    python3 ./named.py &;
fi
if [ $FINGERDP -gt 0 ]; then
    python3 ./fingerd.py &;
fi

