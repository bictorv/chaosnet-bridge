#!/bin/sh
# Starter script for Chaosnet services not already built-in in cbridge (typically stream services).

# Make sure the chaosnet library is found - YOU MAY NEED TO EDIT THIS
CBRIDGE_TOOLS=../tools
PYTHONPATH=$CBRIDGE_TOOLS:$PYTHONPATH

# Start DOMAIN server (the stream protocol; cbridge has the simple DNS protocol built-in)
DOMAINP=0
# The NAME protocol (corresponding to TCP finger, port 79)
NAMEDP=0
# The FINGER protocol (for lisp machines and other single-user machines)
FINGERDP=0
# The LOAD protocol
LOADDP=0
# The HOSTAB protocol
HOSTABP=0

# Read config file
[ -f ./cbridge-services.conf ] && . ./cbridge-services.conf

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
$CBRIDGE_TOOLS/hostat -q -t 3 3040 || echo FYI: No route to Router.Chaosnet.NET?

if [ $DOMAINP -gt 0 ]; then
    python3 $CBRIDGE_TOOLS/domain.py &
fi
if [ $NAMEDP -gt 0 ]; then
    python3 $CBRIDGE_TOOLS/named.py &
fi
if [ $FINGERDP -gt 0 ]; then
    if [ "$AFFILIATION" != "" ]; then
	python3 $CBRIDGE_TOOLS/fingerd.py -a $AFFILIATION &
    else
	python3 $CBRIDGE_TOOLS/fingerd.py &
    fi
fi
if [ $LOADDP -gt 0 ]; then
    python3 $CBRIDGE_TOOLS/loadd.py &
fi

if [ $HOSTABP -gt 0 ]; then
    python3 $CBRIDGE_TOOLS/hostabd.py -s $HOSTAB_DNS -D $HOSTAB_DOMAIN &
fi
