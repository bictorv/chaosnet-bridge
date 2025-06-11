#!/bin/sh
# Firewall script for cbridge, to avoid having the world access your Chaosnet over UDP

# Name of the iptables input chain to use (don't use INPUT, more work to clean up)
CHAIN=Cbridge_INPUT

if [ "$1" = "stop" ]; then
    if [ "$CHAIN" != INPUT ]; then
	# delete the rule using the chain
	iptables -D INPUT -j $CHAIN
	# flush all the rules in the chain
	iptables -F $CHAIN
	# remove the chain
	iptables -X $CHAIN
	exit
    fi
fi

CHUDP_port=`cat cbridge.conf | grep -v ';' | grep -e '^chudp' | awk '{ print $2 }'`
if [ "x$CHUDP_port" = "x" ]; then
    CHUDP_port=42042
fi
CHUDP_sources=`cat cbridge.conf | grep -v ';' | grep 'link chudp' | awk '{ print $3 }'`
if [ "x$CHUDP_sources" = "x" ]; then
    # No chudp links, done
    exit
fi
echo "Using CHUDP port ${CHUDP_port}"

if [ "$CHAIN" != "INPUT" ]; then
    # create a new chain
    iptables -N $CHAIN
    # flush it in case it existed
    iptables -F $CHAIN
fi

for src in $CHUDP_sources; do
    h=`echo $src | sed -e 's/:.*//'`
    p=`echo $src | sed -e 's/[^:]*//' -e 's/://'`
    if [ "$p" = "" ]; then p=42042; fi
    echo "Accept from $h on port $p"
    iptables -A $CHAIN -s $h -p udp -m udp --sport $p --dport $CHUDP_port -j ACCEPT
done
# Log and drop all else
iptables -A $CHAIN -p udp -m udp --dport $CHUDP_port -j LOG --log-prefix '[Unknown_CHUDP]'
iptables -A $CHAIN -p udp -m udp --dport $CHUDP_port -j DROP

# Finally enable the use of the chain
if [ "$CHAIN" != "INPUT" ]; then
    iptables -I INPUT -j $CHAIN
fi
