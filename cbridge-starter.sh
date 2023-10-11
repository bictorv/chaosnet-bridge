#!/bin/sh
# Starter script for use with systemctl service cbridge.service or launchd net.chaosnet.cbridge
#
# This is ridiculous.
# I would have expected After=network.online ns-lookup.target to take care of this,
# but without it, any DNS name parsing might fail with "temporary errors" causing config parsing to fail,
# and cbridge will not start.

# Maybe cd before starting cbridge
if [ $# -gt 0 ]; then
    cd $1
fi

# Check that DNS services are up
i=0
while ! /usr/bin/host -t a router.chaosnet.net > /dev/null; do
    # /sbin/ip -o addr show dev eth0 | grep 'inet ';
    i=$((i+1));
    sleep 2;
done
if [ $i -gt 0 ]; then
   echo "Waited $i rounds for DNS to come up";
fi

# Now wait for the Chaosnet DNS server to be available.
# This is needed for TLS cert checking.
i=0
srv=""
if grep -q -E '^tls ' cbridge.conf; then
    # See if some special server is configured
    if grep -q -E '^dns .*server ' cbridge.conf; then
	srv=`grep ^dns cbridge.conf | sed -e 's/dns .*server //' | sed -e 's/ .*//'`
    fi
    if [ "X$srv" = "X" ]; then
	# Default DNS server
	srv=dns.chaosnet.net
    fi
    while ! /usr/bin/host -t a -c ch router.chaosnet.net $srv > /dev/null; do
	i=$((i+1));
	sleep 2;
    done
    if [ $i -gt 0 ]; then
	echo "Waited $i rounds for Chaosnet DNS to come up";
    fi
fi

./cbridge-starter-services.sh &
exec ./cbridge
