#!/bin/sh
# Starter script for use with systemctl service cbridge.service.
#
# This is ridiculous.
# I would have expected After=network.online ns-lookup.target to take care of this,
# but without it, any DNS name parsing might fail with "temporary errors" causing config parsing to fail,
# and cbridge will not start.
i=0
while ! /usr/bin/host -t a router.chaosnet.net > /dev/null; do
    # /sbin/ip -o addr show dev eth0 | grep 'inet ';
    i=$((i+1));
    sleep 2;
done
if [ $i -gt 0 ]; then
   echo "Waited $i rounds for DNS to come up";
fi
./cbridge-starter-services.sh &
exec ./cbridge
