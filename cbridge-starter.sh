#!/bin/sh
# Starter script for use with systemctl service cbridge.service.
#
# This is ridiculous.
# I would have expected After=network.online ns-lookup.target to take care of this,
# but without it, any DNS name parsing might fail with "temporary errors" causing config parsing to fail,
# since IP only has a temporary 169.x.y.z address, 
# and cbridge will not start.
i=0
while /sbin/ip -o addr show dev eth0 | /bin/grep -q 'inet 169'; do
    # /sbin/ip -o addr show dev eth0 | grep 'inet ';
    i=$((i+1));
    sleep 2;
done
if [ $i -gt 0 ]; then
   echo "Waited $i rounds for network to come up";
fi
exec ./cbridge
