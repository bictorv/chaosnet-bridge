#!/usr/bin/env python3

# Get the host addresses and subnets that respond to STATUS.
# Cache the results, they won't change super often.

print("Content-Type: text/html")    # HTML is following
# encourage caching: only serve new output every 30 seconds
print("Cache-Control: max-age=30")
print()                             # blank line, end of headers

import os, urllib
from bhostat import ChaosSimpleStatus
from chaosnet import dns_name_of_address, dns_netname

qs = urllib.parse.parse_qs(os.getenv('QUERY_STRING'),keep_blank_values=True)
sn = -1
if 'subnet' in qs and len(qs['subnet']) > 0:
    sn = int(qs['subnet'][0],8)
to = 2
if 'timeout' in qs:
    to = int(qs['timeout'][0])

s = ChaosSimpleStatus([sn],dict(timeout=to))
print("<label style='vertical-align: top' for=\"host\">Host/subnet:</label>")
print("<select name='host' id='host' multiple=\"multiple\">")
print(" <option value=\"-1\">All hosts on all subnets</option>")
hosts = list(s.hosts)
hosts.sort(key=str.lower)
for h in hosts:
    print(" <option value=\"{}\">{}</option>".format(h,h))
subs = list(s.subnets)
subs.sort()
for s in subs:
    print(" <option value=\"{:o}\">Subnet {:o} ({})</option>".format(s,s, dns_netname(s)))
print("</select>")
# @@@@ alternatively, provide XML for the caller to transform. Should be wrapped in some element
# print("<hosts>")
# for h in s.hosts:
#     print(" <host>{}</host>".format(h))
# print("</hosts>")
# print("<haddrs>")
# for h in s.haddrs:
#     print(" <haddr>{:o}</haddr>".format(h))
# print("</haddrs>")
# print("<subnets>")
# for s in s.subnets:
#     print(" <subnet>{:o}</subnet>".format(s))
# print("</subnets>")
