#!/usr/bin/env python3

# Run one service, for sub-requests

import sys, re, time
import os, urllib, json

print("Content-Type: application/json; charset=utf-8")    # JSON is following
# encourage caching: only serve new output every 30 seconds
print("Cache-Control: max-age=30")
print()                             # blank line, end of headers

from chaosnet import BroadcastStatusDict, BroadcastUptimeDict, BroadcastTimeDict, BroadcastDumpRoutingTableDict, BroadcastLastSeenDict, NamesDict, BroadcastLoadDict, BroadcastLoadDict, BroadcastFingerDict

# @@@@ keep in sync with hinfo.py
slist = dict(# dns=dict(s=HTMLDNSinfo, desc="DNS info"),
             status=dict(s=BroadcastStatusDict, desc="Host status"),
             time=dict(s=BroadcastTimeDict,svg="clock.svg"),
             uptime=dict(s=BroadcastUptimeDict,svg="clock.svg"),
             finger=dict(s=BroadcastFingerDict, desc="LispM Finger",svg="dragon.svg"),
             # fake
             loadname=dict(s=BroadcastLoadDict, desc="Timesharing Finger",svg="dragon.svg",timeout=2),
             load=dict(s=BroadcastLoadDict,svg="sload.svg",timeout=2),
             name=dict(s=NamesDict,desc="Name/Whois", onlyhost=True, seealso='loadname'),
             routing=dict(s=BroadcastDumpRoutingTableDict, header="Routing tables",svg='contor.svg'),
             lastseen=dict(s=BroadcastLastSeenDict, desc="LastSeen"))

qs = urllib.parse.parse_qs(os.getenv('QUERY_STRING'),keep_blank_values=True)
host = qs['host'] if 'host' in qs else None
user = qs['user'] if 'user' in qs else None
srvc = qs['service'] if 'service' in qs else None

# Handle comma-or-space separated hosts/subnets
if host and len(host) == 1:
    if "," in host[0]:
        host = list(map(lambda x: x.strip(), host[0].split(",")))
    else:
        host = host[0].split()

# Note difference from service.py: only one service per request here.
if host and srvc and len(srvc) == 1:
    # parse octal number strings
    hn = [int(h,8) if isinstance(h,str) and re.match("^(-1|[0-7]+)$", h) else h for h in host]
    s = srvc[0]
    if s.lower() in slist:
        x = slist[s.lower()]
        to = x['timeout'] if 'timeout' in x else 3
        if user and s.lower() == 'name':
            d = x['s'](hn,options=dict(timeout=to),args=["/W {}".format(",".join(user))]).dict_result()
        else:
            d = x['s'](hn,options=dict(timeout=to)).dict_result()
        print(json.dumps(d))
    else:
        print("<!-- no such service: '{}' -->".format(s), file=sys.stderr)
else:
    print("<!-- no service: ",srvc," -->", file=sys.stderr)

