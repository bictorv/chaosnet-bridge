#!/usr/bin/env python3

# Run one service, for sub-requests

import sys, re, time
import os, urllib
# Obsolete
# import cgitb
# cgitb.enable()

print("Content-Type: text/html; charset=utf-8")    # HTML is following
# encourage caching: only serve new output every 30 seconds
print("Cache-Control: max-age=30")
print()                             # blank line, end of headers

print('''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">''')
# print("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML//EN\">\n<html>")
print('''<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/> 
    <title>Chaosnet Service</title>
</head>
<body>''')

from bhostat_html import HTMLFinger, HTMLStatus, HTMLTime, HTMLUptime, HTMLDumpRoutingTable, HTMLName, HTMLLoadName, HTMLLoad, HTMLDNSinfo, HTMLLastSeen

# @@@@ keep in sync with hinfo.py
slist = dict(dns=dict(s=HTMLDNSinfo, desc="DNS info"),
             status=dict(s=HTMLStatus, desc="Host status"),
             time=dict(s=HTMLTime,svg="clock.svg"),
             uptime=dict(s=HTMLUptime,svg="clock.svg"),
             finger=dict(s=HTMLFinger, desc="LispM Finger",svg="dragon.svg"),
             loadname=dict(s=HTMLLoadName, desc="Timesharing Finger",svg="dragon.svg"),
             load=dict(s=HTMLLoad,svg="sload.svg"),
             name=dict(s=HTMLName,desc="Name/Whois", onlyhost=True, seealso='loadname'),
             routing=dict(s=HTMLDumpRoutingTable, header="Routing tables",svg='contor.svg'),
             lastseen=dict(s=HTMLLastSeen, desc="LastSeen"))

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

if host and srvc and len(srvc) == 1:
    s = srvc[0]
    if s.lower() in slist:
        x = slist[s.lower()]
        hs = list(map(lambda h: int(h,8) if isinstance(h,str) and re.match("^(-1|[0-7]+)$", h) else h, host))
        # call the service
        if 'header' in x:
            sname = x['header']
        elif 'desc' in x:
            sname = x['desc']
        else:
            sname = s.capitalize()
        if 'onlyhost' in x and x['onlyhost'] and len(list(filter(lambda h: isinstance(h,str), hs))) == 0:
            if 'seealso' in x:
                y = slist[x['seealso']]
                also = " See also the {} service.".format(y['desc'] if 'desc' in y else x['seealso'].capitalize())
            else:
                also = ""
            print("<!-- Service {} can only be called with a host argument, not with subnets.{} -->".format(sname, also))
        else:
            u = "" if user is None or s.lower() != 'name' else ", ".join(user)+" at "
            hh = ", ".join(map(lambda h: h if isinstance(h,str) else "all subnets" if h == -1 else "subnet {:o}".format(h) if h < 0x400 else "host {:o}".format(h),hs[:5]+(["..."] if len(hs) > 5 else [])))
            if 'svg' in x:
                print("<object type='image/svg+xml' data='{}' width='30%' height='100%' style='float: right;'></object>".
                      format(x['svg']))
            # @@@@ Add Refresh button
            print("<h2>{} for {}{}".format(sname,u, hh))
            print('<button value="Refresh" title="Refresh {} - last refreshed {}" type="button" onclick="loadService(\'{}\',\'{}\',\'{}\')">&#10226;</button>'.format(sname,time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime()),
                                                                                                                                                                      os.getenv('QUERY_STRING'),s,sname))
            print("</h2>")
            if user and s.lower() == 'name':
                x['s'](hs,dict(timeout=3),args=["/W {}".format(",".join(user))])
            else:
                x['s'](hs,dict(timeout=3))
    else:
        print("<!-- no such service: '{}' -->".format(s), file=sys.stderr)
else:
    print("<!-- no service: ",srvc," -->", file=sys.stderr)

print("</body></html>")
