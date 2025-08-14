#!/usr/bin/env python3

import os.path, time, sys, re
import os, urllib
from os import access
# Obsolete
# import cgitb
# cgitb.enable()
from chaosnet import ChaosSocketError

from bhostat_html import HTMLFinger, HTMLStatus, HTMLTime, HTMLUptime, HTMLDumpRoutingTable, HTMLLoadName, HTMLName, HTMLLoad, HTMLDNSinfo, HTMLLastSeen

# Given a host name/address (or perhaps subnet) as arg,
# present a choice of info to collect for it (inserting it in sections of the resulting page, with "reload" buttons):
# - LASTCN
# and make all output names/addresses clickable (leading here).
# Given a host+uname (e.g. output from NAME/FINGER), do a NAME /W

# @@@@ keep in sync with service.py
slist = dict(dns=dict(s=HTMLDNSinfo, desc="DNS info"),
             status=dict(s=HTMLStatus),
             time=dict(s=HTMLTime,svg="clock.svg"),
             uptime=dict(s=HTMLUptime),
             finger=dict(s=HTMLFinger, desc="LispM Finger"),
             loadname=dict(s=HTMLLoadName, desc="Timesharing Finger"),
             load=dict(s=HTMLLoad),
             name=dict(s=HTMLName,desc="Name/Whois", onlyhost=True, seealso='loadname'),
             routing=dict(s=HTMLDumpRoutingTable, header="Routing tables"),
             lastseen=dict(s=HTMLLastSeen, desc="LastSeen"))

qs = urllib.parse.parse_qs(os.getenv('QUERY_STRING'),keep_blank_values=True)
host = qs['host'] if 'host' in qs else None
user = qs['user'] if 'user' in qs else None
srvc = qs['service[]'] if 'service[]' in qs else None
# be supportive
if srvc is None:
    srvc = qs['service'] if 'service' in qs else None

if host and len(host) == 1:
    if "," in host[0]:
        host = list(map(lambda x: x.strip(), host[0].split(",")))
    else:
        host = host[0].split()

print("Content-Type: text/html; charset=utf-8")    # HTML is following
print()                             # blank line, end of headers

print('''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">''')

# sub-requests are fun, do it all over the place
print('''<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/> 
  <title>Chaosnet services</title>
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js" type="text/javascript"></script>
<!-- see https://www.kryogenix.org/code/browser/sorttable/ -->
  <script src="sorttable.js" type="text/javascript"></script>
  <link rel="stylesheet" type="text/css" href="tty.css" />
  <script src="hinfo.js" type="text/javascript"></script>
</head>''')

# first set up the text field for hosts, then the fetched select options, and run any services asked for immediately
harg = " ".join(host) if host else ""
sarg = " ".join(srvc) if srvc else ""
uarg = ",".join(user) if user else ""
print("<body onload='setupHostsAndServices(\"{0}\",\"{1}\",\"{2}\");loadHostsAndSubnets(\"{0}\",\"{1}\",\"{2}\");loadServices()'>".format(harg,sarg, uarg))

print('<a href="hostat.html">Status</a>&nbsp;<a href="time.html">Time</a>&nbsp;<a href="uptime.html">Uptime</a>&nbsp;<a href="finger.html">Finger</a>&nbsp;<a class="current" href="hinfo.py">More services</a>')
print("<h1>Chaosnet services</h1>")
print("<p>What services do you require? Please select a host/subnet or more, and a service or more, then click Run.</p>")
print("<p style='font-size: 67%'>Note: info for individual subnets not directly connected might be wrong or missing.</p>")

# Print form at beginning
print('''<div><form id='hostform'>
<span id='hostselect'>
<label for="host">Host/subnet</label>
<input type="text" name="host" id="host" onchange="enableRunButtonByHost(this)" />
</span>''')
print('<button style="vertical-align: top" value="Refresh" title="Refresh host/subnet list" type="button" onclick="loadHostsAndSubnets(\'{}\',\'{}\',\'{}\')">&#10226;</button>'.format(harg,sarg,uarg))
print('''
<div id='services'>
<span id="service_checkboxes">
<label><input type="checkbox" name="service[]" value="all" id="allServices" onchange="selectAllServices(this)" />All services</label>''')
# print the service checkboxes
for s in slist:
    x = slist[s.lower()]
    if 'desc' in x:
        sname = x['desc']
    else:
        sname = s.capitalize()
    print("<label><input id='checkbox_{0}' type=\"checkbox\" name=\"service[]\" value=\"{0}\" onchange=\"uncheckAllServices(this);unhideUserInput(this)\" />{1}</label>".format(s, sname))
print("</span>")

# unhide this when Name protocol checked
print('''<div id='userinput' hidden='hidden'>
<label for='user'>User (for Name/Whois):</label>
<input type='text' name='user' id='user' />
</div>
</div>
<input type='button' value="Run" onclick="loadServices()" id='runbutton' disabled='disabled' />
<input type='button' value='Clear' onclick='clearServices()' />
</form></div>''')

# Placeholders for the service.py output, see loadService.
for s in slist:
    print("<div class='service_container' id=\"{}\"></div>".format(s))

print('''</body>
</html>''')
