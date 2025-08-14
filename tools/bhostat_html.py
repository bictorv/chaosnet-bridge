# Copyright © 2024 Björn Victor (bjorn@victor.se)
# Extension of bhostat.py to produce results in HTML rather than plain text.

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from bhostat import Status, ChaosUptime, ChaosTime, ChaosFinger, ChaosDumpRoutingTable, ChaosName, ChaosLoadName, ChaosLoad, ChaosLastSeen, ChaosSimpleStatus, host_name, debug, SimpleStreamProtocol
from chaosnet import dns_name_of_address, get_dns_host_info, dns_info_for, dns_resolver_name, dns_resolver_address, set_dns_resolver_address, ChaosError, EOFError
from datetime import timedelta
import sys, html, re

# Make it easier to make tables
class HTMLtable():
    table = None
    columns = None
    def __init__(self,cols):
        self.columns = cols
    def start(self, id, tclass):
        return "<table id='{}' class='{} sortable '>".format(id,tclass)
    def item(self,val,cclass):
        # @@@@ entity-encode values before calling.
        classstring = "" if cclass is None else " class='{}' ".format(cclass)
        if isinstance(val,tuple) and isinstance(val[1],dict):
            # A value can be a pair of a value and a dict of attribute-values
            kv = " ".join("{}=\"{}\"".format(k,v) for k,v in val[1].items())
            return "<td{} {}>{}</td>".format(classstring,kv,val[0])
        else:
            return "<td{}>{}</td>".format(classstring,val)
    def header(self):
        return "<thead>\n <tr>"+"".join(map (lambda hc: self.item(hc[0],hc[1]), self.columns))+"</tr>\n</thead>"
    def row(self,values):
        return " <tr>"+"".join(map(lambda v,hc: self.item(v,hc[1]), values, self.columns))+"</tr>"
    def end(self):
        return "</table>"


class HTMLStatus(Status):
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),
                                ("Name","status_name")]+
                               list(map(lambda h: (h,"status_num"),["Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected"])))
        return self.table.start('status_table','status')+self.table.header()
    def footer(self):
        return self.table.end()
        # return "</table>"
    def printer(self,src,data):
        hname,statuses = self.parse_status_data(src,data)
        # Now print it
        # Find the DNS name if possible
        dname = dns_name_of_address(src,onlyfirst=False,timeout=2)
        if dname is None:
            first = hname
        elif dname.lower().startswith(hname.lower()+".") or dname.lower() == hname.lower():
            # don't use title unless it clarifies something
            first = dname
        else:                   # make a pretty title
            first = "<a title=\"{}\">{}</a>".format(html.escape(hname,quote=True), dname)
        if statuses is not None:
            # Put name for later rows with "display: none" so it doesn't show, but table can be sorted,
            # and change the attribute after sorting.
            # Make link decoration (for sorting headers) a frame, like Lispm?
            srcaddr = "{:o}".format(src)
            for s in statuses:
                print(self.table.row([srcaddr,first,
                                      "<a href='hinfo.py?service[]=dns&host={0:o}'>{0:o}</a>".format(s)]
                                     +list(statuses[s].values())))
                # Only print the name for the first subnet entry
                # first = ""
                # srcaddr = ""

class HTMLUptime(ChaosUptime):
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Name","status_name"),("Uptime","status_num")])
        return self.table.start('uptime_table','uptime')+self.table.header()
    def footer(self):
        return self.table.end()
    def printer(self,src,data):
        up,s = self.parse_uptime_data(data)
        # Now print it
        # find the DNS name if possible
        if up is not None:
            dname = dns_name_of_address(src,onlyfirst=False,timeout=2)
            if dname is None:
                first = "{:o}".format(src)
            else:
                first = dname
            print(self.table.row(["{:o}".format(src),first,(up,dict(sorttable_customkey=s))]))

class HTMLTime(ChaosTime):
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Name","status_name"),("Time","status_center"),("Delta","status_center")])
        return self.table.start('time_table','time')+self.table.header()
        # return "<table id='time_table' class=\"time sortable \">\n<thead><tr><th class=\"status_num\">Addr</th><th class=\"status_name\">Name</th><th>Time</th><th>Delta</th></tr></thead>"
    def footer(self):
        return self.table.end()
    def printer(self,src,data):
        ts,t,dt = self.parse_time_data(data)
        # Now print it
        # find the DNS name if possible
        # print("<!-- {} {} {} -->".format(ts,t,dt), file=sys.stderr)
        if t is not None:
            dname = dns_name_of_address(src,onlyfirst=False,timeout=2)
            if dname is None:
                first = "{:o}".format(src)
            else:
                first = dname
            print(self.table.row(["{:o}".format(src),first,(ts,dict(sorttable_customkey=t)),
                                  ("{}{}".format("+" if dt >= 0 else "-",timedelta(milliseconds=abs(1000*dt))),dict(sorttable_customkey=dt))]))
            # print("<tr><td class=\"status_num\">{:o}</td><td class=\"status_name\">{}</td><td sorttable_customkey=\"{}\">{}</td><td sorttable_customkey=\"{}\" class=\"status_center\">{}{}</td></tr>"
            #           .format(src,first,t,ts,dt,"+" if dt >= 0 else "-",timedelta(milliseconds=abs(1000*dt))))

class HTMLDumpRoutingTable(ChaosDumpRoutingTable):
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Host","status_name"),("Net","status_num"),("Meth","status_num"),("Cost","status_num")])
        return self.table.start('routing_table','routing')+self.table.header()
    def footer(self):
        return self.table.end()
    def printer(self,src,data):
        # hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
        saddr = "{:o}".format(src)
        hname = dns_name_of_address(src,onlyfirst=False,timeout=2)
        rtt = self.parse_routing_data(data)
        for sub in rtt:
            print(self.table.row([saddr,hname,"{:o}".format(sub),"{:o}".format(rtt[sub]['method']),rtt[sub]['cost']]))

class HTMLLastSeen(ChaosLastSeen):
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Host","status_name"),("Seen","status_name"),("SeenAddr","status_num"),("#in","status_num"),("Via","status_num"),("FC","status_num"),("Age","status_num")])
        return self.table.start('lastseen_table','lastseen')+self.table.header()
    def footer(self):
        return self.table.end()
    def printer(self,src,data):
        # hname = "{} ({:o})".format(host_name("{:o}".format(src)), src)
        saddr = "{:o}".format(src)
        hname = dns_name_of_address(src,onlyfirst=False,timeout=2)
        cn = self.parse_lastcn_data(data)
        for addr in cn:
            e = cn[addr]
            a = timedelta(seconds=e['age'])
            print(self.table.row([saddr,hname,dns_name_of_address(addr,onlyfirst=False,timeout=2),"{:o}".format(addr),e['input'],"{:o}".format(e['via']),e['fc'],(a,dict(sorttable_customkey=e['age']))]))

class GroupAffiliation:
    # Show a cute tooltip for the affiliation.
    # See INQUIR;INQUIR
    group_affiliations = dict({'+':"Official maintainter/Liaison on some MIT computer system.",
                               '$':"Official maintainter/Liaison on some ARPANET computer system.",
                               '@':"This is an alias for someone known under another name."},
                              A="Artificial Intelligence Lab person.",
                              B="Educational Computing Group person.",
                              C="Theory Group person.",
                              L="Laboratory for Computer Science person.",
                              P="Plasma Fusion Center person.",
                              S="MIT guest - student/staff/faculty not in one of the other groups.",
                              T="Guest (tourist).",
                              V="NIL Group.",
                              Z="Clinical Decision Making person.",
                              O="Other.  This designates a program, not a person."
                              )
    group_relations = dict(A="Administrative",
                           F="Faculty",
                           G="Graduate student",
                           P="Publications/Editing",
                           R="Research associate",
                           S="DSR (sponsored research)",
                           U="Undergraduate student",
                           X="Ex-user (former MIT staff/faculty)",
                           N="") # none
    def group_affiliation_desc(self,affiliation_and_relation):
        atext = ""
        rtext = ""
        rel = ""
        if len(affiliation_and_relation) == 2:
            rel = affiliation_and_relation[1]
            aff = affiliation_and_relation[0]
        else:
            aff = affiliation_and_relation
        if aff in self.group_affiliations:
            atext = self.group_affiliations[aff]
        if rel in self.group_relations:
            rtext = " ("+self.group_relations[rel]+")"
        if len(atext) > 0:
            return (affiliation_and_relation,dict(title="Affiliation: "+html.escape(atext+rtext,quote=True)))
        else:
            return affiliation_and_relation


class HTMLDNSinfo:
    field_names = dict(netname="Network name",
                       canonical="Canonical name",
                       addrs="Address(es)",
                       hinfo="Host info",
                       os="Operating system",
                       cpu="CPU",
                       responsible="Responsible person",
                       txt="Other info")
    def __init__(self,hosts,options=None):
        print("<dl>")
        # if -1, do a STATUS broadcast to find out
        sbn = list(filter(lambda x: isinstance(x,int) and x <= 0xff, hosts))
        if len(sbn) > 0 and len(hosts) > len(sbn):
            s = ChaosSimpleStatus(sbn,dict(timeout=2))
            # @@@@ this filtering should be done for all broadcast services?
            # @@@@ as is, ChaosHostat, LastSeen etc for non-connected subnet (e.g. 13) will return info for localhost
            # However, if localhost is on e.g. net 6 and 7, you ask for net 7, you might get a reply from the net 6 address of localhost.
            # @@@@ Why did I do it that way, why does cbridge answer first and check the bitmask later?
            # Add filtering also to be able to do "remote broadcast" (e.g. net 13) by broadcasting to all (on the path)
            # and filtering the result.
            if -1 not in sbn and len(sbn) > 0:
                # Filter out those not on the selected subnets, but keep the selected ones
                subs = list((s.subnets & set(sbn) | set(sbn)))
                hsts = [x[0] for x in s.hname_addrs if int(x[1]/256) in sbn]
            else:
                subs = list(s.subnets)
                hsts = list(s.hosts)
            subs.sort()
            hsts.sort()
            hosts = subs+hsts
            print("<!-- using {!r} for hosts -->".format(hosts), file=sys.stderr)
        for host in hosts:
            if host == -1:
                print("<dt>Can't check all subnets (yet), please pick individuals.</dt>")
                continue
            info = dns_info_for(host)
            self.formatter(host,info)
        print("</dl>")
    def formatter(self, name, info):
        print("<dt>{}</dt>".format(name if isinstance(name,str) else "Address {:o}".format(name) if name > 0xff else "Subnet {:o}".format(name)))
        print("<dd><dl>")
        for k in ['netname','name','canonical','addrs','hinfo','responsible','txt']:
            if k in info:
                print("<dt>{}:</dt><dd>{}</dd>".format(
                    self.field_names[k] if k in self.field_names else k.capitalize(),
                    self.format_field(k,info[k])))
        print("</dl></dd>")
    def format_rp(self,val):
        return "Email {}{}".format(
            val['mbox'],        # maybe make a mailto: link one day?
            html.escape(" ({})".format(", ".join(", ".join(x) for x in val['text'])) if 'text' in val and val['text'] and len(val['text']) > 0 else ""))
    def format_field(self, key, val):
        if key == 'responsible':
            return "</dd><dd>".join(self.format_rp(v) for v in val)
        elif key =='hinfo':
            return html.escape("a {} system running {}".format(val['cpu'],val['os']))
        elif key == 'addrs':
            return "{}".format(", ".join("{:o} (on subnet {:o})".format(x, int(x/256)) for x in val))
        elif isinstance(val,list) and len(list(filter(lambda x: not(isinstance(x,int)), val))) == 0:
            # list of only ints
            return "{}".format(", ".join(format(x,'o') for x in val))
        elif isinstance(val,list) and len(list(filter(lambda x: not(isinstance(x,str)), val))) == 0:
            # list of only strs
            return html.escape(", ".join(val))
        elif isinstance(val,list) and len(list(filter(lambda x: not(isinstance(x,list)), val))) == 0:
            # list of only lists
            return html.escape(", ".join(", ".join(x) for x in val))
        else:
            return html.escape(val)
        


class HTMLName(ChaosName,GroupAffiliation):
    def __init__(self, hosts, options=None, args=[]):
        self.args = args
        for host in hosts:
            try:
                p = SimpleStreamProtocol(host,"NAME",options=options,args=args)
                self.formatter(p,host,len(hosts)>1)
            except EOFError:
                if len(hosts) > 1:
                    print("<h3>[{}]</h3>".format(host))
                print("<p>No info from {}</p>".format(host))
            except ChaosError as m:
                print(m, file=sys.stderr)
                pass
    def formatter(self,p,host,print_individual_header):
        # Parse NAME output to give it structure.
        # Read first line
        # - if it is short: "No users", empty etc, just show it
        # - headers: collect and save indexes of starts
        #   Header heuristic: "[A-Z][a-z]+ ?[a-z]*" (with zero, one, or two dashes before+after)
        # if headers, read successive lines, and create rows based on header indexes.
        # A gross hack is applied to detect and handle the affiliation part of ITS output (which doesn't have a header).
        hack_its_uname = False
        if self.args and len(self.args) > 0:
            # probably /W, and that output is too hairy
            print("<pre>", end='')
            p.copy_until_eof()
            print("</pre>")
            return
        line = str(p.conn.get_line(),"ascii")
        if '\t' in line:
            if debug:
                print("Found tab in NAME output from {}".format(host), file=sys.stderr)
            line = line.expandtabs()
        if re.search("  +",line):
            headers = []
            indexes = []
            rows = []
            s = 0
            # since regexps can't count, use explicit variants with --Header--, -Header-, and Header
            for m in re.finditer("(--[A-Z]+[a-z]* ?[a-z]*--)|(-[A-Z]+[a-z]* ?[a-z]*-)|([A-Z]+[a-z]* ?[a-z]*)",line): # "  +"
                # save index of next header start
                indexes.append(m.start() if m.start() != 1 else 0)
                # save this header
                headers.append(line[m.start():m.end()].strip())
                s = m.end()
            if len(line[s:].strip()) > 0:
                headers.append(line[s:].strip())
            # @@@@ ITS affiliation hack alert
            if headers[0] == '-User-':
                # Check header before looking up in DNS, for speed
                hn = dns_name_of_address(host) if re.match("^[0-7]+$",host) else host
                hi = get_dns_host_info(hn, timeout=2)
                if hi and 'os' in hi and hi['os'].lower() == "its":
                    # add an empty affiliation header
                    headers = headers[0:1]+[""]+headers[1:]
                    hack_its_uname = True
            try:
                nl = str(p.conn.get_line(),"ascii")
                while len(nl) > 0:
                    row = []
                    istart = 1
                    s = 0
                    if hack_its_uname:
                        # Hack the first element
                        uname = nl[s:indexes[1]].strip()
                        # check for "UNAME FR" where F is affiliation and R is relation
                        m = re.match("([A-Z]+) +([A-Z]{1,2}|[$@+-]|-->)$",uname)
                        if m:
                            # append them separately
                            # row.append("<a href='hinfo.py?service=name&host={}&user={}>{}</a>".format(host,m.group(1),m.group(1)))
                            row.append(m.group(1))
                            row.append(self.group_affiliation_desc(m.group(2)))
                        else:
                            row.append(uname)
                            row.append("") # empty affiliation, perhaps
                        s = indexes[1]   # skip over
                        istart = 2
                    # Collect the elements of the row
                    for i in indexes[istart:]:
                        row.append(nl[s:i].strip())
                        s = i
                    # and the last one
                    row.append(nl[s:].strip())
                    rows.append(row)
                    nl = str(p.conn.get_line(),"ascii")
            except ChaosError as m:
                # print(m,file=sys.stderr)
                pass
            tbl = HTMLtable(list(map(lambda h: (h,"status_name"), headers)))
            if print_individual_header:
                print("<h3>[{}]</h3>".format(host))
            print(tbl.start('name_table','name')+tbl.header())
            for r in rows:
                r[0] = "<a href='hinfo.py?service[]=name&host={}&user={}'>{}</a>".format(host,r[0],r[0])
                print(tbl.row(r))
            print(tbl.end())
        else:
            # no headers, just use first line
            if print_individual_header:
                print("<h3>[{}]</h3>".format(host))
            if len(line.strip()) == 0:
                print("<p>(No info.)</p>")
            elif len(line) < 20:  # short msg, like "No users"
                print("<p>{}</p>".format(html.escape(line)))
            else:
                print("<pre>{}</pre>".format(html.escape(line)))

class HTMLLoadName(ChaosLoadName):
    def call_name(self, hname, options=None):
        self.print_header(hname)
        HTMLName([hname], options=options)
    def print_header(self, hname):
        print("<h3>[{}]</h3>".format(hname))
    def print_n_users(self, n):
        print("<p>Users: {}</p>".format(n))
    def nonprinter(self,datas):
        if len(datas) > 0:
            hnames = []
            # Collect the host names of empty hosts - use short name here
            for src,d in datas:
                hnames.append(host_name("{:o}".format(src)))
            # Report it.
            print("<p>No users on "+", ".join(hnames)+".</p>")

class HTMLLoad(ChaosLoad):
    def header(self):
        self.table = HTMLtable([("Host","status_name"),("Fair Share","status_num"),("Users","status_num")])
        return self.table.start('load_table','load')+self.table.header()
    def footer(self):
        return self.table.end()
    def printer(self, src, data):
        try:
            hname = dns_name_of_address(src,onlyfirst=False,timeout=2)
        except:
            hname = "{:o}".format(src)
        fields = list(map(lambda x: str(x.split(b':')[1],'ascii').strip('.\0 '),data.split(b"\r\n")))
        print("{!r}".format(fields[1]), file=sys.stderr)
        print(self.table.row(["<a href='hinfo.py?service[]=name&host={0}'>{0}</a>".format(hname) if fields[1] != "0" else hname,
                              fields[0],fields[1]]))


class HTMLFinger(ChaosFinger,GroupAffiliation):
    def header(self):
        # debug = True
        self.table = HTMLtable([("User","status_name"),("","status_name"),("Name","status_name"),("Host","status_name"),
                                ("Idle","status_num"),("Location","status_name")])
        return self.table.start('finger_table','finger')+self.table.header()
    def footer(self):
        return self.table.end()
    def printer(self,src,data):
        hname = host_name("{:o}".format(src))
        fields,idle = self.parse_finger_data(data)
        if fields[0] == "":
            return False
        # uname affiliation pname hname idle loc
        print(self.table.row([fields[0],self.group_affiliation_desc(fields[4]),fields[3],hname,(fields[2],dict(sorttable_customkey=idle)),fields[1]]))
        return True
    def nonprinter(self,freelist):
        if len(freelist) > 0:
            print("<h3>Free (lisp) machines:</h3>")
            tbl = HTMLtable([("Host","status_name"),("Location","status_name"),("Idle","status_num")])
            print(tbl.start('free_lispm','finger')+tbl.header())
            for src,data in freelist:
                hname = host_name("{:o}".format(src))
                f = list(map(lambda x: str(x,'ascii'),data.split(b"\215")))
                print(tbl.row([hname,f[1],"{:s}".format(f[2]) if f[2] != "" else ""]))
            print(tbl.end())
        else:
            print("<p>No free lisp machines.</p>")

                
