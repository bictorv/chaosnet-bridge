# Copyright © 2024-2026 Björn Victor (bjorn@victor.se)
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

# @@@@ make tooltips for short host names

from bhostat import ChaosSimpleStatus, debug
from chaosnet import BroadcastStatusDict, BroadcastUptimeDict, BroadcastTimeDict, BroadcastDumpRoutingTableDict, BroadcastLastSeenDict, NamesDict, BroadcastLoadDict, BroadcastLoadDict, BroadcastFingerDict
from chaosnet import dns_name_of_address, get_dns_host_info, dns_info_for, dns_resolver_name, dns_resolver_address, set_dns_resolver_address, host_name, get_canonical_name, parse_idle_time_string, ChaosError, EOFError
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

def name_host_with_tooltip(addr, user=None, longname=False):
    if isinstance(addr,int) or re.match("^[0-7]+$",addr):
        dname = dns_name_of_address(addr, timeout=2)
        hname = host_name(addr) if not longname else dname
        if not longname:
            hname = hname.split(".", maxsplit=1)[0] # even a STATUS reply might have a domain
    else:
        dname = get_canonical_name(addr)
        hname = dname
        if not longname:
            hname = hname.split(".", maxsplit=1)[0]
    if user is None:
        return "<a title='More info about {0}' href='hinfo.py?host={0}&service[]=dns&service[]=uptime&service[]=load&service[]=name'>{1}</a>".format(dname,hname)
    elif re.match(r"___\d\d\d", user):
        return user
    else:
        return "<a title='Whois {1}@{0}' href='hinfo.py?service[]=name&host={0}&user={1}'>{2}</a>".format(dname,user,user)

class HTMLSimple:
    def __init__(self, hosts, args=[], options=None):
        result = self.getter_class(hosts, args=args, options=options).dict_result()
        print(self.header())
        self.printer(result)
        print(self.footer())
    def footer(self):
        # default implementation
        return self.table.end()

class HTMLStatus(HTMLSimple):
    getter_class = BroadcastStatusDict

    def header(self):
        self.table = HTMLtable([("Addr","status_num"),
                                ("Name","status_name")]+
                               list(map(lambda h: (h,"status_num"),["Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected"])))
        return self.table.start('status_table','status')+self.table.header()
    def printer(self,result):
        for r in result:
            src = r['source']
            # make a pretty title
            first = name_host_with_tooltip(src, longname=True)
            if r['status'] is not None:
                # Put name for later rows with "display: none" so it doesn't show, but table can be sorted,
                # and change the attribute after sorting.
                # Make link decoration (for sorting headers) a frame, like Lispm?
                srcaddr = "{:o}".format(src)
                for s in r['status']:
                    print(self.table.row([srcaddr,first,
                                          "<a href='hinfo.py?service[]=dns&host={0:o}'>{0:o}</a>".format(s)]
                                         +list(r['status'][s].values())))
                    # Only print the name for the first subnet entry
                    # first = ""
                    # srcaddr = ""

class HTMLUptime(HTMLSimple):
    getter_class = BroadcastUptimeDict
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Name","status_name"),("Uptime","status_num")])
        return self.table.start('uptime_table','uptime')+self.table.header()
    def printer(self,result):
        for up in [r for r in result if r is not None]:
            print(self.table.row(["{:o}".format(up['source']),name_host_with_tooltip(up['source'],longname=True),(up['delta'],dict(sorttable_customkey=up['sec']))]))

class HTMLTime(HTMLSimple):
    getter_class = BroadcastTimeDict
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Name","status_name"),("Time","status_center"),("Delta","status_center")])
        return self.table.start('time_table','time')+self.table.header()
    def printer(self,result):
        for t in [r for r in result if r is not None]:
            print(self.table.row(["{:o}".format(t['source']),name_host_with_tooltip(t['source'],longname=True),
                                  (t['dt'],dict(sorttable_customkey=t['timestamp'])),
                                  ("{}{}".format("+" if t['delta'] >= 0 else "-",timedelta(milliseconds=abs(1000*t['delta']))),dict(sorttable_customkey=t['delta']))]))

class HTMLDumpRoutingTable(HTMLSimple):
    getter_class = BroadcastDumpRoutingTableDict
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Host","status_name"),("Net","status_num"),("Meth","status_num"),("Cost","status_num")])
        return self.table.start('routing_table','routing')+self.table.header()
    def printer(self,result):
        for rtt in result:
            hname = name_host_with_tooltip(rtt['source'], longname=True)
            saddr = "{:o}".format(rtt['source'])
            for sub in rtt['routingtable']:
                print(self.table.row([saddr,hname,"{:o}".format(sub),"{:o}".format(rtt['routingtable'][sub]['method']),rtt['routingtable'][sub]['cost']]))

class HTMLLastSeen(HTMLSimple):
    getter_class = BroadcastLastSeenDict
    def header(self):
        self.table = HTMLtable([("Addr","status_num"),("Host","status_name"),("Seen","status_name"),("SeenAddr","status_num"),("#in","status_num"),("Via","status_num"),("FC","status_num"),("Age","status_num")])
        return self.table.start('lastseen_table','lastseen')+self.table.header()
    def printer(self,result):
        for r in result:
            saddr = "{:o}".format(r['source'])
            hname = name_host_with_tooltip(r['source'], longname=True)
            for addr in r['lastseen']:
                e = r['lastseen'][addr]
                a = timedelta(seconds=e['age'])
                print(self.table.row([saddr,hname,name_host_with_tooltip(addr,longname=True),"{:o}".format(addr),e['input'],"{:o}".format(e['via']),e['fc'],(a,dict(sorttable_customkey=e['age']))]))

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
        


class HTMLName(HTMLSimple,GroupAffiliation):
    getter_class = NamesDict
    def __init__(self, hosts, args=[], options=None):
        result = self.getter_class(hosts, args=args, options=options).dict_result()
        if len(result) == 1 and 'rawlines' in result[0]:
            # Skip table header/footer for rawlines case.
            # This doesn't handle a mix of rawlines and non-rawlines, but this is the typical case.
            self.printer(result)
        else:
            print(self.header())
            self.printer(result)
            print(self.footer())

    def header(self):
        self.table = HTMLtable([("User","status_name"),("","status_name"),("Personal name","status_name"),
                                ("Jobname","status_name"), ("Idle","status_num"),
                                ("TTY","status_name"), ("Host","status_name"),("Location","status_name")])
        return self.table.start('name_table','name')+self.table.header()
    def printer(self, result):
        for hn in result:
            if isinstance(hn['source'], int):
                hname = dns_name_of_address(hn['source'], timeout=2)
            else:
                hname = get_canonical_name(hn['source'])
            if isinstance(hname,str):
                dot = hname.find(".")
                if dot >= 0:
                    hname = hname[:dot]
            if 'rawlines' in hn:
                print("<pre>{}</pre>".format(hn['rawlines']))
            else:
                for n in hn['lines']:
                    print(self.table.row([
                        name_host_with_tooltip(hn['source'], n['userid']),
                        self.group_affiliation_desc(n['affiliation']), n['pname'], n['jobname'], 
                        (n['idle'],dict(sorttable_customkey=parse_idle_time_string(n['idle']))),
                        n['tty'], name_host_with_tooltip(hn['source']), n['location']]))
                
class HTMLLoadName(HTMLName):
    def __init__(self, hosts, args=[], options=None):
        llist = BroadcastLoadDict(hosts, args=args, options=options).dict_result()
        self.nousers = [l['source'] for l in llist if l['users'] == 0]
        nlist = NamesDict(["{:o}".format(l['source']) for l in llist if l['users'] > 0], args=args, options=options).dict_result()
        print(self.header())
        self.printer([n for n in nlist if n is not None])
        print(self.footer())
    def footer(self):
        if len(self.nousers) == 0:
            return super().footer()
        else:
            return super().footer() + "\n<p>No users on {}.</p>".format(", ".join(map(lambda s: host_name(s), self.nousers)))

class HTMLLoad(HTMLSimple):
    getter_class = BroadcastLoadDict
    def header(self):
        self.table = HTMLtable([("Host","status_name"),("Fair Share %","status_num"),("Users","status_num")])
        return self.table.start('load_table','load')+self.table.header()
    def printer(self, result):
        for r in result:
            print(self.table.row([name_host_with_tooltip(r['source'],longname=True), r['share'], r['users']]))


class HTMLFinger(HTMLSimple,GroupAffiliation):
    getter_class = BroadcastFingerDict
    def header(self):
        self.free_lispm = []
        self.table = HTMLtable([("User","status_name"),("","status_name"),("Name","status_name"),("Host","status_name"),
                                ("Idle","status_num"),("Location","status_name")])
        return self.table.start('finger_table','finger')+self.table.header()
    def printer(self,result):
        for hn in result:
            if len(hn['uname']) == 0:
                self.free_lispm.append(hn)
            else:
                # uname affiliation pname hname idle loc
                print(self.table.row([hn['uname'],self.group_affiliation_desc(hn['affiliation']), hn['pname'],
                                      name_host_with_tooltip(hn['source']),
                                      (hn['idle'],dict(sorttable_customkey=parse_idle_time_string(hn['idle']))),
                                      hn['location']]))
    def footer(self):
        if len(self.free_lispm) == 0:
            return super().footer() + "\n<p>No free lisp machines.</p>"
        else:
            s = "<h3>Free (lisp) machines:</h3>\n"
            tbl = HTMLtable([("Host","status_name"),("Location","status_name"),("Idle","status_num")])
            s += tbl.start('free_lispm','finger')+tbl.header()
            for hn in self.free_lispm:
                s += tbl.row([name_host_with_tooltip(hn['source']),hn['location'],hn['idle']])
            s += tbl.end()
            return super().footer() + s

# Just for debug/development
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet simple protocol client',
                                         epilog="If the service is unknown and a host is given, "+\
                                         "tries to contact the service at the host and prints its output. "+\
                                         "If no service arg is given, but the first subnet arg is the name of a known service, "+\
                                         "and another subnet arg exists, the first subnet arg is used as service arg.")
    parser.add_argument("subnets", metavar="SUBNET/HOST", nargs='+', #type=int, 
                            help="Hosts to contact or Subnets (octal) to broadcast on, -1 for all subnets, or 0 for the local subnet")
    args = parser.parse_args()
    if -1 in args.subnets and len(args.subnets) != 1:
        # "all" supersedes all other
        args.subnets = [-1]
    elif 0 in args.subnets and len(args.subnets) != 1:
        # "local" supersedes all other
        args.subnets = [0]
    # Parse "subnet" args as octal numbers (if they can be)
    args.subnets = list(map(lambda x: int(x,8) if isinstance(x,str) and (x.isdigit() or x =="-1") else x, args.subnets))
    HTMLLoadName(args.subnets)
