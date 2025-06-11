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

from bhostat import Status
from chaosnet import dns_name_of_address, dns_resolver_name, dns_resolver_address, set_dns_resolver_address

class HTMLStatus(Status):
    def header(self):
        return "<table id='status_table' class=\"status sortable \">\n<thead><tr><th class=\"status_num\">Addr</th><th class=\"status_name\">Name</th><th class=\"status_num\">"+"</th><th class=\"status_num\">".join(["Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected"])+"</th></tr></thead>"
    def footer(self):
        return "</table>"
    def printer(self,src,data):
        hname,statuses = self.parse_status_data(src,data)
        # Now print it
        if True or " " in hname: # and not no_host_names:
            # This must be a "pretty name", so find the DNS name if possible
            dname = dns_name_of_address(src,onlyfirst=False,timeout=2)
            if dname is None:
                first = hname
            else:
                first = "<a title=\"{}\">{}</a>".format(dname, hname)
        else:
            first = hname
        if statuses is not None:
            # Put name for later rows with "display: none" so it doesn't show, but table can be sorted,
            # and change the attribute after sorting.
            # Make link decoration (for sorting headers) a frame, like Lispm?
            srcaddr = "{:o}".format(src)
            for s in statuses:
                print(("<tr><td class=\"status_num\">{}</td><td class=\"status_name\">{}</td><td class=\"status_num\">{:o}</td>"+"<td class=\"status_num\">{}</td>"*len(statuses[s])).format(srcaddr,first,s,*statuses[s].values())+"</tr>")
                # Only print the name for the first subnet entry
                # first = ""
                # srcaddr = ""
