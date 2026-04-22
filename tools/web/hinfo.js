// Gross hacks, should be cleaned up.
function loadHostsAndSubnets(ihosts,iserv,iuser) {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
	    var hs = document.getElementById('hostselect');
	    if (hs != null) {
		hs.innerHTML = this.responseText;
	    }
            setupHostsAndServices(ihosts,iserv,iuser);
	}
    }
    // @@@@ consider making this return XML and transforming it nicely here?
    // This now returns a select with options.
    xhttp.open("GET","allhosts.py", true);
    xhttp.send();
}
function name_host_with_tooltip(dname) {
    const hname = dname.split(".",1)[0];
    return(`<a title="More info about ${dname}" href="hinfo.py?host=${dname}&service[]=dns&service[]=uptime&service[]=load&service[]=name">${hname}</a>`);
}
function name_user_with_tooltip(user,dname) {
    if (user.match(/___\d\d\d/)) // ITS not-logged-in
	return user;
    return(`<a title='Whois ${user}@${dname}' href="hinfo.py?service[]=name&host=${dname}&user=${user}">${user}</a>`);
}
function parse_idle_time_string(s) {
    if (typeof(s) == "number") {	// already a number?
	return s;
    }
    if (s == "") {
	return 0;
    }
    if (s.startsWith("*:**")) {	// could be "*:**."
	return 0xffff;		// many minutes!
    }
    var m = s.match(/(\d+):(\d+)/);
    if (m) {			// HH:MM?
	return(Number.parseInt(m[1])*60+Number.parseInt(m[2]));
    }
    m = s.match(/(\d+)d/);
    if (m) {			// NNd?
	return Number.parseInt(m[1])*24*60;
    }
    m = s.match(/(\d+)/);
    if (m) {			// Plain MM?
	return Number.parseInt(m[1]);
    }
    return s;			// Don't know.
}
function loadNameService(src, sid, tbl, headers) {
    // Load Name service, and when result comes, add it to the table at "sid".
    // @@@@ consider integrating Finger service in this?
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
	    var resplist = JSON.parse(this.responseText);
	    if (resplist.length == 0)
		return;
	    var resp = resplist[0];
	    // make the table visible - shouldn't be needed since it's freshly created when load returns
	    // tbl.style.display = "block";
	    // get a hold of the tbody
	    var b = tbl.getElementsByTagName("tbody")[0];
	    // create a host element
	    var dname = resp['dname'];
	    var h = document.createElement("td");
	    if (resp.dname) {
		h.innerHTML = name_host_with_tooltip(dname);
	    } else {
		h.innerHTML = resp['source'];
	    }
	    h.className = 'status_name sortable ';
	    for (n of resp["lines"]) {
		// make a new row for each parsed line
		var r = document.createElement("tr");
		var fields = ["userid","affiliation","pname","jobname","idle","tty",h,"location"];
		for (l in fields) {
		    if (typeof(fields[l]) == "string") {
			var e = document.createElement("td");
			e.className = headers[l][1];
			if (fields[l] == "userid")
			    e.innerHTML = name_user_with_tooltip(n[fields[l]],dname);
			else if (fields[l] == "affiliation")
			    // @@@@ group_affiliation_desc
			    e.innerHTML = `<a title="Affiliation">${n[fields[l]]}</a>`;
			else
			    e.innerHTML = n[fields[l]];
			if (fields[l] == "idle") {
			    e.setAttribute("sorttable_customkey",parse_idle_time_string(n["idle"]));
			}
			r.appendChild(e);
		    } else {
			r.appendChild(fields[l].cloneNode(true));
		    }
		}
		// and append the tr to the tbody
		b.appendChild(r);
	    }
	    fixupSVG(tbl.parentNode);	// adjust the SVG (do this for each added host)
	}
    }
    xhttp.open("GET","jsonservice.py?service=name&host="+src, true);
    xhttp.send();
}
function loadTimesharingFinger(svcargs, sid, nameofservice) {
    // Run load service, and when result comes, call name for each.
    var xhttp = new XMLHttpRequest();
    // parse the host URL argument
    sargs = new URLSearchParams(svcargs);
    shost = sargs.get("host");
    // make a nice description of the argument
    var host_desc = [];
    for (h of shost.split(",")) {
	var hn = Number.parseInt(h, 8); // try it as an octal number
	if (Number.isNaN(hn))
	    host_desc.push(h);	// was a host name
	else if (hn == -1)
	    host_desc.push("all hosts");
	else if (hn < 0x400)
	    host_desc.push("subnet "+Number(hn).toString(8));
	else
	    host_desc.push("host "+Number(hn).toString(8));
    }
    xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
	    var resp = JSON.parse(this.responseText);
	    var todo_hosts = [];
	    var free_hosts = [];
	    // see what needs to be done
	    for (i in resp) {
		if (resp[i].users > 0) {
		    todo_hosts.push(resp[i].dname);
		} else {
		    free_hosts.push(resp[i].dname.split(".",1)[0]);
		}
	    }
	    var div = document.getElementById(sid)
	    var p = div.getElementsByTagName("p")[0];
	    var svg = document.createElement("object");
	    svg.setAttribute("type", "image/svg+xml");
	    svg.setAttribute("width", "20%");
	    svg.setAttribute("height", "100%");
	    svg.setAttribute("data", "dragon.svg");
	    svg.style = "float: right;";
	    div.appendChild(svg);
	    const s = 'loadname';
	    const nu = new Date().toDateString() + " " + new Date().toLocaleTimeString();
	    // New header (@@@@ maybe should be h2, but doesn't really matter)
	    p.innerHTML = nameofservice+" for "+host_desc.join(", ")+" "+
		`<button value="Refresh" title="Refresh ${nameofservice} - last refreshed ${nu}" type="button" onclick="loadService(\'${svcargs}\',\'${s}\',\'${nameofservice}\')">&#10226;</button>`+
		`<button value="Clear" title="Clear section" type="button" onclick="clearService(\'${s}\')">&#10005;</button>`;
	    // create a table like in HTMLtable, replace the current sid node with it
	    if (todo_hosts.length > 0) {
		var table = document.createElement("table");
		table.id = "name_table";
		table.className = 'name sortable ';
		var ts = "<thead><tr>";
		header_fields = [["User","status_name"],["","status_name"],["Personal name","status_name"],
				 ["Jobname","status_name"],["Idle","status_num"],["TTY","status_name"],
				 ["Host","status_name"],["Location","status_name"]];
		for (h of header_fields) {
		    ts += "<td class="+h[1]+">"+h[0]+"</td>";
		}
		table.innerHTML = ts + "</tr></thead><tbody></tbody>"; // @@@@ check that tbody is ok with sortable
		div.appendChild(table);
		// @@@@ should add some "Work in progress" indicator, cleared when first row is added
		// for each of the responding hosts with users > 0, load name service
		for (h of todo_hosts) {
		    console.log("Host "+h+" has users, calling NAME");
		    loadNameService(h, sid, table, header_fields);
		}
		fixupTable(table);	// make it sortable
	    }
	    if (free_hosts.length > 0) {
		var f = document.createElement("p");
		f.innerHTML = "No users on "+free_hosts.join(", ")+".";
		div.appendChild(f);
	    }
	    fixupSVG(div);	// adjust the SVG (this is done for each added host, too)
	}
    }
    // Get load service
    document.getElementById(sid).innerHTML = "<p>Checking "+nameofservice+" for "+host_desc.join(", ")+"...<span class='cursor'>&nbsp;</span></p>";
    xhttp.open("GET","jsonservice.py?"+svcargs, true);
    xhttp.send();
}
function loadService(svcargs, sid, name) {
    if (svcargs.match(/service=loadname/)) {
	console.log("Using new TimesharingFinger service");
	return loadTimesharingFinger(svcargs,sid,name);
    }
    // load a service with svcargs, putting the result in the element with id sid
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
            cont = document.getElementById(sid)
            cont.innerHTML = this.responseText;
	    // fix up the size of any SVG object
            fixupSVG(cont);
	    // fix sortable tables
            for(tb of cont.getElementsByClassName('sortable')) {
		fixupTable(tb);
            }
	}
    }
    document.getElementById(sid).innerHTML = "<p>Checking "+name+"...<span class='cursor'>&nbsp;</span></p>";
    xhttp.open("GET","service.py?"+svcargs, true);
    xhttp.send();
}
function loadServices() {
    // load all services we are asked for
    hosts = []
    s = document.getElementById('host');
    // collect host args, either from the simple textinput or from the select options
    if (s.tagName == "INPUT") {
        hosts.push(s.value);
    } else {
        for(o of s.options) {
            if (o.selected) {
		hosts.push(o.value);
            }
        }
    }
    // if we have any hosts, check if we have services
    if (hosts.length > 0 && hosts[0].length > 0) {
        for(e of document.getElementById('service_checkboxes').getElementsByTagName('input')) {
            if (e.checked && e.value != "all") {
		sargs = "host="+hosts.join(",")+"&service="+e.value;
		// special hack for NAME service
		if (e.value == 'name' && document.getElementById('user').value.trim().length > 0) {
                    sargs = sargs + "&user=" + document.getElementById('user').value.trim();
		}
		// load the service, using the checkbox label for name
		loadService(sargs, e.value, e.nextSibling.textContent.trim());
            }
        }
    }
}
function fixupSVG(cont) {
    /* cf https://codepen.io/anon/pen/KVyRQr */
    for (s of cont.getElementsByTagName('object')) {
	// @@@@ should check that it's an SVG object
        /* perhaps set width to page w - table w? Not needed. */
        s.height = getComputedStyle(cont).getPropertyValue('height');
    }
}
function fixupTable(tbl) {
    sorttable.makeSortable(tbl);
    // madness - but Firefox says a title attribute is illegal for th?
    var hr = tbl.tHead.rows[0].cells;
    for (var i=0; i < hr.length; i++) {
        hr[i].title = "Click to sort";
    }
}
function unhideUserInput(elem) {
    // if we're (de)selecting the NAME service, (un)hide the user input
    if (elem.value == 'name') {
        // when NAME service is selected, allow input of username
        u = document.getElementById('userinput');
        u.hidden = !elem.checked;
    }
}
function uncheckAllServices(elem) {
    // when (de)selecting a service, (un)check the "all" checkbox
    if (!(elem.checked)) {
        document.getElementById('allServices').checked = false;
    }
    enableRunButton(elem);
}
function selectAllServices(allbox) {
    // when (de)selecting the All checkbox, (un)check all service checkboxes
    for(e of document.getElementById('service_checkboxes').getElementsByTagName('input')) {
        e.checked = allbox.checked;
    }
    enableRunButton(allbox);
}
function clearServices() {
    // clear all services and inputs, and empty all output
    s = document.getElementById('host');
    if (s.tagName == "INPUT") {
        s.value = "";
    } else {
        for (o of s.options) {
            o.selected = false;
        }
    }
    for(e of document.getElementById('service_checkboxes').getElementsByTagName('input')) {
        e.checked = false;
        if (e.value != "all") {
	    clearService(e.value);
        }
    }
    document.getElementById('user').value = "";
    // no service selected, so Run button should be disabled.
    document.getElementById('runbutton').disabled = true;
}
function clearService(s) {
    document.getElementById(s.trim()).innerHTML = "";
}
function enableRunButtonByHost(elem) {
    // If we have some host selected, then enable the Run button if we have a service checked
    if (elem.tagName == "INPUT" && elem.value.trim().length > 0) {
        hselect = true;
    } else if (elem.tagName == "SELECT") {
        for (o of elem.options) {
            if (o.selected) {
		hselect = true;
		break;
            }
        }
    }
    if (hselect) {
        for (o of document.getElementById('service_checkboxes').getElementsByTagName('input')) {
            if (o.checked) {
		document.getElementById('runbutton').disabled = false;
		break;
            }
        }
    }
}
function enableRunButton(elem) {
    // If we have some service selected, then enable the Run button if we have a host selected
    if (elem.checked) {
        // if a service checkbox is checked, enable the Run button if a host/subnet is selected too.
        rbutt = document.getElementById('runbutton');
        h = document.getElementById('host');
        if (h.tagName == "INPUT" && h.value.trim().length > 0) {
            rbutt.disabled = false;
        } else {
            for (o of h.options) {
		if (o.selected) {
		    rbutt.disabled = false;
		    break;
		}
            }
        }
    } else {
        // check if ANY service is selected, else disable runbutton
        anycheck = false;
        for (o of document.getElementById('service_checkboxes').getElementsByTagName('input')) {
            if (o.checked) {
		anycheck = true;
		break;
            }
        }
        if (!anycheck) {
            rbutt.disabled = true;
        }
    }
}
function setupHostsAndServices(hosts,serv,user) {
    // Set up input fields based on GET args given
    hselect = false;
    if (true) { // hosts.length > 0
        s = document.getElementById('host');
        if (s.tagName == "INPUT") {
            s.value = hosts;
            if (hosts.trim().length > 0) {
		hselect = true;
            }
        } else if (s.tagName == "SELECT") {
            s.onchange=function() { enableRunButtonByHost(s); };
            for (o of s.options) {
		o.onchange=function() { enableRunButtonByHost(o); };
		// o.onselect=function() { enableRunButtonByHost(this); };
		if (hosts.search(o.value) >= 0) {
		    o.selected = true;
		    hselect = true;
		} else {
		    o.selected = false;
		}
            }
        }
    }
    if (serv.length > 0) {
        for (o of document.getElementById('service_checkboxes').getElementsByTagName('input')) {
            if (serv.search("\\b"+o.value+"\\b") >= 0) {
		o.checked = true;
		if (hselect) {
		    document.getElementById('runbutton').disabled = false;
		}
            } else {
		o.checked = false;
            }
        }
    }
    if (user.length > 0) {
        u=document.getElementById('user');
        u.value = user;
        document.getElementById('userinput').hidden = false;
    }
}
