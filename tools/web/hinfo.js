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
function loadService(svcargs, sid, name) {
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
            document.getElementById(e.value).innerHTML = "";
        }
    }
    document.getElementById('user').value = "";
    // no service selected, so Run button should be disabled.
    document.getElementById('runbutton').disabled = true;
}
function enableRunButtonByHost(elem) {
    // If we have some host selected, then enable the Run button if we have a service checked
    if (elem.tagName == "INPUT" && elem.value.trim().length > 0) {
        hselect = true;
    } else {
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
        } else {
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
            if (serv.search(o.value) >= 0) {
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
