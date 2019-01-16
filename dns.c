// Usage:
// Look up the CN of new TLS connections to see that the host exists,
// and when a SNS appears, check that it comes from the matching address/host.
//
// "DNS tunnelling" from Chaos to UDP.
// Configuration: on/off, DNS forwarder IP, chaos address domain, number of open requests?, debug
// - get a request (RFC), pass query + source host/index to a consumer thread, which responds (ANS) when answer arrives/not
// -- when to send LOS? on non-answer (from DNS) failures
// - use standard consumer/producer lock and semaphores

// TODO
// x add config parsing
// x add to mycontacts: either
// -- make mycontacts dynamic (contacts.c) and add dns_responder to it (in init_dns?)
// x- or just add it in contacts.c, using an #if
// x call init_chaos_dns from main
// x start dns_forwarder_thread
// x parse name/addr in TLS code

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#include "cbridge.h"

// @@@@ these should be configurable at runtime, of course
#ifndef CHAOS_DNS_SERVER
#define CHAOS_DNS_SERVER "130.238.19.25"
#endif
#ifndef CHAOS_ADDR_DOMAIN
// NOT dot-terminated
#define CHAOS_ADDR_DOMAIN "CH-ADDR.NET"
#endif

static int trace_dns = 0;
int do_dns_forwarding = 0;
static char chaos_dns_server[4*3+3+1] = CHAOS_DNS_SERVER;
static char chaos_address_domain[NS_MAXDNAME] = CHAOS_ADDR_DOMAIN;

// resolver state, shared between threads (maybe a bad idea)
struct __res_state chres;

// consumer/producer lock and semaphores
static pthread_mutex_t dns_lock;
static sem_t dns_thread_writer, *dns_thread_writerp;
static sem_t dns_thread_reader, *dns_thread_readerp;

// structure for a DNS request coming in over Chaos
#define CHREQ_MAX 10		/* max concurrent requests @@@@ runtime config? */
struct chaos_dns_req {
  u_short srcaddr;		/* where from */
  u_short srcindex;		/* at what index */
  u_short dstaddr;		/* where was the RFC sent? */
  u_short dstindex;
  u_char *req;			/* malloc:ed copy of request */
  int reqlen;			/* and its length */
};
// circular buffer, len CHREQ_MAX
static struct chaos_dns_req *chreq;
static int *chreq_wix;			/* write index */
static int *chreq_rix;			/* read index */

// not thread safe: extern int h_errno;

static void dns_describe_packet(u_char *pkt, int len);

// called by handle_rfc for an RFC to the "DNS" contact
void
dns_responder(u_char *rfc, int len)
{
  if (sem_trywait(dns_thread_writerp) < 0) {
    if (errno == EAGAIN) {
      // no room for request - don't hang, let other end resend request
      if (trace_dns) fprintf(stderr,"DNS: no room for request, dropping it (wix %d)\n", *chreq_wix);
      return;
    } else {
      perror("sem_trywait(dns responder)");
      exit(1);
    }
  }

  PTLOCK(dns_lock);
  // fill in data
  struct chaos_header *ch = (struct chaos_header *)rfc;
  struct chaos_dns_req *q = &chreq[*chreq_wix];
  int qlen = ch_nbytes(ch)-4; // 4 = "DNS "
  q->srcaddr = ch_srcaddr(ch);
  q->srcindex = ch_srcindex(ch);
  q->dstaddr = ch_destaddr(ch);
  q->dstindex = ch_destindex(ch);
  u_char *req = malloc(qlen);
  if (req == NULL) {
    perror("malloc(dns responder)");
    exit(1);
  }
  // PDP11 swap
  ntohs_buf((u_short *)&rfc[CHAOS_HEADERSIZE+4], (u_short *)req, qlen);
  q->req = req;
  q->reqlen = qlen;
  // update index for next RFC to come
  if (trace_dns) fprintf(stderr,"DNS: added request at wix %d\n", *chreq_wix);
  *chreq_wix = ((*chreq_wix)+1) % CHREQ_MAX;
  PTUNLOCK(dns_lock);

  // tell forwarder to get going
  if (sem_post(dns_thread_readerp) < 0) {
    perror("sem_post(dns responder)");
    exit(1);
  }
}

// from libresolv, ns_parse
// * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
// * Copyright (c) 1996,1999 by Internet Software Consortium.
int
ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count) {
	const u_char *optr = ptr;

	for ((void)NULL; count > 0; count--) {
		int b, rdlength;

		b = dn_skipname(ptr, eom);
		if (b < 0)
			return -EMSGSIZE; // RETERR(EMSGSIZE);
		ptr += b/*Name*/ + NS_INT16SZ/*Type*/ + NS_INT16SZ/*Class*/;
		if (section != ns_s_qd) {
			if (ptr + NS_INT32SZ + NS_INT16SZ > eom)
			  return -EMSGSIZE; // RETERR(EMSGSIZE);
			ptr += NS_INT32SZ/*TTL*/;
			NS_GET16(rdlength, ptr);
			ptr += rdlength/*RData*/;
		}
	}
	if (ptr > eom)
	  return -EMSGSIZE; // RETERR(EMSGSIZE);
	return (ptr - optr);
}
int
truncate_dns_pkt(u_char *pkt, int len)
{
  // truncate a [raw] packet "manually"
  int i;
  int size = 6*2;		/* header size */
  ns_msg m;

  // get some assistance from the libresolv parser
  if (ns_initparse(pkt, len, &m) < 0) {
    // bail out, do nothing
    // @@@@ should handle this - do it manually.
    if (trace_dns) fprintf(stderr,"%% DNS: parsing failed, not truncating\n");
    return len;
  }

  for (i = 0; i < ns_s_max; i++) {
    // check each section
    if (ns_msg_count(m, i) > 0) {
      // calculate length of section
      int l = (((i < ns_s_max-1) && (m._sections[i+1] != NULL)) ? m._sections[i+1] : ns_msg_end(m)) - m._sections[i];
      if (size + l > 488) {
	// this section is too long, truncate where in it
	// Look at RRs, add them one by one while under 488
	u_char *p = (u_char *)m._sections[i];	
	int nrr = 0;
	while ((size < 488) && (size < len)) {
	  // skip over a RR, finding length of the RR
	  int rrlen = ns_skiprr(p, ns_msg_end(m), i, 1);
	  if (rrlen < 0) {
	    fprintf(stderr,"Failed skipping RR!\n");
	    return -1;
	  }
	  if (size + rrlen < 488) {
	    // this RR is OK to include
	    nrr++;
	    size += rrlen;
	    p += rrlen;
	  } else {
	    // time to truncate: this and following RRs are not to be included
	    if (trace_dns) fprintf(stderr,"DNS: truncating section %d\n", i);
	    int j;
	    // update counts of this and later sections,
	    u_short *pwords = (u_short *)pkt;
	    pwords[2+i] = htons(nrr);
	    m._counts[i] = nrr;
	    for (j = i+1; j < ns_s_max; j++) {
	      pwords[2+j]  = 0;
	      m._counts[j] = 0;
	      m._sections[j] = NULL;
	    }
	    // update eom
	    m._eom = p;
	    // and return new size
	    return size;
	  }
	}
      }
      // include this whole section
      size += l;
    }
  }
}


// Standard consumer thread
void *
dns_forwarder_thread(void *v)
{
  res_state statp = &chres;
  u_char answer[NS_PACKETSZ*4];	/* fit ridiculous amounts to avoid ns_initparse breaking */
  int anslen;
  u_char ans[CH_PK_MAXLEN];	/* incl header+trailer */
  struct chaos_header *ap = (struct chaos_header *)&ans;

  while (1) {
    // wait for someting to do
    if (sem_wait(dns_thread_readerp) < 0) {
      perror("sem_wait(dns forwarder)");
      exit(1);
    }

    PTLOCK(dns_lock);
    struct chaos_dns_req *q = &chreq[*chreq_rix];
    if ((q->reqlen == 0) || (q->req == NULL)) {
      fprintf(stderr,"%% DNS: reading request at rix %d but it is NULL!\n", *chreq_rix);
      PTUNLOCK(dns_lock);
      continue;
    }
    if (trace_dns) {
      fprintf(stderr,"DNS: reading request at rix %d\n", *chreq_rix);
      if (verbose) {
	fprintf(stderr,"DNS request from Chaos %#o, len %d:\n", q->srcaddr, q->reqlen);
	dns_describe_packet(q->req, q->reqlen);
      }
    }

    // forward the query
    if ((anslen = res_nsend(statp, q->req, q->reqlen, (u_char *)&answer, sizeof(answer))) >= 0) {
      // success, free the RFC buffer
      free(q->req);
      q->req = NULL;
      q->reqlen = 0;

      if (trace_dns) {
	fprintf(stderr,"DNS: got answer, len %d\n", anslen);
	if (verbose)
	  dns_describe_packet(answer, anslen);
      }

      // Check that the answer fits in a Chaos pkt
      // libresolv seems to handle truncation to 512 bytes, but here we need manual truncation to 488.
      if (anslen > 488) {
	// test case: amnesia.lmi.com. on pi3
	if (trace_dns) fprintf(stderr,"%% DNS: answer doesn't fit in Chaos ANS, truncating\n");

	anslen = truncate_dns_pkt(answer, anslen);
	if (trace_dns) fprintf(stderr,"%% DNS: answer truncated to length %d\n", anslen);
	if (anslen < 0) {
	  // in case truncation failed, just skip it
	  PTUNLOCK(dns_lock);
	  if (sem_post(dns_thread_writerp) < 0) {
	    perror("sem_post(dns_forwarder)");
	  }
	  continue;
	}
	// set Truncated flag, cf RFC 1035 p26f
	answer[2] |= 2;
      }

      // update the index for next round
      *chreq_rix = ((*chreq_rix)+1) % CHREQ_MAX;

      // create the ANS pkt
      memset(ans,0,sizeof(ans));
      set_ch_opcode(ap, CHOP_ANS);
      set_ch_destaddr(ap, q->srcaddr);
      set_ch_destindex(ap, q->srcindex);
      set_ch_srcaddr(ap, q->dstaddr);
      PTUNLOCK(dns_lock);

      // @@@@ set random srcindex
      // Lambda and Symbolics only have 0200 unique ones (see CHAOS::MAXIMUM-INDEX)
      // ITS has 64 unique ones (six bits, see $CHXUN)
      set_ch_srcindex(ap, 0);
      // only 488 fit in a pkt
      // PDP11 swap
      htons_buf((u_short *)answer,(u_short *)&ans[CHAOS_HEADERSIZE], anslen > 488 ? 488 : anslen);
      set_ch_nbytes(ap, anslen > 488 ? 488 : anslen);

      send_chaos_pkt((u_char *)&ans, ch_nbytes(ap)+CHAOS_HEADERSIZE);

    } else {
      // query failed @@@@ maybe send LOS?
      if (trace_dns) fprintf(stderr,"DNS: query failed, error code %d\n", statp->res_h_errno);
      PTUNLOCK(dns_lock);
    }
    // tell responder there is room for one more
    if (sem_post(dns_thread_writerp) < 0) {
      perror("sem_post(dns forwarder)");
    }
  }
}

// given a Chaosnet address, return its domain name in namestr.
// Use e.g. for verification when adding a TLS route (received SNS)
int
dns_name_of_addr(u_short chaddr, u_char *namestr, int namestr_len)
{
  res_state statp = &chres;
  char qstring[12+6];
  u_char answer[NS_PACKETSZ];
  int anslen;
  ns_msg m;
  ns_rr rr;
  int i, offs;

  // note that chaos_address_domain should NOT end with dot.
  sprintf(qstring,"%o.%s.", chaddr, chaos_address_domain);

  if ((anslen = res_nquery(statp, qstring, ns_c_chaos, ns_t_ptr, (u_char *)&answer, sizeof(answer))) < 0) {
    if (trace_dns) fprintf(stderr,"DNS: PTR of %s failed, errcode %d: %s\n", qstring, statp->res_h_errno, hstrerror(statp->res_h_errno));
    *namestr = '\0';
    return -1;
  }

  if (trace_dns && verbose) {
    fprintf(stderr,"DNS: got response for PTR of %s\n", qstring);
    dns_describe_packet(answer, anslen);
  }

  if (ns_initparse((u_char *)&answer, anslen, &m) < 0) {
    fprintf(stderr,"ns_init_parse failure code %d", statp->res_h_errno);
    return -1;
  }

  if (ns_msg_getflag(m, ns_f_rcode) != ns_r_noerror) {
    if (trace_dns) fprintf(stderr,"DNS: bad response code %d\n", ns_msg_getflag(m, ns_f_rcode));
    *namestr = '\0';
    return -1;
  }
  if (ns_msg_count(m, ns_s_an) < 1) {
    if (trace_dns) fprintf(stderr,"DNS: bad answer count %d\n", ns_msg_count(m, ns_s_an));
    *namestr = '\0';
    return -1;
  }
  for (i = 0; i < ns_msg_count(m, ns_s_an); i++) {
    if (ns_parserr(&m, ns_s_an, i, &rr) < 0) {
      if (trace_dns) fprintf(stderr,"DNS: failed to parse answer RR %d\n", i);
      return -1;
    }
    if (ns_rr_type(rr) == ns_t_ptr) {
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)namestr, namestr_len)) < 0) {
	if (trace_dns) fprintf(stderr,"DNS: failed to expand PTR domain %d\n", i);
	return -1;
      } else
	// there can/should be only one.
	return strlen((char *)namestr);
    } else if (trace_dns) {
      fprintf(stderr,"%% DNS: warning - asked for PTR for %s but got answer type %s\n",
	      qstring, p_type(ns_rr_type(rr)));
    }
  }
  return -1;
}

// given a domain name (including ending period!) and addr of a u_short vector,
// fill in all Chaosnet addresses for it, and return the number of found addresses.
// Use e.g. for verification when a new TLS conn is created (both server and client end?)
int 
dns_addrs_of_name(u_char *namestr, u_short *addrs, int addrs_len)
{
  res_state statp = &chres;
  char a_dom[NS_MAXDNAME];
  int a_addr;
  char qstring[NS_MAXDNAME];
  u_char answer[NS_PACKETSZ];
  int anslen;
  ns_msg m;
  ns_rr rr;
  int i, ix = 0, offs;

  sprintf(qstring,"%s.", namestr);

  if ((anslen = res_nquery(statp, qstring, ns_c_chaos, ns_t_a, (u_char *)&answer, sizeof(answer))) < 0) {
    if (trace_dns) {
      fprintf(stderr,"DNS: addrs of %s failed, errcode %d: %s\n", qstring, statp->res_h_errno, hstrerror(statp->res_h_errno));
    }
    return -1;
  }

  if (trace_dns && verbose) {
    fprintf(stderr,"DNS: got response for addrs of %s\n", qstring);
    dns_describe_packet(answer, anslen);
  }

  if (ns_initparse((u_char *)&answer, anslen, &m) < 0) {
    fprintf(stderr,"ns_init_parse failure code %d",statp->res_h_errno);
    return -1;
  }

  if (ns_msg_getflag(m, ns_f_rcode) != ns_r_noerror) {
    if (trace_dns) fprintf(stderr,"DNS: bad response code %d\n", ns_msg_getflag(m, ns_f_rcode));
    return -1;
  }
  if (ns_msg_count(m, ns_s_an) < 1) {
    if (trace_dns) fprintf(stderr,"DNS: bad answer count %d\n", ns_msg_count(m, ns_s_an));
    return -1;
  }
  for (i = 0; i < ns_msg_count(m, ns_s_an); i++) {
    if (ns_parserr(&m, ns_s_an, i, &rr) < 0) { 
      if (trace_dns) fprintf(stderr,"DNS: failed to parse answer RR %d\n", i);
      return -1;
    }
    if (ns_rr_type(rr) == ns_t_a) {
      if (((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&a_dom, sizeof(a_dom))) < 0)
	  ||
	  ((a_addr = ns_get16(ns_rr_rdata(rr)+offs)) < 0))
	return -1;
      if (strncasecmp(a_dom, chaos_address_domain, strlen(chaos_address_domain)) == 0) {
	// only use addresses in "our" address domain
	if (ix < addrs_len) {
	  addrs[ix++] = a_addr;
	}
      } else if (trace_dns) {
	fprintf(stderr,"%% DNS: warning - address for %s is in %s which is different from %s\n",
		namestr, a_dom, chaos_address_domain);
      }
    } else if (trace_dns) {
      fprintf(stderr,"%% DNS: warning - asked for A for %s but got answer type %s\n",
	      namestr, p_type(ns_rr_type(rr)));
    }
  }
  return ix;
}

void
init_chaos_dns(int do_forwarding)
{
  res_state statp = &chres;

  if (do_forwarding) {
    // init lock and semaphores
    pthread_mutex_init(&dns_lock, NULL);
#if __APPLE__
    // no support for "anonymous" semaphores
    if ((dns_thread_readerp = sem_open("/cbridge-dns-reader", O_CREAT, S_IRWXU, 0)) < 0) {
      perror("sem_open(/cbridge-dns-reader)");
      exit(1);
    }
    if ((dns_thread_writerp = sem_open("/cbridge-dns-writer", O_CREAT, S_IRWXU, CHREQ_MAX)) < 0) {
      perror("sem_open(/cbridge-dns-writer)");
      exit(1);
    }
#else
    if (sem_init(&dns_thread_reader, 0, 0) < 0) {
      perror("sem_init(dns reader)");
      exit(1);
    }
    if (sem_init(&dns_thread_writer, 0, CHREQ_MAX) < 0) {
      perror("sem_init(dns writer)");
      exit(1);
    }
    dns_thread_readerp = &dns_thread_reader;
    dns_thread_writerp = &dns_thread_writer;
#endif

    // allocate shared structure
    if ((chreq = malloc(sizeof(struct chaos_dns_req)*CHREQ_MAX)) == NULL) {
      perror("malloc(chreq)");
      exit(1);
    }
    if ((chreq_wix = malloc(sizeof(chreq_wix))) == NULL) {
      perror("malloc(chreq_wix)");
      exit(1);
    }
    if ((chreq_rix = malloc(sizeof(chreq_rix))) == NULL) {
      perror("malloc(chreq_rix)");
      exit(1);
    }
    memset((char *)chreq, 0, sizeof(struct chaos_dns_req)*CHREQ_MAX);
    *chreq_wix = *chreq_rix = 0;
  }

  // initialize resolver library
  if (res_ninit(statp) < 0) {
    fprintf(stderr,"Can't init statp\n");
    exit(1);
  }
  // make sure to make recursive requests
  statp->options |= RES_RECURSE;
  // change nameserver
  if (inet_aton(chaos_dns_server, &statp->nsaddr_list[0].sin_addr) < 0) {
    perror("inet_aton (chaos_dns_server does not parse)");
    exit(1);
  } else {
    statp->nsaddr_list[0].sin_family = AF_INET;
    statp->nsaddr_list[0].sin_port = htons(53);
    statp->nscount = 1;
  }
  // what about the timeout? RES_TIMEOUT=5s, statp->retrans (RES_MAXRETRANS=30 s? ms?), ->retry (RES_DFLRETRY=2, _MAXRETRY=5)
}

// **** for parsing/printing config

// parse a line beginning with "dns" (after parsing the "dns" keyword)
// args:
//   server 1.2.3.4
//   addrdomain ch-addr.net.
//   forwarder on/off
//   trace on/off
int
parse_dns_config_line()
{
  char *tok = NULL;
  while ((tok = strtok(NULL," \t\r\n")) != NULL) {
    if (strcasecmp(tok, "server") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"dns: no server specified\n"); return -1; }
      strncpy(chaos_dns_server, tok, sizeof(chaos_dns_server));
    }
    else if (strcasecmp(tok, "addrdomain") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"dns: no addrdomain specified\n"); return -1; }
      strncpy(chaos_address_domain, tok, sizeof(chaos_address_domain));
      if (chaos_address_domain[strlen(chaos_address_domain)-1] == '.') {
	fprintf(stderr,"dns: addrdomain should not be dot-terminated (fixing it for you)\n");
	chaos_address_domain[strlen(chaos_address_domain)-1] = '\0';
      }
    }
    else if (strcasecmp(tok, "forwarder") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0))
	do_dns_forwarding = 1;
      else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0))
	do_dns_forwarding = 0;
      else { fprintf(stderr,"dns: invalid forwarder arg %s specified\n", tok); return -1; }
    }
    else if (strcasecmp(tok, "trace") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0))
	trace_dns = 1;
      else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0))
	trace_dns = 0;
      else { fprintf(stderr,"dns: invalid trace arg %s specified\n", tok); return -1; }
    }
    else {
      fprintf(stderr,"dns config keyword %s unknown\n", tok);
      return -1;
    }
  }
  return 0;
}

void
print_config_dns()
{
  res_state statp = &chres;
  printf(" Chaos DNS forwarder %s\n Chaos address domain %s\n DNS tracing %s\n",
	 chaos_dns_server, chaos_address_domain, trace_dns ? "on" : "off");
  if (trace_dns) {
    printf(" DNS options %#lx, nsaddrs %d, family %d, port %d", statp->options, statp->nscount, statp->nsaddr_list[0].sin_family, ntohs(statp->nsaddr_list[0].sin_port));
    printf(", addr %s\n", inet_ntoa(statp->nsaddr_list[0].sin_addr));
  }

  if (chreq != NULL) {
    int i;
    PTLOCK(dns_lock);
    printf(" DNS request queue:\n  i\tsrc\tsix\tlen\n");
    for (i = 0; i < CHREQ_MAX; i++) {
      if (chreq[i].reqlen > 0)
	printf("  %d\t%#o\t%#o\t%d\n", i, chreq[i].srcaddr, chreq[i].srcindex, chreq[i].reqlen);
    }
    PTUNLOCK(dns_lock);
  }
}

// **** for debugging

static void
dns_show_flags(ns_msg m) {
  printf("Flags: ");
  if (ns_msg_getflag(m, ns_f_aa)) printf("AA (Authoritative) ");
  if (ns_msg_getflag(m, ns_f_tc)) printf("TC (Truncated) ");
  if (ns_msg_getflag(m, ns_f_rd)) printf("RD (Recursion Desired) ");
  if (ns_msg_getflag(m, ns_f_ra)) printf("RA (Recursion Available) ");
  if (ns_msg_getflag(m, ns_f_z)) printf("Z ");
  if (ns_msg_getflag(m, ns_f_ad)) printf("AD ");
  if (ns_msg_getflag(m, ns_f_cd)) printf("CD ");
  printf("\n");
}

static void
dns_show_section(int sect, ns_msg m) 
{
  int i, x;
  int offs;
  char a_dom[NS_MAXDNAME], b_dom[NS_MAXDNAME];
  u_int a_addr;
  ns_rr rr;

  // Loop over answers and find the A entries
  for (i = 0; i < ns_msg_count(m, sect); i++) {
    if (ns_parserr(&m, sect, i, &rr) < 0) {
      perror("ns_parserr");
      return;
      //exit(1);
    }
    if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_a) && (ns_rr_class(rr) == ns_c_chaos)) {
      // Expand the address domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&a_dom, sizeof(a_dom))) < 0) {
	perror("dn_expand");
	exit(1);
      }
      // and get the address
      if ((a_addr = ns_get16(ns_rr_rdata(rr)+offs)) < 0) {
	perror("ns_get16");
	return;
	//exit(1);
      }
      printf(" %d: %s addr domain %s, addr %#o\n", i, ns_rr_name(rr), a_dom, a_addr);
    } else if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_a) && (ns_rr_class(rr) == ns_c_in)) {
      struct in_addr in;
      memcpy(&in, ns_rr_rdata(rr), sizeof(in));
      printf(" %d: %s addr %s\n", i, ns_rr_name(rr), inet_ntoa(in));
    } else if ((ns_rr_rdlen(rr) > 0) && ((ns_rr_type(rr) == ns_t_cname) || (ns_rr_type(rr) == ns_t_ptr) || (ns_rr_type(rr) == ns_t_ns))) {
      // Expand the domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&a_dom, sizeof(a_dom))) < 0) {
	perror("dn_expand");
	exit(1);
      }
      printf(" %d: %s %s %s\n", i, ns_rr_name(rr), p_type(ns_rr_type(rr)), a_dom);
    } else if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_rp)) {
      // Expand the mbox domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&a_dom, sizeof(a_dom))) < 0) {
	perror("dn_expand");
	return;
	//exit(1);
      }
      // Expand the txt domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr)+offs, (char *)&b_dom, sizeof(b_dom))) < 0) {
	perror("dn_expand");
	return;
	//exit(1);
      }
      printf(" %d: %s %s %s \"%s\"\n", i, ns_rr_name(rr), p_type(ns_rr_type(rr)), a_dom, b_dom);
    } else if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_hinfo)) {
      char *rd, cpu[256], os[256];
      rd = (char *)ns_rr_rdata(rr);
      x = *rd;
      strncpy(cpu, rd+1, x);
      cpu[x] = '\0';
      rd += x+1;
      x = *rd;
      strncpy(os, rd+1, x);
      os[x] = '\0';
      printf(" %d: %s hinfo %s %s\n", i, ns_rr_name(rr), cpu, os);
    } else if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_txt)) {
      char txt[256];
      x = *ns_rr_rdata(rr);
      strncpy(txt, (char *)ns_rr_rdata(rr)+1, x);
      txt[x] = '\0';
      printf(" %d: %s txt \"%s\"\n", i, ns_rr_name(rr), txt);
    } else
      printf(" %d: %s rrtype %s (%d) rrclass %s (%d), rdlen %d\n", i, ns_rr_name(rr), p_type(ns_rr_type(rr)), ns_rr_type(rr), p_class(ns_rr_class(rr)), ns_rr_class(rr), ns_rr_rdlen(rr));
  }
}

void dumppkt_raw(unsigned char *ucp, int cnt);

static void
dns_describe_packet(u_char *pkt, int len)
{
  res_state statp = &chres;
  ns_msg m;
  ns_rr rr;

  if (ns_initparse(pkt, len, &m) < 0) {
    fprintf(stderr,"ns_initparse failure code %d: %s\n",statp->res_h_errno, hstrerror(statp->res_h_errno));
    if (debug) dumppkt_raw(pkt, len);
    return;
  }
  // dumppkt_raw(pkt, 4*2);	/* header, qd, an */
  printf("Pkt len %d, Msg ID %d, Type %s, Opcode %d, Rcode %d\n",
	 len, ns_msg_id(m), ns_msg_getflag(m, ns_f_qr) == 0 ? "query" : "response",
	 ns_msg_getflag(m, ns_f_opcode), ns_msg_getflag(m, ns_f_rcode));
  dns_show_flags(m);
  printf("Counts: Ques %d, Ans %d, NS %d, Add %d\n",
	 ns_msg_count(m,ns_s_qd), ns_msg_count(m,ns_s_an), ns_msg_count(m,ns_s_ns), ns_msg_count(m,ns_s_ar));

  if (ns_msg_count(m, ns_s_qd) > 0) {
    printf("Questions:\n");
    dns_show_section(ns_s_qd, m);
  }

  if (ns_msg_count(m, ns_s_an) > 0) {
    printf("Answers:\n");
    dns_show_section(ns_s_an, m);
  }
  if (ns_msg_count(m, ns_s_ns) > 0) {
    printf("Name servers:\n");
    dns_show_section(ns_s_ns, m);
  }
  if (ns_msg_count(m, ns_s_ar) > 0) {
    printf("Additional:\n");
    dns_show_section(ns_s_ar, m);
  }
}
