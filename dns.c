/* Copyright © 2005, 2017-2023 Björn Victor (bjorn@victor.se) */
/*  Bridge program for various Chaosnet implementations. */
/*
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Usage:
// Look up the CN of new TLS connections to see that the host exists,
// and when a SNS appears, check that it comes from the matching address/host.
//
// "DNS tunnelling" from Chaos to UDP.
// Configuration: on/off, DNS forwarder IP, chaos address domain, number of open requests?, debug
// - get a request (RFC), pass query + source host/index to a consumer thread, which responds (ANS) when answer arrives/not
// -- when to send LOS? on non-answer (from DNS) failures
// - use standard consumer/producer lock and semaphores

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#include "cbridge.h"

// Default DNS server for Chaosnet class records - this server needs to handle the CH class!
#ifndef CHAOS_DNS_SERVER
#define CHAOS_DNS_SERVER "dns.chaosnet.net"
#endif
#ifndef CHAOS_ADDR_DOMAIN
// NOT dot-terminated
#define CHAOS_ADDR_DOMAIN "CH-ADDR.NET"
#endif

static int trace_dns = 0;
int do_dns_forwarding = 0;
static int n_dns_servers = 0;
#define MAX_DNS_SERVERS MAXNS	// MAXNS from resolv.h
static char *chaos_dns_servers[MAX_DNS_SERVERS];
// Need to have space for "%o." prefix
static char chaos_address_domain[NS_MAXDNAME-7] = CHAOS_ADDR_DOMAIN;

// consumer/producer lock and semaphores
static pthread_mutex_t dns_lock = PTHREAD_MUTEX_INITIALIZER;
// Really: if anonymous semaphores are not supported (see init_chaos_dns)
#if __APPLE__ == 0
static sem_t dns_thread_writer, dns_thread_reader;
#endif
static sem_t *dns_thread_writerp, *dns_thread_readerp;

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
static struct chaos_dns_req chreq[CHREQ_MAX];
static int chreq_wix = 0;			/* write index */
static int chreq_rix = 0;			/* read index */

// not thread safe: extern int h_errno;

static void dns_describe_packet(u_char *pkt, int len);
static void init_chaos_dns_state(res_state statp);

// called by handle_rfc for an RFC to the "DNS" contact
void
dns_responder(u_char *rfc, int len)
{
  if (!do_dns_forwarding)
    // just ignore it
    return;

  if (sem_trywait(dns_thread_writerp) < 0) {
    if (errno == EAGAIN) {
      // no room for request - don't hang, let other end resend request
      if (trace_dns) fprintf(stderr,"DNS: no room for request, dropping it (wix %d)\n", chreq_wix);
      return;
    } else {
      perror("sem_trywait(dns responder)");
      abort();
    }
  }

  PTLOCKN(dns_lock,"dns_lock");
  // fill in data
  struct chaos_header *ch = (struct chaos_header *)rfc;
  struct chaos_dns_req *q = &chreq[chreq_wix];
  int qlen = ch_nbytes(ch)-4; // 4 = "DNS "
  u_char *data = &rfc[CHAOS_HEADERSIZE+4];
  if (ch_opcode(ch) == CHOP_BRD) {
    // skip subnet mask
    qlen -= ch_ackno(ch);
    data += ch_ackno(ch);
  }
  q->srcaddr = ch_srcaddr(ch);
  q->srcindex = ch_srcindex(ch);
  q->dstaddr = ch_destaddr(ch);
  q->dstindex = ch_destindex(ch);
  u_char *req = malloc(qlen);
  if (req == NULL) {
    perror("malloc(dns responder)");
    abort();
  }
  // PDP11 swap
  ntohs_buf((u_short *)data, (u_short *)req, qlen);
  q->req = req;
  q->reqlen = qlen;
  // update index for next RFC to come
  if (trace_dns) fprintf(stderr,"DNS: added request at wix %d\n", chreq_wix);
  chreq_wix = ((chreq_wix)+1) % CHREQ_MAX;
  PTUNLOCKN(dns_lock,"dns_lock");

  // tell forwarder to get going
  if (sem_post(dns_thread_readerp) < 0) {
    perror("sem_post(dns responder)");
    abort();
  }
}

// from libresolv, ns_parse
// * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
// * Copyright (c) 1996,1999 by Internet Software Consortium.
static int
cb_ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count) {
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
static int
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
      if (size + l > CH_PK_MAX_DATALEN) {
	// this section is too long, truncate where in it
	// Look at RRs, add them one by one while under 488
	u_char *p = (u_char *)m._sections[i];	
	int nrr = 0;
	while ((size < CH_PK_MAX_DATALEN) && (size < len)) {
	  // skip over a RR, finding length of the RR
	  int rrlen = cb_ns_skiprr(p, ns_msg_end(m), i, 1);
	  if (rrlen < 0) {
	    fprintf(stderr,"Failed skipping RR!\n");
	    return -1;
	  }
	  if (size + rrlen < CH_PK_MAX_DATALEN) {
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
  // should never get here
  return len;
}


// Standard consumer thread
void *
dns_forwarder_thread(void *v)
{
  // resolver state, local to each thread
  struct __res_state chres;
  res_state statp = &chres;
  memset(&chres, 0, sizeof(chres));
  u_char answer[NS_PACKETSZ*4];	/* fit ridiculous amounts to avoid ns_initparse breaking */
  int anslen;
  u_char ans[CH_PK_MAXLEN];	/* incl header+trailer */
  struct chaos_header *ap = (struct chaos_header *)&ans;

  init_chaos_dns_state(statp);

  while (1) {
    // wait for someting to do
    if (sem_wait(dns_thread_readerp) < 0) {
      perror("sem_wait(dns forwarder)");
      abort();
    }

    PTLOCKN(dns_lock,"dns_lock");
    struct chaos_dns_req *q = &chreq[chreq_rix];
    if ((q->reqlen == 0) || (q->req == NULL)) {
      fprintf(stderr,"%% DNS: reading request at rix %d but it is NULL!\n", chreq_rix);
      PTUNLOCKN(dns_lock,"dns_lock");
      continue;
    }
    if (trace_dns) {
      fprintf(stderr,"DNS: reading request at rix %d\n", chreq_rix);
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
      if (anslen > CH_PK_MAX_DATALEN) {
	// test case: amnesia.lmi.com. on pi3
	if (trace_dns) fprintf(stderr,"%% DNS: answer doesn't fit in Chaos ANS, truncating\n");

	anslen = truncate_dns_pkt(answer, anslen);
	if (trace_dns) fprintf(stderr,"%% DNS: answer truncated to length %d\n", anslen);
	if (anslen < 0) {
	  // in case truncation failed, just skip it
	  PTUNLOCKN(dns_lock,"dns_lock");
	  if (sem_post(dns_thread_writerp) < 0) {
	    perror("sem_post(dns_forwarder)");
	  }
	  continue;
	}
	// set Truncated flag, cf RFC 1035 p26f
	answer[2] |= 2;
      }

      // update the index for next round
      chreq_rix = ((chreq_rix)+1) % CHREQ_MAX;

      // create the ANS pkt
      memset(ans,0,sizeof(ans));
      set_ch_opcode(ap, CHOP_ANS);
      set_ch_destaddr(ap, q->srcaddr);
      set_ch_destindex(ap, q->srcindex);
      set_ch_srcaddr(ap, q->dstaddr);
      PTUNLOCKN(dns_lock,"dns_lock");

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
      PTUNLOCKN(dns_lock,"dns_lock");
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
  // resolver state, local to each thread
  struct __res_state chres;
  res_state statp = &chres;
  memset(&chres, 0, sizeof(chres));
  char qstring[NS_MAXDNAME+1];
  u_char answer[NS_PACKETSZ];
  int anslen;
  ns_msg m;
  ns_rr rr;
  int i, offs;

  init_chaos_dns_state(statp);

  // note that chaos_address_domain should NOT end with dot.
  sprintf(qstring,"%o.%s.", chaddr, chaos_address_domain);

  if ((anslen = res_nquery(statp, qstring, ns_c_chaos, ns_t_ptr, (u_char *)&answer, sizeof(answer))) < 0) {
    if (trace_dns) fprintf(stderr,"DNS: PTR of %s failed, errcode %d: %s\n", qstring, statp->res_h_errno, hstrerror(statp->res_h_errno));
    *namestr = '\0';
    // Try to detect errors while resolving, such as the servers being unreachable.
    // TRY_AGAIN is e.g. given when there is no response, which is rather bad for us.
    if ((statp->res_h_errno == TRY_AGAIN) || (statp->res_h_errno == NO_RECOVERY))
      return -2;
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
// Use e.g. for verification when a new TLS conn is created (both server and client end)
int 
dns_addrs_of_name(u_char *namestr, u_short *addrs, int addrs_len)
{
  // resolver state, local to each thread
  struct __res_state chres;
  res_state statp = &chres;
  memset(&chres, 0, sizeof(chres));
  char a_dom[NS_MAXDNAME];
  int a_addr;
  char qstring[NS_MAXDNAME];
  u_char cname_string[NS_MAXDNAME];
  u_char answer[NS_PACKETSZ];
  int anslen;
  ns_msg m;
  ns_rr rr;
  int i, ix = 0, offs, got_cname = 0;

  init_chaos_dns_state(statp);

  sprintf(qstring,"%s.", namestr);

  if ((anslen = res_nquery(statp, qstring, ns_c_chaos, ns_t_a, (u_char *)&answer, sizeof(answer))) < 0) {
    if (trace_dns) {
      fprintf(stderr,"DNS: addrs of %s failed, errcode %d: %s\n", qstring, statp->res_h_errno, hstrerror(statp->res_h_errno));
    }
    // Try to detect errors while resolving, such as the servers being unreachable.
    // TRY_AGAIN is e.g. given when there is no response, which is rather bad for us.
    if ((statp->res_h_errno == TRY_AGAIN) || (statp->res_h_errno == NO_RECOVERY))
      return -2;
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
    } else if (ns_rr_type(rr) == ns_t_cname) {
      if (trace_dns) fprintf(stderr,"%% DNS: got CNAME for %s when asking for A\n", namestr);
      if ((dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&cname_string, sizeof(cname_string))) < 0) {
	if (trace_dns) fprintf(stderr,"%% DNS: could not extract CNAME from record for %s!\n", namestr);
      } else {
	got_cname = 1;
      }
    } else if (trace_dns) {
      fprintf(stderr,"%% DNS: warning - asked for A for %s but got answer type %s\n",
	      namestr, p_type(ns_rr_type(rr)));
    }
  }
  if ((ix == 0) && got_cname) {
    // Server didn't provide the A record as additional info, go ask for it
    if (trace_dns) fprintf(stderr,"%% DNS: recursing on CNAME %s for %s\n", cname_string, namestr);
    return dns_addrs_of_name(cname_string, addrs, addrs_len);
  }
  return ix;
}

// List all NS records of the Chaosnet root domain in the CH class, as suggestions for "dns server" setting.
// Return the number of NS records found
static int
dns_list_root_nameservers(void)
{
  // resolver state, local to each thread
  struct __res_state chres;
  res_state statp = &chres;
  memset(&chres, 0, sizeof(chres));
  char ns_dom[NS_MAXDNAME];
  char qstring[NS_MAXDNAME] = ".";
  u_char answer[NS_PACKETSZ];
  int anslen;
  ns_msg m;
  ns_rr rr;
  int i, offs;
  int nrec = 0;

  init_chaos_dns_state(statp);

  if ((anslen = res_nquery(statp, qstring, ns_c_chaos, ns_t_ns, (u_char *)&answer, sizeof(answer))) < 0) {
    if (trace_dns) {
      fprintf(stderr,"DNS: NS of %s failed, errcode %d: %s\n", qstring, statp->res_h_errno, hstrerror(statp->res_h_errno));
    }
    // Try to detect errors while resolving, such as the servers being unreachable.
    // TRY_AGAIN is e.g. given when there is no response, which is rather bad for us.
    if ((statp->res_h_errno == TRY_AGAIN) || (statp->res_h_errno == NO_RECOVERY))
      return -2;
    return -1;
  }

  if (trace_dns && verbose) {
    fprintf(stderr,"DNS (%s): got response for NS of %s\n", __func__, qstring);
    dns_describe_packet(answer, anslen);
  }

  if (ns_initparse((u_char *)&answer, anslen, &m) < 0) {
    fprintf(stderr,"DNS (%s): ns_initparse failure code %d", __func__, statp->res_h_errno);
    return -1;
  }

  if (ns_msg_getflag(m, ns_f_rcode) != ns_r_noerror) {
    if (trace_dns) fprintf(stderr,"DNS (%s): bad response code %d\n", __func__, ns_msg_getflag(m, ns_f_rcode));
    return -1;
  }
  if (ns_msg_count(m, ns_s_an) < 1) {
    if (trace_dns) fprintf(stderr,"DNS (%s): bad answer count %d\n", __func__, ns_msg_count(m, ns_s_an));
    return -1;
  }
  for (i = 0; i < ns_msg_count(m, ns_s_an); i++) {
    if (ns_parserr(&m, ns_s_an, i, &rr) < 0) { 
      if (trace_dns) fprintf(stderr,"DNS (%s): failed to parse answer RR %d\n", __func__, i);
      return -1;
    }
    if (ns_rr_type(rr) == ns_t_ns) {
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&ns_dom, sizeof(ns_dom))) < 0)
	return -1;
      printf(i == 0 ? "%s" : ",%s", ns_dom);
      nrec++;
    } else if (trace_dns) {
      fprintf(stderr,"%% DNS (%s): warning - asked for NS for %s but got answer type %s\n", __func__,
	      qstring, p_type(ns_rr_type(rr)));
    }
  }
  return nrec;
}


// debug
#if 0
static void print_resolver_state(struct __res_state *sp)
{
  printf("DNS resolver state in thread %p:\n", (void *)pthread_self());
  printf(" Retrans %d, retry %d\n", sp->retrans, sp->retry);
  printf(" Servers: %d\n ", sp->nscount);
  for (int i = 0; i < sp->nscount; i++) {
    printf(" %s:%d", inet_ntoa(sp->nsaddr_list[i].sin_addr), ntohs(sp->nsaddr_list[i].sin_port));
  }
  printf("\n Domains:\n ");
  for (int i = 0; i < MAXDNSRCH && sp->dnsrch[i] != NULL; i++)
    printf(" %s", sp->dnsrch[i]);
  printf("\n Options:\n ");
  if (sp->options & RES_INIT) printf(" Init");
  if (sp->options & RES_DEBUG) printf(" Debug");
  if (sp->options & RES_AAONLY) printf(" AuthOnly");
  if (sp->options & RES_USEVC) printf(" VC");
  if (sp->options & RES_PRIMARY) printf(" Primary");
  if (sp->options & RES_IGNTC) printf(" IgnTC");
  if (sp->options & RES_RECURSE) printf(" Recurse");
  if (sp->options & RES_DEFNAMES) printf(" DefNames");
  if (sp->options & RES_STAYOPEN) printf(" StayOpen");
  if (sp->options & RES_DNSRCH) printf(" LocalTree");
  // insecure
  if (sp->options & RES_NOALIASES) printf(" NoAlias");
#ifdef RES_USE_INET6
  if (sp->options & RES_USE_INET6) printf(" Inet6");
#endif
  if (sp->options & RES_ROTATE) printf(" Rotate");
  if (sp->options & RES_NOCHECKNAME) printf(" NoCheck");
  if (sp->options & RES_KEEPTSIG) printf(" KeepTSIG");
  if (sp->options & RES_BLAST) printf(" Blast");
#ifdef RES_NO_NIBBLE
  if (sp->options & RES_NO_NIBBLE) printf(" NoNibble");
#endif
#ifdef RES_NO_BITSTRING
  if (sp->options & RES_NO_BITSTRING) printf(" NoBitstring");
#endif
  if (sp->options & RES_NOTLDQUERY) printf(" NoTLD");
  if (sp->options & RES_USE_DNSSEC) printf(" DNSSec");
#ifdef RES_USE_DNAME
  if (sp->options & RES_USE_DNAME) printf(" Dname");
#endif
#ifdef RES_USE_A6
  if (sp->options & RES_USE_A6) printf(" A6");
#endif
  if (sp->options & RES_USE_EDNS0) printf(" EDNS0");
#ifdef RES_NO_NIBBLE2
  if (sp->options & RES_NO_NIBBLE2) printf(" NoNibble2");
#endif
  printf("\n");
}
#endif

static int n_parsed_servers = 0;
static struct sockaddr_in parsed_servers[MAX_DNS_SERVERS];

static void 
init_chaos_dns_state(res_state statp) 
{
  // first parse the server names (once), then res_ninit and change nsaddr_list
  if (n_parsed_servers == 0)	// Initialize
    memset(&parsed_servers, 0, sizeof(parsed_servers));
    
  // Use default
  if (n_dns_servers == 0) {
    fprintf(stderr,"DNS: adding default server %s\n", CHAOS_DNS_SERVER);
    chaos_dns_servers[n_dns_servers++] = strdup(CHAOS_DNS_SERVER);
  }
  // parse nameservers
  if (n_parsed_servers == 0) {
    // parse them only first time - under Linux, it somehow fails the second time around (in another thread)
    for (int i = 0; i < n_dns_servers; i++) {
      if (inet_aton(chaos_dns_servers[i], &parsed_servers[n_parsed_servers].sin_addr) <= 0) {
	struct addrinfo *he, hi;
	memset(&hi, 0, sizeof(hi));
	hi.ai_family = AF_INET;
	hi.ai_flags = AI_ADDRCONFIG;
	int val = getaddrinfo(chaos_dns_servers[i], NULL, &hi, &he);
	if (val == 0) {
	  if (he->ai_family == AF_INET) {
	    struct sockaddr_in *s = (struct sockaddr_in *)he->ai_addr;
	    memcpy(&parsed_servers[n_parsed_servers].sin_addr, &s->sin_addr, sizeof(struct in_addr));
	    n_parsed_servers++;
	    if (trace_dns) fprintf(stderr,"DNS: parsed server '%s' OK\n", chaos_dns_servers[i]);
	  } else {
	    fprintf(stderr,"%%%% DNS: wrong address family %d for '%s'\n", he->ai_family, chaos_dns_servers[i]);
	  }
	} else {
	  fprintf(stderr,"%%%% DNS: can not parse DNS server '%s': %s (%s)\n", chaos_dns_servers[i], gai_strerror(val), strerror(errno));
	}
      } else {
	if (trace_dns) fprintf(stderr,"DNS: parsed server '%s' OK\n", chaos_dns_servers[i]);
	n_parsed_servers++;		// Numeric address parsed
      }
    }
    if (trace_dns) fprintf(stderr,"DNS: thread %p parsed %d servers\n", (void *)pthread_self(), n_parsed_servers);
  }
  // initialize resolver library
  if (res_ninit(statp) < 0) {
    fprintf(stderr,"Can't init statp\n");
    abort();
  }
  // make sure to make recursive requests
  statp->options |= RES_RECURSE;
#ifdef RES_DEBUG
  if (trace_dns)		// if tracing, also debug
    statp->options |= RES_DEBUG;
#endif
  // We control domain search lists etc ourselves.
  statp->options |= RES_NOALIASES; // no HOSTALIASES processing
  statp->options &= ~(RES_DNSRCH|RES_DEFNAMES); // no default domain name or searching local domain

  statp->nscount = 0;
  // Now copy the parsed server addrs
  for (int i = 0; i < n_parsed_servers; i++) {
    memcpy(&statp->nsaddr_list[i].sin_addr, &parsed_servers[i].sin_addr, sizeof(struct in_addr));
    statp->nsaddr_list[i].sin_family = AF_INET;
    statp->nsaddr_list[i].sin_port = htons(53);
  }
  statp->nscount = n_parsed_servers;

  if (statp->nscount == 0) {
    fprintf(stderr,"%%%% DNS: could not parse any DNS servers!\n");
    // @@@@ probably exit?
#if 0				// @@@@ debug
  } else if (trace_dns) {
    print_resolver_state(statp);
#endif
  }
  // what about the timeout? RES_TIMEOUT=5s, statp->retrans (RES_MAXRETRANS=30 s? ms?), ->retry (RES_DFLRETRY=2, _MAXRETRY=5)
}

void
init_chaos_dns(int do_forwarding)
{
  if (do_forwarding) {
    // init lock and semaphores
    pthread_mutex_init(&dns_lock, NULL);
#if __APPLE__
    // no support for "anonymous" semaphores
    if ((dns_thread_readerp = sem_open("/cbridge-dns-reader", O_CREAT, S_IRWXU, 0)) < 0) {
      perror("sem_open(/cbridge-dns-reader)");
      abort();
    }
    if ((dns_thread_writerp = sem_open("/cbridge-dns-writer", O_CREAT, S_IRWXU, CHREQ_MAX)) < 0) {
      perror("sem_open(/cbridge-dns-writer)");
      abort();
    }
#else
    if (sem_init(&dns_thread_reader, 0, 0) < 0) {
      perror("sem_init(dns reader)");
      abort();
    }
    if (sem_init(&dns_thread_writer, 0, CHREQ_MAX) < 0) {
      perror("sem_init(dns writer)");
      abort();
    }
    dns_thread_readerp = &dns_thread_reader;
    dns_thread_writerp = &dns_thread_writer;
#endif
  }
}

// **** for parsing/printing config

// parse a line beginning with "dns" (after parsing the "dns" keyword)
// args:
//   server 1.2.3.4,dns.chaosnet.net
//   addrdomain ch-addr.net.
//   forwarder on/off
//   trace on/off
int
parse_dns_config_line()
{
  char *sp, *ep, *tok = NULL;
  while ((tok = strtok(NULL," \t\r\n")) != NULL) {
    if ((strcasecmp(tok, "server") == 0) || (strcasecmp(tok,"servers") == 0)) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"dns: no server specified\n"); return -1; }
      for (sp = tok, ep = index(tok, ','); ep != NULL; sp = ep+1, ep = index(ep+1, ',')) {
	if (n_dns_servers > MAX_DNS_SERVERS) {
	  fprintf(stderr,"Error in dns \"servers\" setting - too many servers listed, max %d\n", MAX_DNS_SERVERS);
	  return -1;
	}
	*ep = '\0';		// zap comma
	if (strlen(sp) == 0) {
	  fprintf(stderr,"Syntax error in dns \"servers\" setting - empty server name/address?\n");
	  return -1;
	}
	chaos_dns_servers[n_dns_servers++] = strdup(sp);
      }
      // add the single one, or the last one
      if (strlen(sp) == 0) {
	fprintf(stderr,"Syntax error in dns \"servers\" setting - empty server\n");
	return -1;
      }
      chaos_dns_servers[n_dns_servers++] = strdup(sp);
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
  if (n_dns_servers == 0) {
    fprintf(stderr,"dns: adding default server %s\n", CHAOS_DNS_SERVER);
    chaos_dns_servers[n_dns_servers++] = strdup(CHAOS_DNS_SERVER);
  }
  return n_dns_servers;
}

void
print_config_dns()
{
  // resolver state, local to each thread
  struct __res_state chres;
  res_state statp = &chres;
  memset(&chres, 0, sizeof(chres));
  init_chaos_dns_state(statp);

  printf("DNS config in thread %p:\n", (void *)pthread_self());
  if (n_dns_servers > 0) {
    printf(" Chaos DNS server%s: ", n_dns_servers == 1 ? "" : "s");
    for (int i = 0; i < n_dns_servers; i++)
      printf(i == 0 ? "%s" : ",%s", chaos_dns_servers[i]);
    printf("\n");
  }
  if (n_dns_servers == 1) {
    // @@@@ but if it is on a private network it's normal to have only one
    printf(" Suggested DNS servers: ");
    int nrec = dns_list_root_nameservers();
    if (nrec > MAX_DNS_SERVERS) 
      printf(" (pick MAX %d of those)", MAX_DNS_SERVERS);
    printf("\n");
  }
  printf(" Chaos address domain %s\n DNS tracing %s\n",
	 chaos_address_domain, trace_dns ? "on" : "off");
  if (trace_dns) {
    printf(" DNS options %#lx, nsaddrs %d, family %d, port %d", statp->options, statp->nscount, statp->nsaddr_list[0].sin_family, ntohs(statp->nsaddr_list[0].sin_port));
    printf(", servers ");
    for (int i = 0; i < n_dns_servers; i++)
      printf(i == 0 ? "%s" : ",%s", inet_ntoa(statp->nsaddr_list[i].sin_addr));
    printf("\n");
  }

  int i, n;
  PTLOCKN(dns_lock,"dns_lock");
  for (i = 0, n = 0; i < CHREQ_MAX; i++) n += chreq[i].reqlen;
  if (n == 0)
    printf(" DNS request queue empty\n");
  else {
    printf(" DNS request queue:\n  i\tsrc\tsix\tlen\n");
    for (i = 0; i < CHREQ_MAX; i++) {
      if (chreq[i].reqlen > 0)
	printf("  %d\t%#o\t%#o\t%d\n", i, chreq[i].srcaddr, chreq[i].srcindex, chreq[i].reqlen);
    }
  }
  PTUNLOCKN(dns_lock,"dns_lock");
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
      //abort();
    }
    if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_a) && (ns_rr_class(rr) == ns_c_chaos)) {
      // Expand the address domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&a_dom, sizeof(a_dom))) < 0) {
	perror("dn_expand");
	abort();
      }
      // and get the address
      if ((a_addr = ns_get16(ns_rr_rdata(rr)+offs)) < 0) {
	perror("ns_get16");
	return;
	//abort();
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
	abort();
      }
      printf(" %d: %s %s %s\n", i, ns_rr_name(rr), p_type(ns_rr_type(rr)), a_dom);
    } else if ((ns_rr_rdlen(rr) > 0) && (ns_rr_type(rr) == ns_t_rp)) {
      // Expand the mbox domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr), (char *)&a_dom, sizeof(a_dom))) < 0) {
	perror("dn_expand");
	return;
	//abort();
      }
      // Expand the txt domain
      if ((offs = dn_expand(ns_msg_base(m), ns_msg_end(m), ns_rr_rdata(rr)+offs, (char *)&b_dom, sizeof(b_dom))) < 0) {
	perror("dn_expand");
	return;
	//abort();
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

extern void dumppkt_raw(unsigned char *ucp, int cnt);

static void
dns_describe_packet(u_char *pkt, int len)
{
  // resolver state, local to each thread
  struct __res_state chres;
  memset(&chres, 0, sizeof(chres));
  res_state statp = &chres;
  ns_msg m;

  init_chaos_dns_state(statp);

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
