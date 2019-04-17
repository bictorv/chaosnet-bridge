/* Copyright © 2005, 2017-2019 Björn Victor (bjorn@victor.se) */
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

#include <sys/types.h>
#include "chudp.h"
#include "cbridge.h"

int chudp_debug = 0;

extern int chudp_dynamic, chudp_port;

static pthread_mutex_t chudp_lock = PTHREAD_MUTEX_INITIALIZER;

/* **** CHUDP protocol functions **** */

void print_chudp_config()
{
  int i;
  char ip[INET6_ADDRSTRLEN];
  printf("CHUDP config: %d routes\n", chudpdest_len);
  for (i = 0; i < chudpdest_len; i++) {
    if (inet_ntop(chudpdest[i].chu_sa.chu_saddr.sa_family,
		  (chudpdest[i].chu_sa.chu_saddr.sa_family == AF_INET
		   ? (void *)&chudpdest[i].chu_sa.chu_sin.sin_addr
		   : (void *)&chudpdest[i].chu_sa.chu_sin6.sin6_addr), ip, sizeof(ip))
	== NULL)
      strerror_r(errno, ip, sizeof(ip));
    //    char *ip = inet_ntoa(chudpdest[i].chu_sa.chu_sin.sin_addr);
    printf(" dest %#o, host %s (%s) port %d\n",
	   chudpdest[i].chu_addr, ip,
	   chudpdest[i].chu_name,
	   ntohs(chudpdest[i].chu_sa.chu_sin.sin_port));
  }
}

int
parse_chudp_config_line()
{
  extern int do_udp6, do_udp;

  char *tok = NULL;
  tok = strtok(NULL, " \t\r\n");
  chudp_port = atoi(tok);
  // check for "dynamic" arg, for dynamic updates from new sources
  ;
  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strncmp(tok,"dynamic",sizeof("dynamic")) == 0)
      chudp_dynamic = 1;
    else if (strncmp(tok,"static",sizeof("static")) == 0)
      chudp_dynamic = 0;
    else if (strncmp(tok,"ipv6", sizeof("ipv6")) == 0)
      do_udp6 = 1;
    else if (strcasecmp(tok, "debug") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0))
	chudp_debug = 1;
      else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0))
	chudp_debug = 0;
      else {
	fprintf(stderr,"chudp: bad 'debug' arg %s specified\n", tok);
	return -1;
      }
    }
    else {
      fprintf(stderr,"bad chudp keyword %s\n", tok);
      return -1;
    }
  }
  if (verbose) printf("Using CHUDP port %d (%s)%s\n",chudp_port, chudp_dynamic ? "dynamic" : "static",
		      (do_udp6 ? ", listening to IPv6" : ""));
  return 0;
}

void reparse_chudp_names()
{
  int i, res;
  struct in_addr in;
  struct in6_addr in6;
  struct addrinfo *he;
  struct addrinfo hi;

  memset(&hi, 0, sizeof(hi));
  hi.ai_family = PF_UNSPEC;
  hi.ai_flags = AI_ADDRCONFIG;

  // @@@@ also reparse TLS hosts?
  PTLOCK(chudp_lock);
  for (i = 0; i < chudpdest_len; i++) {
    if (chudpdest[i].chu_name[0] != '\0'  /* have a name */
	&& (inet_aton(chudpdest[i].chu_name, &in) == 0)   /* which is not an explict addr */
	&& (inet_pton(AF_INET6, chudpdest[i].chu_name, &in6) == 0))  /* and not an explicit ipv6 addr */
      {
	// if (verbose) fprintf(stderr,"Re-parsing chudp host name %s\n", chudpdest[i].chu_name);
	
	if ((res = getaddrinfo(chudpdest[i].chu_name, NULL, &hi, &he)) == 0) {
	  if (he->ai_family == AF_INET) {
	    struct sockaddr_in *s = (struct sockaddr_in *)he->ai_addr;
	    memcpy(&chudpdest[i].chu_sa.chu_sin.sin_addr.s_addr, (u_char *)&s->sin_addr, 4);
	  } else if (he->ai_family == AF_INET6) {
	    struct sockaddr_in6 *s = (struct sockaddr_in6 *)he->ai_addr;
	    memcpy(&chudpdest[i].chu_sa.chu_sin6.sin6_addr, (u_char *)&s->sin6_addr, sizeof(struct in6_addr));
	  } else
	    fprintf(stderr,"Error re-parsing chudp host name %s: unsupported address family %d\n",
		    chudpdest[i].chu_name, he->ai_family);
	  // if (verbose) fprintf(stderr," success: %s\n", inet_ntoa(s->sin_addr));
	  freeaddrinfo(he);
	} else if (stats || verbose) {
	  fprintf(stderr,"Error re-parsing chudp host name %s: %s (%d)\n",
		  chudpdest[i].chu_name,
		  gai_strerror(res), res);
	}
      }
  }
  // if (verbose) print_chudp_config();
  PTUNLOCK(chudp_lock);
}

static void
chudp_dumppkt(unsigned char *ucp, int cnt)
{
    fprintf(stderr,"CHUDP version %d, function %d\n", ucp[0], ucp[1]);
    ch_dumpkt(ucp+CHUDP_HEADERSIZE, cnt-CHUDP_HEADERSIZE);
}


static int chudp_connect(u_short port, sa_family_t family) 
{
  int sock;

  if ((family != AF_INET) && (family != AF_INET6)) {
    fprintf(stderr,"Unsupported address family %d - should be AF_INET or AF_INET6\n", family);
    return -1;
  }

  if ((sock = socket(family, SOCK_DGRAM, 0)) < 0) {
    perror("socket failed");
    exit(1);
  }
  if (family == AF_INET6) {
    struct sockaddr_in6 sin6;
    int one = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0)
      perror("setsockopt(IPV6_V6ONLY)");
    sin6.sin6_family = family;
    sin6.sin6_port = htons(port);
    memcpy(&sin6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
    if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
      perror("bind(v6) failed");
      exit(1);
    }
  } else {
    struct sockaddr_in sin;
    sin.sin_family = family;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock,(struct sockaddr *)&sin, sizeof(sin)) < 0) {
      perror("bind failed");
      exit(1);
    }
  }
  return sock;
}

static void
chudp_send_pkt(int sock, struct sockaddr *sout, unsigned char *buf, int len)
{
  struct chaos_header *ch = (struct chaos_header *)&buf[CHUDP_HEADERSIZE];
  unsigned short cks;
  int i;
  char ip[INET6_ADDRSTRLEN];

  i = CHUDP_HEADERSIZE+CHAOS_HEADERSIZE+ch_nbytes(ch)+CHAOS_HW_TRAILERSIZE;
  if ((i % 2) == 1)
    i++;			/* Align */
  if (i != (len + CHUDP_HEADERSIZE)) {
    if (debug)
      fprintf(stderr,"==== chudp_send: calculated length %lu differs from actual %d\n",
	      i - CHUDP_HEADERSIZE, len);
#if 0 // Don't trust caller!!
    i = (len + CHUDP_HEADERSIZE)/2*2;	/* trust caller, round up */
#endif
  }

#if 1
  //  ip = inet_ntoa(sout->sin_addr);
  if (inet_ntop(sout->sa_family,
		(sout->sa_family == AF_INET ? (void *)&((struct sockaddr_in *)sout)->sin_addr : (void *)&((struct sockaddr_in6 *)sout)->sin6_addr),
		ip, sizeof(ip))

      == NULL)
    strerror_r(errno, ip, sizeof(ip));
  if (chudp_debug || verbose || debug) {
    fprintf(stderr,"CHUDP: Sending %s: %lu + %lu + %d + %lu = %d bytes to %s:%d\n",
	    ch_opcode_name(ch_opcode(ch)),
	    CHUDP_HEADERSIZE, CHAOS_HEADERSIZE, ch_nbytes(ch), CHAOS_HW_TRAILERSIZE, i,
	    ip, ntohs(((struct sockaddr_in *)sout)->sin_port));
    if (debug)
      chudp_dumppkt(buf, i);
  }
#endif
  if (sendto(sock, buf, i, 0, sout,
	     (sout->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) < 0) {
    if (verbose || debug)
      perror("sendto failed");
#if 0 // don't die here, some link may be down. Ideally don't retry until "later"
    exit(1);
#endif
  }
}

static struct chroute *
add_chudp_route(u_short srcaddr)
{
  // see if there is a host route for this, otherwise add it
  PTLOCK(rttbl_lock);
  struct chroute *rt = find_in_routing_table(srcaddr, 1, 1);
  if (rt != NULL) {
    // old route exists
    if (rt->rt_link != LINK_CHUDP) {
      if (chudp_debug || debug)
	fprintf(stderr,"CHUDP: Old %s route to %#o found (type %s), updating to CHUDP Dynamic\n",
		rt_linkname(rt->rt_link), srcaddr, rt_typename(rt->rt_type));
#if CHAOS_TLS
      if (rt->rt_link == LINK_TLS) {
	close_tls_route(rt);
      }
#endif
      rt->rt_link = LINK_CHUDP;
      rt->rt_type = RT_DYNAMIC;
      rt->rt_cost = RTCOST_ASYNCH;
      rt->rt_cost_updated = time(NULL);
    }
  } else {
    // Add a host route
    rt = add_to_routing_table(srcaddr, 0, 0, RT_DYNAMIC, LINK_CHUDP, RTCOST_ASYNCH);
  }
  PTUNLOCK(rttbl_lock);
  return rt;
}

static void
add_chudp_dest(u_short srcaddr, struct sockaddr *sin)
{
  if (chudpdest_len < CHUDPDEST_MAX) {
    if (chudp_debug || verbose || stats) fprintf(stderr,"Adding new CHUDP destination %#o.\n", srcaddr);
    PTLOCK(chudp_lock);
    /* clear any non-specified fields */
    memset(&chudpdest[chudpdest_len], 0, sizeof(struct chudest));
    chudpdest[chudpdest_len].chu_addr = srcaddr;
    memcpy(&chudpdest[chudpdest_len].chu_sa, sin, (sin->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    chudpdest_len++;
    if (chudp_debug || verbose) print_chudp_config();
    PTUNLOCK(chudp_lock);
  } else {
    if (chudp_debug || stats || verbose) fprintf(stderr,"%%%% CHUDP table full, not adding new destination.\n");
    return;
  }
}

static int
chudp_receive(int sock, unsigned char *buf, int buflen)
{
  struct chaos_header *ch = (struct chaos_header *)&buf[CHUDP_HEADERSIZE];
  struct chudp_header *cuh = (struct chudp_header *)buf;
  struct sockaddr_in6 sin;	// #### sockaddr_in6 is larger than sockaddr_in and sockaddr
  char ip[INET6_ADDRSTRLEN];
  int i, cnt, cks;
  u_int sinlen;

  memset(&sin,0,sizeof(sin));
  sinlen = sizeof(sin);
  cnt = recvfrom(sock, buf, buflen, 0, (struct sockaddr *) &sin, &sinlen);
  if (cnt < 0) {
    perror("recvfrom");
    exit(1);
  }
  if (inet_ntop(sin.sin6_family,
		(sin.sin6_family == AF_INET ? (void *)&((struct sockaddr_in *)&sin)->sin_addr
		 : (void *)&((struct sockaddr_in6 *)&sin)->sin6_addr),
		ip, sizeof(ip))
	== NULL)
      strerror_r(errno, ip, sizeof(ip));
  if ((cnt < CHUDP_HEADERSIZE) ||
      (cuh->chudp_version != CHUDP_VERSION) ||
      (cuh->chudp_function != CHUDP_PKT)) {
    if (chudp_debug || verbose) fprintf(stderr,"Bad CHUDP header (size %d) from %s:%d\n",cnt,
			 ip, ntohs(sin.sin6_port));
    // #### look up the source in chudpdest, count rejected pkt
    return 0;
  }
  int found = 0;

#if 1
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&buf[cnt-CHAOS_HW_TRAILERSIZE];
  u_short srctrailer = 0, srcaddr = ch_srcaddr(ch);
  if (cnt >= CHUDP_HEADERSIZE + CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)
    // Prefer HW sender (i.e. the chudp host rather than origin host)
    srctrailer = ntohs(tr->ch_hw_srcaddr);
#endif

  PTLOCK(chudp_lock);
  if (chudp_debug || debug)
    fprintf(stderr,"Looking up %s (%#o trailer %#o) among %d chudp entries\n", ip, srcaddr, srctrailer, chudpdest_len);
  for (i = 0; i < chudpdest_len; i++) {
    if ((chudpdest[i].chu_sa.chu_saddr.sa_family == sin.sin6_family)
	&& (chudpdest[i].chu_sa.chu_sin.sin_port == sin.sin6_port)
	&& (((chudpdest[i].chu_sa.chu_saddr.sa_family == AF_INET) &&
	     (memcmp((u_char *)&chudpdest[i].chu_sa.chu_sin.sin_addr, (u_char *)&((struct sockaddr_in *)&sin)->sin_addr, sizeof(struct in_addr)) == 0))
	    ||
	    ((chudpdest[i].chu_sa.chu_saddr.sa_family == AF_INET6) &&
	     (memcmp((u_char *)&chudpdest[i].chu_sa.chu_sin6.sin6_addr, (u_char *)&((struct sockaddr_in6 *)&sin)->sin6_addr, sizeof(struct in6_addr)) == 0))))
	  {
      found = 1;
#if 0 // needs more testing
      {
	/* Check for pkts with a header source which exists on another link wrt link source */
	/* It's OK to receive a pkt from an addr which is not the link's, since there may be a whole net behind it,
	   but not OK if it's from a another link's address - that's misconfigured, here or there. */
	if (chudpdest[i].chu_addr != srcaddr) {	 // not from the link address
	  struct chroute *rt = find_in_routing_table(srcaddr, 0, 0); // find its link
	  if ((rt != NULL) && (rt->rt_dest == srcaddr)) { // it's on another link!
	    if (chudp_debug || verbose)
	      fprintf(stderr,"CHUDP host %#o is on another link than where it came from (%#o), rejecting/dropping\n",
		      srcaddr, chudpdest[i].chu_addr);
	    PTLOCK(linktab_lock);
	    linktab[(chudpdest[i].chu_addr)>>8].pkt_rejected++;
	    PTUNLOCK(linktab_lock);
	    PTUNLOCK(chudp_lock);
	    return 0;
	  }
	}
      }
#endif
#if 0
      // There may be more than one CHUDP host on a single IP.
      if (chudpdest[i].chu_sa.chu_sin.sin_port != sin.sin6_port) {
	if (chudp_debug || verbose)
	  fprintf(stderr,"CHUDP from %s port different from configured: %d # %d (dropping)\n",
		  ip, ntohs(sin.sin6_port), ntohs(chudpdest[i].chu_sa.chu_sin.sin_port));
	// #### if configured to use dynamic updates/additions also for this case?
	PTUNLOCK(chudp_lock);
	return 0;
      }
#endif
      break;
    }
  }
  PTUNLOCK(chudp_lock);

#if 0
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&buf[cnt-CHAOS_HW_TRAILERSIZE];
  u_short srcaddr = ch_srcaddr(ch);
#else
  if (cnt >= CHUDP_HEADERSIZE + CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)
    // Prefer HW sender (i.e. the chudp host rather than origin host)
    srcaddr = ntohs(tr->ch_hw_srcaddr);
#endif

  if (!found) {
    if (chudp_debug || verbose) fprintf(stderr,"CHUDP from unknown source %s:%d\n",
			 ip, ntohs(sin.sin6_port));
    // if configured to use dynamic updates/additions, do it
    if (chudp_dynamic) {
      add_chudp_dest(srcaddr, (struct sockaddr *)&sin);
    } else
      return 0;
  }
  // make sure there is an up-to-date route of the right type
  add_chudp_route(srcaddr);

#if 1
  if (chudp_debug || verbose || debug) {
    fprintf(stderr,"CHUDP: Received %d bytes (%s) from %s:%d (%#o)\n",
	    cnt, ch_opcode_name(ch_opcode(ch)),
	    ip, ntohs(sin.sin6_port), srcaddr);
    if (debug)
      chudp_dumppkt(buf, cnt);
  }
#endif
  if ((cks = ch_checksum(&buf[CHUDP_HEADERSIZE],cnt-CHUDP_HEADERSIZE)) != 0) {
    if (chudp_debug || verbose) fprintf(stderr,"[Bad checksum %#x (CHUDP)]\n",cks);
    PTLOCK(linktab_lock);
    linktab[srcaddr>>8].pkt_crcerr++;
    PTUNLOCK(linktab_lock);
    return 0;
  }

  return cnt;
}

void * chudp_input(void *v)
{
  /* CHUDP -> others thread */
  int sock = (int)*(int *)v;
  u_int len;
  u_char data[CH_PK_MAXLEN+CHUDP_HEADERSIZE];
  struct chaos_header *ch = (struct chaos_header *)&data[CHUDP_HEADERSIZE];

  while (1) {
    bzero(data,sizeof(data));
    len = chudp_receive(sock, data, sizeof(data));
    /*       len = CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE; */
    if (len >= (CHUDP_HEADERSIZE + CHAOS_HEADERSIZE + CHAOS_HW_TRAILERSIZE)) {
      len -= CHUDP_HEADERSIZE;
      if (debug) fprintf(stderr,"chudp input %d bytes\n", len);
      // check where it's coming from
      u_short srcaddr;
      if (len > (ch_nbytes(ch) + CHAOS_HEADERSIZE)) {
	struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[CHUDP_HEADERSIZE+len-CHAOS_HW_TRAILERSIZE];
	srcaddr = ntohs(tr->ch_hw_srcaddr);
      } else
	srcaddr = ch_srcaddr(ch);
      struct chroute *srcrt = find_in_routing_table(srcaddr, 0, 0);
      forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			srcrt != NULL ? srcrt->rt_cost : RTCOST_ASYNCH,
			(u_char *)ch, len, LINK_CHUDP);
    } else
      if (len > 0 && (chudp_debug || verbose)) fprintf(stderr,"chudp: Short packet %d bytes\n", len);
  }
}

void
forward_on_chudp(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  int i, found;
  u_char chubuf[CH_PK_MAXLEN + CHUDP_HEADERSIZE];
  struct chudp_header *chu = (struct chudp_header *)&chubuf;

  if (chudp_debug || debug)
    fprintf(stderr,"Forward: Sending on CHUDP from %#o to %#o via %#o/%#o (%d bytes)\n",
	    schad, dchad, rt->rt_dest, rt->rt_braddr, dlen);
  /* Add CHUDP header, copy message only once (in case it needs to be sent more than once) */
  memset(&chubuf, 0, sizeof(chubuf));
  chu->chudp_version = CHUDP_VERSION;
  chu->chudp_function = CHUDP_PKT;
  // Assert that dlen+CHUDP_HEADERSIZE <= sizeof(chubuf)
  memcpy(&chubuf[CHUDP_HEADERSIZE], data, dlen);

  found = 0;

  if (debug) {
    fprintf(stderr,"Looking for CHUDP dest for this route:\n");
    fprintf(stderr,"Host\tBridge\tType\tLink\tCost\tMyAddr\n");
    fprintf(stderr,"%#o\t%#o\t%s\t%s\t%d\t%#o\n",
	    rt->rt_dest, rt->rt_braddr, rt_typename(rt->rt_type), rt_linkname(rt->rt_link), rt->rt_cost, rt->rt_myaddr);
  }

  PTLOCK(chudp_lock);
  for (i = 0; (i < chudpdest_len) && !found; i++) {
    if (
#if 0
	dchad == 0		/* broadcast: goes on all links */
	|| 
#endif
	/* direct link to destination */
	(chudpdest[i].chu_addr == dchad)
	/* route to bridge */
	|| 
	(chudpdest[i].chu_addr == rt->rt_braddr)
	/* route to dest */
	|| 
	(rt->rt_braddr == 0 && (chudpdest[i].chu_addr == rt->rt_dest))
	) {
      if (chudp_debug || debug)
	fprintf(stderr,"Forward CHUDP to dest %#o over %#o (%s)\n", dchad, chudpdest[i].chu_addr, chudpdest[i].chu_name);
      found = 1;
      if (chudpdest[i].chu_sa.chu_saddr.sa_family == AF_INET)
	chudp_send_pkt(udpsock, &chudpdest[i].chu_sa.chu_saddr, (u_char *)&chubuf, dlen);
      else
	chudp_send_pkt(udp6sock, &chudpdest[i].chu_sa.chu_saddr, (u_char *)&chubuf, dlen);
      break;
    }
  }
  PTUNLOCK(chudp_lock);
  if (!found && (chudp_debug || verbose || debug))
    fprintf(stderr, "Can't find CHUDP link to %#o via %#o/%#o\n",
	    dchad, rt->rt_dest, rt->rt_braddr);
}

// initialize module
void init_chaos_udp(int ipv4, int ipv6)
{
  if (ipv6) {
    if ((udp6sock = chudp_connect(chudp_port, AF_INET6)) < 0)
      exit(1);
  }
  if (ipv4) {
    if ((udpsock = chudp_connect(chudp_port, AF_INET)) < 0)
      exit(1);
  }
}
