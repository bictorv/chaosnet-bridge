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

// **** Chaosnet-over-IP ****
// See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

// TODO:
// - UP problems, due to Hurricane Electric IPv6 tunnel
// -- he-ipv6 doesn't have ipv4 address (shows as 255.255.255.255)
// -- UP must pick either v4 or v6 because only one device - bad
// -- need to configure interface per link
// - IPv6 broadcast is "more advanced" than IPv4
// - config warning if my IPv6 is link-local?

#include "cbridge.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>


int chip_dynamic = 0;

static pthread_mutex_t chipdest_lock = PTHREAD_MUTEX_INITIALIZER;
struct chipdest chipdest[CHIPDEST_MAX];
int chipdest_len = 0;

static int ip6_sock, ip_sock;

void 
print_chipdest_config()
{
  int i;
  char ip[INET6_ADDRSTRLEN];
  printf("CHIP config: %d routes\n", chipdest_len);
  for (i = 0; i < chipdest_len; i++) {
    if (inet_ntop(chipdest[i].chip_sa.chip_saddr.sa_family,
		  (chipdest[i].chip_sa.chip_saddr.sa_family == AF_INET
		   ? (void *)&chipdest[i].chip_sa.chip_sin.sin_addr
		   : (void *)&chipdest[i].chip_sa.chip_sin6.sin6_addr), ip, sizeof(ip))
	== NULL)
      strerror_r(errno, ip, sizeof(ip));
    //    char *ip = inet_ntoa(chipdest[i].chip_sa.chip_sin.sin_addr);
    printf(" dest %#o, host %s (%s)\n",
	   chipdest[i].chip_addr, ip,
	   chipdest[i].chip_name);
  }
}

// chip dynamic on/off
int
parse_chip_config_line()
{
  char *tok = NULL;
  while ((tok = strtok(NULL," \t\r\n")) != NULL) {
    if (strcasecmp(tok, "dynamic") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0))
	chip_dynamic = 1;
      else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0))
	chip_dynamic = 0;
      else {
	fprintf(stderr,"chip: bad 'dynamic' arg %s specified\n", tok);
	return -1;
      }
    } else {
      fprintf(stderr,"chip config keyword %s unknown\n", tok);
      return -1;
    }
  }
  return 0;
}

void
print_config_chip()
{
  printf("CHIP: dynamic %s\n", chip_dynamic ? "on" : "off");
}

// @@@@ copy-paste of reparse_chudp_names, modularize?
void reparse_chip_names()
{
  int i, res;
  struct in_addr in;
  struct in6_addr in6;
  struct addrinfo *he;
  struct addrinfo hi;

  memset(&hi, 0, sizeof(hi));
  hi.ai_family = PF_UNSPEC;
  hi.ai_flags = AI_ADDRCONFIG;

  PTLOCK(chipdest_lock);
  for (i = 0; i < chipdest_len; i++) {
    if (chipdest[i].chip_name[0] != '\0'  /* have a name */
	&& (inet_aton(chipdest[i].chip_name, &in) == 0)   /* which is not an explict addr */
	&& (inet_pton(AF_INET6, chipdest[i].chip_name, &in6) == 0))  /* and not an explicit ipv6 addr */
      {
	// if (verbose) fprintf(stderr,"Re-parsing chip host name %s\n", chipdest[i].chip_name);
	
	if ((res = getaddrinfo(chipdest[i].chip_name, NULL, &hi, &he)) == 0) {
	  if (he->ai_family == AF_INET) {
	    struct sockaddr_in *s = (struct sockaddr_in *)he->ai_addr;
	    memcpy(&chipdest[i].chip_sa.chip_sin.sin_addr.s_addr, (u_char *)&s->sin_addr, 4);
	  } else if (he->ai_family == AF_INET6) {
	    struct sockaddr_in6 *s = (struct sockaddr_in6 *)he->ai_addr;
	    memcpy(&chipdest[i].chip_sa.chip_sin6.sin6_addr, (u_char *)&s->sin6_addr, sizeof(struct in6_addr));
	  } else
	    fprintf(stderr,"Error re-parsing chip host name %s: unsupported address family %d\n",
		    chipdest[i].chip_name, he->ai_family);
	  // if (verbose) fprintf(stderr," success: %s\n", inet_ntoa(s->sin_addr));
	  freeaddrinfo(he);
	} else if (stats || verbose) {
	  fprintf(stderr,"Error re-parsing chip host name %s: %s (%d)\n",
		  chipdest[i].chip_name,
		  gai_strerror(res), res);
	}
      }
  }
  // if (verbose) print_chipdest_config();
  PTUNLOCK(chipdest_lock);
}

void
init_chaos_ip()
{
  if ((ip_sock = socket(AF_INET, SOCK_RAW, IPPROTO_CHAOS)) < 0) {
    perror("socket(AF_INET, SOCK_RAW, IPPROTO_CHAOS)");
    exit(1);
  } else if (debug)
    fprintf(stderr,"CHIP: IPv4 socket is %d\n", ip_sock);
  if ((ip6_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_CHAOS)) < 0) {
    perror("socket(AF_INET6, SOCK_RAW, IPPROTO_CHAOS)");
    exit(1);
  } else if (debug)
    fprintf(stderr,"CHIP: IPv6 socket is %d\n", ip6_sock);
}

static void
add_chip_dest(u_short srcaddr, sa_family_t fam, u_char *addr)
{
  if (chipdest_len < CHIPDEST_MAX) {
    if (verbose || stats) fprintf(stderr,"Adding new CHIP destination %#o.\n", srcaddr);
    PTLOCK(chipdest_lock);
    /* clear any non-specified fields */
    memset(&chipdest[chipdest_len], 0, sizeof(struct chipdest));
    chipdest[chipdest_len].chip_addr = srcaddr;
    chipdest[chipdest_len].chip_sa.chip_saddr.sa_family = fam;
    if (fam == AF_INET)
      memcpy(&chipdest[chipdest_len].chip_sa.chip_sin.sin_addr, addr, sizeof(struct in_addr));
    else
      memcpy(&chipdest[chipdest_len].chip_sa.chip_sin6.sin6_addr.s6_addr, addr, sizeof(struct in6_addr));
    chipdest_len++;
    if (verbose) print_chipdest_config();
    PTUNLOCK(chipdest_lock);

    // see if there is a host route for this, otherwise add it
    if (*rttbl_host_len < RTTBL_HOST_MAX) {
      int i, found = 0;
      for (i = 0; i < *rttbl_host_len; i++) {
	if (rttbl_host[i].rt_dest == srcaddr) {
	  found = 1;
	  break;
	}
      }
      if (!found) {
	PTLOCK(rttbl_lock);
	if (*rttbl_host_len < RTTBL_HOST_MAX) { // double check
	  // Add a host route (as if "link chip [host] host [srcaddr]" was given)	    
	  rttbl_host[(*rttbl_host_len)].rt_dest = srcaddr;
	  rttbl_host[(*rttbl_host_len)].rt_type = RT_FIXED;
	  rttbl_host[(*rttbl_host_len)].rt_cost = RTCOST_ASYNCH;
	  rttbl_host[(*rttbl_host_len)].rt_link = LINK_IP;
	  (*rttbl_host_len)++;
	  if (verbose) print_routing_table();
	}
	PTUNLOCK(rttbl_lock);
      }
    } else {
      if (stats || verbose) fprintf(stderr,"%%%% Host routing table full, not adding new route.\n");
      // and the chip dest is useless, really.
      return;
    }
  } else {
    if (stats || verbose) fprintf(stderr,"%%%% CHIP table full, not adding new destination.\n");
    return;
  }
}

// @@@@ break this up in parts
void *
chip_input(void *v)
{
  // @@@@ clean up in_addr vs sockaddr etc
  int len, chlen;
  u_short srcaddr;		/* chaos source */
  struct in_addr ip_src;	/* ip source */
  struct in6_addr ip6_src;	/* ipv6 source */
  struct sockaddr_in6 sa;	// #### sockaddr_in6 is larger than sockaddr_in and sockaddr
  socklen_t salen;
  fd_set rfd;
  int maxfd;
  u_char data[CH_PK_MAXLEN+sizeof(struct ip)+sizeof(struct ip6_hdr)];	 /* fuzz */
  u_char *chdata;
  int sval;
  int ipv;
  struct chaos_header *ch;
  
  maxfd = 1+(ip_sock > ip6_sock ? ip_sock : ip6_sock);
  while (1) {
    memset(&sa, 0, sizeof(sa));
    salen = sizeof(sa);
    // select, then recvfrom
    FD_ZERO(&rfd);
    FD_SET(ip_sock, &rfd);
    FD_SET(ip6_sock, &rfd);
    if ((sval = select(maxfd, &rfd, NULL, NULL, NULL)) < 0)
      perror("select(chip_input)");
    else if (sval > 0) {
      if (FD_ISSET(ip_sock, &rfd)) {
	if (debug) fprintf(stderr,"CHIP: receiving from IPv4 socket\n");
	len = recvfrom(ip_sock, &data, sizeof(data), 0, (struct sockaddr *) &sa, &salen);
      } else if (FD_ISSET(ip6_sock, &rfd)) {
	if (debug) fprintf(stderr,"CHIP: receiving from IPv6 socket\n");
	len = recvfrom(ip6_sock, &data, sizeof(data), 0, (struct sockaddr *) &sa, &salen);
      }
      else {
	if (debug) fprintf(stderr,"CHIP: select returned %d but neither v4/v6 socket set\n", sval);
	len = -1;
      }
    } else if (sval == 0) {
      if (debug) fprintf(stderr,"CHIP: select timeout? %d\n", sval);
      len = -1;
    } else {
      perror("CHIP: select");
      len = -1;
    }
    if (debug) fprintf(stderr,"CHIP: received %d bytes\n", len);
    if (len > 0) {
      chdata = (u_char *)&data;
      ch = (struct chaos_header *)chdata;
      chlen = len;
      // Get it in host order
      ntohs_buf((u_short *)chdata, (u_short *)chdata, chlen);

      // Expected length
      int xlen = (CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE);
      if ((xlen % 2) == 1)
	xlen++;			/* alignment */

      // check Chaos trailer (incl checksum)
      if (chlen < xlen) {
	fprintf(stderr,"CHIP: short packet received from %#o, no room for hw trailer: total %d, chaos %d (nbytes %d) (expected %d)\n",
		ch_srcaddr(ch),
		len, chlen, ch_nbytes(ch), xlen);
	if (debug) ch_dumpkt(chdata, chlen);
	PTLOCK(linktab_lock);
	linktab[srcaddr>>8].pkt_badlen++;
	PTUNLOCK(linktab_lock);
	continue;
      } else if (chlen > xlen) {
	if (debug) fprintf(stderr,"CHIP: long pkt received: %d. expected %d\n", chlen, xlen);
      }

      if (debug) fprintf(stderr,"CHIP: sockaddr len %d, family %d\n", salen, ((struct sockaddr *)&sa)->sa_family);
      if (((struct sockaddr *)&sa)->sa_family == AF_INET) {
	ipv = 4;
	memcpy(&ip_src, &((struct sockaddr_in *)&sa)->sin_addr, sizeof(ip_src));
      } else if (((struct sockaddr *)&sa)->sa_family == AF_INET6) {
	ipv = 6;
	memcpy(&ip6_src, &((struct sockaddr_in6 *)&sa)->sin6_addr, sizeof(ip6_src));
      } else {
	fprintf(stderr,"%%%% CHIP: unexpected protocol family %d\n", ((struct sockaddr *)&sa)->sa_family);
	exit(1);
      }
      // Process trailer info
      struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&chdata[chlen-CHAOS_HW_TRAILERSIZE];
      srcaddr = ntohs(tr->ch_hw_srcaddr);
      int cks = ch_checksum(chdata, chlen);
      if (cks != 0) {
	char ipaddr[INET6_ADDRSTRLEN];
	if (inet_ntop(ipv == 4 ? AF_INET : AF_INET6,
		      ipv == 4 ? (void *)&ip_src : (void *)&ip6_src,
		      ipaddr, sizeof(ipaddr)) == NULL)
	  strerror_r(errno,ipaddr,sizeof(ipaddr));
	fprintf(stderr,"CHIP: bad checksum %#x from source %#o (%s)\n", cks, srcaddr, ipaddr);
	PTLOCK(linktab_lock);
	linktab[srcaddr>>8].pkt_crcerr++;
	PTUNLOCK(linktab_lock);
	continue;
      }

      // look up source in CHIP table, verify it exists, maybe add
      int i, found = 0;
      sa_family_t ipfam = (ipv == 4 ? AF_INET : AF_INET6);
      for (i = 0; (i < chipdest_len) && !found; i++) {
	if ((chipdest[i].chip_sa.chip_saddr.sa_family == ipfam)
	    && (((ipfam == AF_INET) && (memcmp(&ip_src, &chipdest[i].chip_sa.chip_sin.sin_addr, sizeof(ip_src)) == 0))
		||
		((ipfam == AF_INET6) && (memcmp(&ip6_src, &chipdest[i].chip_sa.chip_sin6.sin6_addr, sizeof(ip6_src)) == 0)))) {
	  found = 1;
	  break;
	}
      }

      if (verbose || debug || !found) {
	char ipaddr[INET6_ADDRSTRLEN];
	if (inet_ntop(ipv == 4 ? AF_INET : AF_INET6,
		      ipv == 4 ? (void *)&ip_src : (void *)&ip6_src,
		      ipaddr, sizeof(ipaddr)) == NULL)
	  strerror_r(errno,ipaddr,sizeof(ipaddr));
	if (verbose || debug) fprintf(stderr,"CHIP from %s (Chaos hw %#o) received: %d bytes from Chaos source %#o\n",
				      ipaddr, srcaddr, chlen, ch_srcaddr(ch));
	if (debug) ch_dumpkt(chdata, chlen);
	if (!found) {
	  if (!chip_dynamic) {
	    fprintf(stderr,"%%%% CHIP pkt received from unknown source %s - dropping it\n", ipaddr);
	    return 0;
	  } else {
	    if (verbose || debug) fprintf(stderr,"%%%% CHIP adding dest %#o at %s\n", srcaddr, ipaddr);
	    add_chip_dest(srcaddr, (ipv == 4 ? AF_INET : AF_INET6), (ipv == 4 ? (u_char *)&ip_src : (u_char *)&ip6_src));
	  }
	}
      }

      // Find source route, and dispatch the packet
      struct chroute *srcrt = find_in_routing_table(srcaddr, 0, 0);
      forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			srcrt != NULL ? srcrt->rt_type : RT_DIRECT,
			srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
			chdata, chlen, LINK_IP);
    }
  }
}

static void 
chip_send_pkt_ipv4(struct sockaddr_in *sout, u_char *pkt, int pklen)
{
  int c;

  if (debug) {
    fprintf(stderr,"CHIP: About to send IPv4 pkt to %s\n", inet_ntoa(sout->sin_addr));
    dumppkt_raw(pkt, pklen);
  }
  c = sendto(ip_sock, pkt, pklen, 0, (struct sockaddr *)sout, sizeof(struct sockaddr_in));
  if (c < 0)
    perror("chip_send_pkt_ipv4");
  else if (debug)
    fprintf(stderr,"CHIP: chip_send_pkt_ipv4: wrote %d bytes\n", c);
}

static void 
chip_send_pkt_ipv6(struct sockaddr_in6 *sout, u_char *pkt, int pklen)
{
  int c;

  if (debug) {
    char ip6[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &sout->sin6_addr, ip6, sizeof(ip6)) == NULL)
      strerror_r(errno, ip6, sizeof(ip6));
    fprintf(stderr,"CHIP: About to send IPv6 pkt to %s\n", ip6);
    dumppkt_raw(pkt, pklen);
  }
  c = sendto(ip6_sock, pkt, pklen, 0, (struct sockaddr *)sout, sizeof(struct sockaddr_in6));
  if (c < 0)
    perror("chip_send_pkt_ipv6");
  else if (debug)
    fprintf(stderr,"CHIP: chip_send_pkt_ipv6: wrote %d bytes\n", c);
}

static void 
chip_send_pkt(struct sockaddr *sout, u_char *pkt, int pklen)
{
  switch (sout->sa_family) {
  case AF_INET:
    chip_send_pkt_ipv4((struct sockaddr_in *)sout, pkt, pklen);
    break;
  case AF_INET6:
    chip_send_pkt_ipv6((struct sockaddr_in6 *)sout, pkt, pklen);
    break;
  default:
    fprintf(stderr,"%%%% CHIP: unexpected protocol family %d in chip_send_pkt\n",sout->sa_family);
  }
}

// @@@@ break this up in parts
void
forward_on_ip(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  int i, found = 0;

  // Swap back to network order
  htons_buf((u_short *)data, (u_short *)data, dlen);

  // look up in chipdest, send using libnet
  PTLOCK(chipdest_lock);
  for (i = 0; (i < chipdest_len) && !found; i++) {
    if ( // maybe check broadcast at some point
	/* direct link */
	(chipdest[i].chip_addr == dchad) 
	||
	/* link to bridge */
	(chipdest[i].chip_addr == rt->rt_braddr) 
	||
	/* link to dest */
	(rt->rt_braddr == 0 && (chipdest[i].chip_addr == rt->rt_dest))) {
      if (verbose || debug) fprintf(stderr,"Forward CHIP to dest %#o over direct link %#o (%s)\n",
				    dchad, chipdest[i].chip_addr, chipdest[i].chip_name);
      found = 1;
      chip_send_pkt(&chipdest[i].chip_sa.chip_saddr, data, dlen);
    }
  }
  if (!found) {
    // check for subnet match and fill in IP subnet addr
    // IPv4: If chipdest has subnet addr (zero host byte) matching dchad, copy host byte of dchad to last octet of chip_sa
    // IPv6: same (and still _last_ octet).
    for (i = 0; (i < chipdest_len) && !found; i++) {
      if (
	  /* dest is a subnet, and it matches our dest */
	  // (chip_addr is just the subnet, cf parse_link_config)
	  (((chipdest[i].chip_addr & 0xff00) == 0) && ((chipdest[i].chip_addr & 0xff) == (dchad & 0xff00)>>8))
	  ||
	  /* dest is broadcast */
	  (((rt->rt_dest & 0xff) == 0) &&  /* dest is broadcast */
	   ((chipdest[i].chip_addr & 0xff00) == 0) &&  /* this is a subnet dest */
	   ((chipdest[i].chip_addr << 8) == (rt->rt_dest & 0xff00)))  /* and it matches */
	  ) {
	if (chipdest[i].chip_sa.chip_saddr.sa_family == AF_INET) {
	  struct sockaddr_in dip;
	  memcpy(&dip, &chipdest[i].chip_sa.chip_sin, sizeof(dip));
	  if (dchad == 0)	/* broadcast */
	    dip.sin_addr.s_addr |= htonl(0xff);
	  else if ((dchad & 0xff) == 0xff) {
	    if (debug) {
	      fprintf(stderr,"CHIP: not forwarding to Chaos %#o (%#x) because it maps to the broadcast address\n",
		      dchad, dchad);
	    }
	    break;
	  } else
	    dip.sin_addr.s_addr |= htonl(dchad & 0xff);
	  if (debug) fprintf(stderr,"CHIP: subnet link %#o to dest %#o gives IP %s\n",
			     chipdest[i].chip_addr, dchad, inet_ntoa(dip.sin_addr));
	  chip_send_pkt((struct sockaddr *)&dip, data, dlen);
	} else if (chipdest[i].chip_sa.chip_saddr.sa_family == AF_INET6) {
	  if (dchad == 0) {
	    // @@@@ fixme
	    if (verbose || debug) fprintf(stderr,"%%%% CHIP: broadcast to IPv6 not implemented yet\n");
	    break;
	  }
	  struct sockaddr_in6 dip;
	  memcpy(&dip, &chipdest[i].chip_sa.chip_sin6, sizeof(dip));
	  dip.sin6_addr.s6_addr[15] = (dchad & 0xff);
	  if (debug) {
	    char ipaddr[INET6_ADDRSTRLEN];
	    if (inet_ntop(AF_INET6,
			  &dip.sin6_addr,
			  ipaddr, sizeof(ipaddr)) == NULL)
	      strerror_r(errno,ipaddr,sizeof(ipaddr));
	    fprintf(stderr,"CHIP: subnet link %#o to dest %#o gives IPv6 %s\n",
		    chipdest[i].chip_addr, dchad, ipaddr);
	  }
	  chip_send_pkt((struct sockaddr *)&dip, data, dlen);
	} else {
	  fprintf(stderr,"%%%% CHIP: unexpected address family %d\n",chipdest[i].chip_sa.chip_saddr.sa_family);
	  break;
	}
	if (verbose || debug) fprintf(stderr,"Forward CHIP to dest %#o over subnet link %#o (%s)\n",
				      dchad, chipdest[i].chip_addr, chipdest[i].chip_name);
	found = 1;
      }
    }
  }
  PTUNLOCK(chipdest_lock);
  if (!found && (verbose || debug)) {
    fprintf(stderr,"Can't find CHIP link to %#o via %#o/%#o\n",
	    dchad, rt->rt_dest, rt->rt_braddr);
  }
}
