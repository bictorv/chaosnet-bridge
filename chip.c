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
// - implement IPv6 multicast (instead of broadcast)
// - for IPv6, consider how to do subnet mapping properly/in a modern way

#include "cbridge.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>

int chip_dynamic = 0;

static pthread_mutex_t chipdest_lock = PTHREAD_MUTEX_INITIALIZER;
struct chipdest chipdest[CHIPDEST_MAX];
int chipdest_len = 0;

static int chip_debug = 0;
static int ip6_sock, ip_sock;

void 
print_chipdest_config()
{
  int i;
  char ip[INET6_ADDRSTRLEN];
  printf("CHIP config: %d routes\n", chipdest_len);
  for (i = 0; i < chipdest_len; i++) {
    printf(" dest %#o, host %s (%s)\n",
	   chipdest[i].chip_addr, ip46_ntoa(&chipdest[i].chip_sa.chip_saddr, ip, sizeof(ip)),
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
    }
    else if (strcasecmp(tok, "debug") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0))
	chip_debug = 1;
      else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0))
	chip_debug = 0;
      else {
	fprintf(stderr,"chip: bad 'debug' arg %s specified\n", tok);
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

// Given an address (typically with 0 last octet), search for a matching address on our interfaces, and return its last octet
// Used for checking/defaulting "myaddr" parameter of config entries.
// If no matching interface is found, 0 is returned.
static int
last_addr_octet_on_net(struct sockaddr *sa)
{
  struct sockaddr_in *mysin = (struct sockaddr_in *)sa;
  struct sockaddr_in6 *mysin6 = (struct sockaddr_in6 *)sa;
  struct ifaddrs *ifp, *ifp0;
  int octet = 0;
  char ipaddr[INET6_ADDRSTRLEN];

  if (getifaddrs(&ifp0) < 0) {
    perror("getifaddrs");
    return 0;
  }
  if (debug) fprintf(stderr,"Looking for interface matching subnet address %s\n",
		     ip46_ntoa(sa, ipaddr, sizeof(ipaddr)));
  ifp = ifp0;
  while (ifp && (octet == 0)) {
    // if (debug) fprintf(stderr,"Checking interface %s, address %s\n", ifp->ifa_name, ip46_ntoa(ifp->ifa_addr, ipaddr, sizeof(ipaddr)));
    if ((sa->sa_family == AF_INET) && (ifp->ifa_addr->sa_family == AF_INET)) {
      struct sockaddr_in *sin = (struct sockaddr_in *)ifp->ifa_addr;
      u_int mask = ntohl(((struct sockaddr_in *)(ifp->ifa_netmask))->sin_addr.s_addr);
      if ((ntohl(mysin->sin_addr.s_addr) & mask) == (ntohl(sin->sin_addr.s_addr) & mask)) {
	if (debug)
	  fprintf(stderr,"Found matching IP interface %s with address %s\n",
		  ifp->ifa_name, ip46_ntoa(ifp->ifa_addr, ipaddr, sizeof(ipaddr)));
	octet = ntohl(sin->sin_addr.s_addr) & 0xff;
      }
    } else if ((sa->sa_family == AF_INET6) && (ifp->ifa_addr->sa_family == AF_INET6)) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifp->ifa_addr;
      // @@@@ should use ifa_netmask
      if (memcmp(&mysin6->sin6_addr, &sin6->sin6_addr, sizeof(struct in6_addr)-1) == 0) {
	if (debug)
	  fprintf(stderr,"Found matching IPv6 interface %s with address %s\n",
		  ifp->ifa_name, ip46_ntoa(ifp->ifa_addr, ipaddr, sizeof(ipaddr)));
	octet = sin6->sin6_addr.s6_addr[15];
      }
    }
    ifp = ifp->ifa_next;
  }
  freeifaddrs(ifp0);
  return octet;
}

int
validate_chip_entry(struct chipdest *cd, struct chroute *rt, int subnetp, int nchaddr)
{
  if (subnetp) {
    // check that we have an IP address on that net
    char ipaddr[INET6_ADDRSTRLEN];
    int octet = last_addr_octet_on_net(&cd->chip_sa.chip_saddr);
    if (octet == 0) {
      fprintf(stderr,"CHIP subnet mapping with no matching local IP address: %s\n",
	      ip46_ntoa(&cd->chip_sa.chip_saddr, ipaddr, sizeof(ipaddr)));
      // fail validation
      return -1;
    } 
    // validate myaddr parameter and fix it
    if ((rt->rt_myaddr != ((cd->chip_addr << 8) | octet))) {
      // needs fixing
      if (rt->rt_myaddr != 0) // only complain if it has been explicitly set
	fprintf(stderr,"CHIP subnet mapping for subnet %o has bad \"myaddr\" parameter %o, fixing it (should be %o)\n",
		cd->chip_addr, rt->rt_myaddr,
		(cd->chip_addr << 8) | octet);
      else
	fprintf(stderr,"CHIP subnet mapping for subnet %o missing \"myaddr\", should be %o (fixing it)\n",
		cd->chip_addr, (cd->chip_addr << 8) | octet);
      // fix this too
      if ((nchaddr > 0) && (mychaddr[nchaddr-1] == rt->rt_myaddr))
	mychaddr[nchaddr-1] = (cd->chip_addr << 8) | octet;
      rt->rt_myaddr = (cd->chip_addr << 8) | octet;
    }

    // check that the IP address is not complete
    if (cd->chip_sa.chip_sin.sin_family == AF_INET) {
      if ((ntohl(cd->chip_sa.chip_sin.sin_addr.s_addr) & 0xff) != 0) {
	fprintf(stderr,"CHIP subnet %#o link maps to %s but should have IP with last octet 0, fixing it for you\n",
		cd->chip_addr, inet_ntoa(cd->chip_sa.chip_sin.sin_addr));
	cd->chip_sa.chip_sin.sin_addr.s_addr &= htonl(0xffffff00);
	// also fix this, for reparsing.
	sprintf(cd->chip_name, "%s",
		inet_ntoa(cd->chip_sa.chip_sin.sin_addr));
      }
    } else if (cd->chip_sa.chip_sin.sin_family == AF_INET6) {
      fprintf(stderr,"Warning: subnet mapping for IPv6 will not handle RUT broadcasts\n");
      if (cd->chip_sa.chip_sin6.sin6_addr.s6_addr[15] != 0) {
	char ip6[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, &cd->chip_sa.chip_sin6.sin6_addr, ip6, sizeof(ip6)) == NULL)
	  strerror_r(errno, ip6, sizeof(ip6));
	fprintf(stderr,"CHIP subnet %#o link maps to %s but should have IPv6 with last octet 0, fixing it for you\n",
		cd->chip_addr, ip6);
	cd->chip_sa.chip_sin6.sin6_addr.s6_addr[15] = 0;
      }
    }
  }
  // all ok
  return 0;
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
  int one = 1;
  if ((ip_sock = socket(AF_INET, SOCK_RAW, IPPROTO_CHAOS)) < 0) {
    perror("socket(AF_INET, SOCK_RAW, IPPROTO_CHAOS)");
    exit(1);
  } 
  // need to be able to use broadcast, for subnet mappings
  if (setsockopt(ip_sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0)
    perror("setsockopt(ipv4, SO_BROADCAST)");
  if ((ip6_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_CHAOS)) < 0) {
    perror("socket(AF_INET6, SOCK_RAW, IPPROTO_CHAOS)");
    exit(1);
  } 
}

static int
find_in_chipdest(u_short srcaddr, struct sockaddr *sa)
{
  char ipaddr[INET6_ADDRSTRLEN];
  int i;
  struct sockaddr_in *sin = (struct sockaddr_in *)sa;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
  sa_family_t ipfam = sa->sa_family;

  for (i = 0; i < chipdest_len; i++) {
    if (chipdest[i].chip_addr == srcaddr) {
      // found Chaos address match: does IP match?
      if ((chipdest[i].chip_sa.chip_saddr.sa_family == ipfam)
	  && (((ipfam == AF_INET) &&
	       (memcmp(&sin->sin_addr, &chipdest[i].chip_sa.chip_sin.sin_addr, sizeof(struct in_addr)) == 0))
	      ||
	      ((ipfam == AF_INET6) &&
	       (memcmp(&sin6->sin6_addr, &chipdest[i].chip_sa.chip_sin6.sin6_addr, sizeof(struct in6_addr)) == 0)))) {
	// found it
	return 1;
      } else {
	// spoofed packet?
	if (1 || chip_debug || verbose || debug) {
	  fprintf(stderr,"%%%% CHIP: possible Chaos address %#o spoofing in pkt received from %s\n",
		  srcaddr, ip46_ntoa(sa, ipaddr, sizeof(ipaddr)));
	  // @@@@ drop it?
	  return 0;
	}
	break;
      }
    } else if (((chipdest[i].chip_addr & 0xff00) == 0) &&
	       // (chip_addr is just the subnet, cf parse_link_config)
	       ((chipdest[i].chip_addr & 0xff) == (srcaddr & 0xff00)>>8)) {
      // found Chaos subnet match: does IP match?
      // Check that the "hardware trailer" matches the IP header
      // This needs only be the case for subnet-mapped addresses
      if (((ipfam == AF_INET) &&
	   ((ntohl(sin->sin_addr.s_addr) & 0xffffff00) == ntohl(chipdest[i].chip_sa.chip_sin.sin_addr.s_addr)))
	  ||
	  ((ipfam == AF_INET6) &&
	   // check first 15 bytes
	   (memcmp(&sin6->sin6_addr, &chipdest[i].chip_sa.chip_sin6.sin6_addr, sizeof(struct in6_addr)-1) == 0))) {
	// all-but-last octets match,
	// now see if last octet also matches
	if (((ipfam == AF_INET) &&
	     ((ntohl(sin->sin_addr.s_addr) & 0xff) != (srcaddr & 0xff)))
	    ||
	    ((ipfam == AF_INET6) &&
	     ((sin6->sin6_addr.s6_addr[15]) != (srcaddr & 0xff)))) {
	  if (1 || chip_debug || debug || verbose) {
	    fprintf(stderr,"%%%% CHIP subnet: Chaos trailer sender address %#o doesn't match sender IP %s\n",
		    srcaddr, ip46_ntoa(sa, ipaddr, sizeof(ipaddr)));
	    // @@@@ drop packet?
	    return 0;
	  }
	}
	return 1;
      } else {
	// spoofed packet?
	if (1 || chip_debug || verbose || debug) {
	  fprintf(stderr,"%%%% CHIP subnet %#o: possible Chaos address %#o spoofing in pkt received from %s\n",
		  chipdest[i].chip_addr, srcaddr, ip46_ntoa(sa, ipaddr, sizeof(ipaddr)));
	  // @@@@ drop it?
	  return 0;
	}
	break;
      }
    }
  }
  // not found
  return 0;
}

static struct chroute *
add_chip_route(u_short srcaddr)
{
  // see if there is a host route for this, otherwise add it
  PTLOCK(rttbl_lock);
  struct chroute *rt = find_in_routing_table(srcaddr, 1, 1);
  if (rt != NULL) {
    // old route exists
    if (rt->rt_link != LINK_IP) { 
      if (chip_debug || debug)
	fprintf(stderr,"CHIP: Old %s route to %#o found (type %s), updating to CHIP Dynamic\n",
		rt_linkname(rt->rt_link), srcaddr, rt_typename(rt->rt_type));
#if CHAOS_TLS
      if (rt->rt_link == LINK_TLS) {
	close_tls_route(rt);
      }
#endif
      rt->rt_link = LINK_IP;
      rt->rt_type = RT_DYNAMIC;
      rt->rt_cost = RTCOST_ASYNCH;
      rt->rt_cost_updated = time(NULL);
    }
  } else {
    // Add a host route
    rt = add_to_routing_table(srcaddr, 0, 0, RT_DYNAMIC, LINK_IP, RTCOST_ASYNCH);
  }
  PTUNLOCK(rttbl_lock);
  return rt;
}

static void
add_chip_dest(u_short srcaddr, sa_family_t fam, u_char *addr)
{
  if (chipdest_len < CHIPDEST_MAX) {
    if (chip_debug || verbose || stats) fprintf(stderr,"Adding new CHIP destination %#o.\n", srcaddr);
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
    if (chip_debug || verbose) print_chipdest_config();
    PTUNLOCK(chipdest_lock);
  } else {
    if (chip_debug || stats || verbose) fprintf(stderr,"%%%% CHIP table full, not adding new destination.\n");
    return;
  }
}

static void 
chip_input_handle_data(u_char *chdata, int chlen, struct sockaddr *sa, int salen)
{
  u_short srcaddr;		/* chaos source */
  struct sockaddr_in *sin = (struct sockaddr_in *)sa;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
  struct in_addr ip_src;	/* ip source */
  struct in6_addr ip6_src;	/* ipv6 source */
  struct chaos_header *ch = (struct chaos_header *)chdata;
  char ipaddr[INET6_ADDRSTRLEN];

  // Get it in host order
  ntohs_buf((u_short *)chdata, (u_short *)chdata, chlen);

  // Expected length
  // @@@@ check if this is a subnet-mapped Chaosnet/IP,
  // @@@@ and perhaps fill in the "hw trailer" if necessary. Doesn't do checksumming...

  int xlen = (CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE);
  if ((xlen % 2) == 1)
    xlen++;			/* alignment */

  // check Chaos trailer (incl checksum)
  if (chlen < xlen) {
    fprintf(stderr,"CHIP: short packet (%s) received from %#o (%s), no room for hw trailer: chaos len %d (nbytes %d) (expected %d)\n",
	    ch_opcode_name(ch_opcode(ch)),
	    ch_srcaddr(ch), ip46_ntoa(sa, ipaddr, sizeof(ipaddr)),
	    chlen, ch_nbytes(ch), xlen);
    if (debug) {
      dumppkt_raw(chdata, chlen);
      ch_dumpkt(chdata, chlen);
    }
    PTLOCK(linktab_lock);
    linktab[srcaddr>>8].pkt_badlen++;
    PTUNLOCK(linktab_lock);
    return;
  } else if (chlen > xlen) {
    if (chip_debug || debug) fprintf(stderr,"CHIP: long pkt received: %d. expected %d\n", chlen, xlen);
  }

  if (chip_debug || debug) fprintf(stderr,"CHIP: sockaddr len %d, family %d\n", salen, ((struct sockaddr *)&sa)->sa_family);
  // Process trailer info
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&chdata[chlen-CHAOS_HW_TRAILERSIZE];
  srcaddr = ntohs(tr->ch_hw_srcaddr);
  int cks = ch_checksum(chdata, chlen);
  if (cks != 0) {
    fprintf(stderr,"%%%% CHIP: bad checksum %#x from source %#o (%s)\n", cks, srcaddr, ip46_ntoa(sa, ipaddr, sizeof(ipaddr)));
    PTLOCK(linktab_lock);
    linktab[srcaddr>>8].pkt_crcerr++;
    PTUNLOCK(linktab_lock);
    return;
  }

  if (is_mychaddr(srcaddr)) {
    if (chip_debug || debug) fprintf(stderr,"CHIP: received pkt from myself, dropping it\n");
    return;
  }

  // look up source in CHIP table, verify it exists, maybe add
  int found = find_in_chipdest(srcaddr, sa);

  if (chip_debug || verbose || debug || !found) {
    if (verbose || debug) fprintf(stderr,"CHIP from %s (Chaos hw %#o) received: %d bytes from Chaos source %#o\n",
				  ip46_ntoa(sa, ipaddr, sizeof(ipaddr)), srcaddr, chlen, ch_srcaddr(ch));
    if (debug) ch_dumpkt(chdata, chlen);
    if (!found) {
      if (!chip_dynamic) {
	fprintf(stderr,"%%%% CHIP pkt received from unknown source %s (Chaos hw %#o) - dropping it\n", ip46_ntoa(sa, ipaddr, sizeof(ipaddr)), srcaddr);
	return;
      } else {
	if (chip_debug || verbose || debug)
	  fprintf(stderr,"%%%% CHIP adding dest %#o at %s\n", srcaddr, ip46_ntoa(sa, ipaddr, sizeof(ipaddr)));
	add_chip_dest(srcaddr, sa->sa_family, sa->sa_family == AF_INET ? (void *)&sin->sin_addr : (void *)&sin6->sin6_addr);
      }
    }
  }
  // make sure there is an up-to-date route of the right type
  add_chip_route(srcaddr);

  // Find source route, and dispatch the packet
  struct chroute *srcrt = find_in_routing_table(srcaddr, 0, 0);
  forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
		    srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
		    chdata, chlen, LINK_IP);
}

void *
chip_input(void *v)
{
  int len;
  struct sockaddr_storage sa;
  socklen_t salen;
  fd_set rfd;
  int maxfd;
  u_char data[CH_PK_MAXLEN+sizeof(struct ip)+sizeof(struct ip6_hdr)];	 /* fuzz */
  int sval;
  
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
#if 0
	// #### when receiving a broadcast message, the IPv4 header is included, otherwise not.
	len = recvfrom(ip_sock, &data, sizeof(data), 0, (struct sockaddr *) &sa, &salen);
	if (debug) {
	  fprintf(stderr,"CHIP: received %d bytes\n", len);
	  dumppkt_raw(data, len);
	}
	// Heuristics (note: network order)
	if ((data[0] == 0x45) &&  /* version + IHL */
	    (data[9] == 16)) {	/* chaosnet */
	  if (chip_debug || debug) fprintf(stderr,"CHIP: IP header detected, skipping it\n");
	  len -= 20;
	  memcpy(&data[0], &data[20], len);
	}
#else
	u_char hdr[sizeof(struct ip)];  /* #### only works if no IP options */
	struct msghdr msg;
	struct iovec iov[2];
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = (struct iovec *)&iov;
	msg.msg_iovlen = 2;
	msg.msg_name = &sa;
	msg.msg_namelen = salen;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = &data;
	iov[1].iov_len = sizeof(data);
	len = recvmsg(ip_sock, &msg, 0);
	if (len > 0) {
	  if (chip_debug || debug) {
	    fprintf(stderr,"CHIP: received %d bytes\n", len);
	    fprintf(stderr,"CHIP: hdr %zu bytes\n",iov[0].iov_len);
	    if (debug) dumppkt_raw(hdr, iov[0].iov_len);
	    fprintf(stderr,"CHIP: data %zu bytes\n", iov[1].iov_len);
	    if (debug) dumppkt_raw(data, len - iov[0].iov_len);
	  }
	  len -= iov[0].iov_len;
	  // so check if there are header options
	  // @@@@ could mess around and skip options...
	  if (hdr[0] != 0x45) {	/* Expect IP version 4, IP header length 5 words */
	    fprintf(stderr,"%%%% CHIP: bad V+IHL %#x for IP pkt from %s, dropping\n",
		    hdr[0], inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr));
	    len = 0;
	  }
	}
#endif
      } else if (FD_ISSET(ip6_sock, &rfd)) {
	if (chip_debug || debug) fprintf(stderr,"CHIP: receiving from IPv6 socket\n");
	len = recvfrom(ip6_sock, &data, sizeof(data), 0, (struct sockaddr *) &sa, &salen);
      }
      else {
	if (chip_debug || debug) fprintf(stderr,"CHIP: select returned %d but neither v4/v6 socket set\n", sval);
	len = -1;
      }
    } else if (sval == 0) {
      if (chip_debug || debug) fprintf(stderr,"CHIP: select timeout? %d\n", sval);
      len = -1;
    } else {
      perror("CHIP: select");
      len = -1;
    }
    if (chip_debug || debug) fprintf(stderr,"CHIP: received %d bytes\n", len);
    if (len > 0) {
      chip_input_handle_data((u_char *)&data, len, (struct sockaddr *)&sa, salen);
    }
  }
}

static void 
chip_send_pkt_ipv4(struct sockaddr_in *sout, u_char *pkt, int pklen)
{
  int c;

  if (chip_debug || debug) {
    fprintf(stderr,"CHIP: About to send IPv4 pkt to %s\n", inet_ntoa(sout->sin_addr));
    if (debug) dumppkt_raw(pkt, pklen);
  }
  c = sendto(ip_sock, pkt, pklen, 0, (struct sockaddr *)sout, sizeof(struct sockaddr_in));
  if (c < 0)
    perror("chip_send_pkt_ipv4");
  else if (chip_debug || debug)
    fprintf(stderr,"CHIP: chip_send_pkt_ipv4: wrote %d bytes\n", c);
}

static void 
chip_send_pkt_ipv6(struct sockaddr_in6 *sout, u_char *pkt, int pklen)
{
  int c;

  if (chip_debug || debug) {
    char ip6[INET6_ADDRSTRLEN];
    fprintf(stderr,"CHIP: About to send IPv6 pkt to %s\n", ip46_ntoa((struct sockaddr *)sout, ip6, sizeof(ip6)));
    if (debug) dumppkt_raw(pkt, pklen);
  }
  c = sendto(ip6_sock, pkt, pklen, 0, (struct sockaddr *)sout, sizeof(struct sockaddr_in6));
  if (c < 0)
    perror("chip_send_pkt_ipv6");
  else if (chip_debug || debug)
    fprintf(stderr,"CHIP: chip_send_pkt_ipv6: wrote %d bytes\n", c);
}

static void 
chip_send_pkt(struct sockaddr *sout, u_char *pkt, int pklen)
{
  if (chip_debug || debug) {
    fprintf(stderr,"CHIP: Sending Chaos pkt len %d\n", pklen);
    if (debug) ch_dumpkt(pkt, pklen);
  }
  // Swap back to network order
  htons_buf((u_short *)pkt, (u_short *)pkt, pklen);

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

static int
try_forward_individual_dest(struct chroute *rt, u_short dchad, u_char *data, int dlen)
{
  int i;
  for (i = 0; i < chipdest_len; i++) {
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
      chip_send_pkt(&chipdest[i].chip_sa.chip_saddr, data, dlen);
      // success
      return 1;
    }
  }
  // no dest found
  return 0;
}

static int
try_forward_subnet_dest(struct chroute *rt, u_short dchad, u_char *data, int dlen)
{
  int i;
  // check for subnet match and fill in IP subnet addr
  // IPv4: If chipdest has subnet addr (zero host byte) matching dchad, copy host byte of dchad to last octet of chip_sa
  // IPv6: same (and still _last_ octet).
  for (i = 0; i < chipdest_len; i++) {
    if (
	/* CHIP dest is a subnet, and it matches our dest */
	// (chip_addr is just the subnet, cf parse_link_config)
	((dchad != 0) &&
	 ((chipdest[i].chip_addr & 0xff00) == 0) &&
	 ((chipdest[i].chip_addr << 8) == (dchad & 0xff00)))
	||
	/* dest is broadcast, look for the route's subnet */
	((dchad == 0) &&
	 ((rt->rt_dest & 0xff) == 0) &&  /* route dest is broadcast */
	 ((chipdest[i].chip_addr & 0xff00) == 0) &&  /* this is a subnet dest */
	 ((chipdest[i].chip_addr << 8) == (rt->rt_dest & 0xff00)))  /* and it matches */
	) {
      if (chipdest[i].chip_sa.chip_saddr.sa_family == AF_INET) {
	struct sockaddr_in dip;
	memcpy(&dip, &chipdest[i].chip_sa.chip_sin, sizeof(dip));
	if (dchad == 0)	/* broadcast */
	  dip.sin_addr.s_addr |= htonl(0xff);
	else if ((dchad & 0xff) == 0xff) {
	  if (chip_debug || debug) {
	    fprintf(stderr,"CHIP: not forwarding to Chaos %#o (%#x) because it maps to the broadcast address\n",
		    dchad, dchad);
	  }
	  // found a route, although couldn't use it
	  return 1;
	} else
	  dip.sin_addr.s_addr |= htonl(dchad & 0xff);
	if (debug) fprintf(stderr,"CHIP: subnet link %#o to dest %#o gives IP %s\n",
			   chipdest[i].chip_addr, dchad, inet_ntoa(dip.sin_addr));
	chip_send_pkt((struct sockaddr *)&dip, data, dlen);
      } else if (chipdest[i].chip_sa.chip_saddr.sa_family == AF_INET6) {
	if (dchad == 0) {
	  // @@@@ fixme?
	  if (chip_debug || verbose || debug) fprintf(stderr,"%%%% CHIP: broadcast to IPv6 not implemented yet\n");
	  // found a route, although couldn't use it
	  return 1;
	}
	struct sockaddr_in6 dip;
	memcpy(&dip, &chipdest[i].chip_sa.chip_sin6, sizeof(dip));
	dip.sin6_addr.s6_addr[15] = (dchad & 0xff);
	if (chip_debug || debug) {
	  char ipaddr[INET6_ADDRSTRLEN];
	  fprintf(stderr,"CHIP: subnet link %#o to dest %#o gives IPv6 %s\n",
		  chipdest[i].chip_addr, dchad, ip46_ntoa((struct sockaddr *)&dip, ipaddr, sizeof(ipaddr)));
	}
	chip_send_pkt((struct sockaddr *)&dip, data, dlen);
      } else {
	fprintf(stderr,"%%%% CHIP: dest %d unexpected address family %d\n",
		i, chipdest[i].chip_sa.chip_saddr.sa_family);
	// found a route, although broken
	return 1;
      }
      if (chip_debug || verbose || debug) fprintf(stderr,"Forwarded CHIP to dest %#o over subnet link %#o (%s)\n",
				    dchad, chipdest[i].chip_addr, chipdest[i].chip_name);
      // success
      return 1;
    }
  }
  // no dest found
  return 0;
}

void
forward_on_ip(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  int i, found = 0;

  if (RT_BRIDGED(rt))
    // the bridge is on IP, but the dest might not be
    dchad = rt->rt_braddr;
  // look up in chipdest, send using libnet
  PTLOCK(chipdest_lock);
  if (!try_forward_individual_dest(rt, dchad, data, dlen)) {
    if (!try_forward_subnet_dest(rt, dchad, data, dlen)) {
      fprintf(stderr,"%%%% Can't find CHIP link to %#o via %#o/%#o\n",
	      dchad, rt->rt_dest, rt->rt_braddr);
    }
  }
  PTUNLOCK(chipdest_lock);
}
