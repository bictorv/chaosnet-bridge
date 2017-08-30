/* Copyright © 2005, 2017 Björn Victor (bjorn@victor.se) */
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

/* Based on echaos (by Björn), and chudprt (by Björn, partly based on
   one of Brad's chaosd clients). Some code from LambdaDelta (the LMI
   Lambda emulator by Daniel Seagraves), and some from klh10 (the
   PDP10 emulator by Ken Harrenstien). */

/* Bridge program for various Chaosnet implementations.
   Should support as many as desired of
   - Chaos-over-Ethernet [#### currently only one interface]
   - CHUDP (Chaos-over-UDP, used by klh10/its)
   - chaosd (Unix socket protocol, used by the usim CADR emulator)
   - Chaos-over-IP (direct address mapping, used by pdp10x) #### TODO

   Does not hack BRD packets (yet), but noone seems to use them anyway?
   Does not even try to support IPv6.
*/

/* Read MIT AIM 628, in particular secions 3.6 and 3.7. */

// TODO

// Q: if UP should be the main router for subnet 6, but that's only p2p chudp links,
//    how do we configure it to send RUTs for subnet 6 on other nets it may be connected to?
// A: "route subnet 6 bridge 3143" works.
//    Actual host routes have prio, this will add an indirect route,
//    and no route will be found to self.

// perhaps implement TIME for the router?

// add a more silent variant of output, which just notes new chudp
//   links, new routes, real weirdness, etc.
// add parameters for various constans (arp age limit, reparsing interval...)
// validate conf (subnets vs bridges etc)
// minimize copying
// - now net order is swapped to host order when receiving from Ether and Unix,
//   and then swapped back before forwarding,
//   while CHUDP is not swapped but needs copying anyway (because of chudp header)
// - better to not swap Ether/Unix, of course, but need to rewrite chaos.h
//   and make it endian dependent - ugh (but all processors are Intel these days... ;-o)
// - or separate header from data; swap header like now, but keep data intact
// notify if more routes are known than fit in a RUT pkt (but it's 122, come on...)

#ifndef CHAOS_ETHERP
// enable the Chaos-over-Ether code
#define CHAOS_ETHERP 1
#endif

#ifndef ETHER_BPF
// use BPF rather than sockaddr_ll, e.g. for MacOS
#if __APPLE__
#define ETHER_BPF 1
#else
#define ETHER_BPF 0
#endif
#endif

#ifndef COLLECT_STATS
// Collect statistics about packets in/out/CRC errors etc, and respond to STATUS protocol
#define COLLECT_STATS 1
#endif

#ifndef PEEK_ARP
// Peek at sender's MAC address to update ARP table, to avoid ARP traffic.
// This is a quite inefficient way of finding addresses, I think.
#define PEEK_ARP 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#if CHAOS_ETHERP
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#if ETHER_BPF
#include <net/bpf.h>
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif // ETHER_BPF
#endif // CHAOS_ETHERP
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <pthread.h>

#include "chaos.h"		/* chaos pkt format etc */
#include "chudp.h"		/* chudp pkt format etc */
#include "chaosd.h"		/* chaos-over-unix-sockets */

int verbose, debug;
int fd;

void ntohs_buf(u_short *ibuf, u_short *obuf, int len);
void htons_buf(u_short *ibuf, u_short *obuf, int len);

void send_chaos_pkt(u_char *pkt, int len);

void ch_dumpkt(u_char *ucp, int cnt);

#if CHAOS_ETHERP
void print_arp_table();
#endif

// Connection types, cf AIM 628 p14
enum { RT_NOPATH=0,		/* @@@@ where is this from? */
       RT_DIRECT,		/* Directly connected (cable etc) */
       RT_FIXED,		/* Fixed (unvarying) bridge */
       RT_BRIDGE,		/* Bridge (perhaps known via RUT packet) */
};
// Link implementation types
enum { LINK_ETHER=1,		/* Chaos-over-Ethernet */
       LINK_UNIXSOCK,		/* Chaos-over-Unix sockets ("chaosd") */
       LINK_CHUDP,		/* Chaos-over-UDP ("chudp") */
       LINK_INDIRECT,		/* look up the bridge address */
};

// Routing costs, cf AIM 628 p15
#define RTCOST_DIRECT 10
#define RTCOST_ETHER 11
#define RTCOST_ASYNCH 20
// AIM 628 says 'when the cost reaches a "high" value, it sticks there,
// preventing problems with arithmetic overflow' without specifying that high value.
// ITS uses 512 as max (cf SYSTEM;CHAOS, label CHA5C5),
// CADR system 99 also uses 512 (cf LMIO;CHSNCP, function CHAOS:BACKGROUND)
// LMI release 5 also uses 512 (cf SYS:NETWORK.CHAOS;CHSNCP, function CHAOS:BACKGROUND)
// while Symbolics uses 1024 (SYS:NETWORK;CHAOS-DEFS, constant CHAOS:MAXIMUM-ROUTING-COST)
// (The arithmetic overflow seems silly, having 16 bits to store it?)
#define RTCOST_HIGH 512

// Route configuration entry
struct chroute {
  u_short rt_dest;		/* destination addr (subnet<<8 or host) - redundant for subnets */
  u_short rt_braddr;		/* bridge address */
  u_short rt_myaddr;		/* my specific address (on that subnet), or use mychaddr */
  u_char rt_type;		/* connection type */
  u_char rt_link;		/* link implementation */
  u_short rt_cost;		/* cost */
  time_t rt_cost_updated;	/* cost last updated */
};

// Route table, indexed by subnet
struct chroute *rttbl_net;
// and for individual hosts, simple array, where rt_braddr is the dest
struct chroute *rttbl_host;
int *rttbl_host_len;
#define RTTBL_HOST_MAX 64

// Info on this host's direct connection to a subnet. See STATUS protocol in AIM 628.
struct linkstat {
  u_int32_t pkt_in;		/* pkts received */
  u_int32_t pkt_out;		/* pkts transmitted */
  u_int32_t pkt_aborted;	/* pkts aborted by collisions or busy receiver */
  u_int32_t pkt_lost;		/* lost, couldn't be read from buffer */
  u_int32_t pkt_crcerr;		/* CRC errors on rcpt */
  u_int32_t pkt_crcerr_post;	/* no CRC err on rcpt, but CRC errors after reading from buffer */
  u_int32_t pkt_badlen;		/* rejected due to incorrect length */
  u_int32_t pkt_rejected;	/* rejected for other reasons (e.g. forwarded too many times) */
};
// simple array indexed by subnet, updated for send/receives on routes with direct link
struct linkstat *linktab;

pthread_mutex_t charp_lock, rttbl_lock, chudp_lock, linktab_lock;
#define PTLOCK(x) if (pthread_mutex_lock(&x) != 0) fprintf(stderr,"FAILED TO LOCK\n")
#define PTUNLOCK(x) if (pthread_mutex_unlock(&x) != 0) fprintf(stderr,"FAILED TO UNLOCK\n")

// CHUDP table
#define CHUDPDEST_NAME_LEN 128
struct chudest {
  struct sockaddr_in chu_sin;	/* IP addr */
  u_short chu_addr;		/* chaos address (or subnet) */
  char chu_name[CHUDPDEST_NAME_LEN]; /* name given in config, to reparse perhaps */
};
struct chudest *chudpdest;	/* shared mem allocation */
int *chudpdest_len;
#define CHUDPDEST_MAX 64

#if CHAOS_ETHERP
// ARP stuff
#ifndef ETHERTYPE_CHAOS
# define ETHERTYPE_CHAOS 0x0804
#endif
#ifndef ARPHRD_CHAOS		/* this is the original Chaosnet hardware, not the ethernet protocol type */
#define ARPHRD_CHAOS 5
#endif
// old names for new, new names for old?
#ifndef ARPOP_RREQUEST
#define ARPOP_RREQUEST ARPOP_REVREQUEST // 3	/* request protocol address given hardware */
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY ARPOP_REVREPLY // 4	/* response giving protocol address */
#endif


static u_char eth_brd[ETHER_ADDR_LEN] = {255,255,255,255,255,255};
/* Chaos ARP list */
#define CHARP_MAX 16
#define CHARP_MAX_AGE (60*5)	// ARP cache limit
struct charp_ent {
  u_char charp_eaddr[ETHER_ADDR_LEN];
  u_short charp_chaddr;
  time_t charp_age;
};

struct charp_ent *charp_list;	/* shared mem alloc */
int *charp_len;
#endif // CHAOS_ETHERP

static u_char myea[ETHER_ADDR_LEN];		/* My Ethernet address */
#if !ETHER_BPF
static int ifix;		/* ethernet interface index */
#endif

int unixsock = 0, udpsock = 0, chfd = 0, arpfd = 0;

// Config stuff
char myname[32]; /* my chaosnet host name (look it up!). Note size limit by STATUS prot */
static u_short mychaddr = 0;	/* My Chaos address (only for ARP) */
int udpport = 42042;		// default port
u_char chudp_dynamic = 0;	// dynamically add CHUDP entries for new receptions
char ifname[128] = "eth0";	// default interface name
int do_unix = 0, do_udp = 0, do_ether = 0;

// Whether to peek at non-RUT pkts to discover routes
u_char peek_routing_info = 0;	// not implemented

void init_rttbl()
{
  if (pthread_mutex_init(&rttbl_lock, NULL) != 0)
    perror("pthread_mutex_init(rttbl_lock)");
  if ((rttbl_net = malloc(sizeof(struct chroute)*0xff)) == NULL)
    perror("malloc(rttbl_net)");
  if ((rttbl_host = malloc(sizeof(struct chroute)*RTTBL_HOST_MAX)) == NULL)
    perror("malloc(rttbl_host)");
  if ((rttbl_host_len = malloc(sizeof(int))) == NULL)
    perror("malloc(rttbl_host_len)");
  memset((char *)rttbl_net, 0, sizeof(struct chroute)*0xff);
  memset((char *)rttbl_host, 0, sizeof(struct chroute)*RTTBL_HOST_MAX);
  *rttbl_host_len = 0;
}

void init_linktab()
{
  if (pthread_mutex_init(&linktab_lock, NULL) != 0)
    perror("pthread_mutex_init(linktab_lock)");
  if ((linktab = malloc(sizeof(struct linkstat)*256)) == NULL)
    perror("malloc(linktab)");
  memset((char *)linktab, 0, sizeof(struct linkstat)*256);
}

void print_link_stats() 
{
  int i;
  PTLOCK(linktab_lock);
  printf("Link stats:\n"
	 "Subnet\t  In\t Out\t CRC\t Bad\t Rej\n");
  for (i = 0; i < 256; i++) {
    if (linktab[i].pkt_in != 0 || linktab[i].pkt_out != 0 || linktab[i].pkt_crcerr != 0) {
      printf("%#o\t%7d\t%7d\t%7d\t%7d\t%7d\n", i,
	     linktab[i].pkt_in, linktab[i].pkt_out, linktab[i].pkt_crcerr,
	     linktab[i].pkt_badlen, linktab[i].pkt_rejected);
    }
  }
  PTUNLOCK(linktab_lock);
}

void init_chudpdest()
{
  if (pthread_mutex_init(&chudp_lock, NULL) != 0)
    perror("pthread_mutex_init(chudp_lock)");
  if ((chudpdest = malloc(sizeof(struct chudest)*CHUDPDEST_MAX)) == NULL)
    perror("malloc(chudpdest)");
  if ((chudpdest_len = malloc(sizeof(int))) == NULL)
    perror("malloc(chudpdest_len)");
  memset((char *)chudpdest, 0, sizeof(struct chudest)*CHUDPDEST_MAX);
  *chudpdest_len = 0;
}

char *rt_linkname(u_char linktype)
{
  switch (linktype) {
  case LINK_UNIXSOCK: return "Unix";
  case LINK_CHUDP: return "CHUDP";
  case LINK_ETHER: return "Ether";
  case LINK_INDIRECT: return "Indir";
  default: return "Unknown?";
  }
}

char *rt_typename(u_char type)
{
  switch (type) {
  case RT_NOPATH: return "NoPath";
  case RT_DIRECT: return "Direct";
  case RT_FIXED: return "Fixed";
  case RT_BRIDGE: return "Bridge";
  default: return "Unknown?";
  }
}

void
print_routing_table() {
  int i;
  fprintf(stderr,"Routing tables follow:\n");
  if (*rttbl_host_len > 0) {
    fprintf(stderr,"Host\tBridge\tType\tLink\tCost\n");
    for (i = 0; i < *rttbl_host_len; i++)
      if (rttbl_host[i].rt_type != RT_NOPATH)
	fprintf(stderr,"%#o\t%#o\t%s\t%s\t%d\n",
		rttbl_host[i].rt_dest, rttbl_host[i].rt_braddr, rt_typename(rttbl_host[i].rt_type), rt_linkname(rttbl_host[i].rt_link), rttbl_host[i].rt_cost);
  }
  fprintf(stderr,"Net\tBridge\tType\tLink\tCost\tAge\n");
  for (i = 0; i < 0xff; i++)
    if (rttbl_net[i].rt_type != RT_NOPATH)
      fprintf(stderr,"%#o\t%#o\t%s\t%s\t%d\t%ld\n",
	      i, rttbl_net[i].rt_braddr, rt_typename(rttbl_net[i].rt_type), rt_linkname(rttbl_net[i].rt_link), rttbl_net[i].rt_cost,
	      rttbl_net[i].rt_cost_updated > 0 ? time(NULL) - rttbl_net[i].rt_cost_updated : 0);
}

void print_chudp_config()
{
  int i;
  printf("CHUDP config: %d routes\n", *chudpdest_len);
  for (i = 0; i < *chudpdest_len; i++) {
    char *ip = inet_ntoa(chudpdest[i].chu_sin.sin_addr);
    printf(" dest %#o, host %s (%s) port %d\n",
	   chudpdest[i].chu_addr, ip,
	   chudpdest[i].chu_name,
	   ntohs(chudpdest[i].chu_sin.sin_port));
  }
}

void reparse_chudp_names()
{
  int i, res;
  struct in_addr in;
  struct addrinfo *he;
  struct addrinfo hi;

  memset(&hi, 0, sizeof(hi));
  hi.ai_family = PF_INET;

  PTLOCK(chudp_lock);
  for (i = 0; i < *chudpdest_len; i++) {
    if (chudpdest[i].chu_name[0] != '\0'  /* have a name */
	&& inet_aton(chudpdest[i].chu_name, &in) == 0)   /* which is not an explict addr */
      {
	// if (verbose) fprintf(stderr,"Re-parsing chudp host name %s\n", chudpdest[i].chu_name);
	
	if ((res = getaddrinfo(chudpdest[i].chu_name, NULL, &hi, &he)) == 0) {
	  struct sockaddr_in *s = (struct sockaddr_in *)he->ai_addr;
	  memcpy(&chudpdest[i].chu_sin.sin_addr.s_addr, (u_char *)&s->sin_addr, 4);
	  // if (verbose) fprintf(stderr," success: %s\n", inet_ntoa(s->sin_addr));
	  freeaddrinfo(he);
	} else if (verbose) {
	  fprintf(stderr,"Error re-parsing chudp host name %s: %s (%d)\n",
		  chudpdest[i].chu_name,
		  gai_strerror(res), res);
	}
      }
  }
  // if (verbose) print_chudp_config();
  PTUNLOCK(chudp_lock);
}

void *
reparse_chudp_names_thread(void *v)
{
  while (1) {
    sleep(60*5);		// Hmm, how often really?
    reparse_chudp_names();   // occasionally re-parse chu_name strings
  }
}


// Look at an incoming pkt given a connection type and a cost, 
// update our routing table if appropriate. 
// Always look at RUT pkts, and if configured, peek at pkts to discover routing info.
void
peek_routing(u_char *pkt, int pklen, int type, int cost, u_short linktype)
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_short src, pksrc = ch_srcaddr(cha);
  u_char *data = &pkt[CHAOS_HEADERSIZE];
  u_short rsub, rcost;
  int i, pkdlen = ch_nbytes(cha);

  if (pksrc == mychaddr) {
    if (debug) fprintf(stderr,"Got my pkt back (%#o), ignoring\n", pksrc);
    return;
  }
  if (ch_opcode(cha) == 0) {
    fprintf(stderr,"BAD PACKET (wrong byte order?)\n");
    htons_buf((u_short *)pkt,(u_short *)pkt,pklen);
    ch_dumpkt(pkt,pklen);
    ntohs_buf((u_short *)pkt,(u_short *)pkt,pklen);
    return;
  }
  if (pklen >= CHAOS_HEADERSIZE + pkdlen + CHAOS_HW_TRAILERSIZE) {
    struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&pkt[pklen-6];
    src = ntohs(tr->ch_hw_srcaddr);
    if (src == 0)
      src = ch_srcaddr(cha);
  } else {
    src = ch_srcaddr(cha);
  }

  /* Check for RUT pkt */
  int rttbl_updated = 0;
  if (ch_opcode(cha) == CHOP_RUT) {
    if (verbose) fprintf(stderr,"RUT pkt analysis...\n");
    /* See AIM 628 sec 3.7 p15 */
    for (i = 0; i < pkdlen; i += 4) {
      rsub = WORD16(&data[i]);	/* subnet nr */
      rcost = WORD16(&data[i+2]);  /* cost from that bridge */
      if (rttbl_net[rsub].rt_type == RT_DIRECT && (verbose||debug) )
	fprintf(stderr,"DEBUG: Received RUT info for subnet %#o from host %#o.\n"
		" We have DIRECT connction to that subnet - "
		" bug in network structure or sender's software?\n",
		rsub, src);
      if ((rttbl_net[rsub].rt_type == RT_NOPATH)  /* we have no path currently */
	  /* we had a higher (or equal, to update age) cost */
	  || ((rttbl_net[rsub].rt_cost >= (rcost + cost))
	      /* but don't update if we're directly connected already */
	      && (rttbl_net[rsub].rt_type != RT_DIRECT))
	  ) {
	if (rttbl_net[rsub].rt_type == RT_NOPATH) {
	  if (verbose) fprintf(stderr," Adding new route to %#o type %d cost %d via %#o\n",
			       rsub, type, (rcost + cost), src);
	} else if ((rcost + cost) != rttbl_net[rsub].rt_cost) {
	  if (verbose) fprintf(stderr," Updating cost for route to %#o type %d cost %d -> %d via %#o\n",
			       rsub, type, rttbl_net[rsub].rt_cost, (rcost + cost), src);
	} else
	  if (verbose) fprintf(stderr," Updating age for route to %#o type %d cost %d via %#o\n",
			       rsub, type, rttbl_net[rsub].rt_cost, src);
	rttbl_updated = 1;
	PTLOCK(rttbl_lock);
	rttbl_net[rsub].rt_type = RT_BRIDGE; // type;
	rttbl_net[rsub].rt_cost = (rcost + cost);  /* add the cost to go to that bridge */
	// Subnet routes via CHUDP must be indirect (look up bridge host too)
	rttbl_net[rsub].rt_link = (linktype == LINK_CHUDP ? LINK_INDIRECT : linktype);
	rttbl_net[rsub].rt_braddr = src;
	rttbl_net[rsub].rt_dest = src & 0xff00;
	rttbl_net[rsub].rt_cost_updated = time(NULL);
	PTUNLOCK(rttbl_lock);
      }
    }
    if (verbose && rttbl_updated) print_routing_table();
  } 
#if 0 // not finished
  else if (peek_routing_info) {
    /* Not a RUT pkt, note subnet presence?  */
  }
#endif
}

void 
update_route_costs()
{
  // update the cost of all non-direct, non-fixed routes by their age,
  // according to AIM 628 p15.
  int i;
  u_int costinc;

  PTLOCK(rttbl_lock);
  for (i = 0; i < 256; i++) {
    if ((rttbl_net[i].rt_type != RT_NOPATH) &&
	(rttbl_net[i].rt_type != RT_DIRECT) &&
	(rttbl_net[i].rt_type != RT_FIXED)) {
      /* Age by 1 every 4 seconds, max limit, but not fir direct or asynch (cf AIM 628 p15) */
      costinc = (time(NULL) - rttbl_net[i].rt_cost_updated)/4;
      if (debug) fprintf(stderr,"RUT to %d, cost %d => %d\n",i,
			 rttbl_net[i].rt_cost, rttbl_net[i].rt_cost+costinc);
      if ((rttbl_net[i].rt_cost + costinc) > RTCOST_HIGH)
	rttbl_net[i].rt_cost = RTCOST_HIGH;
      else
	rttbl_net[i].rt_cost += costinc;
    }
  }
  PTUNLOCK(rttbl_lock);
}

// Make a RUT pkt for someone (dest), filtering out its own subnet and nets it is the bridge for already.
int
make_routing_table_pkt(u_short dest, u_char *pkt, int pklen)
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_char *data = &pkt[CHAOS_HEADERSIZE];
  int i, cost, nroutes = 0;
  int maxroutes = (pklen-CHAOS_HEADERSIZE)/4;  /* that fit in this pkt, max 122 */
  if (maxroutes > 122)
    maxroutes = 122;

  memset(pkt, 0, pklen);
  set_ch_opcode(cha, CHOP_RUT);

  PTLOCK(rttbl_lock);
  for (i = 0; (i < 0xff) && (nroutes <= maxroutes); i++) {
    if ((rttbl_net[i].rt_type != RT_NOPATH) 
	// don't send a subnet route to the subnet itself (but to individual hosts)
	&& (! (((dest & 0xff) == 0) && (i == (dest>>8))))
	// and not to the bridge itself
	&& (rttbl_net[i].rt_braddr != dest)) {
      data[nroutes*4+1] = i;
      cost = rttbl_net[i].rt_cost;
      data[nroutes*4+2] = (cost >> 8);
      data[nroutes*4+3] = (cost & 0xff);
      if (debug) fprintf(stderr," including net %#o cost %d\n", i, cost);
      nroutes++;
    } else if (debug && (rttbl_net[i].rt_type != RT_NOPATH)) {
      if (i == (dest >> 8))
	fprintf(stderr, " not including net %#o for dest %#o\n", i, dest);
      else if (rttbl_net[i].rt_braddr == dest) 
	fprintf(stderr, " not including net %#o (bridge %#o) for dest %#o\n", i, rttbl_net[i].rt_braddr, dest);
    }
  }
  PTUNLOCK(rttbl_lock);
  set_ch_destaddr(cha, ((dest & 0xff) == 0) ? 0 : dest );  /* well... */
  set_ch_nbytes(cha,nroutes*4);
  if (ch_nbytes(cha) > 0)
    return ch_nbytes(cha)+CHAOS_HEADERSIZE;
  else
    return 0;
}

struct chroute *
find_in_routing_table(u_short dchad, int only_host)
{
  int i;
  if (dchad == mychaddr) {
    // The only reason for defining a route with "self" as destination
    // is when you have a subnet where all hosts are connected by
    // CHUDP links, and you want to announce the subnet by RUT.
#if 0
    if (debug || verbose)
      fprintf(stderr,"Warning: find route: Looking for self in routing table.\n");
#endif
    return NULL;
  }

  /* Check host routing table first */
  for (i = 0; i < *rttbl_host_len; i++) {
#if 1
    if (rttbl_host[i].rt_dest == dchad
	// Check the cost, too.
	&& rttbl_host[i].rt_cost < RTCOST_HIGH) {
      if (rttbl_host[i].rt_link == LINK_INDIRECT) {
	// #### validate config once instead of every time, and simply return the recursive call here
	if (rttbl_host[i].rt_braddr != 0) {
	  struct chroute *res = find_in_routing_table(rttbl_host[i].rt_braddr, 0);
	  if (res == NULL) {
	    fprintf(stderr,"Warning: find route: Indirect link to %#o found, but no route to its bridge %#o\n",
		    dchad, rttbl_host[i].rt_braddr);
	    print_routing_table();
	  }
	  return res;
	} else {
	  fprintf(stderr,"Warning: find route: Indirect link to %#o found, but no bridge address given!\n",
		  dchad);
	  return NULL;
	}
      } else
	return &rttbl_host[i];
    }
#else
    if (rttbl_host[i].rt_braddr == dchad) {
      return &rttbl_host[i];
    }
#endif
  }
  if (only_host) return NULL;	// avoid non-well-founded recursion

  /* Then check subnet routing table */
  u_short sub = (dchad>>8)&0xff;
#if 1
  if (rttbl_net[sub].rt_type != RT_NOPATH
      // Check the cost, too.
      && rttbl_net[sub].rt_cost < RTCOST_HIGH) {
    if (rttbl_net[sub].rt_link == LINK_INDIRECT) {
      // #### validate config once instead of every time, and simply return the recursive call here
      if (rttbl_net[sub].rt_braddr != 0) {
#if 0
	if ((rttbl_net[sub].rt_braddr == mychaddr)
	    || (rttbl_net[sub].rt_braddr == rttbl_net[sub].rt_myaddr))
	  return NULL;
#endif
	struct chroute *res = find_in_routing_table(rttbl_net[sub].rt_braddr, 1);
	if (res == NULL) {
	  fprintf(stderr,"Warning: find route: Indirect link to host %#o on subnet %#o found, but no route to its bridge %#o\n",
		  dchad, sub, rttbl_net[sub].rt_braddr);
	  print_routing_table();
	}
	return res;
      } else {
	fprintf(stderr,"Warning: find route: Indirect link to subnet %#o found, but no bridge address given!\n",
		sub);
	return NULL;
      }
    } else
      return &rttbl_net[sub];
  }
#else
  if ((rttbl_net[sub].rt_type != RT_NOPATH) && (rttbl_net[sub].rt_myaddr != dchad))
    return &rttbl_net[sub];
#endif
  return NULL;
}

static unsigned int
ch_checksum(const unsigned char *addr, int count)
{
  /* RFC1071 */
  /* Compute Internet Checksum for "count" bytes
   *         beginning at location "addr".
   */
  register long sum = 0;

  while( count > 1 )  {
    /*  This is the inner loop */
    sum += *(addr)<<8 | *(addr+1);
    addr += 2;
    count -= 2;
  }

  /*  Add left-over byte, if any */
  if( count > 0 )
    sum += * (unsigned char *) addr;

  /*  Fold 32-bit sum to 16 bits */
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}

// **** Debug stuff
static char *
ch_opcode_name(int op)
  {
    if (op < 017 && op > 0)
      return ch_opc[op];
    else if (op == 0200)
      return "DAT";
    else if (op == 0300)
      return "DWD";
    else
      return "bogus";
  }

void
dumppkt_raw(unsigned char *ucp, int cnt)
{
    int i;

    while (cnt > 0) {
	for (i = 8; --i >= 0 && cnt > 0;) {
	    if (--cnt >= 0)
		fprintf(stderr, "  %02x", *ucp++);
	    if (--cnt >= 0)
		fprintf(stderr, "%02x", *ucp++);
	}
	fprintf(stderr, "\r\n");
    }
}
char *
ch_char(unsigned char x, char *buf) {
  if (x < 32)
    sprintf(buf,"^%c", x+64);
  else if (x == 127)
    sprintf(buf,"^?");
  else if (x < 127)
    sprintf(buf,"%2c",x);
  else
    sprintf(buf,"%2x",x);
  return buf;
}

void
ch_11_puts(unsigned char *out, unsigned char *in) 
{
  int i, x = ((strlen((char *)in)+1)/2)*2;
  for (i = 0; i < x; i++) {
    if (i % 2 == 1)
      out[i-1] = in[i];
    else
      out[i+1] = in[i];
  }
}

unsigned char *
ch_11_gets(unsigned char *in, unsigned char *out, int maxlen)
{
  int i, l = ((strlen((char *)in)+1)/2)*2;
  if (l > maxlen)
    l = maxlen;
  for (i = 0; i < l /* && ((in[i] & 0200) == 0) */; i++) { /* Where did I get 0200 bit from? */
    if (i % 2 == 1)
      out[i] = in[i-1];
    else
      out[i] = in[i+1];
  }
  out[i] = '\0';
  return out;
}

void print_its_string(unsigned char *s)
{
  unsigned char c;
  while (*s) {
    c = *s++;
    switch(c) {
    case 0211:
      c = '\t'; break;
    case 0212:
      c = '\n'; break;
    case 0214:
      c = '\f'; break;
    case 0215:
      putchar('\r');
      c = '\n'; break;
    }
    putchar(c);
  }
}  

void
ch_dumpkt(unsigned char *ucp, int cnt)
{
  int i, row, len;
  char b1[3],b2[3];
  struct chaos_header *ch = (struct chaos_header *)ucp;
  struct chaos_hw_trailer *tr;
  unsigned char *data = malloc(ch_nbytes(ch)+1);

  fprintf(stderr,"Opcode: %o (%s), unused: %o\r\nFC: %o, Nbytes %d.\r\n",
	  ch_opcode(ch), ch_opcode_name(ch_opcode(ch)),
	  ch->ch_opcode_u.ch_opcode_s.ch_unused,
	  ch_fc(ch), ch_nbytes(ch));
  fprintf(stderr,"Dest host: %o, index %o\r\nSource host: %o, index %o\r\n",
	  ch_destaddr(ch), ch_destindex(ch), ch_srcaddr(ch), ch_srcindex(ch));
  fprintf(stderr,"Packet #%o\r\nAck #%o\r\n",
	  ch_packetno(ch), ch_ackno(ch));

  fprintf(stderr,"Data:\r\n");

  len = ch_nbytes(ch);
  tr = (struct chaos_hw_trailer *)&ucp[cnt-6];

  /* Skip headers */
  ucp += CHAOS_HEADERSIZE;

  switch (ch_opcode(ch)) {
  case CHOP_RFC:
    ch_11_gets(ucp, data, ch_nbytes(ch));
    fprintf(stderr,"[Contact: \"%s\"]\n", data);
    break;

  case CHOP_OPN:
  case CHOP_STS:
    {
      unsigned short rcpt, winsz;
      rcpt = WORD16(ucp);
      winsz = WORD16(ucp+2);
      fprintf(stderr,"[Received up to and including %#o, window size %#o]\n",
	     rcpt, winsz);
      break;
    }
  case CHOP_CLS:
  case CHOP_LOS:
    ch_11_gets(ucp, data, ch_nbytes(ch));
    fprintf(stderr,"[Reason: \"%s\"]\n", data);
    break;

  case CHOP_FWD:
    ch_11_gets(ucp, data, ch_nbytes(ch));
    fprintf(stderr,"[New contact name: \"%s\" (host: see Ack field)]\n", data);
    break;

  case CHOP_RUT:
    {
      int nent = ch_nbytes(ch)/4;
      fprintf(stderr,"[%d. routing entries:\n", nent);
      for (i = 0; i < nent; i++) 
	fprintf(stderr," Subnet: %#o, cost %d.\n", WORD16(&ucp[i*4]), WORD16(&ucp[i*4+2]));
      fprintf(stderr,"]\n");
      break;
    }

  case CHOP_MNT:
  case CHOP_EOF:
  case CHOP_UNC:
  case CHOP_ANS:
    break;

  default:
    if (ch_opcode(ch) >= 0300)
      fprintf(stderr,"[16-bit controlled data]\n");
    else if (ch_opcode(ch) >= 0200)
      fprintf(stderr,"[8-bit controlled data]\n");
  }

  int showlen = (len > cnt ? cnt : len);
  for (row = 0; row*8 < showlen; row++) {
    for (i = 0; (i < 8) && (i+row*8 < len); i++) {
      fprintf(stderr, "  %02x", ucp[i+row*8]);
      fprintf(stderr, "%02x", ucp[(++i)+row*8]);
    }
    fprintf(stderr, " (hex)\r\n");
#if 1
    for (i = 0; (i < 8) && (i+row*8 < len); i++) {
      fprintf(stderr, "  %2s", ch_char(ucp[i+row*8],(char *)&b1));
      fprintf(stderr, "%2s", ch_char(ucp[(++i)+row*8],(char *)&b2));
    }
    fprintf(stderr, " (chars)\r\n");
    for (i = 0; (i < 8) && (i+row*8 < len); i++) {
      fprintf(stderr, "  %2s", ch_char(ucp[i+1+row*8],(char *)&b1));
      fprintf(stderr, "%2s", ch_char(ucp[(i++)+row*8],(char *)&b2));
    }
    fprintf(stderr, " (11-chars)\r\n");
#endif
  }
  if (cnt < len)
    fprintf(stderr,"... (header length field > buf len)\n");

  /* Now show trailer */
  if (len % 2)
    len++;			/* Align */
  if (len+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE > cnt)
    fprintf(stderr,"[Incomplete trailer: pkt size %d < (len + trailer size) = %lu]\n",
	    cnt, len+CHAOS_HEADERSIZE);
  else {
    u_int cks = ch_checksum((u_char *)ch, len);
    fprintf(stderr,"HW trailer:\r\n  Dest: %o\r\n  Source: %o\r\n  Checksum: %#x (%#x)\r\n",
	    ntohs(tr->ch_hw_destaddr), ntohs(tr->ch_hw_srcaddr), ntohs(tr->ch_hw_checksum),
	    cks);
  }
}

void
dumppkt(unsigned char *ucp, int cnt)
{
    fprintf(stderr,"CHUDP version %d, function %d\n", ucp[0], ucp[1]);
    ch_dumpkt(ucp+CHUDP_HEADERSIZE, cnt-CHUDP_HEADERSIZE);
}

/* **** CHUDP protocol functions **** */

int chudp_connect(u_short port) 
{
  int sock;
  struct sockaddr_in sin;

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket failed");
    exit(1);
  }
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock,(struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("bind failed");
    exit(1);
  }
  return sock;
}

void
chudp_send_pkt(int sock, struct sockaddr_in *sout, unsigned char *buf, int len)
{
  struct chaos_header *ch = (struct chaos_header *)&buf[CHUDP_HEADERSIZE];
  unsigned short cks;
  int i;
  char *ip;

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
  ip = inet_ntoa(sout->sin_addr);
  if (verbose || debug) {
    fprintf(stderr,"CHUDP: Sending %s: %lu + %lu + %d + %lu = %d bytes to %s:%d\n",
	    ch_opcode_name(ch_opcode(ch)),
	    CHUDP_HEADERSIZE, CHAOS_HEADERSIZE, ch_nbytes(ch), CHAOS_HW_TRAILERSIZE, i,
	    ip, ntohs(sout->sin_port));
    if (debug)
      dumppkt(buf, i);
  }
#endif
  if (sendto(sock, buf, i, 0, (struct sockaddr *)sout, sizeof(struct sockaddr_in)) < 0) {
    perror("sendto failed");
    exit(1);
  }
}

int
chudp_receive(int sock, unsigned char *buf, int buflen)
{
  struct chaos_header *ch = (struct chaos_header *)&buf[CHUDP_HEADERSIZE];
  struct chudp_header *cuh = (struct chudp_header *)buf;
  struct sockaddr_in sin;
  char *ip;
  int i, cnt, cks;
  u_int sinlen;

  memset(&sin,0,sizeof(sin));
  sinlen = sizeof(sin);
  cnt = recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&sin, &sinlen);
  if (cnt < 0) {
    perror("recvfrom");
    exit(1);
  }
  ip = inet_ntoa(sin.sin_addr);
  if ((cnt < CHUDP_HEADERSIZE) ||
      (cuh->chudp_version != CHUDP_VERSION) ||
      (cuh->chudp_function != CHUDP_PKT)) {
    if (verbose) fprintf(stderr,"Bad CHUDP header (size %d) from %s:%d\n",cnt,
			 ip, ntohs(sin.sin_port));
    // #### look up the source in chudpdest, count rejected pkt
    return 0;
  }
  int found = 0;
  PTLOCK(chudp_lock);
  if (debug) fprintf(stderr,"Looking up %s among %d chudp entries\n", ip, *chudpdest_len);
  for (i = 0; i < *chudpdest_len; i++) {
    if (memcmp((u_char *)&chudpdest[i].chu_sin.sin_addr, (u_char *)&sin.sin_addr, sizeof(sin.sin_addr)) == 0) {
      found = 1;
      if (chudpdest[i].chu_sin.sin_port != sin.sin_port) {
	if (verbose) fprintf(stderr,"CHUDP from %s port different from configured: %d # %d (dropping)\n",
			     ip, ntohs(sin.sin_port),
			     ntohs(chudpdest[i].chu_sin.sin_port));
	// #### if configured to use dynamic updates/additions also for this case?
	PTUNLOCK(chudp_lock);
	return 0;
      }
      break;
    }
  }
  PTUNLOCK(chudp_lock);

  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&buf[cnt-CHAOS_HW_TRAILERSIZE];
  u_short srcaddr = ch_srcaddr(ch);

  if (cnt >= CHUDP_HEADERSIZE + CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)
    // Prefer HW sender (i.e. the chudp host rather than origin host)
    srcaddr = ntohs(tr->ch_hw_srcaddr);

  if (!found) {
    if (verbose) fprintf(stderr,"CHUDP from unknown source %s:%d\n",
			 ip, ntohs(sin.sin_port));
    // if configured to use dynamic updates/additions, do it
    if (chudp_dynamic) {
      if (*chudpdest_len < CHUDPDEST_MAX) {
	if (verbose) fprintf(stderr,"Adding new CHUDP destination %#o.\n", srcaddr);
	PTLOCK(chudp_lock);
	chudpdest[*chudpdest_len].chu_addr = srcaddr;
	chudpdest[*chudpdest_len].chu_sin.sin_family = AF_INET;
	chudpdest[*chudpdest_len].chu_sin.sin_port = sin.sin_port;
	memcpy(&chudpdest[*chudpdest_len].chu_sin.sin_addr.s_addr, &sin.sin_addr, sizeof(sin.sin_addr));
	(*chudpdest_len)++;
	if (verbose) print_chudp_config();
	PTUNLOCK(chudp_lock);

	// see if there is a host route for this, otherwise add it
	if (*rttbl_host_len < RTTBL_HOST_MAX) {
	  found = 0;
	  for (i = 0; i < *rttbl_host_len; i++) {
	    if (rttbl_host[i].rt_dest == srcaddr) {
	      found = 1;
	      break;
	    }
	  }
	  if (!found) {
	    PTLOCK(rttbl_lock);
	    if (*rttbl_host_len < RTTBL_HOST_MAX) { // double check
	      // Add a host route (as if "link chudp [host] host [srcaddr]" was given)	    
	      rttbl_host[(*rttbl_host_len)].rt_dest = srcaddr;
	      rttbl_host[(*rttbl_host_len)].rt_type = RT_FIXED;
	      rttbl_host[(*rttbl_host_len)].rt_cost = RTCOST_ASYNCH;
	      rttbl_host[(*rttbl_host_len)].rt_link = LINK_CHUDP;
	      (*rttbl_host_len)++;
	      if (verbose) print_routing_table();
	    }
	    PTUNLOCK(rttbl_lock);
	  }
	} else {
	  if (verbose) fprintf(stderr,"Host routing table full, not adding new route.\n");
	  // and the chudp dest is useless, really.
	  return 0;
	}
      } else {
	if (verbose) fprintf(stderr,"CHUDP table full, not adding new destination.\n");
	return 0;
      }
    } else
      return 0;
  }
#if 1
  if (verbose || debug) {
    fprintf(stderr,"CHUDP: Received %d bytes (%s) from %s:%d (%#o)\n",
	    cnt, ch_opcode_name(ch_opcode(ch)),
	    ip, ntohs(sin.sin_port), srcaddr);
    if (debug)
      dumppkt(buf, cnt);
  }
#endif
  if ((cks = ch_checksum(&buf[CHUDP_HEADERSIZE],cnt-CHUDP_HEADERSIZE)) != 0) {
    if (verbose) fprintf(stderr,"[Bad checksum %#x (CHUDP)]\n",cks);
#if COLLECT_STATS
      PTLOCK(linktab_lock);
      linktab[srcaddr>>8].pkt_crcerr++;
      PTUNLOCK(linktab_lock);
#endif
    return 0;
  }

  return cnt;
}


void
htons_buf(u_short *ibuf, u_short *obuf, int len)
{
  int i;
  for (i = 0; i < len; i += 2)
    *obuf++ = htons(*ibuf++);
}
void
ntohs_buf(u_short *ibuf, u_short *obuf, int len)
{
  int i;
  for (i = 0; i < len; i += 2)
    *obuf++ = ntohs(*ibuf++);
}

/* **** Chaos-over-Unix-Sockets functions **** */
// Based on code by Brad Parker (brad@heeltoe.com), see http://www.unlambda.com/cadr/

/*
 * connect to server using specificed socket type
 */
int
u_connect_to_server(void)
{
    int len;
    struct sockaddr_un unix_addr;
    struct sockaddr_un unixs_addr;


    //printf("connect_to_server()\n");

    if ((fd = socket(PF_UNIX, CHAOSD_SOCK_TYPE, 0)) < 0) {
      perror("socket(AF_UNIX)");
      return -1;
    }

    memset(&unix_addr, 0, sizeof(unix_addr));

    sprintf(unix_addr.sun_path, "%s%s%05u",
	    UNIX_SOCKET_PATH, UNIX_SOCKET_CLIENT_NAME, getpid());

    unix_addr.sun_family = AF_UNIX;
    len = SUN_LEN(&unix_addr);

    unlink(unix_addr.sun_path);

    if (debug) fprintf(stderr,"My unix socket %s\n", unix_addr.sun_path);

    if ((bind(fd, (struct sockaddr *)&unix_addr, len) < 0)) {
      perror("bind(AF_UNIX)");
      close(fd);
      return -1;
    }

    if (chmod(unix_addr.sun_path, UNIX_SOCKET_PERM) < 0) {
      perror("chmod(AF_UNIX)");
      system("/bin/ls -l /var/tmp/");
      close(fd);
      return -1;
    }

//    sleep(1);
        
    memset(&unixs_addr, 0, sizeof(unixs_addr));
    sprintf(unixs_addr.sun_path, "%s%s",
	    UNIX_SOCKET_PATH, UNIX_SOCKET_SERVER_NAME);
    unixs_addr.sun_family = AF_UNIX;
    len = SUN_LEN(&unixs_addr);

    if (debug) fprintf(stderr,"Connecting to server socket %s\n", unixs_addr.sun_path);

    if (connect(fd, (struct sockaddr *)&unixs_addr, len) < 0) {
      if (debug) {
	fprintf(stderr,"cannot connect to socket %s\n",unixs_addr.sun_path);
	perror("connect(AF_UNIX)");
      }
      close(fd);
      return -1;
    }

    if (verbose > 1) printf("fd %d\n", fd);
        
    return fd;
}

int
u_read_chaos(int fd, u_char *buf, int buflen)
{
    int ret, len;
    u_char lenbytes[4];

    ret = read(fd, lenbytes, 4);
    if (ret == 0) {
      perror("read nothing from unix socket");
      return -1;
    }
    if (ret < 0) {
      perror("u_read_chaos");
      return ret;
    }

    len = (lenbytes[0] << 8) | lenbytes[1];

    ret = read(fd, buf, len > buflen ? buflen : len);
    if (ret == 0) {
      perror("read nothing from unix socket");
      return -1;
    }
    if (ret < 0)
      return ret;

    if (debug || (ret != len)) {
      fprintf(stderr,"Read %d of %d bytes from Unix socket\n",ret,len);
      htons_buf((u_short *)buf,(u_short *)buf,len);
      ch_dumpkt(buf,len);
      ntohs_buf((u_short *)buf,(u_short *)buf,len);
    }

    return ret;
}

void
u_send_chaos(int fd, u_char *buf, int buflen)
{
  u_char lenbytes[4];
  struct iovec iov[2];
  int ret;

  struct chaos_header *ch = (struct chaos_header *)buf;

  if (debug) {
    fprintf(stderr,"Sending to Unix socket:\n");
    htons_buf((u_short *)buf,(u_short *)buf,buflen);
    ch_dumpkt(buf,buflen);
    ntohs_buf((u_short *)buf,(u_short *)buf,buflen);
  } else if (verbose) {
    fprintf(stderr,"Unix: Sending %s: %d bytes\n",
	    ch_opcode_name(ntohs(ch->ch_opcode_u.ch_opcode_x)&0xff), buflen);
  }

  lenbytes[0] = (buflen >> 8) & 0xff;
  lenbytes[1] = buflen & 0xff;
  lenbytes[2] = 1;
  lenbytes[3] = 0;

  iov[0].iov_base = lenbytes;
  iov[0].iov_len = 4;

  iov[1].iov_base = buf;
  iov[1].iov_len = buflen;

  ret = writev(fd, iov, 2);
  if (ret <  0) {
    perror("u_send_chaos");
    // return(-1);
  }
}

/* **** Chaos-over-Ethernet functions **** */
#if CHAOS_ETHERP

// Find the ethernet address of the configured interface (ifname)
void get_my_ea() {
  struct ifaddrs *ifx, *ifs = NULL;
  if (getifaddrs(&ifs) < 0) {
    perror("getifaddrs");
    return;
  }
#if ETHER_BPF // really "if on a mac"?
  struct sockaddr_dl *sdl = NULL;
#else
  struct sockaddr_ll *sll = NULL;
#endif
  for (ifx = ifs; ifx != NULL; ifx = ifx->ifa_next) {
    if (strcmp(ifx->ifa_name, ifname) == 0) {
      if (ifx->ifa_addr != NULL) {
#if ETHER_BPF
	sdl = (struct sockaddr_dl *)ifx->ifa_addr;
	memcpy(&myea, LLADDR(sdl), sdl->sdl_alen);
#else
	sll = (struct sockaddr_ll *)ifx->ifa_addr;
	memcpy(&myea, sll->sll_addr, sll->sll_halen);
#endif
      }
      break;
    }
  }
  freeifaddrs(ifs);
}

#if ETHER_BPF
#define BPF_MTU CH_PK_MAXLEN // (BPF_WORDALIGN(1514) + BPF_WORDALIGN(sizeof(struct bpf_hdr)))

// from dpimp.c in klh10 by Ken Harrenstein
/* Packet byte offsets for interesting fields (in network order) */
#define PKBOFF_EDEST 0		/* 1st shortword of Ethernet destination */
#define PKBOFF_ETYPE 12		/* Shortwd offset to Ethernet packet type */
#define PKBOFF_ARP_PTYPE (sizeof(struct ether_header)+sizeof(u_short))  /* ARP protocol type */

/* BPF simple Loads */
#define BPFI_LD(a)  bpf_stmt(BPF_LD+BPF_W+BPF_ABS,(a))	/* Load word  P[a:4] */
#define BPFI_LDH(a) bpf_stmt(BPF_LD+BPF_H+BPF_ABS,(a))	/* Load short P[a:2] */
#define BPFI_LDB(a) bpf_stmt(BPF_LD+BPF_B+BPF_ABS,(a))	/* Load byte  P[a:1] */

/* BPF Jumps and skips */
#define BPFI_J(op,k,t,f) bpf_jump(BPF_JMP+(op)+BPF_K,(k),(t),(f))
#define BPFI_JEQ(k,n) BPFI_J(BPF_JEQ,(k),(n),0)		/* Jump if A == K */
#define BPFI_JNE(k,n) BPFI_J(BPF_JEQ,(k),0,(n))		/* Jump if A != K */
#define BPFI_JGT(k,n) BPFI_J(BPF_JGT,(k),(n),0)		/* Jump if A >  K */
#define BPFI_JLE(k,n) BPFI_J(BPF_JGT,(k),0,(n))		/* Jump if A <= K */
#define BPFI_JGE(k,n) BPFI_J(BPF_JGE,(k),(n),0)		/* Jump if A >= K */
#define BPFI_JLT(k,n) BPFI_J(BPF_JGE,(k),0,(n))		/* Jump if A <  K */
#define BPFI_JDO(k,n) BPFI_J(BPF_JSET,(k),(n),0)	/* Jump if   A & K */
#define BPFI_JDZ(k,n) BPFI_J(BPF_JSET,(k),0,(n))	/* Jump if !(A & K) */

#define BPFI_CAME(k) BPFI_JEQ((k),1)		/* Skip if A == K */
#define BPFI_CAMN(k) BPFI_JNE((k),1)		/* Skip if A != K */
#define BPFI_CAMG(k) BPFI_JGT((k),1)		/* Skip if A >  K */
#define BPFI_CAMLE(k) BPFI_JLE((k),1)		/* Skip if A <= K */
#define BPFI_CAMGE(k) BPFI_JGE((k),1)		/* Skip if A >= K */
#define BPFI_CAML(k) BPFI_JLT((k),1)		/* Skip if A <  K */
#define BPFI_TDNN(k) BPFI_JDO((k),1)		/* Skip if   A & K */
#define BPFI_TDNE(k) BPFI_JDZ((k),1)		/* Skip if !(A & K) */

/* BPF Returns */
#define BPFI_RET(n) bpf_stmt(BPF_RET+BPF_K, (n))	/* Return N bytes */
#define BPFI_RETFAIL() BPFI_RET(0)			/* Failure return */
#define BPFI_RETWIN()  BPFI_RET((u_int)-1)		/* Success return */

// My addition
#define BPFI_SKIP(n) BPFI_J(BPF_JA,0,(n),(n))  /* skip n instructions */

struct bpf_insn bpf_stmt(unsigned short code, bpf_u_int32 k)
{
    struct bpf_insn ret;
    ret.code = code;
    ret.jt = 0;
    ret.jf = 0;
    ret.k = k;
    return ret;
}
struct bpf_insn bpf_jump(unsigned short code, bpf_u_int32 k,
			 unsigned char jt, unsigned char jf)
{
    struct bpf_insn ret;
    ret.code = code;
    ret.jt = jt;
    ret.jf = jf;
    ret.k = k;
    return ret;
}
#endif // ETHER_BPF

/* Get a PACKET/DGRAM socket for the specified ethernet type, on the specified interface */
int
get_packet_socket(u_short ethtype, char *ifname)
{
  int fd;
#if ETHER_BPF
  struct ifreq ifr;
  char bpfname[64];
  int x;

  for (x = 0; x < 16; x++) {
    sprintf(bpfname, "/dev/bpf%d", x);
    if ((fd = open(bpfname, O_RDWR)) < 0) {
      if (errno == EBUSY) {
/* 	if (debug) perror(bpfname); */
	continue;
      } else {
	perror(bpfname);
	return -1;
      } 
    } else
      break;
  }
  if (fd < 0) {
    perror("Failed to open BPF device");
    fprintf(stderr,"Last tried %s\n", bpfname);
    return -1;
  } else
    if (debug) fprintf(stderr,"Opened BPF device %s successfully, fd %d\n",
		       bpfname, fd);

  // set max packet length (shorter for Chaos?). Must be set before interface is attached!
  x = BPF_MTU;
  if (ioctl(fd, BIOCSBLEN, (void *)&x) < 0) {
    perror("ioctl(BIOCSBLEN)");
    close(fd);
    return -1;
  }

  // Become nonblocking
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    flags = 0;
  if (fcntl(fd, F_SETFL, flags|O_NONBLOCK) < 0) {
    perror("fcntl(F_SETFL)");
    close(fd);
    return -1;
  }
#if 1
  // unset header-complete mode (we read and write complete pkts)
  // but we still need to create the header
  x = 0;
  if (ioctl(fd, BIOCSHDRCMPLT, (void *)&x) < 0) {
    perror("ioctl(BIOCSHDRCMPLT)");
    close(fd);
    return -1;
  }
#endif
  // Don't echo my sent pkts back to me, please
  x = 0;
  if (ioctl(fd, BIOCSSEESENT, (void *)&x) < 0) {
    perror("ioctl(BIOCSSEESENT)");
    close(fd);
    return -1;
  }
  // Operate in Immediate Mode: process pkts as they arrive rather than wait for timeout or buffer full
  x = 1;
  if (ioctl(fd, BIOCIMMEDIATE, (void *)&x) < 0) {
    perror("ioctl(BIOCIMMEDIATE)");
    close(fd);
    return -1;
  }
#if 0
  // let Promiscuous mode be, we filter for it
  x = 0;
  if (ioctl(fd, BIOCPROMISC, (void *)&x) < 0) {
    perror("ioctl(BIOCPROMISC)");
    close(fd);
    return -1;
  }
#endif

  // Now build the filter
  struct bpf_version bv;
  if (ioctl(fd, BIOCVERSION, (char *)&bv) < 0) {
    perror("ioctl(BIOCVERSION)");
    close(fd);
    return -1;
  } else if (bv.bv_major != BPF_MAJOR_VERSION ||
	     bv.bv_minor < BPF_MINOR_VERSION) {
    fprintf(stderr, "requires BPF language %d.%d or higher; kernel is %d.%d",
	    BPF_MAJOR_VERSION, BPF_MINOR_VERSION, bv.bv_major, bv.bv_minor);
    close(fd);
    return -1;
  }

  // Here is the BPF program, simple
#define BPF_PFMAX 50
  struct bpf_insn pftab[BPF_PFMAX], *p;
  struct bpf_program pfilter = {0, pftab}, *pfp;

  // must also check for address since if may be promisc although we didn't ask for it
  // tcpdump -i en0 -d 'ether proto 0x0804 && (ether dst 3c:07:54:14:c9:24 || ether dst ff:ff:ff:ff:ff:ff)'
  // (000) ldh      [12]
  // (001) jeq      #0x804           jt 2	jf 10
  // (002) ld       [2]
  // (003) jeq      #0x5414c924      jt 4	jf 6
  // (004) ldh      [0]
  // (005) jeq      #0x3c07          jt 9	jf 10
  // (006) jeq      #0xffffffff      jt 7	jf 10
  // (007) ldh      [0]
  // (008) jeq      #0xffff          jt 9	jf 10
  // (009) ret      #262144
  // (010) ret      #0

  pfp = &pfilter;
  p = pfp->bf_insns;		/* 1st instruction of BPF program */
  // Check the ethernet type field
  *p++ = BPFI_LDH(PKBOFF_ETYPE); /* Load ethernet type field */
  *p++ = BPFI_CAME(ethtype);	/* Skip if right type */
  *p++ = BPFI_RETFAIL();	/* nope, fail */
  if (ethtype == ETHERTYPE_ARP) {
    // For ARP, check the protocol type
    *p++ = BPFI_LDH(PKBOFF_ARP_PTYPE); /* Check the ARP type */
    *p++ = BPFI_CAME(ETHERTYPE_CHAOS);
    *p++ = BPFI_RETFAIL();	/* Not Chaos, ignore */
    // Never mind about destination here, if we get other ARP info that's nice?
  }
  else {
    // For Ethernet pkts, also filter for our own address or broadcast,
    // in case someone else makes the interface promiscuous
    u_short ea1 = (myea[0]<<8)|myea[1];
    u_long ea2 = (((myea[2]<<8)|myea[3])<<8|myea[4])<<8 | myea[5];
    *p++ = BPFI_LD(PKBOFF_EDEST+2);	/* last word of Ether dest */
    *p++ = BPFI_CAME(ea2);
    *p++ = BPFI_SKIP(3); /* no match, skip forward and check for broadcast */
    *p++ = BPFI_LDH(PKBOFF_EDEST);  /* get first part of dest addr */
    *p++ = BPFI_CAMN(ea1);
    *p++ = BPFI_RETWIN();		/* match both, win! */
    *p++ = BPFI_LD(PKBOFF_EDEST+2);	/* 1st word of Ether dest again */
    *p++ = BPFI_CAME(0xffffffff);	/* last hword is broadcast? */
    *p++ = BPFI_RETFAIL();
    *p++ = BPFI_LDH(PKBOFF_EDEST);  /* get first part of dest addr */
    *p++ = BPFI_CAME(0xffff);
    *p++ = BPFI_RETFAIL();	/* nope */
  }
  *p++ = BPFI_RETWIN();		/* win */

  pfp->bf_len = p - pfp->bf_insns; /* length of program */

  if (ioctl(fd, BIOCSETF, (char *)pfp) < 0) {
    perror("ioctl(BIOCSETF)");
    close(fd);
    return -1;
#if 0 // debug
  } else if (debug) {
    fprintf(stderr,"BPF filter len %d:\n", pfp->bf_len);
    for (x = 0; x < pfp->bf_len; x++)
      fprintf(stderr," %d: 0x%04X %2d %2d 0x%0X\n",
	      x,
	      pfp->bf_insns[x].code,
	      pfp->bf_insns[x].jt,
	      pfp->bf_insns[x].jf,
	      pfp->bf_insns[x].k);
#endif // 0
  }

  // Attach to interface
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, BIOCSETIF, (void *)&ifr) < 0) {
    perror("ioctl(BIOCSETIF)");
    close(fd);
    return -1;
  }

  if (myea[0] == 0 && myea[1] == 0) {
    // Find it if needed
    get_my_ea();
  }
  if (myea[0] == 0 && myea[1] == 0) {
    fprintf(stderr,"Cannot find MAC addr of interface %s\n", ifname);
    close(fd);
    return -1;
  }    

#if 0
  // I don't get a signal? But I don't want one anyway.
  if (verbose) {
    if (ioctl(fd, BIOCGRSIG, (void *)&x) >= 0)
      fprintf(stderr,"Signal on BPF reception: %d\n", x);
  }
#endif
  
#else // not BPF, but direct sockaddr_ll
  struct ifreq ifr;
  struct sockaddr_ll sll;

  if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ethtype))) < 0) {
    perror("socket(PF_PACKET, SOCK_DGRAM)");
    return -1;
  }
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, strlen(ifname));
  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl(SIOCGIFINDEX)");
    return -1;
  }
  ifix = ifr.ifr_ifindex;

  if (0 && debug)
    printf("ifindex %d\n", ifix);

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ethtype);
  sll.sll_ifindex = ifix;
  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind");
    return -1;
  }
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, strlen(ifname));
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ) {
    perror("ioctl(SIOCGIFHWADDR)");
    return -1;
  }

  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    fprintf(stderr,"wrong ARPHDR %d ", ifr.ifr_hwaddr.sa_family);
    perror("ioctl");
    return -1;
  }
  if (myea[0] == 0 && myea[1] == 0)
    memcpy(&myea, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

  if (0 && debug) {
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = ifix;
    if (ioctl(fd, SIOCGIFNAME, &ifr) < 0) {
      perror("ioctl(SIOCGIFNAME)");
      return -1;
    }
    printf("ifname %s\n", ifr.ifr_name);
  }
#endif // ETHER_BPF
  return fd;
}

/* Send a packet of the specified type to the specified address  */
void
send_packet (int if_fd, u_short ethtype, u_char *addr, u_char addrlen, u_char *packet, int packetlen)
{
  int cc;
#if !ETHER_BPF
  static struct sockaddr_ll sa;

  memset (&sa, 0, sizeof sa);
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ethtype);
  sa.sll_ifindex = ifix;
  sa.sll_hatype = ARPHRD_ETHER;
  sa.sll_pkttype = PACKET_HOST;
  sa.sll_halen = addrlen;
  memcpy(&sa.sll_addr, addr, addrlen);
#endif // !ETHER_BPF

  if (verbose) {
    struct chaos_header *ch = (struct chaos_header *)packet;
    printf("Ether: Sending %s: %d bytes with protocol 0x%04x (%s) to address ",
	   (ethtype == ETHERTYPE_CHAOS ? ch_opcode_name(ntohs(ch->ch_opcode_u.ch_opcode_x)&0xff) :
	    (ethtype == ETHERTYPE_ARP ? "ARP" : "?")),
	   packetlen, ethtype,
	   (ethtype == ETHERTYPE_ARP ? "ARP" :
	    (ethtype == ETHERTYPE_CHAOS ? "Chaos" : "?")));
    for (cc = 0; cc < addrlen-1; cc++)
      printf("%02X:",addr[cc]);
    printf("%02X\n",addr[cc]);
  }
#if ETHER_BPF
  // construct the header separately to avoid copying
  struct iovec iov[2];
  struct ether_header eh;

  memcpy(&eh.ether_shost, &myea, ETHER_ADDR_LEN);
  memcpy(&eh.ether_dhost, addr, ETHER_ADDR_LEN);
  eh.ether_type = htons(ethtype);

  iov[0].iov_base = (char *) &eh;
  iov[0].iov_len = ETHER_HDR_LEN;
  iov[1].iov_base = packet;
  iov[1].iov_len = packetlen;;

  if (packetlen+sizeof(struct ether_header) > BPF_MTU) {
    fprintf(stderr,"send_packet: buf len %lu vs MTU %lu\n",
	    packetlen+sizeof(struct ether_header), BPF_MTU);
  }
  cc = writev(if_fd, iov, sizeof(iov)/sizeof(*iov));
  packetlen += sizeof(struct ether_header);  /* avoid complaints below */

#else // not BPF
  cc = sendto(if_fd, packet, packetlen, 0, (struct sockaddr *)&sa, sizeof(sa));
#endif // ETHER_BPF

  if (cc == packetlen)
    return;
  else if (cc >= 0) {
    if (debug) fprintf(stderr,"send_packet sent only %d bytes\n", cc);
  } else
    {
      perror("send_packet");
      fprintf(stderr, "\n");
      exit(1);
    }
}

/* Read a packet from the socket. */
#if ETHER_BPF
unsigned int bpf_buf_offset = 0;
unsigned int bpf_buf_length = 0;
uint8_t ether_bpf_buf[BPF_MTU];
#endif // ETHER_BPF

int
get_packet (int if_fd, u_char *buf, int buflen)
{
  int i, rlen;
  u_short protocol;
  u_int64_t src_mac = 0;		// let's hope a 48-bit mac fits

#if ETHER_BPF
  // Based on 3com.c in LambdaDelta by Daniel Seagraves & Barry Silverman
  // see https://github.com/dseagrav/ld
  int res;
  struct bpf_hdr *bpf_header;

  // #### gross hack, don't want to mess with the actual headers
  if (if_fd == arpfd)
    protocol = ntohs(ETHERTYPE_ARP);
  else if (if_fd == chfd)
    protocol = ntohs(ETHERTYPE_CHAOS);
  else
    protocol = -1;

#if 0 //debug
  if (debug) {
    int avail;
    if (ioctl(if_fd, FIONREAD, (void *)&avail) < 0) {
      perror("ioctl(FIONREAD)");
      return 0;
    } else
      fprintf(stderr,"about to read from fd %d: available %d bytes\n", if_fd, avail);
  }
#endif

  if (bpf_buf_offset == 0) {
    // BPF _requires_ you use the same buffer length you configured the filter for
    if ((res = read(if_fd, ether_bpf_buf, sizeof(ether_bpf_buf))) < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
	perror("read BPF ether");
#if 0 //debug
	if (debug) {
	  fprintf(stderr,"failed reading fd %d (chfd %d, arpfd %d) buf %p buflen %d\n", if_fd, chfd, arpfd,
		  buf, buflen);
	  fprintf(stderr,"tried using buflen %d, configured for %lu\n",
		  buflen, BPF_MTU);
	}
#endif
	exit(1);
      }
      else
	if (debug) perror("read BPF ether");
      return 0;
    }
    bpf_buf_length = res;
  }
  bpf_header = (struct bpf_hdr *)(ether_bpf_buf + bpf_buf_offset);

#if 0 //debug
  if (debug) fprintf(stderr,"BPF: read %d bytes from fd (MTU %lu), timeval sec %d\n buflen %d, hdrlen %d, caplen %d, datalen %d, offset %d\n",
		     bpf_buf_length, BPF_MTU,
		     bpf_header->bh_tstamp.tv_sec,
		     buflen, bpf_header->bh_hdrlen, bpf_header->bh_caplen, bpf_header->bh_datalen,
		     bpf_buf_offset);
#endif

  memcpy(buf, (uint8_t *)(ether_bpf_buf + bpf_buf_offset + bpf_header->bh_hdrlen)
	 +sizeof(struct ether_header),  /* skip ether header! */
	 bpf_header->bh_caplen < buflen ? bpf_header->bh_caplen : buflen);
  if (bpf_buf_offset + bpf_header->bh_hdrlen + bpf_header->bh_caplen < bpf_buf_length)
    bpf_buf_offset += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
  else
    bpf_buf_offset = 0;
  if (bpf_header->bh_caplen != bpf_header->bh_datalen) {
    if (debug) fprintf(stderr,"BPF: LENGTH MISMATCH: Captured %d of %d\n",
		       bpf_header->bh_caplen, bpf_header->bh_datalen);
    return 0;			/* throw away packet */
  } else {
    rlen = bpf_header->bh_caplen - sizeof(struct ether_header);
    // if (debug) fprintf(stderr,"BPF: read %d bytes\n", rlen);
  }

  struct ether_header *eh = (struct ether_header *)(ether_bpf_buf + bpf_buf_offset + bpf_header->bh_hdrlen);

  for (i = 0; i < ETHER_ADDR_LEN-1; i++) {
    src_mac |= eh->ether_shost[i];
    src_mac = src_mac<<8;
  }
  src_mac |= eh->ether_shost[i];

#else // not BPF
  struct sockaddr_ll sll;
  socklen_t sllen = sizeof(sll);

  rlen = recvfrom(if_fd, buf, buflen, 0, (struct sockaddr *) &sll, &sllen);
  protocol = sll.sll_protocol;
  for (i = 0; i < sll.sll_halen-1; i++) {
    src_mac |= sll.sll_addr[i];
    src_mac = src_mac<<8;
  }
  src_mac |= sll.sll_addr[i];

#endif // ETHER_BPF
  if (rlen < 0)
    {
      if (errno != EAGAIN) {
	perror ("get_packet: Read error");
	exit(1);
      }
      return 0;
    }
  if (rlen == 0)
    return 0;

  if (verbose) {
#if 0
    if (debug) {
      printf("Received:\n");
      printf(" Family %d\n",sll.sll_family);
      printf(" Protocol %#x (%s)\n",ntohs(sll.sll_protocol),
	     (sll.sll_protocol == htons(ETHERTYPE_ARP) ? "ARP" :
	      (sll.sll_protocol == htons(ETHERTYPE_CHAOS) ? "Chaos" : "?")));
      printf(" Index %d\n",sll.sll_ifindex);
      printf(" Header type %d (%s)\n",sll.sll_hatype,
	     (sll.sll_hatype == ARPHRD_ETHER ? "Ether" :
	      (sll.sll_hatype == ARPHRD_CHAOS ? "Chaos" : "?")));
      printf(" Pkt type %d (%s)\n",sll.sll_pkttype,
	     (sll.sll_pkttype == PACKET_HOST ? "Host" :
	      (sll.sll_pkttype == PACKET_BROADCAST ? "Broadcast" :
	       (sll.sll_pkttype == PACKET_MULTICAST ? "Multicast" :
		(sll.sll_pkttype == PACKET_OTHERHOST ? "Other host" :
		 (sll.sll_pkttype == PACKET_OUTGOING ? "Outgoing" : "?"))))));
      printf(" Addr len %d\n Addr ", sll.sll_halen);
    } else
      printf("Received %d bytes, protocol %#x, from ",
	     rlen, ntohs(sll.sll_protocol));
    for (i = 0; i < sll.sll_halen; i++)
      printf("%02X ", sll.sll_addr[i]);
    printf("\n");
#endif

#if 0
    if (debug && protocol == htons(ETHERTYPE_ARP)) {
      struct arphdr *arp = (struct arphdr *)buf;
      fprintf(stderr,"ARP message received, protocol 0x%04x (%s)\n",
	      ntohs(arp->ar_pro), (arp->ar_hrd == htons(ARPHRD_ETHER) ? "Ether" :
			    (arp->ar_hrd == htons(ARPHRD_CHAOS) ? "Chaos" : "?")));
    }
#endif

    if (protocol == htons(ETHERTYPE_ARP) 
#if 1
	&& (((struct arphdr *)buf)->ar_pro == htons(ETHERTYPE_CHAOS))
#endif
	) {
      struct arphdr *arp = (struct arphdr *)buf;
      if (debug) {
	printf("ARP message:\n");
	printf(" HW format %d (%s)\n",ntohs(arp->ar_hrd),
	       (arp->ar_hrd == htons(ARPHRD_ETHER) ? "Ether" :
		(arp->ar_hrd == htons(ARPHRD_CHAOS) ? "Chaos" : "?")));
	printf(" Protocol format 0x%04x (%s)\n",ntohs(arp->ar_pro),
	       (arp->ar_pro == htons(ETHERTYPE_ARP) ? "ARP" :
		(arp->ar_pro == htons(ETHERTYPE_CHAOS) ? "Chaos" :
		 (arp->ar_pro == htons(ETHERTYPE_IP) ? "IP" : "?"))));
	printf(" HW addr len %d\n Proto addr len %d\n ARP command %d (%s)\n",
	       arp->ar_hln, arp->ar_pln, ntohs(arp->ar_op),
	       arp->ar_op == htons(ARPOP_REQUEST) ? "Request" :
	       (arp->ar_op == htons(ARPOP_REPLY) ? "Reply" :
		(arp->ar_op == htons(ARPOP_RREQUEST) ? "Reverse request" :
		 (arp->ar_op == htons(ARPOP_RREPLY) ? "Reverse reply" : "?"))));
	printf(" Src HW addr: ");
	for (i = 0; i < arp->ar_hln; i++)
	  printf("%02X ", buf[sizeof(struct arphdr)+i]);
	printf("\n Src Protocol addr: ");
	for (i = 0; i < arp->ar_pln; i++)
	  printf("%d ", buf[sizeof(struct arphdr)+arp->ar_hln+i]);
	printf("\n Dst HW addr: ");
	for (i = 0; i < arp->ar_hln; i++)
	  printf("%02X ", buf[sizeof(struct arphdr)+arp->ar_hln+arp->ar_pln+i]);
	printf("\n Dst Protocol addr: ");
	for (i = 0; i < arp->ar_pln; i++)
	  printf("%d ", buf[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln+i]);
	printf("\n");
      } else if (verbose)
	printf("ARP %s for protocol %#x\n",
	       arp->ar_op == htons(ARPOP_REQUEST) ? "Request" :
	       (arp->ar_op == htons(ARPOP_REPLY) ? "Reply" :
		(arp->ar_op == htons(ARPOP_RREQUEST) ? "Reverse request" :
		 (arp->ar_op == htons(ARPOP_RREPLY) ? "Reverse reply" : "?"))),
	       ntohs(arp->ar_pro));
    }
    else if (protocol == htons(ETHERTYPE_CHAOS)) {
#if PEEK_ARP
      struct chaos_header *ch = (struct chaos_header *)buf;
      u_short schad = ntohs(ch_srcaddr(ch));
#if 0
      int i;
      fprintf(stderr,"Chaos pkt received from %#o with MAC %#llx ", schad, src_mac);
      for (i = 0; i < ETHER_ADDR_LEN-1; i++)
	fprintf(stderr,"%02X:", (u_char)(src_mac>>((ETHER_ADDR_LEN-1-i)*8)) & 0xff);
      fprintf(stderr,"%02X\n", (u_char)src_mac & 0xff);
#endif

  /* Now see if we should add this to our Chaos ARP list */
      PTLOCK(charp_lock);
      int found = 0;
      for (i = 0; i < *charp_len; i++)
	if (charp_list[i].charp_chaddr == schad) {
	  found = 1;
#if 0 // actually, skip this for a tiny bit of efficiency
	  charp_list[i].charp_age = time(NULL);  // update
	  int j;
	  for (j = 0; j < ETHER_ADDR_LEN; j++)
	    charp_list[i].charp_eaddr[j] = (u_char)(src_mac>>(ETHER_ADDR_LEN-1-j)*8) & 0xff;
	  if (verbose) {
	    fprintf(stderr,"Updated PEEKED MAC addr for %#o\n", schad);
	    print_arp_table();
	  }
#endif // efficiency
	  break;
	}
      /* It's not in the list already, is there room? */
      if (!found && *charp_len < CHARP_MAX) {
	if (verbose) printf("Adding PEEKED Chaos ARP for %#o\n", schad);
	charp_list[*charp_len].charp_chaddr = schad;
	charp_list[*charp_len].charp_age = time(NULL);
	for (i = 0; i < ETHER_ADDR_LEN; i++)
	  charp_list[*charp_len].charp_eaddr[i] = (u_char)(src_mac>>(ETHER_ADDR_LEN-1-i)*8) & 0xff;
	(*charp_len)++;
	if (verbose) print_arp_table();
      }
      PTUNLOCK(charp_lock);
#endif // PEEK_ARP

      if (debug) {
	printf("Ethernet Chaos message:\n");
	ntohs_buf((u_short *)buf, (u_short *)buf, rlen);
	ch_dumpkt(buf, rlen);
	ntohs_buf((u_short *)buf, (u_short *)buf, rlen);
      }
      else if (verbose) {
	struct chaos_header *ch = (struct chaos_header *)buf;
	ntohs_buf((u_short *)buf, (u_short *)buf, rlen);
#if 1
	printf("Ethernet Chaos message received: %s from %#o to %#o\n",
	       ch_opcode_name(ch_opcode(ch)), ch_srcaddr(ch), ch_destaddr(ch));
#else
	printf(" Opcode: %o (%s), unused: %o\n FC: %o, Nbytes %d.\n",
		ch_opcode(ch), ch_opcode_name(ch_opcode(ch)),
		ch->ch_unused,
		ch_fc(ch), ch_nbytes(ch));
	printf(" Dest host: %o, index %o\n Source host: %o, index %o\n",
		ch_destaddr(ch), ch_destindex(ch), ch_srcaddr(ch), ch_srcindex(ch));
	printf(" Packet #%o\n Ack #%o\n",
		ch_packetno(ch), ch_ackno(ch));
#endif
	ntohs_buf((u_short *)buf, (u_short *)buf, rlen);
      }
#if 0
    if (debug) {
      printf("Received %d bytes:", rlen);
      for (i = 0; i < rlen; i++) {
	if (i % 16 == 0)
	  printf("\n");
	printf("%02x ", buf[i]);
      }
      printf("\n");
    }
#endif
    }
  }

  return rlen;
}

/* **** Chaosnet ARP functions **** */
void init_arp_table()
{
  if (pthread_mutex_init(&charp_lock, NULL) != 0)
    perror("pthread_mutex_init(charp_lock)");
  if ((charp_list = malloc(sizeof(struct charp_ent)*CHARP_MAX)) == NULL)
    perror("malloc(charp_list)");
  if ((charp_len = malloc(sizeof(int))) == NULL)
    perror("malloc(charp_len)");
  memset((char *)charp_list, 0, sizeof(struct charp_ent)*CHARP_MAX);
  *charp_len = 0;
}

u_char *find_arp_entry(u_short daddr)
{
  int i;
  if (debug) fprintf(stderr,"Looking for ARP entry for %#o, ARP table len %d\n", daddr, *charp_len);
  if (daddr == mychaddr) {
    fprintf(stderr,"#### Looking up ARP for my own address, BUG!\n");
    return NULL;
  }
  
  PTLOCK(charp_lock);
  for (i = 0; i < *charp_len; i++)
    if (charp_list[i].charp_chaddr == daddr) {
      if ((charp_list[i].charp_age != 0)
	  && ((time(NULL) - charp_list[i].charp_age) > CHARP_MAX_AGE)) {
	if (verbose) fprintf(stderr,"Found ARP entry for %#o but it is too old (%lu s)\n",
			     daddr, (time(NULL) - charp_list[i].charp_age));
	PTUNLOCK(charp_lock);
	return NULL;
      }
      if (debug) fprintf(stderr,"Found ARP entry for %#o\n", daddr);
      PTUNLOCK(charp_lock);
      return charp_list[i].charp_eaddr;
    }
  PTUNLOCK(charp_lock);
  return NULL;
}

void
send_chaos_arp_request(int fd, u_short chaddr)
{
  u_char req[sizeof(struct arphdr)+(ETHER_ADDR_LEN+2)*2];
  struct arphdr *arp = (struct arphdr *)&req;
  memset(&req, 0, sizeof(req));
  arp->ar_hrd = htons(ARPHRD_ETHER); /* Want ethernet address */
  arp->ar_pro = htons(ETHERTYPE_CHAOS);	/* of a Chaosnet address */
  arp->ar_hln = ETHER_ADDR_LEN;
  arp->ar_pln = sizeof(chaddr);
  arp->ar_op = htons(ARPOP_REQUEST);
  memcpy(&req[sizeof(struct arphdr)], &myea, ETHER_ADDR_LEN);	/* my ether */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN], &mychaddr, sizeof(mychaddr)); /* my chaos */
  /* his chaos */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN+2+ETHER_ADDR_LEN], &chaddr, sizeof(chaddr));

  send_packet(fd, ETHERTYPE_ARP, eth_brd, ETHER_ADDR_LEN, req, sizeof(req));
}

void
send_chaos_arp_reply(int fd, u_short dchaddr, u_char *deaddr, u_short schaddr)
{
  u_char req[sizeof(struct arphdr)+(ETHER_ADDR_LEN+2)*2];
  struct arphdr *arp = (struct arphdr *)&req;
  memset(&req, 0, sizeof(req));
  arp->ar_hrd = htons(ARPHRD_ETHER); /* Want ethernet address */
  arp->ar_pro = htons(ETHERTYPE_CHAOS);	/* of a Chaosnet address */
  arp->ar_hln = ETHER_ADDR_LEN;
  arp->ar_pln = sizeof(u_short);
  arp->ar_op = htons(ARPOP_REPLY);
  memcpy(&req[sizeof(struct arphdr)], &myea, ETHER_ADDR_LEN);	/* my ether */
  /* proxying for this */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN], &schaddr, sizeof(u_short));
  /* His ether */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN+2], deaddr, ETHER_ADDR_LEN);
  /* his chaos */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN+2+ETHER_ADDR_LEN], &dchaddr, sizeof(dchaddr));

  send_packet(fd, ETHERTYPE_ARP, deaddr, ETHER_ADDR_LEN, req, sizeof(req));
}
#endif // CHAOS_ETHERP

#if COLLECT_STATS
void 
status_responder(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short src = ch_srcaddr(ch);
  u_char ans[CH_PK_MAXLEN];
  struct chaos_header *ap = (struct chaos_header *)&ans;
  int i;

  memset(ans, 0, sizeof(ans));
  set_ch_opcode(ap, CHOP_ANS);
  set_ch_destaddr(ap, src);
  set_ch_destindex(ap, ch_srcindex(ch));
  set_ch_srcindex(ap, ch_destindex(ch));

  u_short *dp = (u_short *)&ans[CHAOS_HEADERSIZE];

  // First 32 bytes contain the name of the node, padded on the right with zero bytes.
  ch_11_puts((u_char *)dp, (u_char *)myname);	/* this rounds up to 16-bit border */
  dp += strlen((char *)myname)/2+1;
  for (i = strlen((char *)myname)/2+1; i < 32/2; i++)
    *dp++ = 0;

  int maxentries = 12;		// max 244 words in a Chaos pkt, 16 for Node name, 18 per entry below
  // Low-order half of 32-bit word comes first
  for (i = 0; i < 256 && maxentries-- > 0; i++) {
    if (linktab[i].pkt_in != 0 || linktab[i].pkt_out != 0 || linktab[i].pkt_crcerr != 0) {
      *dp++ = htons(i + 0400);		/* subnet + 0400 */
      *dp++ = htons(16);		/* length in 16-bit words */
      *dp++ = htons(linktab[i].pkt_in & 0xffff);
      *dp++ = htons(linktab[i].pkt_in>>16);
      *dp++ = htons(linktab[i].pkt_out & 0xffff);
      *dp++ = htons(linktab[i].pkt_out>>16);
      *dp++ = htons(linktab[i].pkt_aborted & 0xffff);
      *dp++ = htons(linktab[i].pkt_aborted>>16);
      *dp++ = htons(linktab[i].pkt_lost & 0xffff);
      *dp++ = htons(linktab[i].pkt_lost>>16);
      *dp++ = htons(linktab[i].pkt_crcerr & 0xffff);
      *dp++ = htons(linktab[i].pkt_crcerr>>16);
      *dp++ = htons(linktab[i].pkt_crcerr_post & 0xffff);
      *dp++ = htons(linktab[i].pkt_crcerr_post>>16);
      *dp++ = htons(linktab[i].pkt_badlen & 0xffff);
      *dp++ = htons(linktab[i].pkt_badlen>>16);
      *dp++ = htons(linktab[i].pkt_rejected & 0xffff);
      *dp++ = htons(linktab[i].pkt_rejected>>16);
    }
  }
  if (maxentries == 0)
    fprintf(stderr,"WARNING: your linktab contains too many networks (%d),\n"
	    " %d of them do not fit in STATUS pkt\n",
	    12+maxentries, maxentries);
  set_ch_nbytes(ap, (dp-(u_short *)&ans[CHAOS_HEADERSIZE])*2);

  send_chaos_pkt((u_char *)ap, ch_nbytes(ap)+CHAOS_HEADERSIZE);
}
#endif // COLLECT_STATS

// **** Bridging between links

void forward_chaos_pkt_on_route(struct chroute *rt, u_char *data, int dlen) 
{
  int i;
  u_char chubuf[CH_PK_MAXLEN + CHUDP_HEADERSIZE];
  struct chaos_header *ch = (struct chaos_header *)data;
  struct chudp_header *chu = (struct chudp_header *)&chubuf;

  u_short dchad = ch_destaddr(ch);
  u_short schad = ch_srcaddr(ch);

  // round up, e.g. because of 11-format text. (A single char is in the second byte, not the first.)
  if (dlen % 2)
    dlen++;

  // Update/add trailer here.
  if (dlen < CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)
    dlen += CHAOS_HW_TRAILERSIZE;  /* add trailer if needed */
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[dlen-CHAOS_HW_TRAILERSIZE];
  // HW dest is next-hop destination
  tr->ch_hw_destaddr = rt->rt_dest > 0 ? htons(rt->rt_dest) : htons(ch_destaddr(ch));
  // HW sender is me!
  tr->ch_hw_srcaddr = rt->rt_myaddr > 0 ? htons(rt->rt_myaddr) : htons(mychaddr);

  int cks = ch_checksum(data,dlen-2); /* Don't checksum the checksum field */
  tr->ch_hw_checksum = htons(cks);



  switch (rt->rt_link) {
#if CHAOS_ETHERP
  case LINK_ETHER:
    if (debug) fprintf(stderr,"Forward ether from %#o to %#o\n", schad, dchad);
    htons_buf((u_short *)ch, (u_short *)ch, dlen);
    if (dchad == 0) {		/* broadcast */
      if (debug) fprintf(stderr,"Forward: Broadcasting on ether from %#o\n", schad);
      send_packet(chfd, ETHERTYPE_CHAOS, eth_brd, ETHER_ADDR_LEN, data, dlen);
    } else {
      u_char *eaddr = find_arp_entry(dchad);
      if (eaddr != NULL) {
	if (debug) fprintf(stderr,"Forward: Sending on ether from %#o to %#o\n", schad, dchad);
	send_packet(chfd, ETHERTYPE_CHAOS, eaddr, ETHER_ADDR_LEN, data, dlen);
      } else {
	if (debug) fprintf(stderr,"Forward: Don't know %#o, sending ARP request\n", dchad);
	send_chaos_arp_request(arpfd, dchad);
	// Chaos sender will retransmit, surely.
      }
    }
    break;
#endif // CHAOS_ETHERP
  case LINK_UNIXSOCK:
    // There can be only one?
    htons_buf((u_short *)ch, (u_short *)ch, dlen);
    if (unixsock > 0) {
      if (debug) fprintf(stderr,"Forward: Sending on unix from %#o to %#o\n", schad, dchad);
      u_send_chaos(unixsock, data, dlen);
    }
    break;
  case LINK_CHUDP:
    if (debug) fprintf(stderr,"Forward: Sending on CHUDP from %#o to %#o via %#o/%#o (%d bytes)\n", schad, dchad, rt->rt_dest, rt->rt_braddr, dlen);
    /* Add CHUDP header, copy message only once (in case it needs to be sent more than once) */
    memset(&chubuf, 0, sizeof(chubuf));
    chu->chudp_version = CHUDP_VERSION;
    chu->chudp_function = CHUDP_PKT;
    // Assert that dlen+CHUDP_HEADERSIZE <= sizeof(chubuf)
    memcpy(&chubuf[CHUDP_HEADERSIZE], data, dlen);

    int found = 0;
    PTLOCK(chudp_lock);
    for (i = 0; i < *chudpdest_len; i++) {
      if (dchad == 0		/* broadcast */
	  || (chudpdest[i].chu_addr == dchad)  /* direct link */
	  || (chudpdest[i].chu_addr == rt->rt_braddr)  /* bridge */
	  || (rt->rt_braddr == 0 && (chudpdest[i].chu_addr == rt->rt_dest))
	  ) {
	if (debug) fprintf(stderr,"Forward CHUDP to dest %d\n", i);
	found = 1;
	chudp_send_pkt(udpsock, &chudpdest[i].chu_sin, (u_char *)&chubuf, dlen);
      }
    }
    PTUNLOCK(chudp_lock);
    if (!found && (verbose || debug))
      fprintf(stderr, "Can't find CHUDP link to %#o via %#o/%#o\n",
	      dchad, rt->rt_dest, rt->rt_braddr);
    break;
  default:
    if (verbose) fprintf(stderr,"Can't forward pkt on bad link type %d\n", rt->rt_link);
  }
}

void forward_chaos_pkt(int src, u_char type, u_char cost, u_char *data, int dlen, u_char src_linktype) 
{
  struct chaos_header *ch = (struct chaos_header *)data;
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[dlen-CHAOS_HW_TRAILERSIZE];

#if COLLECT_STATS
  u_short schad = ch_srcaddr(ch);  /* source */
  if (dlen >= CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE) {
    // use hw trailer if available
    if (schad != 0) {
      schad = htons(tr->ch_hw_srcaddr);
    }
  }
#endif
  u_short dchad = ch_destaddr(ch);  /* destination */
  u_char fwc = ch_fc(ch);	/* forwarding count */

#if COLLECT_STATS
  if (src >= 0) {
    PTLOCK(linktab_lock);
    linktab[src>>8].pkt_in++;
    PTUNLOCK(linktab_lock);
  } else if (debug)
    fprintf(stderr,"No source given in forward from %#o to %#o\n",
	    schad, dchad);
#endif

  if (ch_srcaddr(ch) == mychaddr) {
    // Should not happen. Unless Unix sockets.
    if (src_linktype != LINK_UNIXSOCK) {
      if (verbose) fprintf(stderr,"Dropping pkt from self to %#o (src %#o - hw %#o, type %s, link %s) \n",
			   dchad, src, ntohs(tr->ch_hw_srcaddr), 
			   rt_typename(type), rt_linkname(src_linktype));
      if (debug) ch_dumpkt(data, dlen);
    }
    return;
  }

  if (++fwc > CH_FORWARD_MAX) {	/* over-forwarded */
    if (verbose) fprintf(stderr,"Dropping over-forwarded pkt for %#o\n", dchad);
#if COLLECT_STATS
    if (src >= 0) {
      PTLOCK(linktab_lock);
      linktab[src>>8].pkt_rejected++;
      PTUNLOCK(linktab_lock);
    }
#endif
    return;
  }
  set_ch_fc(ch,fwc);		/* update */

  struct chroute *rt = find_in_routing_table(dchad, 0);
  if ((rt != NULL)
      && (rt->rt_link == LINK_UNIXSOCK) && (src_linktype == LINK_UNIXSOCK)) {
    // Unix socket echoes my own packets
    if (debug) fprintf(stderr,"[Not routing %s from %#o to %#o back to source route (%s)]\n",
			 ch_opcode_name(ch_opcode(ch)),
			 ch_srcaddr(ch), dchad, rt_linkname(rt->rt_link));
    return;
  }

  peek_routing(data, dlen, type, cost, src_linktype); /* check for RUT */

  if (dchad == mychaddr) {
#if COLLECT_STATS
    // should potentially handle BRD packets, but nobody sends them anyway?
    if (ch_opcode(ch) == CHOP_RFC
	&& strncmp((char *)&data[CHAOS_HEADERSIZE],"STATUS",6)
	&& ((ch_nbytes(ch) == 6) || data[CHAOS_HEADERSIZE+7] == ' ')) {
      if (verbose) fprintf(stderr,"RFC for STATUS received, responding\n");
      status_responder(data, dlen);
    }
    else
#endif // COLLECT_STATS
      if (debug) {
	fprintf(stderr,"%s pkt for self (%#o) received, not forwarding.\n",
		ch_opcode_name(ch_opcode(ch)),
		mychaddr);
	if (ch_opcode(ch) == CHOP_RFC) {
	  fprintf(stderr," Contact: ");
	  int max = ch_nbytes(ch);
	  u_char ch[3], *cp = &data[CHAOS_HEADERSIZE];
	  while (*cp && (max > 0)) {
	    ch_char(*cp,(char *)ch);
	    fprintf(stderr,"%s %d", ch, *cp);
	    cp++;
	    max--;
	  }
	  fprintf(stderr,"\n");
	}
      }
    return;			/* after checking for RUT */
  }

  if (dchad == 0) {		/* broadcast */
    // send on all links to the same subnet.
    // But how can we know they didn't also receive it, and sent it on their links?
    // Possibly do this for BRD packets, which have a storm prevention feature?
    // Punt for now:
    // Only live use of broadcast I've seen is for RUT, which is handled above by peek_routing
    // if (debug) fprintf(stderr,"Broadcast received, MAYBE IMPLEMENT FORWARDING OF IT?\n");
    return;
  }

  if (rt) {
    if (verbose) fprintf(stderr,"Forwarding %s from %#o (%s) to %#o on  %#o bridge/subnet %#o (%s)\n",
			 ch_opcode_name(ch_opcode(ch)),
			 ch_srcaddr(ch),
			 (src_linktype != 0 ? rt_linkname(src_linktype) : "?"),
			 dchad, rt->rt_dest, rt->rt_braddr,
			 rt_linkname(rt->rt_link));

#if COLLECT_STATS
    PTLOCK(linktab_lock);
    linktab[rt->rt_dest >>8 ].pkt_out++;
    PTUNLOCK(linktab_lock);
#endif
    forward_chaos_pkt_on_route(rt, data, dlen);
  } else {
    if (verbose) fprintf(stderr,"Can't find route to %#o\n", dchad);
#if COLLECT_STATS
    if (src >= 0) {
      PTLOCK(linktab_lock);
      linktab[src>>8].pkt_rejected++;
      PTUNLOCK(linktab_lock);
    }
#endif
  }    
}

// Periodically send RUT pkts (cf AIM 628 p15)
void send_rut_pkt(struct chroute *rt, u_char *pkt, int c) 
{
  struct chaos_header *cha = (struct chaos_header *)pkt;

  // Update source address, perhaps	  
  set_ch_srcaddr(cha, (rt->rt_myaddr == 0 ? mychaddr : rt->rt_myaddr));

  switch (rt->rt_link) {
#if CHAOS_ETHERP
  case LINK_ETHER:
    set_ch_destaddr(cha, 0);
    break;
#endif // CHAOS_ETHERP
  case LINK_UNIXSOCK:
    if ((rt->rt_dest & 0xff) != 0)
      set_ch_destaddr(cha, rt->rt_dest);  /* host */
    else
      set_ch_destaddr(cha, 0);	/* subnet (broadcast) - does chaosd handle this? */
    break;
  case LINK_CHUDP:
    if ((rt->rt_dest & 0xff) == 0) {
      // subnet route - send it to the bridge
      set_ch_destaddr(cha, rt->rt_braddr);
    } else
      // direct route
      set_ch_destaddr(cha, rt->rt_dest);
    break;
  }
#if COLLECT_STATS
  PTLOCK(linktab_lock);
  if (ch_destaddr(cha) == 0)
    linktab[rt->rt_dest >> 8].pkt_out++;
  else
    linktab[ch_destaddr(cha) >> 8].pkt_out++;
  PTUNLOCK(linktab_lock);
#endif

  forward_chaos_pkt_on_route(rt, pkt, c);
}

void *
route_cost_updater(void *v)
{
  while (1) {
    sleep(4);
    update_route_costs();
  }
}

void * rut_sender(void *v)
{
  int i, c;
  u_char pkt[CH_PK_MAXLEN];


  while (1) {
    /* Send to all subnets which are not through a bridge */
    for (i = 0; i < 256; i++)
      if ((rttbl_net[i].rt_type != RT_NOPATH) && (rttbl_net[i].rt_type != RT_BRIDGE)
	  && (rttbl_net[i].rt_link != LINK_INDIRECT)) {
	if (debug) fprintf(stderr,"Making RUT pkt for net %#o\n", i);
	if ((c = make_routing_table_pkt(i<<8, &pkt[0], sizeof(pkt))) > 0) {
	  send_rut_pkt(&rttbl_net[i], pkt, c);
	}
      }
    /* And to all individual hosts */
    for (i = 0; i < *rttbl_host_len; i++) {
      if (rttbl_host[i].rt_link != LINK_INDIRECT) {
	if (debug) fprintf(stderr,"Making RUT pkt for link %d bridge %#o dest %#o => %#o\n", i,
			     rttbl_host[i].rt_braddr, rttbl_host[i].rt_dest,
			     rttbl_host[i].rt_braddr == 0 ? rttbl_host[i].rt_dest : rttbl_host[i].rt_braddr);
	if ((c = make_routing_table_pkt(rttbl_host[i].rt_braddr == 0 ? rttbl_host[i].rt_dest : rttbl_host[i].rt_braddr,
					&pkt[0], sizeof(pkt))) > 0) {
	  send_rut_pkt(&rttbl_host[i], pkt, c);
	}
      }
    }

    // By AIM 628, do this every 15 s
    sleep(15);
  }
}

// Send a chaos packet from this host (e.g RUT, STATUS)
void send_chaos_pkt(u_char *pkt, int len) 
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_short dchad = ch_destaddr(cha);

  struct chroute *rt = find_in_routing_table(dchad, 0);

  if (rt == NULL) {
    if (debug) fprintf(stderr,"Can't find route to send pkt to %#o\n", dchad);
    return;
  }

  // Update source address, perhaps	  
  set_ch_srcaddr(cha, (rt->rt_myaddr == 0 ? mychaddr : rt->rt_myaddr));

  if (verbose) fprintf(stderr,"Sending pkt (%s) from me (%#o) to %#o (%s)\n",
		       ch_opcode_name(ch_opcode(cha)),
		       ch_srcaddr(cha),
		       ch_destaddr(cha),
		       rt_linkname(rt->rt_link));
#if COLLECT_STATS
  PTLOCK(linktab_lock);
  linktab[rt->rt_dest>>8].pkt_out++;
  PTUNLOCK(linktab_lock);
#endif

    forward_chaos_pkt_on_route(rt, pkt, len);
}


void * unix_input(void *v)
{
  /* Unix -> others thread */
  u_char data[CH_PK_MAXLEN];
  int len, blen = sizeof(data);
  u_char *pkt = data;

#if COLLECT_STATS
  u_char us_subnet = 0;		/* unix socket subnet */
  int i;
  for (i = 0; i < *rttbl_host_len; i++) {
    if (rttbl_host[i].rt_link == LINK_UNIXSOCK) {
      us_subnet = rttbl_host[i].rt_dest >> 8;
      break;
    }
  }
#endif

  while (1) {
    memset(pkt, 0, blen);
    if (unixsock < 0 || (len = u_read_chaos(unixsock, pkt, blen)) < 0) {
      if (unixsock > 0)
	close(unixsock);
      unixsock = -1;		// avoid using it until it's reopened
      if (verbose) fprintf(stderr,"Error reading Unix socket - please check if chaosd is running\n");
      sleep(5);			/* wait a bit to let chaosd restart */
      unixsock = u_connect_to_server();
    } else {
      if (debug) fprintf(stderr,"unix input %d bytes\n", len);

      ntohs_buf((u_short *)pkt, (u_short *)pkt, len);

#if COLLECT_STATS
      struct chaos_header *ch = (struct chaos_header *)pkt;
      if (len == ch_nbytes(ch)+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE) {
	struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
	// check for bogus/ignorable trailer or checksum.
	// Symbolics known to send trailer checksum -1
	if ((tr->ch_hw_destaddr != 0 && tr->ch_hw_srcaddr != 0 && tr->ch_hw_checksum != 0)
	    && tr->ch_hw_checksum != 0xffff) {
	  u_short schad = ch_srcaddr(ch);
	  u_int cks = ch_checksum(pkt, len);
	  if (cks != 0) {
	    // See if it is a weird case, usim byte swapping bug?
	    tr->ch_hw_checksum = ntohs(tr->ch_hw_checksum);
	    if (ch_checksum(pkt, len) != 0) {
	      // Still bad
	      if (verbose || debug) {
		fprintf(stderr,"[Bad checksum %#x from %#o (Unix)]\n", cks, schad);
		fprintf(stderr,"HW trailer\n dest %#o, src %#o, cks %#x\n",
			tr->ch_hw_destaddr, tr->ch_hw_srcaddr, tr->ch_hw_checksum);
		ch_dumpkt(pkt, len);
	      }
	      // Use link source net, can't really trust data
	      PTLOCK(linktab_lock);
	      linktab[us_subnet].pkt_crcerr++;
	      PTUNLOCK(linktab_lock);
	      continue;
	    } else {
	      // weird case, usim byte swapping bug?
	      if (debug) fprintf(stderr,"[Checksum from %#o (Unix) was fixed by swapping]\n", schad);
	      PTLOCK(linktab_lock);
	      // Count it, but accept it.
	      linktab[us_subnet].pkt_crcerr_post++;
	      PTUNLOCK(linktab_lock);
	    }
	  }
	} else if (debug)
	  fprintf(stderr,"Received zero HW trailer (%#o, %#o, %#x) from Unix\n",
		  tr->ch_hw_destaddr, tr->ch_hw_srcaddr, tr->ch_hw_checksum);
      } else if (debug) {
	fprintf(stderr,"Unix: Received no HW trailer (len %d != %lu = %d+%lu+%lu)\n",
		len, ch_nbytes(ch)+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE,
		ch_nbytes(ch), CHAOS_HEADERSIZE, CHAOS_HW_TRAILERSIZE);
	ch_dumpkt(pkt, len);
      }
#endif
      // check where it's coming from, prefer trailer info
      u_short srcaddr;
      if (len > (ch_nbytes(ch) + CHAOS_HEADERSIZE)) {
	struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
	srcaddr = tr->ch_hw_srcaddr;
      } else
	srcaddr = ch_srcaddr(ch);
      if (srcaddr == mychaddr) {
	// Unix socket server/chaosd echoes everything to everyone
	if (debug) fprintf(stderr,"unix_input: dropping echoed pkt from self\n");
	continue;
      }
      struct chroute *srcrt = find_in_routing_table(srcaddr, 0);
      forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			srcrt != NULL ? srcrt->rt_type : RT_DIRECT,
			srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
			pkt, len, LINK_UNIXSOCK);
    }
  }
}


void * chudp_input(void *v)
{
  /* CHUDP -> others thread */
  u_int len;
  u_char data[CH_PK_MAXLEN+CHUDP_HEADERSIZE];
  struct chaos_header *ch = (struct chaos_header *)&data[CHUDP_HEADERSIZE];

  while (1) {
    bzero(data,sizeof(data));
    len = chudp_receive(udpsock, data, sizeof(data));
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
      struct chroute *srcrt = find_in_routing_table(srcaddr, 0);
      forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			srcrt != NULL ? srcrt->rt_type : RT_BRIDGE,
			srcrt != NULL ? srcrt->rt_cost : RTCOST_ASYNCH,
			(u_char *)ch, len, LINK_CHUDP);
    } else
      if (len > 0 && verbose) fprintf(stderr,"chudp: Short packet %d bytes\n", len);
  }
}

#if CHAOS_ETHERP
void print_arp_table()
{
  int i;
  if (*charp_len > 0) {
    printf("Chaos ARP table:\n"
	   "Chaos\tEther\t\t\tAge (s)\n");
    for (i = 0; i < *charp_len; i++)
      printf("%#o\t\%02X:%02X:%02X:%02X:%02X:%02X\t%lu\n",
	     charp_list[i].charp_chaddr,
	     charp_list[i].charp_eaddr[0],
	     charp_list[i].charp_eaddr[1],
	     charp_list[i].charp_eaddr[2],
	     charp_list[i].charp_eaddr[3],
	     charp_list[i].charp_eaddr[4],
	     charp_list[i].charp_eaddr[5],
	     (time(NULL) - charp_list[i].charp_age));
  }
}

void handle_arp_input(u_char *data, int dlen)
{
  if (debug) fprintf(stderr,"Handle ARP\n");
  /* Chaos over Ethernet */
  struct arphdr *arp = (struct arphdr *)data;
  u_short schad = ntohs((data[sizeof(struct arphdr)+arp->ar_hln]<<8) |
			data[sizeof(struct arphdr)+arp->ar_hln+1]);
  u_char *sead = &data[sizeof(struct arphdr)];
  u_short dchad =  ntohs((data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln]<<8) |
			 data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln+1]);
  if (debug) printf("ARP rcv: Dchad: %o %o => %o\n",
		    data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln+1]<<8,
		    data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln],
		    dchad);

  /* See if we proxy for this one */
  if (arp->ar_op == htons(ARPOP_REQUEST)) {
    if (dchad == mychaddr) {
      if (verbose) printf("ARP: Sending reply for %#o (me) to %#o\n", dchad, schad);
      send_chaos_arp_reply(arpfd, schad, sead, dchad); /* Yep. */
    } else {
      if (debug) printf("ARP: Looking up %#o...\n",dchad);
      struct chroute *found = find_in_routing_table(dchad, 0);
      if (found != NULL &&
	  found->rt_link != LINK_ETHER && found->rt_type != RT_BRIDGE) {
	/* Only proxy for non-ether links, and not for indirect (bridge) routes */
	if (verbose) {
	  fprintf(stderr,"ARP: Sending proxy ARP reply for %#o to %#o\n", dchad, schad);
	  // fprintf(stderr," route link %s, type %s\n", rt_linkname(found->rt_link), rt_typename(found->rt_type));
	}
	send_chaos_arp_reply(arpfd, schad, sead, dchad); /* Yep. */
	return;
      }
    }
  }
  /* Now see if we should add this to our Chaos ARP list */
  PTLOCK(charp_lock);
  int i, found = 0;
  for (i = 0; i < *charp_len; i++)
    if (charp_list[i].charp_chaddr == schad) {
      found = 1;
      charp_list[i].charp_age = time(NULL);  // update
      if (memcmp(&charp_list[i].charp_eaddr, sead, ETHER_ADDR_LEN) != 0)
	memcpy(&charp_list[i].charp_eaddr, sead, ETHER_ADDR_LEN);
      else
	if (verbose) {
	  fprintf(stderr,"ARP: Updated MAC addr for %#o\n", schad);
	  print_arp_table();
	}
      break;
    }
  /* It's not in the list already, is there room? */
  if (!found && *charp_len < CHARP_MAX) {
    if (verbose) printf("Adding Chaos ARP for %#o\n", schad);
    charp_list[*charp_len].charp_chaddr = schad;
    charp_list[*charp_len].charp_age = time(NULL);
    memcpy(&charp_list[(*charp_len)++].charp_eaddr, sead, ETHER_ADDR_LEN);
    if (verbose) print_arp_table();
  }
  PTUNLOCK(charp_lock);
}

void arp_input(int arpfd, u_char *data, int dlen) {
  int len;
  struct arphdr *arp = (struct arphdr *)data;

  if ((len = get_packet(arpfd, data, dlen)) < 0) {
    if (debug) perror("Couldn't read ARP");
    return;
  }
  if (arp->ar_hrd == htons(ARPHRD_ETHER) &&
      (arp->ar_pro == htons(ETHERTYPE_CHAOS))) {
    if (debug) fprintf(stderr,"Read ARP len %d\n", len);
    handle_arp_input(data, len);
  } else if (0 && debug) {		/* should not happen for BPF case, which filters this */
    fprintf(stderr,"Read from ARP but wrong HW %d or prot %#x\n",
	    ntohs(arp->ar_hrd), ntohs(arp->ar_pro));
  }
}


void * ether_input(void *v)
{
  /* Ether -> others thread */
  fd_set rfd;
  int len, sval, maxfd = (chfd > arpfd ? chfd : arpfd)+1;
  u_char data[CH_PK_MAXLEN];
  struct chaos_header *cha = (struct chaos_header *)&data;

  while (1) {
    FD_ZERO(&rfd);
    if (chfd > 0)
      FD_SET(chfd,&rfd);
    if (arpfd > 0)
      FD_SET(arpfd,&rfd);

    bzero(data,sizeof(data));

    if ((sval = select(maxfd, &rfd, NULL, NULL, NULL)) < 0)
      perror("select");
    else if (sval > 0) {
      if (arpfd > 0 && FD_ISSET(arpfd, &rfd)) {
	/* Read an ARP packet */
	if (0 && verbose) fprintf(stderr,"ARP available\n");
	arp_input(arpfd, (u_char *)&data, sizeof(data));
      }	/* end of ARP case */
      if (chfd > 0 && FD_ISSET(chfd, &rfd)) {
	// Read a Chaos packet, peeking ether address for ARP optimization
	if ((len = get_packet(chfd, (u_char *)&data, sizeof(data))) < 0)
	  return NULL;
	if (debug) fprintf(stderr,"ether RCV %d bytes\n", len);
	if (len == 0)
	  continue;
	ntohs_buf((u_short *)cha, (u_short *)cha, len);
	if (debug) ch_dumpkt((u_char *)&data, len);
#if 1 // At least LMI Lambda does not include (a valid) chaosnet trailer
      // (not even constructs one) but we read more than the packet size shd be
	if (len >= ch_nbytes(cha)+CHAOS_HEADERSIZE)
	  len = ch_nbytes(cha)+CHAOS_HEADERSIZE;
#else // what we would have done...
#if COLLECT_STATS
	if (len >= ch_nbytes(cha)+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE) {
	  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
	  // check for bogus/ignorable trailer or checksum.
	  // Symbolics known to send trailer checksum -1
	  if (// (tr->ch_hw_destaddr != 0 && tr->ch_hw_srcaddr != 0 && tr->ch_hw_checksum != 0)
	      //&&
	      (tr->ch_hw_checksum != 0xffff)) {
	    u_short cks = ch_checksum(data, len);
	    if (cks != 0) {
	      u_short schad = ch_srcaddr(cha);
	      if (verbose) {
		fprintf(stderr,"[Bad checksum %#x from %#o (Ether)]\n", cks, schad);
		fprintf(stderr,"HW trailer\n dest %#o, src %#o, cks %#x\n",
			tr->ch_hw_destaddr, tr->ch_hw_srcaddr, tr->ch_hw_checksum);
		ch_dumpkt((u_char *)&data, len);
	      }
	      // #### Use link source net, can't really trust data
#if 0
	      PTLOCK(linktab_lock);
	      linktab[schad>>8].pkt_crcerr++;
	      PTUNLOCK(linktab_lock);
#endif
	      continue;
	    }
	  } else if (debug)
	    fprintf(stderr,"Received zero HW trailer (%#o, %#o, %#x) from Ether\n",
		    tr->ch_hw_destaddr, tr->ch_hw_srcaddr, tr->ch_hw_checksum);
	}
#endif // COLLECT_STAS
#endif // 0
	// check where it's coming from
	u_short srcaddr;
#if 0 // #### see above
	if (len > (ch_nbytes(cha) + CHAOS_HEADERSIZE)) {
	  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
	  srcaddr = tr->ch_hw_srcaddr;
	} else
#endif
	  srcaddr = ch_srcaddr(cha);
	struct chroute *srcrt = find_in_routing_table(srcaddr, 0);
	forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			  srcrt != NULL ? srcrt->rt_type : RT_DIRECT,
			  srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
			  (u_char *)&data, len, LINK_ETHER);  /* forward to appropriate links */
      }
    }
  }
}
#endif // CHAOS_ETHERP

// **** Main program

int parse_route_config() 
{
  // route host|subnet x bridge y [cost c type t]
  u_short addr, sval;
  struct chroute *rt;
  int subnetp = 0;

  char *tok = strtok(NULL," \t\r\n");
  if (strcasecmp(tok,"host") == 0) 
    subnetp = 0;
  else if (strcasecmp(tok, "subnet") == 0) 
    subnetp = 1;
  else {
    fprintf(stderr,"bad route keyword %s\n", tok);
    return -1;
  }
  tok = strtok(NULL, " \t\r\n");
  if (tok == NULL) {
    fprintf(stderr,"bad route config: no addr\n");
    return -1;
  }
  if (sscanf(tok,"%ho",&addr) != 1) {
    fprintf(stderr,"bad octal value %s\n", tok);
    return -1;
  }
  if (subnetp) {
    rt = &rttbl_net[addr];
    rt->rt_dest = addr<<8;
  } else {
    rt = &rttbl_host[(*rttbl_host_len)++];
    // #### should handle errors better and discard allocated rttbl_host entry
    rt->rt_dest = addr;
  }
  tok = strtok(NULL, " \t\r\n");
  if (tok == NULL) {
    fprintf(stderr,"bad route config (%#o): no bridge\n", addr);
    return -1;
  }
  if (strcasecmp(tok,"bridge") != 0) {
    fprintf(stderr,"bad route config (%#o): no bridge\n", addr);
    return -1;
  }
  tok = strtok(NULL, " \t\r\n");
  if (tok == NULL) {
    fprintf(stderr,"bad route config (%#o): no bridge addr\n", addr);
    return -1;
  }
  if (sscanf(tok,"%ho",&sval) != 1) {
    fprintf(stderr,"bad octal bridge value %s\n", tok);
    return -1;
  }
  rt->rt_braddr = sval;
  rt->rt_type = RT_FIXED;	/* manually configured, probably fixed? */
  rt->rt_link = LINK_INDIRECT;	/* i.e. look up route to bridge */

  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strcasecmp(tok, "myaddr") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (sscanf(tok,"%ho",&sval) != 1) {
	fprintf(stderr,"bad octal myaddr value %s\n", tok);
	return -1;
      }
      rt->rt_myaddr = sval;
    } else if (strcasecmp(tok, "type") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (strcasecmp(tok, "direct") == 0) {
	rt->rt_type = RT_DIRECT;
	if (rt->rt_cost == 0) rt->rt_cost = RTCOST_DIRECT;
      }
      else if (strcasecmp(tok,"fixed") == 0) {
	rt->rt_type = RT_FIXED;
	if (rt->rt_cost == 0) rt->rt_cost = RTCOST_ETHER;
      }
      else if (strcasecmp(tok,"bridge") == 0) {
	rt->rt_type = RT_BRIDGE;
	rt->rt_cost_updated = time(NULL);
	if (rt->rt_cost == 0) rt->rt_cost = RTCOST_ETHER;
      }
      else {
	fprintf(stderr,"bad link type %s for link to %#o\n", tok, addr);
	return -1;
      }
    } else if (strcasecmp(tok, "cost") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (strcasecmp(tok, "direct") == 0)
	rt->rt_cost = RTCOST_DIRECT;
      else if (strcasecmp(tok, "ether") == 0)
	rt->rt_cost = RTCOST_ETHER;
      else if (strcasecmp(tok, "asynch") == 0)
	rt->rt_cost = RTCOST_ASYNCH;
      else {
	fprintf(stderr,"bad cost %s for link to %#o\n", tok, addr);
	return -1;
      }
    } else {
      fprintf(stderr,"bad keyword %s for link to %#o\n", tok, addr);
      return -1;
    }
  }
  if (rt->rt_cost == 0) rt->rt_cost = RTCOST_ETHER;
  return 0;
}

int parse_link_config()
{
  // link ether|unix|chudp ... host|subnet y [type t cost c]
  u_short addr, subnetp, sval;
  struct addrinfo *he, hints;
  struct sockaddr_in *s;
  struct chroute rte;
  struct chroute *rt = &rte;
  char *tok = strtok(NULL," \t\r\n");

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET;

  memset(rt, 0, sizeof(rte));
  if (tok == NULL) {
    fprintf(stderr,"bad link config: no parameters\n");
    return -1;
  }
  if (strcasecmp(tok, "ether") == 0) {
    do_ether = 1;
    // one day, parse interface name
    rt->rt_link = LINK_ETHER;
    rt->rt_type = RT_DIRECT;
    rt->rt_cost = RTCOST_DIRECT;
  } else if (strcasecmp(tok, "unix") == 0) {
    do_unix = 1;
    rt->rt_link = LINK_UNIXSOCK;
    rt->rt_type = RT_DIRECT;
    rt->rt_cost = RTCOST_DIRECT;
  } else if (strcasecmp(tok, "chudp") == 0) {
    int res;

    do_udp = 1;
    rt->rt_link = LINK_CHUDP;
    rt->rt_type = RT_FIXED;
    rt->rt_cost = RTCOST_ASYNCH;
    rt->rt_cost_updated = time(NULL);

    tok = strtok(NULL," \t\r\n");
    u_short port;
    char *sep = index(tok, ':');
    if (sep == NULL)
      port = CHUDP_PORT;
    else
      port = atoi((char *)sep+1);
    if (sep) *sep = '\0';
    if ((res = getaddrinfo(tok, NULL, &hints, &he)) == 0) {
      // chudpdest[*chudpdest_len].chu_addr = (subnet_p ? rt->rt_braddr : addr);
      s = (struct sockaddr_in *)he->ai_addr;
      chudpdest[*chudpdest_len].chu_sin.sin_family = AF_INET;
      chudpdest[*chudpdest_len].chu_sin.sin_port = htons(port);
      memcpy(&chudpdest[*chudpdest_len].chu_sin.sin_addr.s_addr, (u_char *)&s->sin_addr, 4);
      memcpy(&chudpdest[*chudpdest_len].chu_name, tok, CHUDPDEST_NAME_LEN);
      (*chudpdest_len)++;
      if (sep) *sep = ':';
    } else {
      if (sep) *sep = ':';
      fprintf(stderr,"bad chudp arg %s: %s (%d)\n", tok,
	      gai_strerror(res), res);
      return -1;
    }
  }
  // host|subnet y type t cost c
  tok = strtok(NULL," \t\r\n");
  if (strcasecmp(tok,"host") == 0) 
    subnetp = 0;
  else if (strcasecmp(tok, "subnet") == 0) 
    subnetp = 1;
  else {
    fprintf(stderr,"bad link keyword %s\n", tok);
    return -1;
  }
  tok = strtok(NULL, " \t\r\n");
  if (tok == NULL) {
    fprintf(stderr,"bad link config: no addr\n");
    return -1;
  }
  if (sscanf(tok,"%ho",&addr) != 1) {
    fprintf(stderr,"bad octal value %s\n", tok);
    return -1;
  }
  if (subnetp)
    rt->rt_dest = addr<<8;
  else
    rt->rt_dest = addr;
  if (rt->rt_link == LINK_CHUDP) {
    chudpdest[*chudpdest_len - 1].chu_addr = addr;
    if (subnetp) {
      fprintf(stderr,"Error: CHUDP links must be to hosts, not subnets.\n"
	      "Change\n"
	      " link chudp %s:%d subnet %o\n"
	      "to\n"
	      " link chudp %s:%d host NN\n"
	      " route subnet %o bridge NN\n"
	      "where NN is the actual chudp host\n",
	      chudpdest[*chudpdest_len -1].chu_name, ntohs(chudpdest[*chudpdest_len -1].chu_sin.sin_port),
	      addr,
	      chudpdest[*chudpdest_len -1].chu_name, ntohs(chudpdest[*chudpdest_len -1].chu_sin.sin_port),
	      addr);
      return -1;
    }
  }

  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strcasecmp(tok, "myaddr") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (sscanf(tok,"%ho",&sval) != 1) {
	fprintf(stderr,"bad octal myaddr value %s\n", tok);
	return -1;
      }
      rt->rt_myaddr = sval;
    } else if (strcasecmp(tok, "type") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (strcasecmp(tok, "direct") == 0) {
	rt->rt_type = RT_DIRECT;
	if (rt->rt_cost == 0) rt->rt_cost = RTCOST_DIRECT;
      }
      else if (strcasecmp(tok,"fixed") == 0) {
	rt->rt_type = RT_FIXED;
	if (rt->rt_cost == 0) rt->rt_cost = RTCOST_ETHER;
      }
      else if (strcasecmp(tok,"bridge") == 0) {
	rt->rt_type = RT_BRIDGE;
	rt->rt_cost_updated = time(NULL);
	if (rt->rt_cost == 0) rt->rt_cost = RTCOST_ETHER;
      }
      else {
	fprintf(stderr,"bad link type %s for link to %#o\n", tok, addr);
	return -1;
      }
    } else if (strcasecmp(tok, "cost") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (strcasecmp(tok, "direct") == 0)
	rt->rt_cost = RTCOST_DIRECT;
      else if (strcasecmp(tok, "ether") == 0)
	rt->rt_cost = RTCOST_ETHER;
      else if (strcasecmp(tok, "asynch") == 0)
	rt->rt_cost = RTCOST_ASYNCH;
      else {
	fprintf(stderr,"bad cost %s for link to %#o\n", tok, addr);
	return -1;
      }
    } else {
      fprintf(stderr,"bad keyword %s for link to %#o\n", tok, addr);
      return -1;
    }
  }
  struct chroute *rrt;
  if (subnetp)
    rrt = &rttbl_net[addr];
  else
    rrt = &rttbl_host[(*rttbl_host_len)++];
  memcpy(rrt, rt, sizeof(struct chroute));
  return 0;
}

int parse_config_line(char *line)
{
  char *tok = NULL;
  tok = strtok(line," \t\r\n");
  if (tok == NULL)
    return 0;
  if (tok[0] == '#' || tok[0] == ';')
    return 0;			// Comment
  if (strcasecmp(tok, "chaddr") == 0) {
    tok = strtok(NULL," \t\r\n");
    if (tok != NULL) {
      if (sscanf(tok,"%ho",&mychaddr) != 1) {
	mychaddr = 0;
	fprintf(stderr,"chaddr: bad octal argument %s\n",tok);
	return -1;
      } else if (verbose)
	printf("Using default chaos address %#o\n", mychaddr);
    }
    return 0;
  }
  else if (strcasecmp(tok, "myname") == 0) {
    tok = strtok(NULL," \t\r\n");
    if (tok != NULL) {
      if (strlen(tok) < sizeof(myname)) {
	strncpy(myname, tok, sizeof(myname));
      } else {
	fprintf(stderr,"myname too long: max %lu bytes allowed.\n", sizeof(myname));
	return -1;
      }
    }
    return 0;
  }
  else if (strcasecmp(tok, "chudp") == 0) {
    tok = strtok(NULL, " \t\r\n");
    udpport = atoi(tok);
    do_udp = 1;
    // #### check for "dynamic" arg, for dynamic updates from new sources
    tok = strtok(NULL, " \t\r\n");
    if (tok != NULL) {
      if (strncmp(tok,"dynamic",sizeof("dynamic")) == 0)
	chudp_dynamic = 1;
      else if (strncmp(tok,"static",sizeof("static")) == 0)
	chudp_dynamic = 0;
      else {
	fprintf(stderr,"bad chudp keyword %s\n", tok);
	return -1;
      }
    }
    if (verbose) printf("Using CHUDP port %d (%s)\n",udpport, chudp_dynamic ? "dynamic" : "static");
    return 0;
  }
  else if (strcasecmp(tok, "ether") == 0) {
    tok = strtok(NULL," \t\r\n");
    strncpy(ifname,tok,sizeof(ifname));
    get_my_ea();
    do_ether = 1;
    if (verbose) {
      int i;
      printf("Using Ethernet interface %s, ether address ", ifname);
      for (i = 0; i < ETHER_ADDR_LEN-1; i++)
	printf("%02X:",myea[i]);
      printf("%02X\n",myea[i]);
    }
    return 0;
  }
  else if (strcasecmp(tok, "route") == 0) {
    return parse_route_config();
  }
  else if (strcasecmp(tok, "link") == 0) {
    return parse_link_config();
  }
  else {
    fprintf(stderr,"config keyword %s unknown\n", tok);
    return -1;
  }
}

void parse_config(char *cfile)
{
  // Obtain configuration
  FILE *config = fopen(cfile,"r");
  if (!config) {
    fprintf(stderr,"Can't open config file '%s'\n",cfile);
    perror("fopen");
    exit(1);
  } else {
    while (!feof(config)){
      char buf[512];
      if (fgets(buf,sizeof(buf),config) != NULL) {
	if (parse_config_line(buf) < 0) {
	  fprintf(stderr,"Error parsing config file %s\n", cfile);
	  exit(1);
	}
      }
    }
  }
}

void
usage(char *pname)
{
  fprintf(stderr,"Usage: %s [-c configfile | -d | -v ]\n Default configfile 'cbridge.conf'\n", pname);
  exit(1);
}

int
main(int argc, char *argv[])
{
  signed char c;		/* gaah. */
  char cfile[256] = "cbridge.conf";
  extern char *optarg;

  // Init shared mem data structures
  init_rttbl();
  init_chudpdest();
#if CHAOS_ETHERP
  init_arp_table();
#endif // CHAOS_ETHERP
#if COLLECT_STATS
  init_linktab();
#endif
  if (gethostname(myname, sizeof(myname)) < 0) {
    perror("gethostname");
    strcpy(myname,"UNKNOWN");
  } else {
    char *c = index(myname,'.');  /* only use unqualified part */
    if (c)
      *c = '\0';
    *myname = toupper(*myname);	/* and prettify lowercase unix-style name */
  }

  // parse args
  while ((c = getopt(argc, argv, "c:vd")) != -1) {
    switch (c) {
    case 'd':
      fprintf(stderr,"Debug on\n");
      debug++;
      break;
    case 'v':
      fprintf(stderr,"Verbose on\n");
      verbose++;
      break;
    case 'c':
      if (verbose) fprintf(stderr,"Config file %s\n", optarg);
      strncpy(cfile, optarg, sizeof(cfile));
      break;
    default:
      usage(argv[0]);
    }
  }

  parse_config(cfile);

  // Print config
  if (verbose) {
    printf("Using Chaos host name %s\n", myname);

    print_routing_table();
    if (*chudpdest_len > 0)
      print_chudp_config();

#if CHAOS_ETHERP
    print_arp_table();
#endif // CHAOS_ETHERP
  }

  // Check config, validate settings
  if (mychaddr == 0) {
    fprintf(stderr,"Configuration error: must set chaddr (my Chaos address)\n");
    exit(1);
  }

  // Open links that have been configured
  if (do_unix) {
    if ((unixsock = u_connect_to_server()) < 0)
      //exit(1);
      fprintf(stderr,"Warning: couldn't open unix socket - check if chaosd is running?\n");
  }
  if (do_udp) {
    if ((udpsock = chudp_connect(udpport)) < 0)
      exit(1);
  }
  if (do_ether) {
#if CHAOS_ETHERP
    if ((arpfd = get_packet_socket(ETHERTYPE_ARP, ifname)) < 0)
      exit(1);
    if ((chfd = get_packet_socket(ETHERTYPE_CHAOS, ifname)) < 0)
      exit(1);
#else
    fprintf(stderr,"Your config asks for Ether, but its support not compiled\n");
#endif // CHAOS_ETHERP
  }

  // Now start the different threads
  pthread_t threads[5];
  int ti = 0;

  if (do_unix || unixsock > 0) {
    if (verbose) fprintf(stderr, "Starting thread for UNIX socket\n");
    if (pthread_create(&threads[ti++], NULL, &unix_input, NULL) < 0) {
      perror("pthread_create(unix_input)");
      exit(1);
    }
  }
  if (udpsock > 0) {
    if (verbose) fprintf(stderr, "Starting thread for UDP socket\n");
    if (pthread_create(&threads[ti++], NULL, &chudp_input, NULL) < 0) {
      perror("pthread_create(chudp_input)");
      exit(1);
    }
  }
#if CHAOS_ETHERP
  if ((chfd > 0) || (arpfd > 0)) {
    if (verbose) fprintf(stderr,"Starting thread for Ethernet\n");
    if (pthread_create(&threads[ti++], NULL, &ether_input, NULL) < 0) {
      perror("pthread_create(ether_input)");
      exit(1);
    }
  }
#endif // CHAOS_ETHERP

  if (verbose) fprintf(stderr,"Starting RUT sender thread\n");
  if (pthread_create(&threads[ti++], NULL, &rut_sender, NULL) < 0) {
    perror("pthread_create(rut_sender)");
    exit(1);
  }

  if (verbose) fprintf(stderr,"Starting route cost updating thread\n");
  if (pthread_create(&threads[ti++], NULL, &route_cost_updater, NULL) < 0) {
    perror("pthread_create(route_cost_updater)");
    exit(1);
  }
  if (do_udp) {
    if (verbose) fprintf(stderr,"Starting hostname re-parsing thread\n");
    if (pthread_create(&threads[ti++], NULL, &reparse_chudp_names_thread, NULL) < 0) {
      perror("pthread_create(route_cost_updater)");
      exit(1);
    }
  }

  while(1) {
    sleep(15);			/* ho hum. */
#if COLLECT_STATS
    if (verbose) print_link_stats();
#endif
  }
  exit(0);
}
