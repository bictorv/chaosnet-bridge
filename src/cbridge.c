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

/* Based on echaos (by Björn), and chudprt (by Björn, partly based on
   one of Brad's chaosd clients). Some code from LambdaDelta (the LMI
   Lambda emulator by Daniel Seagraves), and some from klh10 (the
   PDP10 emulator by Ken Harrenstien). */

/* Bridge program for various Chaosnet implementations.
   Support many link-layer implementations:
   - Chaos-over-Ethernet
   - CHUDP (Chaos-over-UDP, used by klh10/its)
   - Chaos-over-TLS (using two bytes of record length)
   - chaosd (Unix socket protocol, used by the usim CADR emulator)
   - Chaos-over-IP (IP address mapping, used by pdp10x)
     see also "Cisco's implementation of Chaosnet", same type of mapping
     https://docstore.mik.ua/univercd/cc/td/doc/product/software/ssr83/rpc_r/48381.htm

   Also implements the transport layer (Network Control Program), see ncp.c and NCP.md
*/

/* Read MIT AIM 628, in particular secions 3.6 and 3.7. */

// TODO

// #### clean up routing table issues
// invent host-route protocol (RUTH? RBG?)

// autoconf please

// logging:
// - lock to avoid mixed output from different threads
// -- need two output fns, one assuming a lock is held, one with built-in locking.
// -- or recursive mutex.
// - improve granularity, e.g. to only log "major" events
// -- define "levels" as in LambdaDelta (higher for more details, 0 for no output, 1 for "major stuff")
// -- levels: emergency, major, minor, info, debug
// - turn on/off module-specific tracing (similar to LambdaDelta again)
// - consider including thread id, include time
// "tls trace 5" or "routing trace 1" or "arp trace 2" etc?

// CHUDP version 2, using network order (big-endian). Also fix klh10/CH11 for this.
// Can this be modular enough to keep within the chudp "module"? Needs per-link config.

// validate conf (subnets vs bridges etc)
// - multiple links/routes to same chaddr
// - make sure thois host has a subnet-specific chaos addr on all defined links
// detect unexpected traffic
// - e.g. source addr 3150 from link with addr 3160 (which has another link)
// - or traffic from a defined subnet arriving on a different link

// add parameters for various constants (arp age limit, reparsing interval...)

// minimize copying
// - now net order is swapped to host order when receiving from Ether and Unix,
//   and then swapped back before forwarding,
//   while CHUDP is not swapped but needs copying anyway (because of chudp header)
// - better to not swap Ether/Unix, of course, but need to rewrite chaos.h
//   and make it endian dependent - ugh (but all processors are Intel these days... ;-o)
// - or separate header from data; swap header like now, but keep data intact
// notify if more routes are known than fit in a RUT pkt (but it's 122, come on...)

#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <sys/wait.h>



#include "cbridge.h"
#include "chudp.h"		/* chudp pkt format etc */
#include "firewall.h"

int verbose, debug, stats, tls_debug = 0;

#if CHAOS_ETHERP
void print_arp_table();
#endif


// Route table, indexed by subnet
struct chroute rttbl_net[256];
// and for individual hosts, simple array, where rt_braddr is the dest
struct chroute rttbl_host[RTTBL_HOST_MAX];
int rttbl_host_len = 0;

// array indexed first by net, then by host. Second level dynamically allocated.
struct hostat *hosttab[256];
pthread_mutex_t hosttab_lock = PTHREAD_MUTEX_INITIALIZER;

// simple array indexed by subnet, updated for send/receives on routes with direct link
struct linkstat linktab[256];

pthread_mutex_t rttbl_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t linktab_lock = PTHREAD_MUTEX_INITIALIZER;

// @@@@ move configuration of this, and then move declaration
struct chudest chudpdest[CHUDPDEST_MAX];
int chudpdest_len = 0;

// Private, non-routed subnets
static u_short private_subnet[256];
static u_short number_of_private_subnets = 0;
// Hosts file for private subnets
static char *private_hosts_file = NULL;

#if CHAOS_TLS

char tls_ca_file[PATH_MAX] = "ca-chain.cert.pem";  /* trust chain */
char tls_key_file[PATH_MAX];	/* private key */
char tls_cert_file[PATH_MAX];	/* certificate */
char tls_crl_file[PATH_MAX];	/* certificate revocation list */
// allow clients from different subnets to connect, here are my different addrs
u_short tls_myaddrs[TLSDEST_MAX];		/* my chaos addresses on TLS server links */
int tls_n_myaddrs = 0;
int tls_server_port = 42042;

int do_tls = 0, do_tls_server = 0;
int do_tls_ipv6 = 0;

pthread_mutex_t tlsdest_lock = PTHREAD_MUTEX_INITIALIZER;	/* for locking tlsdest */
struct tls_dest tlsdest[TLSDEST_MAX];	/* table of tls_dest entries */
int tlsdest_len = 0;

int parse_tls_config_line(void);
#endif // CHAOS_TLS

int parse_chudp_config_line(void);
int parse_usockets_config(void);

#if CHAOS_IP
int do_chip = 0;
int parse_chip_config_line(void);
void print_config_chip(void);
#endif

#if CHAOS_DNS
extern int do_dns_forwarding;
void init_chaos_dns(int do_forwarding);
int parse_dns_config_line(void);
void print_config_dns(void);
void *dns_forwarder_thread(void *v);
#endif

// NCP
extern int ncp_enabled;
void *ncp_user_server(void *v);
int parse_ncp_config_line(void);
void packet_to_conn_handler(u_char *pkt, int len);
void print_ncp_stats(void);
int parse_private_hosts_file(char *f);
void print_private_hosts_config(void);

time_t boottime;

// Config stuff @@@@ some to be moved to respective module
char myname[32]; /* my chaosnet host name (look it up!). Note size limit by STATUS prot */
#define NCHADDR 8
int nchaddr = 0;
u_short mychaddr[NCHADDR];	/* My Chaos address (only for ARP) */
int chudp_port = 42042;		// default UDP port
int chudp_dynamic = 0; // dynamically add CHUDP entries for new receptions
int do_unix = 0, do_udp = 0, do_udp6 = 0, do_ether = 0;

// for each implementation
void forward_on_chudp(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen);
void forward_on_usocket(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen);
#if CHAOS_ETHERP
void forward_on_ether(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen);
#endif
#if CHAOS_TLS
void forward_on_tls(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen);
#endif
#if CHAOS_IP
void forward_on_ip(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen);
#endif

// contacts
int handle_rfc(struct chaos_header *ch, u_char *data, int dlen);
int make_routing_table_pkt(u_short dest, u_char *pkt, int pklen);

// chudp
void init_chaos_udp(int v6, int v4);
void print_chudp_config(void);
void reparse_chudp_names(void);

#if CHAOS_ETHERP
// chether
void print_arp_table(void);
void print_config_ether(void);
int parse_ether_config_line(void);
int parse_ether_link_config(void);
int postparse_ether_link_config(struct chroute *rt);
#endif

#if CHAOS_TLS
// chtls
void init_chaos_tls();
void print_tlsdest_config(void);
#endif

#if CHAOS_IP
// chip
void reparse_chip_names();
void print_chipdest_config();
#endif

// usockets
void print_config_usockets(void);

// threads @@@@ document args?
void *unix_input(void *v);
void *chudp_input(void *v);
#if CHAOS_ETHERP
void *ether_input(void *v);
#endif
#if CHAOS_IP
void *chip_input(void *v);
#endif
#if CHAOS_TLS
void *tls_server(void *v);
void *tls_input(void *v);
void *tls_connector(void *arg);
#endif

int is_mychaddr(u_short addr) 
{
  int i;
  for (i = 0; i < nchaddr && i < NCHADDR; i++)
    if (mychaddr[i] == addr)
      return 1;
  return 0;
}

int mychaddr_on_net(u_short addr)
{
  int i;
  for (i = 0; i < nchaddr && i < NCHADDR; i++)
    if ((mychaddr[i] & 0xff00) == (addr & 0xff00))
      return mychaddr[i];
  return 0;
}

u_short find_closest_addr(u_short haddrs[], int naddrs)
{
  // search haddrs for the address closest to one of mine
  // Simplest: just look for an addr on the same subnet as one of mine
  int i, a;
  if (naddrs <= 0) {
    fprintf(stderr,"find_closest_addr called with %d addresses to search\n", naddrs);
    abort();
  }
  if (naddrs == 1)
    // only one choice
    return haddrs[0];
  for (i = 0; i < naddrs; i++) {
    if ((a = mychaddr_on_net(haddrs[i])) != 0)
      return haddrs[i];
  }

  // then find a route and use the local end of that
  struct chroute *rt = find_in_routing_table(haddrs[0], 0, 0);
  if ((rt != NULL) && (rt->rt_myaddr > 0))
    return rt->rt_myaddr;

  // default
  return haddrs[0];
}
u_short find_my_closest_addr(u_short addr)
{
  // search mychaddrs for the address closest to the one given
  // Simplest: just look for an addr on the same subnet
  int a;
  if (nchaddr == 1)
    // only one choice
    return mychaddr[0];
  if ((a = mychaddr_on_net(addr)) != 0)
    return a;

  // then find a route and use the local end of that
  struct chroute *rt = find_in_routing_table(addr, 0, 0);
  if ((rt != NULL) && (rt->rt_myaddr > 0))
    return rt->rt_myaddr;

  // default
  return mychaddr[0];
}

void add_mychaddr(u_short addr)
{
  if (!is_mychaddr(addr)) {
    if (nchaddr < NCHADDR)
      mychaddr[nchaddr++] = addr;
    else
      fprintf(stderr,"out of local chaos addresses, please increase NCHADDR from %d\n", NCHADDR);
  }
}

int valid_chaos_host_address(u_short addr)
{
  // both subnet and host part must be non-zero
  return ((addr > 0xff) && ((addr & 0xff) != 0));
}

int is_private_subnet(u_short subnet)
{
  return private_subnet[subnet];
}

int valid_opcode(int opc)
{
  return !((opc == 0) || ((opc > CHOP_BRD) && (opc < CHOP_DAT)));
}

void print_link_stats() 
{
  int i;
  PTLOCKN(linktab_lock,"linktab_lock");
  printf("Link stats:\n"
	 "Subnet\t  In\t Out\t Abort\t Lost\t CRC\t Ram\t Bitc\t Rej\n");
  for (i = 0; i < 256; i++) {
    if (linktab[i].pkt_in != 0 || linktab[i].pkt_out != 0 || linktab[i].pkt_crcerr != 0) {
      printf("%#o\t%7d\t%7d\t%7d\t%7d\t%7d\t%7d\t%7d\t%7d\n", i,
	     linktab[i].pkt_in, linktab[i].pkt_out, linktab[i].pkt_aborted, linktab[i].pkt_lost,
	     linktab[i].pkt_crcerr, linktab[i].pkt_crcerr_post,
	     linktab[i].pkt_badlen, linktab[i].pkt_rejected);
    }
  }
  PTUNLOCKN(linktab_lock,"linktab_lock");
}

// call this with hosttab_lock held
struct hostat *
find_hostat_entry(u_short addr)
{
  struct hostat *net = hosttab[addr>>8];
  if (net == NULL) {
    if ((net = malloc(sizeof(struct hostat)*256)) == NULL) 
      perror("malloc(hosttab entry)");
    memset((char *)net, 0, sizeof(struct hostat)*256);
    hosttab[addr>>8] = net;
  }
  return &hosttab[addr>>8][addr&0xff];
}

void print_host_stats()
{
  int n, i;
  PTLOCKN(hosttab_lock,"hosttab_lock");
  printf("Host stats:\n"
	 "Host\t  In\t Via\t Last seen\t FC\n");
  for (n = 0; n < 256; n++) {
    struct hostat *he = hosttab[n];
    if (he != NULL) {
      for (i = 0; i < 256; i++) {
	// fprintf(stderr,"hosttab[%d][%i] = %p\n", n, i, he[i]);
	if (he[i].hst_in != 0 || he[i].hst_last_hop != 0 || he[i].hst_last_seen != 0) {
	  printf("%#o\t%7d\t%#o\t%ld\t%d\n", (n << 8) | i,
		 he[i].hst_in, he[i].hst_last_hop,
		 he[i].hst_last_seen > 0 ? time(NULL) - he[i].hst_last_seen : 0,
		 he[i].hst_last_fc);
	}
      }
    }
  }
  PTUNLOCKN(hosttab_lock,"hosttab_lock");
}

char *rt_linkname(u_char linktype)
{
  switch (linktype) {
  case LINK_UNIXSOCK: return "Unix";
  case LINK_CHUDP: return "CHUDP";
#if CHAOS_TLS
  case LINK_TLS: return "TLS";
#endif
#if CHAOS_IP
  case LINK_IP: return "CHIP";
#endif
#if CHAOS_ETHERP
  case LINK_ETHER: return "Ether";
#endif
  default: return "Unknown?";
  }
}

char *rt_typename(u_char type)
{
  switch (type) {
  case RT_NOPATH: return "NoPath";
  case RT_STATIC: return "Static";
  case RT_DYNAMIC: return "Dynamic";
  default: return "Unknown?";
  }
}

void
print_routing_table()
{
  int i;
  printf("Routing tables follow:\n");
  if (rttbl_host_len > 0) {
    printf("Host\tBridge\tType\tLink\tMyAddr\tCost\tAge\n");
    for (i = 0; i < rttbl_host_len; i++)
      if (rttbl_host[i].rt_link != LINK_NOLINK) {
	printf("%#o\t%#o\t%s\t%s\t%#o\t%d\t%ld",
	       rttbl_host[i].rt_dest, rttbl_host[i].rt_braddr, rt_typename(rttbl_host[i].rt_type),
	       rt_linkname(rttbl_host[i].rt_link),
	       rttbl_host[i].rt_myaddr,
	       rttbl_host[i].rt_cost,
	       rttbl_host[i].rt_cost_updated > 0 ? time(NULL) - rttbl_host[i].rt_cost_updated : 0);
#if CHAOS_TLS
	if (rttbl_host[i].rt_tls_muxed[0] != 0) {
	  int j;
	  printf("\tmux: %o", rttbl_host[i].rt_tls_muxed[0]);
	  for (j = 1; j < CHTLS_MAXMUX && rttbl_host[i].rt_tls_muxed[j] != 0; j++) {
	    printf(",%o",rttbl_host[i].rt_tls_muxed[j]);
	  }
	}
#endif
	printf("\n");
      }
  }
  printf("Net\tBridge\tType\tLink\tMyAddr\tCost\tAge\n");
  for (i = 0; i < 0xff; i++)
    if (rttbl_net[i].rt_link != LINK_NOLINK)
      printf("%#o\t%#o\t%s\t%s\t%#o\t%d\t%ld\n",
	     i, rttbl_net[i].rt_braddr, rt_typename(rttbl_net[i].rt_type), rt_linkname(rttbl_net[i].rt_link),
	     rttbl_net[i].rt_myaddr,
	     rttbl_net[i].rt_cost,
	     rttbl_net[i].rt_cost_updated > 0 ? time(NULL) - rttbl_net[i].rt_cost_updated : 0);
}

struct chroute *
add_to_routing_table(u_short dest, u_short braddr, u_short myaddr, int type, int link, int cost)
{
  // !!!! call this with rttbl_lock already locked
  struct chroute *r = NULL;
  // make a routing entry for host dest through braddr using myaddr, route type, link type, cost
  // @@@@ perhaps validate data?
  if (rttbl_host_len < RTTBL_HOST_MAX) {
    rttbl_host[rttbl_host_len].rt_dest = dest;
    rttbl_host[rttbl_host_len].rt_braddr = braddr;  /* direct, not through a bridge */
    // find a "myaddr" entry for the subnet of the bridge
    if ((myaddr == 0) && (braddr != 0)) {
      int i;
      for (i = 0; i < nchaddr; i++) {
	if ((mychaddr[i] & 0xff00) == (braddr & 0xff00)) {
	  myaddr = mychaddr[i];
	  if (verbose) fprintf(stderr,"%%%% Fill in myaddr %#o for new route to %#o via %#o (%s)\n",
			       myaddr, dest, braddr, rt_linkname(link));
	  break;
	}
      }
      if (myaddr == 0)
	fprintf(stderr,"%%%% Don't know my address for net %#o when adding route to %#o via %#o (%s)\n",
		(braddr & 0xff00)>>8, dest, braddr, rt_linkname(link));
    }
    rttbl_host[rttbl_host_len].rt_myaddr = myaddr;  /* if 0, the main address is used */
    rttbl_host[rttbl_host_len].rt_type = type;
    rttbl_host[rttbl_host_len].rt_link = link;
    rttbl_host[rttbl_host_len].rt_cost = cost;
    rttbl_host[rttbl_host_len].rt_cost_updated = time(NULL); // cost doesn't change but keep track of when it came up
    r = &rttbl_host[rttbl_host_len];
    rttbl_host_len++;
    if (verbose) print_routing_table();
  } else
    fprintf(stderr,"%%%% host route table full (NOT adding %s for %#o), increase RTTBL_HOST_MAX!\n",
	    rt_linkname(link), dest);
  return r;
}

void *
reparse_link_host_names_thread(void *v)
{
  while (1) {
    sleep(60*5);		// Hmm, how often really?
    reparse_chudp_names();   // occasionally re-parse chu_name strings
#if CHAOS_IP
    reparse_chip_names();
#endif
  }
}


// Look at an incoming RUT pkt given a connection type and a cost, 
// and update our routing table if appropriate. 
void
peek_routing(u_char *pkt, int pklen, int cost, u_short linktype)
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_short src, pksrc = ch_srcaddr(cha);
  u_char *data = &pkt[CHAOS_HEADERSIZE];
  u_short rsub, rcost;
  int i, pkdlen = ch_nbytes(cha);

  if (is_mychaddr(pksrc)) {
    // Already checked by caller
    if (debug) fprintf(stderr,"Got my pkt back (%#o), ignoring\n", pksrc);
    return;
  }
  if ((ch_opcode(cha) == 0) || ((ch_opcode(cha) > CHOP_BRD) && (ch_opcode(cha) < CHOP_DAT))) {
    fprintf(stderr,"BAD PACKET opcode %#o (wrong byte order?)\n", ch_opcode(cha));
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
      if (is_private_subnet(rsub)) {
	// Never mind about somebody's private network
	// They should not announce it: print warning, @@@@ but not every time
	fprintf(stderr," Received RUT info for subnet %#o from host %#o,\n"
		" but that subnet is private and should not be announced.\n",
		rsub, src);
	continue;
      }
      if (rttbl_net[rsub].rt_type == RT_STATIC && (verbose||debug) )
	fprintf(stderr,"DEBUG: Received RUT info for subnet %#o from host %#o.\n"
		" We have a STATIC route to that subnet - "
		" bug in network structure or sender's software?\n",
		rsub, src);
      if ((rcost + cost) > RTCOST_HIGH) {
	// Don't add routes which are immediately stale
	if (verbose) fprintf(stderr," Received RUT for subnet %#o from host %#o with high cost already: %d+%d > %d",
			     rsub, src, rcost, cost, RTCOST_HIGH);
      }
      else if ((rttbl_net[rsub].rt_type == RT_NOPATH)  /* we have no path currently */
	  /* we had a higher (or equal, to update age) cost */
	  || ((rttbl_net[rsub].rt_cost >= (rcost + cost))
	      /* but don't update if we have a static route */
	      && (rttbl_net[rsub].rt_type != RT_STATIC))
	  ) {
	if (rttbl_net[rsub].rt_type == RT_NOPATH) {
	  if (verbose) fprintf(stderr," Adding new route to %#o type %d cost %d via %#o\n",
			       rsub, RT_DYNAMIC, (rcost + cost), src);
	} else if ((rcost + cost) != rttbl_net[rsub].rt_cost) {
	  if (verbose) fprintf(stderr," Updating cost for route to %#o type %d cost %d -> %d via %#o\n",
			       rsub, RT_DYNAMIC, rttbl_net[rsub].rt_cost, (rcost + cost), src);
	} else
	  if (verbose) fprintf(stderr," Updating age for route to %#o type %d cost %d via %#o\n",
			       rsub, RT_DYNAMIC, rttbl_net[rsub].rt_cost, src);
	rttbl_updated = 1;
	PTLOCKN(rttbl_lock,"rttbl_lock");
	rttbl_net[rsub].rt_type = RT_DYNAMIC; // type;
	rttbl_net[rsub].rt_cost = (rcost + cost);  /* add the cost to go to that bridge */
	rttbl_net[rsub].rt_link = linktype;
	// Note the bridge: the sender of the RUT pkt
	rttbl_net[rsub].rt_braddr = src;
	// Note it's a subnet route
	rttbl_net[rsub].rt_dest = src & 0xff00;
	rttbl_net[rsub].rt_cost_updated = time(NULL);
	PTUNLOCKN(rttbl_lock,"rttbl_lock");
      }
      else if (debug) {
	fprintf(stderr," not updating net %#o (cost %d): have type %s, cost %d\n",
		rsub, rcost, rt_typename(rttbl_net[rsub].rt_type), rttbl_net[rsub].rt_cost);
      }
    }
    if (verbose && rttbl_updated) print_routing_table();
  } 
}

void 
update_route_costs()
{
  // update the cost of all dynamic routes by their age,
  // according to AIM 628 p15.
  int i;
  u_int costinc = 0;
  static time_t lasttime = 0;
  // last time we updated the routing costs
  if (lasttime == 0) lasttime = time(NULL);

  PTLOCKN(rttbl_lock,"rttbl_lock");
  for (i = 0; i < 256; i++) {
    if (rttbl_net[i].rt_type == RT_DYNAMIC) {
      /* Age by 1 every 4 seconds, max limit, but not for direct or asynch (cf AIM 628 p15) */
      costinc = (time(NULL) - lasttime)/4;
      if (costinc > 0) {
	if (debug) fprintf(stderr,"RUT to %d, cost %d => %d\n",i,
			   rttbl_net[i].rt_cost, rttbl_net[i].rt_cost+costinc);
	if ((rttbl_net[i].rt_cost + costinc) > RTCOST_HIGH)
	  rttbl_net[i].rt_cost = RTCOST_HIGH;
	else
	  rttbl_net[i].rt_cost += costinc;
      }
    }
  }
  if (costinc > 0)
    lasttime = time(NULL);
  PTUNLOCKN(rttbl_lock,"rttbl_lock");
}


struct chroute *
find_in_routing_table(u_short dchad, int only_host, int also_nopath)
{
  int i;
  if (is_mychaddr(dchad)) {
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
  for (i = 0; i < rttbl_host_len; i++) {
    if ((rttbl_host[i].rt_dest == dchad)
	&& 
	(also_nopath ||		/* look for old routes */
	 ((rttbl_host[i].rt_type != RT_NOPATH)
	  && 
	  // Check the cost, too.
	  (rttbl_host[i].rt_cost < RTCOST_HIGH)))) {
      struct chroute *rt = &rttbl_host[i];
      if (debug) fprintf(stderr,"Found host route to dest %#o: %s dest %#o %s bridge %#o myaddr %#o\n", dchad,
			 rt_linkname(rt->rt_link), rt->rt_dest, rt_typename(rt->rt_type), rt->rt_braddr, rt->rt_myaddr);
      return rt;
    }
  }
  if (only_host) return NULL;
  
  /* Then check subnet routing table */
  u_short sub = (dchad>>8)&0xff;
  if ((rttbl_net[sub].rt_type != RT_NOPATH)
      // Check the cost, too.
      && (rttbl_net[sub].rt_cost < RTCOST_HIGH)) {
    struct chroute *rt = &rttbl_net[sub];
    if (rttbl_net[sub].rt_braddr != 0) {
      if (is_mychaddr(rttbl_net[sub].rt_braddr))
	// This is an announce-only route, when we have individual
	// links to all hosts on the subnet - but apparently not to
	// this one. Drop it.
	return NULL;
      
      if (debug) fprintf(stderr,"Found subnet %#o route to dest %#o: %s dest %#o %s bridge %#o myaddr %#o\n", sub, dchad,
			 rt_linkname(rt->rt_link), rt->rt_dest, rt_typename(rt->rt_type), rt->rt_braddr, rt->rt_myaddr);
      return &rttbl_net[sub];
    } else {
      // No bridge, so directly connected subnet route, e.g. Ether
      if (debug) fprintf(stderr,"Found directly connected subnet %#o route to dest %#o: %s dest %#o %s bridge %#o myaddr %#o\n",
			 sub, dchad,
			 rt_linkname(rt->rt_link), rt->rt_dest, rt_typename(rt->rt_type), rt->rt_braddr, rt->rt_myaddr);
      return &rttbl_net[sub];
    }
  }
  // no route found
  return NULL;
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

// Note: this is for strings, not general data.
int 
get_packet_string(struct chaos_header *pkt, u_char *out, int outsize) 
{
  u_short *dataw = (u_short *)&((u_char *)pkt)[CHAOS_HEADERSIZE];
  int len;
  if (outsize <= (ch_nbytes(pkt) + (ch_nbytes(pkt) % 2))) {
    fprintf(stderr,"%%%% Warning: get_packet_string called with small outsize %d\n", outsize);
    len = outsize-1;
  } else {
    len = ch_nbytes(pkt);
  }
  if (ch_opcode(pkt) == CHOP_BRD) {
    // skip bitmask
    if (debug) printf("BRD get_packet_string: ackno %d nbytes %d outsize %d\n",
		      ch_ackno(pkt), ch_nbytes(pkt), outsize);
    if (ch_ackno(pkt) < len) {
      dataw = (u_short *)&((u_char *)pkt)[CHAOS_HEADERSIZE+ch_ackno(pkt)];
      // @@@@ check all similar pointer arithmetic for "underflow"
      len -= ch_ackno(pkt);
    }
  }
  ntohs_buf(dataw, (u_short *)out, len % 2 ? len+1 : len);
  out[len] = '\0';
  return len;
}

void
handle_pkt_for_me(struct chaos_header *ch, u_char *data, int dlen, u_short dchad)
{
  if (ch_opcode(ch) == CHOP_RUT)
    // RUT is handled separately
    return;
  if ((ch_opcode(ch) == CHOP_RFC) || (ch_opcode(ch) == CHOP_BRD))  {
    if (verbose)
      fprintf(stderr,"%s pkt for self (%#o) from <%#o,%#x> received, checking if we handle it\n",
	      ch_opcode_name(ch_opcode(ch)),
	      dchad, ch_srcaddr(ch), ch_srcindex(ch));
    // see what contact they look for
    if (!handle_rfc(ch, data, dlen)) {
      packet_to_conn_handler(data, dlen);
    }
  }
  else {    
    if (verbose) {
      fprintf(stderr,"%s pkt for self (%#o) received from <%#o,%#x>",
	      ch_opcode_name(ch_opcode(ch)),
	      dchad, ch_srcaddr(ch), ch_srcindex(ch));
      if (ch_opcode(ch) == CHOP_RFC) {
	fprintf(stderr,"; Contact: ");
	// @@@@ use generic fcn for this
	int max = ch_nbytes(ch);
	u_char *cp = &data[CHAOS_HEADERSIZE];
	u_char *cont = (u_char *)calloc(max+1, sizeof(u_char));
	if (cont != NULL) {
	  ch_11_gets(cp, cont, max);
	  char *space = index((char *)cont, ' ');
	  if (space) *space = '\0'; // show only contact name, not args
	  fprintf(stderr,"%s\n", cont);
	  free(cont);
	} else
	  fprintf(stderr,"calloc(%d) failed\n", max+1);
      } else
	fprintf(stderr,"\n");
    }
    packet_to_conn_handler(data, dlen);
  }
}

// **** Bridging between links

void
forward_chaos_pkt_on_route(struct chroute *rt, u_char *data, int dlen) 
{
  struct chaos_header *ch = (struct chaos_header *)data;

  u_short dchad = ch_destaddr(ch);
  u_short schad = ch_srcaddr(ch);

  // Don't forward between private and non-private subnets (but OK within the same (private) subnet)
  if (((schad >> 8) != (dchad >> 8)) &&
      ((is_private_subnet(schad >> 8) && !is_private_subnet(dchad >> 8)) ||
       (is_private_subnet(dchad >> 8) && !is_private_subnet(schad >> 8)))) {
    if (debug || verbose) 
      fprintf(stderr,"Not forwarding between private and non-private subnets: src %#o dst %#o\n",
	      schad, dchad);
    // incf dropped packets
    PTLOCKN(linktab_lock,"linktab_lock");
    linktab[schad>>8].pkt_rejected++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
    return;
  }

  // round up to full 16-bit word
  dlen += (dlen % 2);

  // Update/add trailer here.
  if (dlen < CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)
    dlen += CHAOS_HW_TRAILERSIZE;  /* add trailer if needed */
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[dlen-CHAOS_HW_TRAILERSIZE];
  // HW dest is next-hop destination
  if (ch_destaddr(ch) == 0)
    // unless it's broadcast
    tr->ch_hw_destaddr = 0;
  else
    tr->ch_hw_destaddr = rt->rt_braddr > 0 ? htons(rt->rt_braddr) : (rt->rt_dest > 0 ? htons(rt->rt_dest) : htons(ch_destaddr(ch)));
  // HW sender is me!
  // Find proper mychaddr entry if none given
  if (rt->rt_myaddr <= 0) {
    // Should not happen, add_to_routing_table now tries to fill it in.
    tr->ch_hw_srcaddr = tr->ch_hw_destaddr > 0 ? htons(mychaddr_on_net(ntohs(tr->ch_hw_destaddr))) : htons(mychaddr[0]);
  } else
    tr->ch_hw_srcaddr = htons(rt->rt_myaddr);

  int cks = ch_checksum(data,dlen-2); /* Don't checksum the checksum field */
  tr->ch_hw_checksum = htons(cks);

  switch (rt->rt_link) {
#if CHAOS_ETHERP
  case LINK_ETHER:
    forward_on_ether(rt, schad, dchad, ch, data, dlen);
    break;
#endif // CHAOS_ETHERP
  case LINK_UNIXSOCK:
    forward_on_usocket(rt, schad, dchad, ch, data, dlen);
    break;
#if CHAOS_TLS
  case LINK_TLS:
    forward_on_tls(rt, schad, dchad, ch, data, dlen);
    break;
#endif
#if CHAOS_IP
  case LINK_IP:
    forward_on_ip(rt, schad, dchad, ch, data, dlen);
    break;
#endif
  case LINK_CHUDP:
    forward_on_chudp(rt, schad, dchad, ch, data, dlen);
    break;
  default:
    if (verbose) fprintf(stderr,"Can't forward pkt on bad link type %d\n", rt->rt_link);
  }
}

void 
forward_chaos_broadcast_on_route(struct chroute *rt, int sn, u_char *data, int dlen) 
{
  u_char copy[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)data;
  u_char mask[32];
  memset(mask, 0, sizeof(mask));
  htons_buf((u_short *)&data[CHAOS_HEADERSIZE], (u_short *)mask, ch_ackno(ch));
  if (verbose) fprintf(stderr,"Forwarding %s (fc %d) from %#o to subnet %#o on %#o bridge/subnet %#o (%s)\n",
		       ch_opcode_name(ch_opcode(ch)),
		       ch_fc(ch),
		       ch_srcaddr(ch),
		       sn, rt->rt_dest, rt->rt_braddr,
		       rt_linkname(rt->rt_link));
#if 0
  // @@@@ instead: clear bit N when receiving from subnet link for N
  // clear bit if we're sending to a subnet link,
  // but if it's a host link, keep it and let the other end resend it if it has further host links to that subnet
  if (RT_SUBNETP(rt) && (sn < ch_ackno(ch)*8)) {
    mask[sn/8] = mask[sn/8] & ~(1<<(sn % 8));
    ntohs_buf((u_short *)mask, (u_short *)&data[CHAOS_HEADERSIZE], ch_ackno(ch));
  }
#endif
  // forward
  PTLOCKN(linktab_lock,"linktab_lock");
  linktab[rt->rt_dest >>8 ].pkt_out++;
  PTUNLOCKN(linktab_lock,"linktab_lock");
  // send a copy, since it may be swapped in the process of sending
  memcpy(copy, data, dlen);
  forward_chaos_pkt_on_route(rt, copy, dlen);
}


void 
forward_chaos_broadcast_pkt(struct chroute *src, u_char *data, int dlen) 
{
  struct chaos_header *ch = (struct chaos_header *)data;
  // forward on all direct links matching the requested subnets, after clearing that subnet in the mask
  // EXCEPT the link it came in on

  int i, sn, nsubn = ch_ackno(ch)*8;
  u_short ssubnet = ch_srcaddr(ch) >> 8;
  u_char mask[32];
  htons_buf((u_short *)&data[CHAOS_HEADERSIZE], (u_short *)mask, ch_ackno(ch));
  if (debug)
    fprintf(stderr,"BRD mask %d in %02x%02x%02x%02x => %02x%02x%02x%02x\n", nsubn,
	    data[CHAOS_HEADERSIZE],data[CHAOS_HEADERSIZE+1],data[CHAOS_HEADERSIZE+2],data[CHAOS_HEADERSIZE+3],
	    mask[0], mask[1], mask[2], mask[3]);

  struct chroute *rt;
  PTLOCKN(rttbl_lock, "rttbl_lock");
  // for all rttbl_host entries except the source, which are direct links,
  //   if its subnet is in the mask, forward there (after clearing bit)
  for (i = 0; i < rttbl_host_len; i++) {
    rt = &rttbl_host[i];
    sn = (rt->rt_dest)>>8;
    if ((sn != ssubnet) &&
	((is_private_subnet(sn) && !is_private_subnet(ssubnet)) ||
	 (!is_private_subnet(sn) && is_private_subnet(ssubnet)))) {
      // Don't forward between private and non-private subnets
      if (debug || verbose)
	fprintf(stderr,"BRD not forwarded (private) from subnet %#o to host %#o on subnet %#o\n", 
		ssubnet, rt->rt_dest, sn);
      continue;
    }
    if ((sn < nsubn) && (RT_DIRECT(rt)) && (src != rt) && (mask[sn/8] & (1<<(sn % 8)))) {
      forward_chaos_broadcast_on_route(rt, sn, data, dlen);
    } else if (debug)
      fprintf(stderr,"BRD not forwarded to %s host route %d (sn %#o, dest %#o, bit %d)\n", 
	      RT_DIRECT(rt) ? "direct" : "indirect", 
	      i, sn, rt->rt_dest, (mask[sn/8] & (1<<(sn % 8))));
  }
  // for all rttbl_net entries except the source, which are direct links
  //   if the subnet is set, forward there (after clearing bit)
  for (sn = 1; sn < 256 && sn < nsubn; sn++) {
    if ((sn != ssubnet) &&
	((is_private_subnet(sn) && !is_private_subnet(ssubnet)) ||
	 (!is_private_subnet(sn) && is_private_subnet(ssubnet)))) {
      // Don't forward between private and non-private subnets
      if (debug || verbose)
	fprintf(stderr,"BRD not forwarded (private) from subnet %#o to subnet %#o\n", 
		ssubnet, sn);
      continue;
    }
    rt = &rttbl_net[sn];
    if ((src != rt) && (rttbl_net[sn].rt_link != LINK_NOLINK) && 
	(RT_DIRECT(rt)) && (mask[sn/8] & (1<<(sn % 8)))) {
      forward_chaos_broadcast_on_route(rt, sn, data, dlen);
    } else if (debug && rttbl_net[sn].rt_link != LINK_NOLINK)
      fprintf(stderr,"BRD not forwarded to subnet %#o %s route (bit %d)\n", 
	      sn, RT_DIRECT(rt) ? "direct" : "indirect", 
	      (mask[sn/8] & (1<<(sn % 8))));
  }
  PTUNLOCKN(rttbl_lock, "rttbl_lock");
}

void 
forward_chaos_pkt(struct chroute *src, u_char cost, u_char *data, int dlen, u_char src_linktype) 
{
  struct chaos_header *ch = (struct chaos_header *)data;
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[dlen-CHAOS_HW_TRAILERSIZE];

  u_short schad = 0;		   /* source (for hosttab) */
  u_short dchad = ch_destaddr(ch);  /* destination */
  u_char fwc = ch_fc(ch);	/* forwarding count */

  if (dlen >= CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE) {
    // use hw trailer if available
    schad = htons(tr->ch_hw_srcaddr);
  } else if (src != NULL) {
    // if it's a direct link, and the source is on my subnet, use it
    if (RT_DIRECT(src) && ((ch_srcaddr(ch) & 0xff00) == (src->rt_myaddr & 0xff00)))
      schad = ch_srcaddr(ch);
    else if (RT_BRIDGED(src))
      // else use the bridge's address
      schad = src->rt_braddr;
    else {
      // don't know an address, so use the link type instead as an indication (cf dump-routing-table)
      schad = (u_short)src->rt_link;
      // assert(schad < 0400);
    }
  }
  if (src != NULL) {
    PTLOCKN(linktab_lock,"linktab_lock");
    linktab[(src->rt_dest)>>8].pkt_in++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
    PTLOCKN(hosttab_lock,"hosttab_lock");
    struct hostat *he = find_hostat_entry(ch_srcaddr(ch));
    he->hst_in++;
    he->hst_last_seen = time(NULL);
    he->hst_last_hop = schad;
    he->hst_last_fc = ch_fc(ch);
    PTUNLOCKN(hosttab_lock,"hosttab_lock");
  } else if (debug)
    fprintf(stderr,"No source route given in forward from %#o to %#o\n",
	    schad, dchad);

  fwc++;
  if (fwc > CH_FORWARD_MAX) {	/* over-forwarded */
    if (verbose) fprintf(stderr,"%%%% Dropping over-forwarded pkt for %#o\n", dchad);
    if (src != NULL) {
      PTLOCKN(linktab_lock,"linktab_lock");
      linktab[(src->rt_dest)>>8].pkt_rejected++;
      PTUNLOCKN(linktab_lock,"linktab_lock");
    }
    return;
  }
  set_ch_fc(ch,fwc);		/* update */

  struct chroute *rt = find_in_routing_table(dchad, 0, 0);

  // From me?
  if (is_mychaddr(ch_srcaddr(ch)) || (rt != NULL && ch_srcaddr(ch) == rt->rt_myaddr)) {
    // Should not happen. Unless Unix sockets.
    if (src_linktype != LINK_UNIXSOCK) {
      if (verbose) fprintf(stderr,"Dropping pkt from self to %#o (src %#o - hw %#o, link %s) \n",
			   dchad, ch_srcaddr(ch), ntohs(tr->ch_hw_srcaddr), 
			   rt_linkname(src_linktype));
      if (debug) ch_dumpkt(data, dlen);
    }
    return;
  }

  if ((rt != NULL) && (rt->rt_link == LINK_UNIXSOCK) && (src_linktype == LINK_UNIXSOCK)) {
      // Unix socket echoes my own packets.
      if (debug) fprintf(stderr,"[Not routing %s from %#o to %#o back to source route (%s)]\n",
			 ch_opcode_name(ch_opcode(ch)),
			 ch_srcaddr(ch), dchad, rt_linkname(rt->rt_link));
    return;
  }

  peek_routing(data, dlen, cost, src_linktype); /* check for RUT */

  // Allow firewall to do its job
  if ((ch_opcode(ch) == CHOP_RFC) || (ch_opcode(ch) == CHOP_BRD)) {
    if (firewall_handle_forward(ch) < 0) {
      if (debug || verbose) fprintf(stderr,"Firewall says to drop %s packet from %#o to %#o.\n",
				    ch_opcode_name(ch_opcode(ch)),
				    ch_srcaddr(ch), ch_destaddr(ch));
      return;			// Firewall says "no"
    }
  }

  // To me?
  if (is_mychaddr(dchad) || (dchad == 0) || (rt != NULL && rt->rt_myaddr == dchad)) {
    if ((debug || verbose) && (dchad == 0)) 
      fprintf(stderr,"Broadcast pkt received from %#o hw %#o rt %s type %s to %#o, trying to handle it\n",
	      schad, ntohs(tr->ch_hw_srcaddr), src != NULL ? rt_linkname(src->rt_link) : "(null)", rt_linkname(src_linktype),
	      dchad);
    // Let firewall have a more precise say for BRD pkts to me
    if ((ch_opcode(ch) == CHOP_BRD) && (firewall_handle_pkt_for_me(ch) < 0)) {
      if (debug || verbose) fprintf(stderr,"Firewall says to drop %s packet from %#o to me (%#o).\n",
				    ch_opcode_name(ch_opcode(ch)),
				    ch_srcaddr(ch), ch_destaddr(ch));
      // don't drop it, the broadcast case below needs it
    } else
      // OK, take care of it
      handle_pkt_for_me(ch, data, dlen, dchad);
    if (dchad != 0) // check for BRD below, but other packets are now done
      return;			/* after checking for RUT (above) */
  }

  if (dchad == 0) {		/* broadcast */
    if (ch_opcode(ch) == CHOP_BRD) {
      if (debug) fprintf(stderr,"BRD pkt received, trying to forward it\n");
      // Check that there is a mask, and validate length requirement
      if ((ch_ackno(ch) > 0) && (ch_ackno(ch) <= 32) && ((ch_ackno(ch) % 4) == 0)) {
#if 1
	// Clear bitmask bit for the subnet we got it from (if it came from a subnet link)
	// Host links will not reflect the BRD back, by keeping track of where it came from (in forward_chaos_broadcast_pkt)
	if (src != NULL) { // NULL source means we are the origin, probably
	  u_int sn = src->rt_dest >> 8;
	  if (RT_SUBNETP(src) && (sn < ch_ackno(ch) * 8)) {
	    u_char *mask = &data[CHAOS_HEADERSIZE];
	    if (debug) fprintf(stderr,"BRD from subnet %#o mask byte %#x => %#x\n", sn, mask[sn/8], mask[sn/8] & ~(1<<(sn % 8)));
	    mask[sn/8] = mask[sn/8] & ~(1<<(sn % 8));
	  } else if (debug) 
	    fprintf(stderr,"BRD from subnet %#o NOT clearing bit: mask contains %#o subnets\n", sn, ch_ackno(ch) * 8);
	}
#endif
	forward_chaos_broadcast_pkt(src, data, dlen);
      } else if (debug || verbose) {
	fprintf(stderr,"Bad BRD mask length %d (mod 4 is %d)\n", ch_ackno(ch), ch_ackno(ch) % 4);
      }
    }
    // if not BRD (or bad BRD mask), simply drop it (handled above)
    return;
  }

  if (rt) {
    if (verbose) fprintf(stderr,"Forwarding %s (fc %d) from %#o (%s) to %#o on  %#o bridge/subnet %#o (%s)\n",
			 ch_opcode_name(ch_opcode(ch)),
			 ch_fc(ch),
			 ch_srcaddr(ch),
			 (src_linktype != 0 ? rt_linkname(src_linktype) : "?"),
			 dchad, rt->rt_dest, rt->rt_braddr,
			 rt_linkname(rt->rt_link));

    PTLOCKN(linktab_lock,"linktab_lock");
    linktab[rt->rt_dest >>8 ].pkt_out++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
    forward_chaos_pkt_on_route(rt, data, dlen);
  } else {
    if (verbose) fprintf(stderr,"Can't find route to %#o\n", dchad);
    if (src != NULL) {
      PTLOCKN(linktab_lock,"linktab_lock");
      linktab[(src->rt_dest)>>8].pkt_rejected++;
      PTUNLOCKN(linktab_lock,"linktab_lock");
    }
  }    
}

// Periodically send RUT pkts (cf AIM 628 p15)
void send_rut_pkt(struct chroute *rt, u_char *pkt, int c) 
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_short mya;
  if (rt->rt_myaddr != 0)
    // obey config
    mya = rt->rt_myaddr;
  else
    // find out
    mya = mychaddr_on_net(ch_destaddr(cha));

  // Update source address
  set_ch_srcaddr(cha, (mya == 0 ? mychaddr[0] : mya));

  if (rt->rt_link == LINK_NOLINK) {
    if (debug) fprintf(stderr,"%%%% Not sending RUT on %s link to %#o\n",
		       rt_typename(rt->rt_link), rt->rt_dest);
    return;			/* ignore */
  }
  // Destination of RUT packets should always be 0
  set_ch_destaddr(cha, 0);	/* broadcast */

  PTLOCKN(linktab_lock,"linktab_lock");
  if (ch_destaddr(cha) == 0)
    linktab[rt->rt_dest >> 8].pkt_out++;
  else
    linktab[ch_destaddr(cha) >> 8].pkt_out++;
  PTUNLOCKN(linktab_lock,"linktab_lock");

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

void *
rut_sender(void *v)
{
  int i, c;
  u_char pkt[CH_PK_MAXLEN];


  while (1) {
    /* Send to all subnets which are not through a bridge */
    for (i = 0; i < 256; i++) {
      struct chroute *rt = &rttbl_net[i];
      if ((rt->rt_type != RT_NOPATH) && RT_DIRECT(rt)) {
	if (debug) fprintf(stderr,"Making RUT pkt for net %#o\n", i);
	if ((c = make_routing_table_pkt(i<<8, &pkt[0], sizeof(pkt))) > 0) {
	  send_rut_pkt(rt, pkt, c);
	} else if (debug)
	  fprintf(stderr," no RUT data to send for net %#o\n", i);
      }
    }
    /* And to all individual hosts */
    for (i = 0; i < rttbl_host_len; i++) {
      struct chroute *rt = &rttbl_host[i];
      if ((rt->rt_type != RT_NOPATH) && RT_DIRECT(rt)) {
	if (debug) fprintf(stderr,"Making RUT pkt for link %d bridge %#o dest %#o => %#o\n", i,
			     rt->rt_braddr, rt->rt_dest,
			     rt->rt_braddr == 0 ? rt->rt_dest : rt->rt_braddr);
	if ((c = make_routing_table_pkt(rt->rt_braddr == 0 ? rt->rt_dest : rt->rt_braddr,
					&pkt[0], sizeof(pkt))) > 0) {
	  send_rut_pkt(rt, pkt, c);
	} else if (debug)
	  fprintf(stderr," no RUT data to send for link %d\n", i);
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

  if (is_mychaddr(dchad) || (dchad == 0)) {
    // shortcut. We don't need to update FC or link stats.
    handle_pkt_for_me(cha, pkt, len, dchad);
    if (dchad != 0)
      return;
  }

  if (ch_opcode(cha) == CHOP_BRD) {
    forward_chaos_broadcast_pkt(NULL, pkt, len);
    return;
  }

  struct chroute *rt = find_in_routing_table(dchad, 0, 0);

  if (rt == NULL) {
    if (debug) fprintf(stderr,"Can't find route to send pkt to %#o\n", dchad);
    return;
  }

  // Update source address, perhaps	  
  if (ch_srcaddr(cha) == 0)
    set_ch_srcaddr(cha, (rt->rt_myaddr == 0 ? mychaddr[0] : rt->rt_myaddr));

  if (verbose) fprintf(stderr,"Sending pkt %#x (%s) from me (%#o) to %#o (pkt dest %#o) %s dest %#o %s bridge %#o myaddr %#o\n",
		       ch_packetno(cha), ch_opcode_name(ch_opcode(cha)),
		       ch_srcaddr(cha), dchad,
		       ch_destaddr(cha),
		       rt_linkname(rt->rt_link),
		       rt->rt_dest, rt_typename(rt->rt_type), rt->rt_braddr, rt->rt_myaddr
		       );
  PTLOCKN(linktab_lock,"linktab_lock");
  linktab[rt->rt_dest>>8].pkt_out++;
  PTUNLOCKN(linktab_lock,"linktab_lock");

  forward_chaos_pkt_on_route(rt, pkt, len);
}


// **** Config parsing

static int
parse_route_params(struct chroute *rt, u_short addr)
{
  char *tok;
  u_short sval;

  rt->rt_type = RT_STATIC;	/* manually configured */
  rt->rt_cost = RTCOST_ETHER;	/* default */
  rt->rt_link = LINK_NOLINK;

  struct chroute *brt = find_in_routing_table(rt->rt_braddr, 1, 1);
  if (brt != NULL) {
    rt->rt_link = brt->rt_link;
    rt->rt_cost = brt->rt_cost;
  } else if (is_mychaddr(rt->rt_braddr) && RT_SUBNETP(rt)) {
    // Announce-only route (for subnet with only host links)
    // Find a link that matches the subnet, use its link type & cost
    PTLOCKN(rttbl_lock,"rttbl_lock");
    int i;
    for (i = 0; i < rttbl_host_len; i++) {
      if ((rttbl_host[i].rt_dest & 0xff00) == rt->rt_dest) {
	rt->rt_link = rttbl_host[i].rt_link;
	rt->rt_cost = rttbl_host[i].rt_cost;
	rt->rt_cost_updated = time(NULL);
	if (verbose) fprintf(stderr,"route to %#o: found matching link to %#o (%s cost %d)\n",
			     rt->rt_dest, rttbl_host[i].rt_dest, rt_linkname(rt->rt_link), rt->rt_cost);
	break;
      }
    }
    PTUNLOCKN(rttbl_lock,"rttbl_lock");
    if (rt->rt_link == LINK_NOLINK) {
      fprintf(stderr,"route to %#o: can't find matching link, thus link implementation is unknown.\n"
	      "%%%% No route added! Maybe you need to reorder your config?\n",
	      rt->rt_dest);
    }
  } else {
    fprintf(stderr,"route to %#o: can't find route to its bridge %#o, thus link is unknown.\n"
	    "%%%% No route added! Try to reorder your config - put \"route\" definitions after \"link\" definitions.\n",
	    rt->rt_dest, rt->rt_braddr);
  }

  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strcasecmp(tok, "myaddr") == 0) {
      tok = strtok(NULL," \t\r\n");
      if ((sscanf(tok,"%ho",&sval) != 1) || !valid_chaos_host_address(sval)) {
	fprintf(stderr,"bad octal myaddr value %s\n", tok);
	return -1;
      }
      rt->rt_myaddr = sval;
      add_mychaddr(sval);
#if 0
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
#endif
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
      fprintf(stderr,"bad keyword %s for link/route to %#o\n", tok, addr);
      return -1;
    }
  }
  return 0;
}

static int
parse_route_config() 
{
  // route host|subnet x bridge y [cost c]
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
    if ((addr == 0) || (addr > 0xff)) {
      fprintf(stderr,"bad subnet number \"%s\"\n", tok);
      return -1;
    } 
    rt = &rttbl_net[addr];
    rt->rt_dest = addr<<8;
  } else {
    rt = &rttbl_host[rttbl_host_len++];
    if (!valid_chaos_host_address(addr)) {
      fprintf(stderr,"bad route address \"%s\"\n", tok);
      return -1;
    }
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
  if ((sscanf(tok,"%ho",&sval) != 1) || !valid_chaos_host_address(sval)) {
    fprintf(stderr,"bad octal bridge value %s\n", tok);
    return -1;
  }
  rt->rt_braddr = sval;

  if (parse_route_params(rt, addr) < 0)
    return -1;
  return 0;
}

static int
parse_link_args(struct chroute *rt, u_short addr)
{
  u_short sval;
  char *tok;

  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strcasecmp(tok, "myaddr") == 0) {
      tok = strtok(NULL," \t\r\n");
      if ((sscanf(tok,"%ho",&sval) != 1) || !valid_chaos_host_address(sval)) {
	fprintf(stderr,"bad octal myaddr value %s\n", tok);
	return -1;
      }
      rt->rt_myaddr = sval;
      add_mychaddr(sval);
#if 0
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
#endif
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
#if CHAOS_TLS
    } else if (strcasecmp(tok,"mux") == 0) {
      tok = strtok(NULL," \t\r\n");
      int nmux = 0;
      char *cma, *tp = tok;
      while (nmux < CHTLS_MAXMUX) {
	if ((sscanf(tp,"%ho", &sval) != 1) || !valid_chaos_host_address(sval)) {
	  fprintf(stderr,"bad octal mux value %s\n", tp);
	  return -1;
	} else if ((sval & 0xff00) != (rt->rt_myaddr & 0xff00)) {
	  // more sanity checks after parsing: the muxed addresses are directly reachable
	  fprintf(stderr,"Error: mux address %o must be on my subnet %o\n", sval, (rt->rt_myaddr >> 8));
	  return -1;
	} else if (rt->rt_tls_muxed[nmux] != 0) {
	  fprintf(stderr,"Error: mux addresses already defined - use mux with comma-separated list\n");
	  return -1;
	} else {
	  rt->rt_tls_muxed[nmux++] = sval;
	}
	if ((cma = index(tp,',')) != NULL) {
	  tp = cma+1;
	  if (nmux == CHTLS_MAXMUX)
	    fprintf(stderr,"%%%% Warning: max number of mux addresses (%d) parsed, skipping the rest. Increase CHTLS_MAXMUX?\n", nmux);
	  continue;
	} else {
	  break;
	}
      }
#endif
    } else {
      fprintf(stderr,"bad keyword %s for link to %#o\n", tok, addr);
      return -1;
    }
  }
  // all ok
  return 0;
}

static int
parse_ip_params(char *type, struct sockaddr *sa, int default_port, char *nameptr, int nameptr_len)
{
  char *tok;
  int res;
  u_short port = default_port;
  char *sep = NULL, sepchar;
  struct addrinfo *he, hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
#ifdef AI_ADDRCONFIG		// Use AI_ADDRCONFIG if appropriate
#ifdef AI_MASK			// and it is a valid flag
  if (AI_MASK & AI_ADDRCONFIG)
#endif
    hints.ai_flags = AI_ADDRCONFIG;
#endif

  tok = strtok(NULL," \t\r\n");
  if (default_port > 0) {
    // Parse port, if given: try first | and then : for separator (| works better with numeric IPv6 addresses)
    // First try | for separator
    sep = rindex(tok,'|');
    if ((sep != NULL) && strlen(sep) > 1) {
      sepchar = '|';
      port = atoi((char *)sep+1);
      if ((port == 0) || (port < 1024)) {
	fprintf(stderr,"bad port number '%s'\n", sep+1);
	return -1;
      }
      // zap separator for getaddrinfo
      *sep = '\0';
    } else {
      sep = rindex(tok, ':');
      if ((sep != NULL) && (strlen(sep) > 1)) {
	struct in6_addr ip6;
	if (inet_pton(AF_INET6, tok, &ip6) == 0) {
	  // Only parse a port if it isn't an IPv6 address
	  sepchar = ':';
	  port = atoi((char *)sep+1);
	  if ((port == 0) || (port < 1024)) {
	    fprintf(stderr,"bad port number '%s'\n", sep+1);
	    return -1;
	  }
	  // zap separator for getaddrinfo
	  *sep = '\0';
	}
      }
    }
  }

  if ((res = getaddrinfo(tok, NULL, &hints, &he)) == 0) {
    sa->sa_family = he->ai_family;
    if (he->ai_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)he->ai_addr;
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      sin->sin_port = htons(port);
      memcpy(&sin->sin_addr, &s->sin_addr, sizeof(struct in_addr));
    } else if (he->ai_family == AF_INET6) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)he->ai_addr;
      struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
      sin->sin6_port = htons(port);
      memcpy(&sin->sin6_addr, &s->sin6_addr, sizeof(struct in6_addr));
    } else {
      fprintf(stderr,"error parsing %s host %s: unknown address family %d\n",
	      type, tok, he->ai_family);
      return -1;
    }
    strncpy(nameptr, tok, nameptr_len);
  } else {
    if (sep != NULL)
      *sep = sepchar;		/* put separator back for error messages */
    fprintf(stderr,"bad %s arg %s: %s (%d)\n",
	    type, tok, gai_strerror(res), res);
    return -1;
  }
  
  // all ok
  return 0;
}


static int
parse_link_config()
{
  // link ether|unix|chudp|tls ... host|subnet y [type t cost c]
  u_short addr, subnetp;
  struct chroute rte;
  struct chroute *rt = &rte;
  char *tok = strtok(NULL," \t\r\n");

  memset(rt, 0, sizeof(rte));
  if (tok == NULL) {
    fprintf(stderr,"bad link config: no parameters\n");
    return -1;
  }
  if (strcasecmp(tok, "chudp") == 0) {
    rt->rt_link = LINK_CHUDP;
    rt->rt_type = RT_STATIC;
    rt->rt_cost = RTCOST_ASYNCH;
    rt->rt_cost_updated = time(NULL);

    if (parse_ip_params("chudp", &chudpdest[chudpdest_len].chu_sa.chu_saddr, CHUDP_PORT,
			(char *)&chudpdest[chudpdest_len].chu_name, CHUDPDEST_NAME_LEN) < 0)
      return -1;
    // @@@@ don't do it separately for ipv6/v4
    if (chudpdest[chudpdest_len].chu_sa.chu_saddr.sa_family == AF_INET)
      do_udp = 1;
    else if (chudpdest[chudpdest_len].chu_sa.chu_saddr.sa_family == AF_INET6)
      do_udp6 = 1;
    chudpdest_len++;

#if CHAOS_ETHERP
  } else if (strcasecmp(tok, "ether") == 0) {
    do_ether = 1;
    rt->rt_link = LINK_ETHER;
    rt->rt_type = RT_STATIC;
    rt->rt_cost = RTCOST_DIRECT;
    if (parse_ether_link_config() < 0)
      return -1;
  } else if (strcasecmp(tok, "unix") == 0) {
    do_unix = 1;
    rt->rt_link = LINK_UNIXSOCK;
    rt->rt_type = RT_STATIC;
    rt->rt_cost = RTCOST_DIRECT;
#endif

#if CHAOS_TLS
  } else if (strcasecmp(tok, "tls") == 0) {
    rt->rt_link = LINK_TLS;
    rt->rt_type = RT_STATIC;
    rt->rt_cost = RTCOST_ASYNCH;
    rt->rt_cost_updated = time(NULL);

    if (parse_ip_params("tls", &tlsdest[tlsdest_len].tls_sa.tls_saddr, CHAOS_TLS_PORT,
			(char *)&tlsdest[tlsdest_len].tls_name, TLSDEST_NAME_LEN) < 0)
      return -1;
    do_tls = 1;
    tlsdest_len++;
#endif // CHAOS_TLS

#if CHAOS_IP
  } else if (strcasecmp(tok, "chip") == 0) {
    rt->rt_link = LINK_IP;
    rt->rt_type = RT_STATIC;
    rt->rt_cost = RTCOST_ASYNCH;
    rt->rt_cost_updated = time(NULL);

    if (parse_ip_params("chip", &chipdest[chipdest_len].chip_sa.chip_saddr, 0,
			(char *)&chipdest[chipdest_len].chip_name, CHIPDEST_NAME_LEN) < 0)
      return -1;
    do_chip = 1;
    chipdest_len++;
#endif
  }

  // host|subnet y type t cost c
  tok = strtok(NULL," \t\r\n");
  if (strcasecmp(tok,"host") == 0) 
    subnetp = 0;
  else if (strcasecmp(tok, "subnet") == 0) 
    subnetp = 1;
  else {
    fprintf(stderr,"bad link keyword %s, expected \"host\" or \"subnet\"\n", tok);
    return -1;
  }
  tok = strtok(NULL, " \t\r\n");
  if (tok == NULL) {
    fprintf(stderr,"bad link config: no %s addr\n", (subnetp ? "subnet" : "host"));
    return -1;
  }
#if CHAOS_TLS && CHAOS_DNS
  // This hack will only work for TLS links, and only if DNS is being used
  if ((rt->rt_link == LINK_TLS) && (strcasecmp(tok, "unknown") == 0)) {
    addr = 0;
    rt->rt_dest = 0;
  } else {
#endif
    if (sscanf(tok,"%ho",&addr) != 1) {
      fprintf(stderr,"bad octal value %s\n", tok);
      return -1;
    }
    if (subnetp) {
      if ((addr == 0) || (addr > 0xff)) {
	fprintf(stderr,"bad subnet number \"%s\"\n", tok);
	return -1;
      }
      rt->rt_dest = addr<<8;
    } else {
      if (!valid_chaos_host_address(addr)) {
	fprintf(stderr,"bad host address \"%s\"\n", tok);
	return -1;
      }
      rt->rt_dest = addr;
    }
#if CHAOS_TLS && CHAOS_DNS
  }
#endif
  if (parse_link_args(rt, addr) < 0)
    return -1;

  if (rt->rt_link == LINK_CHUDP) {
    chudpdest[chudpdest_len - 1].chu_addr = addr;
    if (subnetp) {
      fprintf(stderr,"Error: CHUDP links must be to hosts, not subnets.\n"
	      "Change\n"
	      " link chudp %s:%d subnet %o\n"
	      "to\n"
	      " link chudp %s:%d host NN\n"
	      " route subnet %o bridge NN\n"
	      "where NN is the actual chudp host\n",
	      chudpdest[chudpdest_len -1].chu_name, ntohs(chudpdest[chudpdest_len -1].chu_sa.chu_sin.sin_port),
	      addr,
	      chudpdest[chudpdest_len -1].chu_name, ntohs(chudpdest[chudpdest_len -1].chu_sa.chu_sin.sin_port),
	      addr);
      return -1;
    }
  }
#if CHAOS_TLS
  if (rt->rt_link == LINK_TLS) {
    // Copy the mux addresses for convenience
    memcpy(tlsdest[tlsdest_len - 1].tls_muxed, rt->rt_tls_muxed, sizeof(tlsdest[tlsdest_len - 1].tls_muxed));
    int i, j, found = 0;
    for (i = 0; i < CHTLS_MAXMUX && rt->rt_tls_muxed[i] != 0; i++) {
      // Check that each muxed address is directly reachable
      for (j = 0; j < rttbl_host_len; j++) {
	if ((rttbl_host[j].rt_link != LINK_NOLINK) && RT_DIRECT(&rttbl_host[j]) 
	    && (rttbl_host[j].rt_dest == rt->rt_tls_muxed[i])) {
	  found = 1;
	  break;
	}
      }
      if (!found) {
	if ((rttbl_net[rt->rt_tls_muxed[i]>>8].rt_link != LINK_NOLINK) && RT_DIRECT(&rttbl_net[rt->rt_tls_muxed[i]>>8])) {
	  fprintf(stderr,"%%%% Warning: using a subnet link for a mux address (%o) might break routing\n", rt->rt_tls_muxed[i]);
	  // look for next mux address
	  found = 0;
	} else {
	  fprintf(stderr,"Error: muxed address %o not directly reachable through another link\n", rt->rt_tls_muxed[i]);
	  return -1;
	}
      } else
	found = 0;		// look for next mux address
    }
    if ((addr != 0) && ((addr >> 8) != (rt->rt_myaddr >> 8))) {
      fprintf(stderr,"Error: TLS destination address %o must be on same subnet as TLS \"myaddr\" %o\n",
	      addr, rt->rt_myaddr);
	return -1;
    }
    tlsdest[tlsdest_len - 1].tls_addr = addr;
    tlsdest[tlsdest_len - 1].tls_myaddr = rt->rt_myaddr;
    if (subnetp) {
      fprintf(stderr,"Error: TLS links must be to hosts, not subnets.\n"
	      "Change\n"
	      " link tls %s:%d subnet %o\n"
	      "to\n"
	      " link tls %s:%d host NN\n"
	      " route subnet %o bridge NN\n"
	      "where NN is the actual tls host\n",
	      tlsdest[tlsdest_len -1].tls_name, ntohs(tlsdest[tlsdest_len -1].tls_sa.tls_sin.sin_port),
	      addr,
	      tlsdest[tlsdest_len -1].tls_name, ntohs(tlsdest[tlsdest_len -1].tls_sa.tls_sin.sin_port),
	      addr);
      return -1;
    }
  }
#endif // CHAOS_TLS
#if CHAOS_IP
  if (rt->rt_link == LINK_IP) {
    chipdest[chipdest_len - 1].chip_addr = addr;
    if (validate_chip_entry(&chipdest[chipdest_len - 1], rt, subnetp, nchaddr) < 0) {
      chipdest_len--; // forget invalid chipdest
      return -1;
    }
  }
#endif // CHAOS_IP
#if CHAOS_ETHERP
  if (rt->rt_link == LINK_ETHER) {
    if (postparse_ether_link_config(rt) < 0)
      return -1;
  }
#endif

  // @@@@ check if mychaddr has an entry for the subnet of the newly defined link
  struct chroute *rrt;
  if (subnetp)
    rrt = &rttbl_net[addr];
  else
    rrt = &rttbl_host[rttbl_host_len++];
  memcpy(rrt, rt, sizeof(struct chroute));
  return 0;
}

static int
parse_private_subnet()
{
  char *tok = strtok(NULL," \t\r\n");
  unsigned long addr;
  char *s, *end = tok;

  if (tok == NULL) {
    fprintf(stderr, "expected subnet list\n");
    return -1;
  }

  for (s = tok; *end != 0; s = end + 1) {
    addr = strtoul(s, &end, 8);
    if (*end != ',' && *end != 0) {
      fprintf(stderr, "bad private subnet list: %s\n", tok);
      return -1;
    }
    if ((addr > 0377) || (addr == 0)) {
      fprintf(stderr, "bad private subnet number: %lo\n", addr);
      return -1;
    }
#ifdef PRIVATE_CHAOS_SUBNET
    if (addr == PRIVATE_CHAOS_SUBNET)
      fprintf(stderr,"Note: subnet %#lo is globally private, no need to add it in \"private subnet\" config.\n",
	      addr);
#endif
    private_subnet[addr] = 1;
    number_of_private_subnets++;
  }

  return 0;
}

static int
parse_private_hosts()
{
  char *tok = strtok(NULL," \t\r\n");
  if (tok == NULL) {
    fprintf(stderr, "expected hosts file name\n");
    return -1;
  }
  private_hosts_file = strdup(tok);
  return 0;
}

static int
parse_private_config()
{
  // private [subnet <list>] [hosts <file>]
  char *tok = strtok(NULL," \t\r\n");

  if (tok == NULL) {
    fprintf(stderr,"bad private config: no parameters\n");
    return -1;
  }

  do {
    if (strcasecmp(tok, "subnet") == 0) {
      if (parse_private_subnet() < 0)
	return -1;
    }
    else if (strcasecmp(tok, "hosts") == 0) {
      return parse_private_hosts();
    }
    else {
      fprintf(stderr,"bad private keyword %s, expected \"subnet\" or \"hosts\"\n", tok);
      return -1;
    }
    tok = strtok(NULL," \t\r\n");
  } while(tok != NULL);

  return 0;
}

static int
parse_config_line(char *line)
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
      u_short sval;
      if (nchaddr >= NCHADDR) {
	fprintf(stderr,"out of local chaos addresses, please increas NCHADDR from %d\n",
		NCHADDR);
	return -1;
      }
      if (sscanf(tok,"%ho",&sval) != 1) {
	fprintf(stderr,"chaddr: bad octal argument %s\n",tok);
	return -1;
      } else if (!valid_chaos_host_address(sval)) {
	fprintf(stderr,"chaddr: bad address %#o (both net and host part must be non-zero)\n", sval);
	return -1;
      } else if (verbose)
	printf("Using default Chaos address %#o\n", sval);
      mychaddr[nchaddr++] = sval;
    }
    return 0;
  }
  else if (strcasecmp(tok, "myname") == 0) {
    tok = strtok(NULL," \t\r\n");
    if (tok != NULL) {
      if (strlen(tok) < sizeof(myname)) {
	strncpy(myname, tok, sizeof(myname));
      } else {
	fprintf(stderr,"myname too long: max %zu bytes allowed.\n", sizeof(myname));
	return -1;
      }
    }
    return 0;
  }
  else if (strcasecmp(tok, "chudp") == 0) {
    do_udp = 1;
    return parse_chudp_config_line();
  }
#if CHAOS_TLS
  // tls key keyfile cert certfile ca-chain ca-chain-cert-file [myaddr %o] [ server [ portnr ]]
  else if (strcasecmp(tok, "tls") == 0) {
    // do_tls = 1;
    int v = parse_tls_config_line();
    if (v && do_tls_server)
      do_tls = 1;
    return v;
  }
#endif // CHAOS_TLS
#if CHAOS_DNS
  else if (strcasecmp(tok, "dns") == 0) {
    return parse_dns_config_line();
  }
#endif
#if CHAOS_IP
  else if (strcasecmp(tok,"chip") == 0) {
    // this is pointless unless chip is "dynamic", but...
    // do_chip = 1;
    return parse_chip_config_line();
  }
#endif
#if CHAOS_ETHERP
  else if (strcasecmp(tok, "ether") == 0) {
    // do_ether = 1;
    return parse_ether_config_line();
  }
#endif
  else if (strcasecmp(tok, "unix") == 0)
    return parse_usockets_config();
  else if (strcasecmp(tok, "ncp") == 0) {
    return parse_ncp_config_line();
  }
  else if (strcasecmp(tok, "route") == 0) {
    return parse_route_config();
  }
  else if (strcasecmp(tok, "link") == 0) {
    return parse_link_config();
  }
  else if (strcasecmp(tok, "private") == 0) {
    return parse_private_config();
  }
  else if (strcasecmp(tok,"firewall") == 0) {
    return parse_firewall_config_line();
  } else {
    fprintf(stderr,"config keyword %s unknown\n", tok);
    return -1;
  }
}

static void
parse_config(char *cfile)
{
  // Obtain configuration
  FILE *config = fopen(cfile,"r");
  if (!config) {
    char cwd[MAXPATHLEN];
    fprintf(stderr,"Can't open config file '%s' in %s\n",cfile,getcwd(cwd,sizeof(cwd)));
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
    fclose(config);
  }
}

// Validate that all addresses my mychaddr (declared by "myaddr" params and "chaddr" config)
// have a corresponding link
static void
validate_mychaddrs_links(void)
{
  int i, h, found = 0;
  for (i = 0; i < nchaddr; i++) {
    for (h = 0; h < rttbl_host_len; h++) {
      if ((rttbl_host[h].rt_dest >> 8) == (mychaddr[i] >> 8)) {
	// continue with next mychaddr
	found = 1;
	break;
      }
    }
    if (rttbl_net[mychaddr[i] >> 8].rt_link != LINK_NOLINK)
      found = 1;
    if (!found)
      fprintf(stderr,"%%%% WARNING: myaddr %#o does not seem to have a link defined?\n", mychaddr[i]);
    found = 0;
  }
}

#if CHAOS_DNS
// Validate that all addresses in mychaddr (declared by "myaddr" params and "chaddr" config)
// indeed belong to the Chaos DNS host "mylongname".
static void
validate_mychaddrs_dns(u_char *mylongname)
{
  int i, j;
  u_short myaddrs[16];
  int naddrs = dns_addrs_of_name(mylongname, (u_short *)&myaddrs, 16);
  if (naddrs < -1)
    fprintf(stderr,"%%%% DNS config problem: failure when finding Chaos addresses of your host name %s\n"
	    "%%%% - please check your DNS server settings?\n", mylongname);
  if (naddrs <= 0) {
    fprintf(stderr,"%%%% DNS config problem: can't get Chaos addresses of your Chaos host name %s\n",
	    mylongname);
  } else if (debug)
    fprintf(stderr,"DNS found %d addresses of %s (configured to use %d)\n", naddrs, mylongname, nchaddr);
  for (j = 0; j < nchaddr; j++) {
    int found = 0;
    if (debug) fprintf(stderr," Looking for %#o\n", mychaddr[j]);
    for (i = 0; i < naddrs; i++) {
      if (myaddrs[i] == mychaddr[j]) {
	found = 1;
	break;
      }
    }
    if (!found)
      fprintf(stderr,"Warning: configured to use addr %#o which is not an address of %s in DNS\n",
	      mychaddr[j], mylongname);
  }
}
#endif

// **** Main program

// Print stats on SIGINFO/SIGUSR1
void
print_stats(int sig)
{
  int i;
  if (sig != 0) {
    // fprintf(stderr,"Signal %d received\n", sig);
    printf("My Chaosnet host name %s\n",
	    myname);
    if (nchaddr > 0) {
      printf(" using address%s ", (nchaddr != 1 ? "es" : ""));
      for (i = 0; i < nchaddr && i < NCHADDR; i++)
	printf("%#o ", mychaddr[i]);
      printf("\n");
    }
    if (do_unix)
      print_config_usockets();
    if (do_udp || do_udp6)
      printf("CHUDP enabled on port %d (%s)\n", chudp_port, chudp_dynamic ? "dynamic" : "static");
#if CHAOS_ETHERP
    if (do_ether)
      print_config_ether();
#endif
#if CHAOS_TLS
    if (do_tls || do_tls_server) {
      printf("Using TLS myaddrs %#o",tls_myaddrs[0]);
      for (i = 1; i < tls_n_myaddrs; i++)
	printf(",%#o", tls_myaddrs[i]);
      printf(", keyfile %s, certfile %s, ca-chain %s, crl %s\n", 
	     tls_key_file, tls_cert_file, tls_ca_file, tls_crl_file);
      if (do_tls_server)
	printf(" and starting TLS server at port %d (%s)\n", tls_server_port, do_tls_ipv6 ? "IPv6" : "IPv4");
    }
#endif
#if CHAOS_IP
    print_config_chip();
#endif
#if CHAOS_DNS
    print_config_dns();
    if (do_dns_forwarding) {
      printf(" DNS forwarder enabled\n");
    }
#endif
    if (number_of_private_subnets > 0) {
      printf("Configured %d private subnet%s: ", number_of_private_subnets, 
	     number_of_private_subnets != 1 ? "s" : "");
      for (int i = 0; i < 256; i++)
	if (private_subnet[i]) printf("%#o ", i);
      printf("\n");
      if (private_hosts_file != NULL) {
	printf(" and private hosts from file \"%s\" follow:\n", private_hosts_file);
	print_private_hosts_config();
      }
    }
  }
#if CHAOS_ETHERP
  print_arp_table();
#endif
  print_routing_table();
  print_chudp_config();
#if CHAOS_TLS
  print_tlsdest_config();
#endif
#if CHAOS_IP
  print_chipdest_config();
#endif
  print_link_stats();
  print_host_stats();

  print_ncp_stats();
  print_firewall_rules();	// to get #matches
}

void
usage(char *pname)
{
  fprintf(stderr,"Usage: %s [-c configfile | -d | -v | -s | -t ]\n Default configfile 'cbridge.conf'\n", pname);
  exit(1);
}

int
main(int argc, char *argv[])
{
  signed char c;		/* gaah. */
  char cfile[256] = "cbridge.conf";
  extern char *optarg;

  // parse args
  while ((c = getopt(argc, argv, "c:vdst")) != -1) {
    switch (c) {
    case 'd':
      fprintf(stderr,"Debug on\n");
      debug++;
      break;
    case 'v':
      fprintf(stderr,"Verbose on\n");
      verbose++;
      break;
    case 's':
      fprintf(stderr,"Stats on\n");
      stats++;
      break;
    case 'c':
      if (verbose) fprintf(stderr,"Config file %s\n", optarg);
      strncpy(cfile, optarg, sizeof(cfile));
      break;
#if CHAOS_TLS
    case 't':
      fprintf(stderr,"TLS debug on\n");
      tls_debug++;
      break;
#endif
    default:
      usage(argv[0]);
    }
  }

  // clear myname
  memset(myname, 0, sizeof(myname));

  // initialize private subnets
  memset(private_subnet, 0, sizeof(private_subnet));
#ifdef PRIVATE_CHAOS_SUBNET
  private_subnet[PRIVATE_CHAOS_SUBNET] = 1;
  number_of_private_subnets = 1;
#endif

  // parse config
  parse_config(cfile);

  if (private_hosts_file != NULL && parse_private_hosts_file(private_hosts_file) < 0) {
    fprintf(stderr, "Configuration error: bad private hosts file %s\n", private_hosts_file);
    exit(1);
  }

  // Check config, validate settings
  if (mychaddr[0] == 0) {
    fprintf(stderr,"Configuration error: no Chaos address known, use global \"chaddr\" or \"myaddr\" link param to set one.\n");
    exit(1);
  }
  // validate that all myaddr have a link
  validate_mychaddrs_links();

#if CHAOS_DNS
  // after config, can init DNS
  init_chaos_dns(do_dns_forwarding);

  // check if myname should/can be initialized
  if (myname[0] == '\0') {
    u_char mylongname[256];
    int nlen;
    // look up my address
    if (debug) fprintf(stderr,"Validating address %#o\n", mychaddr[0]);
    if ((nlen = dns_name_of_addr(mychaddr[0], mylongname, sizeof(mylongname))) > 0) {
      if (debug) fprintf(stderr," found name %s\n", mylongname);
      validate_mychaddrs_dns(mylongname);

      // use first part only
      char *c = index((char *)mylongname, '.');
      if (c) *c = '\0';
      // prettify in case lower
      mylongname[0] = toupper(mylongname[0]);
      strncpy(myname, (char *)mylongname, sizeof(myname));
    } else if (nlen < -1) {
      fprintf(stderr,"%%%% DNS config problem: failure when looking up main address %#o in DNS\n"
	      "%%%% - please check your DNS server settings.\n", mychaddr[0]);
    } else {
      fprintf(stderr,"%%%% DNS config problem: can't find main address %#o in DNS\n", mychaddr[0]);
    }
  }
#endif

  // check if myname need be initialized
  if (myname[0] == '\0') {
    if (gethostname(myname, sizeof(myname)) < 0) {
      perror("gethostname");
      // make it ugly
      strcpy(myname,"UNKNOWN");
    } else {
      char *c = index(myname,'.');  /* only use unqualified part */
      if (c)
	*c = '\0';
      // Hack hack
      int l = strlen(myname);
      if (l > 2) {
	// check long host names for short alpha prefixes,
	// and upcase them (e.g. "mx12" => "MX12")
	int d,i;
	for (d = 0; d < l && isalpha(myname[d]); d++);
	if (d < 2) {
	  for (i = 0; i < d; i++)
	    myname[i] = toupper(myname[i]);
	} else
	  // long name with more alphas at start
	  // e.g. "pegasus" => "Pegasus"
	  *myname = toupper(*myname);	/* and prettify lowercase unix-style name */
      } else {
	// short host name, upcase it (e.g. "up" => "UP")
	for (l = 0; myname[l] != '\0'; l++)
	  myname[l] = toupper(myname[l]);
      }
    }
  }

  if (strlen(myname) > 32) {
    // I wonder if this ever will happen.
    fprintf(stderr,"%%%% Warning: your host name is longer than fits in a STATUS packet (32).\r\n");
  }

#if CHAOS_TLS
  // Just a little user-friendly config validation
  if (do_tls || do_tls_server) {
    char *files[] = {tls_ca_file, tls_key_file, tls_cert_file, tls_crl_file };
    char err[PATH_MAX + sizeof("%%%% cannot access ")+3];
    int i;
    for (i = 0; i < 4; i++) {
      if ((strlen(files[i]) > 0) && (access(files[i], R_OK) != 0)) {
	sprintf(err,"%%%% cannot access \"%s\"",files[i]);
	perror(err);
	fprintf(stderr,"%%%% configured for TLS keyfile \"%s\", certfile \"%s\", ca-chain \"%s\", crl \"%s\"\n",
	       tls_key_file, tls_cert_file, tls_ca_file, tls_crl_file);
#if 0
	exit(1);
#endif
      }
    }
  }
#endif

  // Check if routes might need some help
  if (nchaddr > 1) {
    // Only do this if we have more than one Chaos address, which indicates we are connected to more than one subnet,
    // with subnet link or a host link to another subnet, or that we might get a dynamic link.
    int i;
    for (i = 0; i < rttbl_host_len; i++) {
      if ((rttbl_host[i].rt_link != LINK_NOLINK) && (rttbl_host[i].rt_link != LINK_TLS)) {
	if (rttbl_net[rttbl_host[i].rt_dest >> 8].rt_link == LINK_NOLINK) {
	  int sn = rttbl_host[i].rt_dest >> 8;
	  fprintf(stderr,"Warning: you have a host %s link to %#o but no subnet route declared\n"
		  " Consider adding a \"route subnet %o bridge %o\" statement (after all link statements),\n"
		  " so the rest of the network gets to know about net %#o?\n",
		  rt_linkname(rttbl_host[i].rt_link), rttbl_host[i].rt_dest,
		  sn, rttbl_host[i].rt_dest, sn);
	}
      }
    }
  }

#if 1
  if (verbose)
    // Print config
    print_stats(1);
#endif

  // remember when we restarted. This is more interesting than the host boot time.
  boottime = time(NULL);

  // Now start the different threads
  pthread_t threads[256];	/* random medium constant */
  int ti = 0, e = 0;

  // Block SIGINFO/SIGUSR1 in all threads, enable it in main thread below
  sigset_t ss;
  sigemptyset(&ss);
#ifdef SIGINFO
  sigaddset(&ss, SIGINFO);
#endif
  sigaddset(&ss, SIGUSR1);
  if ((e = pthread_sigmask(SIG_BLOCK, &ss, NULL)) != 0)
    fprintf(stderr,"pthread_sigmask(SIG_BLOCK): %s", strerror(e));

  if (do_unix) {
    if (verbose) fprintf(stderr, "Starting thread for UNIX socket\n");
    if ((e = pthread_create(&threads[ti++], NULL, &unix_input, NULL)) != 0) {
      fprintf(stderr,"pthread_create(unix_input): %s", strerror(e));
      abort();
    }
  }
  if (do_udp) {
    if (verbose) fprintf(stderr, "Starting thread for UDP sockets\n");
    if ((e = pthread_create(&threads[ti++], NULL, &chudp_input, &do_udp6)) != 0) {
      fprintf(stderr,"pthread_create(chudp_input): %s", strerror(e));
      abort();
    }
  }
#if CHAOS_ETHERP
  if (do_ether) {
    if (verbose) fprintf(stderr,"Starting thread for Ethernet\n");
    if ((e = pthread_create(&threads[ti++], NULL, &ether_input, NULL)) != 0) {
      fprintf(stderr,"pthread_create(ether_input): %s", strerror(e));
      abort();
    }
  }
#endif // CHAOS_ETHERP
#if CHAOS_IP
  if (do_chip) {
    if (verbose) fprintf(stderr,"Starting thread for Chaos-over-IP\n");
    if ((e = pthread_create(&threads[ti++], NULL, &chip_input, NULL)) != 0) {
      fprintf(stderr,"pthread_create(chip_input): %s", strerror(e));
      abort();
    }
  }
#endif

#if CHAOS_TLS
  if (do_tls_server || do_tls) {
    if (verbose) fprintf(stderr,"Initializing openssl library\n");
    init_chaos_tls();
  }

  if (do_tls_server) {
    if (verbose) fprintf(stderr,"Starting thread for TLS server\n");
    if ((e = pthread_create(&threads[ti++], NULL, &tls_server, NULL)) != 0) {
      fprintf(stderr,"pthread_create(tls_server): %s", strerror(e));
      abort();
    }
  }
  if (do_tls || do_tls_server) {
    if (verbose) fprintf(stderr,"Starting thread for TLS input\n");
    if ((e = pthread_create(&threads[ti++], NULL, &tls_input, NULL)) != 0) {
      fprintf(stderr,"pthread_create(tls_input): %s", strerror(e));
      abort();
    }
    int i;
    for (i = 0; i < tlsdest_len; i++) {
      if (!tlsdest[i].tls_serverp) {
	if (verbose) fprintf(stderr,"Starting thread for TLS client connector %d\n", i);
	if ((e = pthread_create(&threads[ti++], NULL, &tls_connector, &tlsdest[i])) != 0) {
	  fprintf(stderr,"pthread_create(tls_connector %d): %s", i, strerror(e));
	  abort();
	}
      }
    }    
  }
#endif
#if CHAOS_DNS
  if (do_dns_forwarding) {
    if (verbose) fprintf(stderr,"Starting thread for DNS forwarder\n");
    if ((e = pthread_create(&threads[ti++], NULL, &dns_forwarder_thread, NULL)) != 0) {
      fprintf(stderr,"pthread_create(dns_forwarder_thread): %s", strerror(e));
      abort();
    }
  }
#endif

  if ((nchaddr > 1) || (rttbl_host_len > 0)) {
    // Only do this if we're directly on more than one net, or using host links -
    // otherwise we're not really a bridge, just an NCP interface.
    if (verbose) fprintf(stderr,"Starting RUT sender thread\n");
    if ((e = pthread_create(&threads[ti++], NULL, &rut_sender, NULL)) != 0) {
      fprintf(stderr,"pthread_create(rut_sender): %s", strerror(e));
      abort();
    }
  } else {
    if (verbose) fprintf(stderr,"Not starting RUT sender thread: only %d network%s, %d host link%s\n",
			 nchaddr, nchaddr != 1 ? "s" : "",
			 rttbl_host_len, rttbl_host_len != 1 ? "s" : "");
  }

  if (verbose) fprintf(stderr,"Starting route cost updating thread\n");
  if ((e = pthread_create(&threads[ti++], NULL, &route_cost_updater, NULL)) != 0) {
    fprintf(stderr,"pthread_create(route_cost_updater): %s", strerror(e));
    abort();
  }
  if (do_udp || do_udp6
#if CHAOS_IP
      || do_chip
#endif
      ) {
    if (verbose) fprintf(stderr,"Starting hostname re-parsing thread\n");
    if ((e = pthread_create(&threads[ti++], NULL, &reparse_link_host_names_thread, NULL)) != 0) {
      fprintf(stderr,"pthread_create(reparse_link_host_names_thread): %s", strerror(e));
      abort();
    }
  }

  if (ncp_enabled) {
    if (verbose) fprintf(stderr,"Starting NCP\n");
    if ((e = pthread_create(&threads[ti++], NULL, &ncp_user_server, NULL)) != 0) {
      fprintf(stderr,"pthread_create(ncp_user_server): %s", strerror(e));
      abort();
    }
  }

  // Make sure the system reclaims resources automatically, we don't pthread_join them.
  for (int i = 0; i < ti; i++) {
    if ((e = pthread_detach(threads[i])) != 0) {
      fprintf(stderr,"pthread_detach (thread %d): %s\n", i, strerror(e));
      abort();
    }
  }

  // Now unblock SIGINFO/SIGUSR1 in this thread
  if ((e = pthread_sigmask(SIG_UNBLOCK, &ss, NULL)) != 0)
    fprintf(stderr,"pthread_sigmask(SIG_BLOCK emptyset): %s", strerror(e));

  // and set up a handler
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = print_stats;
  sigemptyset(&sa.sa_mask);

#ifdef SIGINFO
  // Easy debugging, press ^T - but why do I get two signals?
  if (verbose || debug) fprintf(stderr,"Enabling SIGINFO\n");
  sigaddset(&sa.sa_mask, SIGINFO);
  if (sigaction(SIGINFO, &sa, NULL) < 0)
    perror("sigaction(SIGINFO)");
#endif
  if (verbose || debug) fprintf(stderr,"Enabling SIGUSR1\n");
  sigaddset(&sa.sa_mask, SIGUSR1);
  if (sigaction(SIGUSR1, &sa, NULL) < 0)
    perror("sigaction(SIGUSR1)");

  while(1) {
    sleep(15);			/* ho hum. */
    if (stats) {
      print_stats(0);
    }
  }
  exit(0);
}
