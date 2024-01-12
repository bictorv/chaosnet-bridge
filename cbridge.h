/* Copyright © 2005, 2017-2021 Björn Victor (bjorn@victor.se) */
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

#ifndef CHAOS_ETHERP
// enable the Chaos-over-Ether code
#define CHAOS_ETHERP 1
#endif

#ifndef CHAOS_TLS
// enable the Chaos-over-TLS code
#define CHAOS_TLS 1
#endif

#ifndef CHAOS_IP
// enable the Chaos-over-IP code
#define CHAOS_IP 1
#endif

#ifndef CHAOS_DNS
// enable the DNS code (forwarder and internal host/addr parser)
#define CHAOS_DNS 1
#endif

#if CHAOS_ETHERP
#ifndef ETHER_BPF
// use BPF rather than sockaddr_ll, e.g. for MacOS
#if __APPLE__ || __OpenBSD__ || __NetBSD__
#define ETHER_BPF 1
#else
#define ETHER_BPF 0
#endif
#endif
#endif

// This subnet is allocated for private non-routed use.
// No routing information about that subnet should be sent outside
// that subnet, no packets from that subnet should be sent to other
// subnets, and any packets received from that subnet on another
// subnet should be dropped. This is similar to the IP private
// networks such as 10.x.y.z or 192.168.x.y.  Subnet 376 is the
// standard, and more can be configured by "private subnet".
#define PRIVATE_CHAOS_SUBNET 0376

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <fcntl.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#if __OpenBSD__ || __NetBSD__
#include <netinet/if_ether.h>
#else
#include <net/ethernet.h>
#endif
#include <ifaddrs.h>
#if CHAOS_ETHERP
#if ETHER_BPF
#include <net/bpf.h>
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif // ETHER_BPF
#endif // CHAOS_ETHERP

#if CHAOS_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#endif
#include <pthread.h>

// Chaos packet defs, opcodes, etc
#include "cbridge-chaos.h"

#if 1
#define PTLOCKN(x,yyyname) { int yyy; if ((yyy = pthread_mutex_lock(&x)) != 0) fprintf(stderr,"%s line %d: FAILED TO LOCK %s: %s (%d)\n", __FILE__, __LINE__, yyyname, strerror(yyy), yyy); }
#define PTUNLOCKN(x,yyyname) { int yyy; if ((yyy = pthread_mutex_unlock(&x)) != 0) fprintf(stderr,"%s line %d: FAILED TO UNLOCK %s: %s (%d) %p\n", __FILE__, __LINE__, yyyname, strerror(yyy), yyy, &x); }
#else
// more extra debug
#define PTLOCKN(x,yyyname) { int yyy; if ((yyy = pthread_mutex_lock(&x)) != 0) fprintf(stderr,"%s line %d: FAILED TO LOCK %s: %s (%d)\n", __FILE__, __LINE__, yyyname, strerror(yyy), yyy); else fprintf(stderr,"%s line %d: locked %s\n", __FILE__, __LINE__, yyyname); }
#define PTUNLOCKN(x,yyyname) { int yyy; if ((yyy = pthread_mutex_unlock(&x)) != 0) fprintf(stderr,"%s line %d: FAILED TO UNLOCK %s: %s (%d) %p\n", __FILE__, __LINE__, yyyname, strerror(yyy), yyy, &x); else fprintf(stderr,"%s line %d: UNlocked %s\n", __FILE__, __LINE__, yyyname); }
#endif

// ==== Route/routing/link structures

// Connection types, cf AIM 628 p14, which states Direct, Fixed, and Bridged.
// We have other ways of saying whether it's bridged or direct, but instead need this:
typedef enum rttype {
  RT_NOPATH=0,
  RT_STATIC,			/* Static route (from config file) */
  RT_DYNAMIC,  /* Dynamic, from RUT pkt or "dynamic" CHUPD/CHIP/etc */
} rttype_t;
// Link implementation types
typedef enum linktype {
  LINK_NOLINK=0,
  LINK_UNIXSOCK,	      /* Chaos-over-Unix sockets ("chaosd") */
  LINK_CHUDP,			/* Chaos-over-UDP ("chudp") */
#if CHAOS_ETHERP
  LINK_ETHER,			/* Chaos-over-Ethernet */
#endif
#if CHAOS_TLS
  LINK_TLS,			/* Chaos-over-TLS */
#endif
#if CHAOS_IP
  LINK_IP,			/* Chaos-over-IP */
#endif
} linktype_t;

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

#define RTTBL_HOST_MAX 64
// Route configuration entry
struct chroute {
  u_short rt_dest;		/* destination addr (subnet<<8 or host) - NOT redundant for subnets, we might not know the index in rttbl_host */
  u_short rt_braddr;		/* bridge address */
  u_short rt_myaddr;		/* my specific address (on that subnet), or use mychaddr */
  rttype_t rt_type;		/* connection type */
  linktype_t rt_link;		/* link implementation */
  u_short rt_cost;		/* cost */
  time_t rt_cost_updated;	/* cost last updated */
#if CHAOS_TLS
// Number of addresses we can multiplex on a connection
#define CHTLS_MAXMUX 4
  u_short rt_tls_muxed[CHTLS_MAXMUX]; /* Other addresses we're muxing for */
#endif
};
#define RT_BRIDGED(rt) ((rt)->rt_braddr != 0)
#define RT_DIRECT(rt) ((rt)->rt_braddr == 0)
#define RT_SUBNETP(rt) (((rt)->rt_dest & 0xff) == 0)
#define RT_PATHP(rt) ((rt)->rt_type != RT_NOPATH)

// STATUS protocol, MIT AIM 628.
// Info on this host's direct connection to a subnet. 
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

// LASTCN protocol, invented by BV
// keep track of when we last saw a host, and from where (and how many pkts we've seen from it)
struct hostat {
  u_int32_t hst_in;		/* pkts received */
  u_int16_t hst_last_hop;	/* last hop router */
  time_t hst_last_seen;		/* time last seen */
  u_int8_t hst_last_fc;		/* forwarding count last time seen */
};

// ================ CHUDP ================
// CHUDP table
#define CHUDPDEST_MAX 64
#define CHUDPDEST_NAME_LEN 128
struct chudest {
  u_short chu_addr;		/* chaos address (or subnet) */
  char chu_name[CHUDPDEST_NAME_LEN]; /* name given in config, to reparse */
  union {
    struct sockaddr chu_saddr;	/* generic sockaddr */
    struct sockaddr_in chu_sin;	/* IP addr */
    struct sockaddr_in6 chu_sin6;  /* IPv6 addr */
  } chu_sa;
};

// ================ TLS ================

#if CHAOS_TLS
#define TLSDEST_MAX 32
// max length of a CN
#define TLSDEST_NAME_LEN 128
// here is a TLS destination
struct tls_dest {
  u_short tls_addr;		/* remote chaos address */
  u_short tls_myaddr;		/* my address on this link */
  char tls_name[TLSDEST_NAME_LEN]; /* name given in (client) config or from CN (in servers) */
  int tls_serverp; /* 1 if server end - don't bother with mutex/cond stuff */
  union {			/* The IP of the other end */
    struct sockaddr tls_saddr;	/* generic sockaddr */
    struct sockaddr_in tls_sin;	/* IP addr */
    struct sockaddr_in6 tls_sin6;  /* IPv6 addr */
  } tls_sa;
  pthread_mutex_t tcp_reconnect_mutex;  /* would you please reconnect me? */
  pthread_cond_t tcp_reconnect_cond;
  int tls_sock;			/* TCP socket */
  SSL *tls_ssl;			/* SSL conn */
  u_short tls_muxed[CHTLS_MAXMUX]; /* See above: Other addresses we're muxing for */
  time_t tls_connection_time;	   /* when was the last connection/attempt made? */
  int tls_open_tries;		   /* how many times we tried to open until successful */
};

// TLS stuff
#define CHAOS_TLS_PORT 42042
#define CBRIDGE_TCP_MAXLEN (CH_PK_MAXLEN+2+12)
// timeout in select (and if no open connections)
#define TLS_INPUT_RETRY_TIMEOUT 1

#endif // CHAOS_TLS

// ================ IP ================
#if CHAOS_IP
#ifndef IPPROTO_CHAOS
// See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#  define IPPROTO_CHAOS 16	/* Chaos */
#endif

#define CHIPDEST_MAX 64
#define CHIPDEST_NAME_LEN 128
struct chipdest {
  u_short chip_addr;		/* chaos address or subnet */
  char chip_name[CHIPDEST_NAME_LEN];
  union {
    struct sockaddr chip_saddr;
    struct sockaddr_in chip_sin;	/* IPv4 addr */
    struct sockaddr_in6 chip_sin6;
  } chip_sa;
};
#endif // CHAOS_IP

// ================ data declarations ================

// @@@@ replace by better logging system, levels, facilities...
extern int verbose, debug, stats;

// locks for datastructures
extern pthread_mutex_t rttbl_lock, linktab_lock;

// Route table, indexed by subnet
extern struct chroute rttbl_net[];
// and for individual hosts, simple array, where rt_braddr is the dest
extern struct chroute rttbl_host[];
extern int rttbl_host_len;

// CHUDP link configurations
extern struct chudest chudpdest[];
extern int chudpdest_len;	/* cf CHUDPDEST_MAX */

// for LASTCN: array indexed first by net, then by host. Second level dynamically allocated.
extern struct hostat *hosttab[];
extern pthread_mutex_t hosttab_lock;

// for STATUS: simple array indexed by subnet, updated for send/receives on routes with direct link
extern struct linkstat linktab[];

#if CHAOS_TLS
// TLS link configuration
extern pthread_mutex_t tlsdest_lock;	/* for locking tlsdest */
extern struct tls_dest tlsdest[];	/* table of tls_dest entries */
extern int tlsdest_len;	/* cf TLSDEST_MAX */
#endif

// array of my chaosnet addresses, first element is the default
// @@@@ replace by function
extern int nchaddr; // number of addresses in mychaddr
extern u_short mychaddr[];

#if CHAOS_IP
extern int chipdest_len;
extern struct chipdest chipdest[CHIPDEST_MAX];
#endif

// ================ function declarations ================

void send_chaos_pkt(u_char *pkt, int len);
int is_mychaddr(u_short addr);
int mychaddr_on_net(u_short addr);
u_short find_closest_addr(u_short addrs[], int naddrs);
u_short find_my_closest_addr(u_short addr);
void add_mychaddr(u_short addr);
int valid_chaos_host_address(u_short addr);
int is_private_subnet(u_short subnet);
int valid_opcode(int opc);

char *rt_linkname(u_char linktype);
char *rt_typename(u_char type);

struct chroute *add_to_routing_table(u_short dest, u_short braddr, u_short myaddr, int type, int link, int cost);

void htons_buf(u_short *ibuf, u_short *obuf, int len);
void ntohs_buf(u_short *ibuf, u_short *obuf, int len);
int get_packet_string(struct chaos_header *pkt, u_char *out, int outsize);
void print_buf(u_char *ucp, int cnt);
void ch_dumpkt(u_char *ucp, int cnt);
void dumppkt_raw(unsigned char *ucp, int cnt);
unsigned int ch_checksum(const unsigned char *addr, int count);
char *ip46_ntoa(struct sockaddr *sa, char *buf, int buflen);

int ch_11_gets(unsigned char *in, unsigned char *out, int maxlen);
int ch_11_puts(unsigned char *out, unsigned char *in);
char *ch_opcode_name(int op);

#if CHAOS_TLS
void close_tls_route(struct chroute *rt);
#endif

#if CHAOS_IP
int validate_chip_entry(struct chipdest *cd, struct chroute *rt, int subnetp, int nchaddr);
#endif

void print_routing_table(void);

struct chroute *find_in_routing_table(u_short dchad, int only_host, int also_nopath);
void forward_chaos_pkt(struct chroute *src, u_char cost, u_char *data, int dlen, u_char src_linktype);

#if CHAOS_DNS
int dns_name_of_addr(u_short chaddr, u_char *namestr, int namestr_len);
int dns_addrs_of_name(u_char *namestr, u_short *addrs, int addrs_len);
#endif
