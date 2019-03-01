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

// Uses libpcap for input, libnet for output

#include "cbridge.h"

// For Linux, install libnet1-dev
#if __APPLE__
// For Mac using "port", install libnet11 (not libnet).
// It's installed in /opt/local/{include,lib} on Mac
// For some reason these need to be defined before including libnet.h - how stable/reliable is this library...?
#define LIBNET_LIL_ENDIAN 1
#define __GLIBC__ 1
#endif

#include "libnet.h"
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>


extern char ifname[128];	/* default */
char chip_ifname[128];		/* chip specific config */

static struct in_addr my_ip;
static struct libnet_in6_addr my_ip6;

static pthread_mutex_t chipdest_lock = PTHREAD_MUTEX_INITIALIZER;
struct chipdest chipdest[CHIPDEST_MAX];
int chipdest_len = 0;

static libnet_ptag_t ip_ptag = 0;
static libnet_t *ip_ctx;		/* libnet context */
static libnet_ptag_t ip6_ptag = 0;
static libnet_t *ip6_ctx;		/* libnet context */
static char ip_errbuf[LIBNET_ERRBUF_SIZE];
  
// pcap
static pcap_t *ip_pc;
static char pc_errbuf[PCAP_ERRBUF_SIZE];

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

// chip ip a.b.c.d ipv6 aa:bb::42 interface eth0
int
parse_chip_config_line()
{
  char *tok = NULL;
  while ((tok = strtok(NULL," \t\r\n")) != NULL) {
    if (strcasecmp(tok, "ip") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"chip: no ip address specificed\n"); return -1; }
      if (inet_aton(tok, &my_ip) != 1) { fprintf(stderr,"chip: invalid ip address '%s'\n", tok); return -1; }
    } else if (strcasecmp(tok, "ipv6") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"chip: no ipv6 address specificed\n"); return -1; }
      if (inet_pton(AF_INET6, tok, &my_ip6) != 1) { fprintf(stderr,"chip: invalid ipv6 address '%s'\n", tok); return -1; }
    } else if (strcasecmp(tok, "interface") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"chip: no interface specificed\n"); return -1; }
      strncpy(chip_ifname, tok, sizeof(chip_ifname));
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
  char ip6[INET6_ADDRSTRLEN];

  // oh horror.
  if (chip_ifname[0] == '\0')
    memcpy(chip_ifname, ifname, sizeof(chip_ifname));

  if (inet_ntop(AF_INET6, &my_ip6, ip6, sizeof(ip6)) == NULL)
    strerror_r(errno, ip6, sizeof(ip6));
  printf("CHIP: using interface %s, IP address %s, IPv6 address %s\n", chip_ifname, inet_ntoa(my_ip), ip6);
}

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
  // if (verbose) print_chip_config();
  PTUNLOCK(chipdest_lock);
}

void
init_chaos_ip()
{
  // init libnet
  if ((ip_ctx = libnet_init(LIBNET_RAW4, chip_ifname, ip_errbuf)) == NULL) {
    fprintf(stderr,"libnet_init failed\n");
    exit(1);
  }
  // IPv6 needs a separate context
  if ((ip6_ctx = libnet_init(LIBNET_RAW6, chip_ifname, ip_errbuf)) == NULL) {
    fprintf(stderr,"libnet_init failed (IPv6)\n");
    exit(1);
  }
  // there may be more than one address on the interface
  if (my_ip.s_addr == 0)
    my_ip.s_addr = libnet_get_ipaddr4(ip_ctx);  /* save my IPv4 address on that interface */
  // there is very probably more than one address on the interface
  // @@@@ consider doing a version of libnet_get_ipaddr6 which looks for non-LL addresses?
  if (my_ip6.libnet_s6_addr[0] == 0) {
    my_ip6 = libnet_get_ipaddr6(ip6_ctx);  /* save my IPv6 address on that interface */
  }
  

  // init libpcap
  if ((ip_pc = pcap_create(chip_ifname, pc_errbuf)) == NULL) {
    perror("pcap_create");
    exit(1);
  }
  if (pcap_set_snaplen(ip_pc, ETHER_MTU + 100) < 0) {	/* fuzz */
    perror("pcap_set_snaplen");
    exit(1);
  }
  if (pcap_set_immediate_mode(ip_pc, 1) < 0) {
    perror("pcap_set_immediate_mode");
    exit(1);
  }

  if (pcap_activate(ip_pc) < 0) {
    perror("pcap_activate");
    exit(1);
  }

  struct bpf_insn bpf_pftab[128];
  struct bpf_program bpf_pfilter = {0, bpf_pftab};
  struct bpf_program *pfp = &bpf_pfilter;
  char bpfilter[64];
  sprintf(bpfilter, "(ip proto %d) || (ip6 proto %d)", IPPROTO_CHAOS, IPPROTO_CHAOS);
  if (pcap_compile(ip_pc, pfp, bpfilter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
    perror("pcap_compile");
    exit(1);
  }
  if (pcap_setfilter(ip_pc, pfp) < 0) {
    perror("pcap_setfilter");
    exit(1);
  }
  if (pcap_setdirection(ip_pc, PCAP_D_IN) < 0) {
    perror("pcap_setdirection");
    exit(1);
  }
  if (pcap_set_datalink(ip_pc, DLT_EN10MB) < 0) {
    perror("pcap_set_datalink");
    exit(1);
  }
}

void *
chip_input(void *v)
{
  int len, chlen;
  u_short srcaddr;		/* chaos source */
  struct in_addr ip_src;	/* ip source */
  struct in6_addr ip6_src;	/* ipv6 source */
  struct pcap_pkthdr pkt_header;
  const u_char *pkt_data;
#if 0
  // @@@@ IPv6
  u_char data[CH_PK_MAXLEN+IP_HEADER_SIZE+ETHER_HEADER_SIZE];
  u_char *ipdata = &data[ETHER_HEADER_SIZE];
  u_char *chdata = &data[IP_HEADER_SIZE+ETHER_HEADER_SIZE];
#else
  u_char *ipdata, *chdata;
#endif
  int iphl, ipv;
  struct chaos_header *ch;
  
  int fd = pcap_get_selectable_fd(ip_pc);

  while (1) {
    pkt_data = pcap_next(ip_pc, &pkt_header);
    if (pkt_data) {
#if 0
      // Do we really need to copy it? Naah.
      bzero(data, sizeof(data));
      memcpy(data, pkt_data, len);
#else
      ipdata = (u_char *)pkt_data + ETHER_HEADER_SIZE;
      iphl = ((struct ip *)ipdata)->ip_hl;
      ipv = ((struct ip *)ipdata)->ip_v;
      chdata = (u_char *)pkt_data + ETHER_HEADER_SIZE + iphl;
#endif
      ch = (struct chaos_header *)chdata;
      len = pkt_header.caplen;
      chlen = len - (ETHER_HEADER_SIZE+iphl);

      // Check length
      if (chlen <= 0) {
	if (debug) fprintf(stderr,"pcap_next: no content, only %d bytes read\n", len);
	continue;
      }
      // check Chaos trailer (incl checksum)
      if (chlen < (CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)) {
	fprintf(stderr,"CHIP: short packet received, no room for hw trailer: %d\n", len);
	PTLOCK(linktab_lock);
	linktab[srcaddr>>8].pkt_badlen++;
	PTUNLOCK(linktab_lock);
	continue;
      } else if (chlen > (CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE)) {
	fprintf(stderr,"CHIP: long pkt received: %d. expected %ld\n",
		len, (ETHER_HEADER_SIZE+iphl+CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE));
      }


      // get IP sender
      if (ipv == 4) {
	memcpy(&ip_src, (u_char *)&((struct ip *)ipdata)->ip_src.s_addr, sizeof(ip_src));
	// @@@@ maybe get ip_dest too, and check it's for us, and whether it's broadcast
      } else if (ipv == 6) {
	memcpy(&ip6_src, (u_char *)&((struct ip6_hdr *)ipdata)->ip6_src, sizeof(ip6_src));
      } else {
	fprintf(stderr,"%%%% CHIP: IP version not 4 or 6 (%d), dropping\n", ipv);
	continue;
      }

      // Get it in host order
      ntohs_buf((u_short *)chdata, (u_short *)chdata, chlen);

      // Process trailer info
      struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)(chdata-CHAOS_HW_TRAILERSIZE);
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
	fprintf(stderr,"CHIP from %s (Chaos hw %#o) received: %d bytes from Chaos source %#o\n",
		ipaddr, srcaddr, chlen, ch_srcaddr(ch));
	if (!found) {
	  fprintf(stderr,"%%%% CHIP pkt received from unknown source %s - dropping it\n", ipaddr);
	  return 0;
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
  u_long src_ip, dst_ip;

  dst_ip = ((struct sockaddr_in *)sout)->sin_addr.s_addr;
  src_ip = my_ip.s_addr;

  // Construct an IP packet
  if ((ip_ptag = libnet_build_ipv4(LIBNET_IPV4_H + pklen,  /* length */
				   0,  /* TOS */
				   0,	 /* IP ID @@@@ */
				   0,  /* IP frag */
				   64,  /* TTL */
				   IPPROTO_CHAOS,  /* IP protocol */
				   0,  /* checksum (autofill) */
				   src_ip,  /* source IP */
				   dst_ip,  /* dest IP */
				   pkt,	 /* payload */
				   pklen,  /* payload length */
				   ip_ctx,  /* libnet context */
				   ip_ptag)) == -1) {  /* reuse previous packet if you can */
    fprintf(stderr,"CHIP: build ipv4 failed: %s\n", libnet_geterror(ip_ctx));
    exit(1);
  }

  if (debug) {
    fprintf(stderr,"CHIP: About to send IP pkt:\n");
    dumppkt_raw(libnet_getpbuf(ip_ctx, ip_ptag), libnet_getpbuf_size(ip_ctx, ip_ptag));
  }

  if (debug) fprintf(stderr,"CHIP: Sending %d bytes\n", libnet_getpacket_size(ip_ctx));
  if ((c = libnet_write(ip_ctx)) == -1) {
    fprintf(stderr,"CHIP: write failed: %s\n", libnet_geterror(ip_ctx));
    exit(1);
  } 
}

static void 
chip_send_pkt_ipv6(struct sockaddr_in6 *sout, u_char *pkt, int pklen)
{
  int c;
  struct libnet_in6_addr dst_ip6;

  memcpy(&dst_ip6, &sout->sin6_addr.s6_addr, sizeof(dst_ip6));

  // Construct an IPv6 packet
  if ((ip6_ptag = libnet_build_ipv6(0, /* traffic class */
				   0, /* flow label */
				   LIBNET_IPV6_H + pklen, /* total length */
				   IPPROTO_CHAOS,  /* next header */
				   64,  /* hop limit */
				   my_ip6,  /* source IP */
				   dst_ip6,  /* dest IP */
				   pkt,	 /* payload */
				   pklen,  /* payload length */
				   ip6_ctx,  /* libnet context */
				   ip6_ptag)) == -1) {  /* reuse previous packet if you can */
    fprintf(stderr,"CHIP: build ipv6 failed: %s\n", libnet_geterror(ip_ctx));
    exit(1);
  }

  if (debug) {
    fprintf(stderr,"CHIP: About to send IPv6 pkt:\n");
    dumppkt_raw(libnet_getpbuf(ip_ctx, ip_ptag), libnet_getpbuf_size(ip_ctx, ip_ptag));
  }

  if (debug) fprintf(stderr,"CHIP: Sending %d bytes\n", libnet_getpacket_size(ip_ctx));
  if ((c = libnet_write(ip_ctx)) == -1) {
    fprintf(stderr,"CHIP: write failed: %s\n", libnet_geterror(ip_ctx));
    exit(1);
  } 
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

void
forward_on_ip(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  int i, found = 0;

  // Swap back to network order
  htons_buf((u_short *)ch, (u_short *)ch, dlen);

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
	  ((chipdest[i].chip_addr & 0xff00) == 0) && ((chipdest[i].chip_addr & 0xff) == (dchad & 0xff00)>>8)
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
	  else
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
