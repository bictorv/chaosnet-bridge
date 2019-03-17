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

#include "cbridge.h"

// TODO
// rewrite using pcap (replace BPF) - then implement multiple interfaces?

extern char ifname[128];

/* **** Chaos-over-Ethernet functions **** */

static int chfd = 0, arpfd = 0;

static u_char myea[ETHER_ADDR_LEN];		/* My Ethernet address */
static u_char eth_brd[ETHER_ADDR_LEN] = {255,255,255,255,255,255};

static pthread_mutex_t charp_lock = PTHREAD_MUTEX_INITIALIZER;

#if !ETHER_BPF
static int ifix;		/* ethernet interface index */
#endif


// Chaos ARP table
static struct charp_ent charp_list[CHARP_MAX];
static int charp_len = 0;			/* cf CHARP_MAX */

// Find the ethernet address of the configured interface (ifname)
static void get_my_ea() {
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
static int
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
static void
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
    if (debug && (ethtype == ETHERTYPE_CHAOS)) {
      u_char pk[CH_PK_MAXLEN];
      ntohs_buf((u_short *)packet, (u_short *)pk, packetlen);
      ch_dumpkt(pk, packetlen);
    }
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

static int
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
      } else if (stats || verbose) {
	printf("ARP %s for protocol %#x",
	       arp->ar_op == htons(ARPOP_REQUEST) ? "Request" :
	       (arp->ar_op == htons(ARPOP_REPLY) ? "Reply" :
		(arp->ar_op == htons(ARPOP_RREQUEST) ? "Reverse request" :
		 (arp->ar_op == htons(ARPOP_RREPLY) ? "Reverse reply" : "?"))),
	       ntohs(arp->ar_pro));
	printf(", dest addr ");
	if (arp->ar_pln == 2)
	  printf("%#o ", ntohs(buf[sizeof(struct arphdr)+(2 * (arp->ar_hln))+arp->ar_pln]<<8 |
			       buf[sizeof(struct arphdr)+(2 * (arp->ar_hln))+arp->ar_pln+1]));
	else
	  for (i = 0; i < arp->ar_pln; i++)
	    printf("%#x ", buf[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln+i]);
	printf("from src ");
	for (i = 0; i < arp->ar_hln; i++)
	  printf("%02X ", buf[sizeof(struct arphdr)+i]);
	printf("\n");
      }
    }
    else if (protocol == htons(ETHERTYPE_CHAOS)) {
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

void print_arp_table()
{
  int i;
  if (charp_len > 0) {
    printf("Chaos ARP table:\n"
	   "Chaos\tEther\t\t\tAge (s)\n");
    for (i = 0; i < charp_len; i++)
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

static u_char *find_arp_entry(u_short daddr)
{
  int i;
  if (debug) fprintf(stderr,"Looking for ARP entry for %#o, ARP table len %d\n", daddr, charp_len);
  if (is_mychaddr(daddr)) {	// #### maybe also look for rt_myaddr matches...
    fprintf(stderr,"#### Looking up ARP for my own address, BUG!\n");
    return NULL;
  }
  
  PTLOCK(charp_lock);
  for (i = 0; i < charp_len; i++)
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

// Find my chaos address on the ether link #### check config that there are no conflicting addrs?
static u_short find_ether_chaos_address() {
  int i;
  u_short ech = 0;
  PTLOCK(rttbl_lock);
  for (i = 0; i < rttbl_host_len; i++) {
    if (rttbl_host[i].rt_link == LINK_ETHER) {
      ech = rttbl_host[i].rt_myaddr;
      break;
    }
  }
  if (ech == 0) {
    for (i = 0; i < 255; i++) {
      if (rttbl_net[i].rt_link == LINK_ETHER) {
	ech = rttbl_net[i].rt_myaddr;
	break;
      }
    }
  }
  PTUNLOCK(rttbl_lock);
  return (ech == 0 ? mychaddr[0] : ech);  // hmm, are defaults good?
}

void
send_chaos_arp_request(int fd, u_short chaddr)
{
  static u_short eth_chaddr = 0;
  u_char req[sizeof(struct arphdr)+(ETHER_ADDR_LEN+2)*2];
  struct arphdr *arp = (struct arphdr *)&req;

  if (eth_chaddr == 0) {
    eth_chaddr = find_ether_chaos_address();
    if (verbose) fprintf(stderr,"My Ethernet Chaos addr is %#o\n", eth_chaddr);
  }

  memset(&req, 0, sizeof(req));
  arp->ar_hrd = htons(ARPHRD_ETHER); /* Want ethernet address */
  arp->ar_pro = htons(ETHERTYPE_CHAOS);	/* of a Chaosnet address */
  arp->ar_hln = ETHER_ADDR_LEN;
  arp->ar_pln = sizeof(chaddr);
  arp->ar_op = htons(ARPOP_REQUEST);
  memcpy(&req[sizeof(struct arphdr)], &myea, ETHER_ADDR_LEN);	/* my ether */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN], &eth_chaddr, sizeof(eth_chaddr)); /* my chaos */
  /* his chaos */
  memcpy(&req[sizeof(struct arphdr)+ETHER_ADDR_LEN+2+ETHER_ADDR_LEN], &chaddr, sizeof(chaddr));

  send_packet(fd, ETHERTYPE_ARP, eth_brd, ETHER_ADDR_LEN, req, sizeof(req));
}

static void
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

static void handle_arp_input(u_char *data, int dlen)
{
  if (debug) fprintf(stderr,"Handle ARP\n");
  /* Chaos over Ethernet */
  struct arphdr *arp = (struct arphdr *)data;
  static u_short eth_chaddr = 0;
  u_short schad = ntohs((data[sizeof(struct arphdr)+arp->ar_hln]<<8) |
			data[sizeof(struct arphdr)+arp->ar_hln+1]);
  u_char *sead = &data[sizeof(struct arphdr)];
  u_short dchad =  ntohs((data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln]<<8) |
			 data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln+1]);

  // don't create a storm
  if (memcmp(sead, eth_brd, ETHER_ADDR_LEN) == 0)
    return;

  if (eth_chaddr == 0) {
    eth_chaddr = find_ether_chaos_address();
    if (verbose) fprintf(stderr,"My Ethernet Chaos addr is %#o\n", eth_chaddr);
  }

  if (debug) printf("ARP rcv: Dchad: %o %o => %o\n",
		    data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln+1]<<8,
		    data[sizeof(struct arphdr)+arp->ar_hln+arp->ar_hln+arp->ar_pln],
		    dchad);

  /* See if we proxy for this one */
  if (arp->ar_op == htons(ARPOP_REQUEST)) {
    if (dchad == eth_chaddr || is_mychaddr(dchad)) {
      if (verbose) printf("ARP: Sending reply for %#o (me) to %#o\n", dchad, schad);
      send_chaos_arp_reply(arpfd, schad, sead, dchad); /* Yep. */
    } else {
      if (debug) printf("ARP: Looking up %#o...\n",dchad);
      struct chroute *found = find_in_routing_table(dchad, 0, 0);
      if (found != NULL && found->rt_dest == dchad
	  && found->rt_link != LINK_ETHER && found->rt_type == RT_DIRECT) {
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
  for (i = 0; i < charp_len; i++)
    if (charp_list[i].charp_chaddr == schad) {
      found = 1;
      charp_list[i].charp_age = time(NULL);  // update age
      if (memcmp(&charp_list[i].charp_eaddr, sead, ETHER_ADDR_LEN) != 0) {
	memcpy(&charp_list[i].charp_eaddr, sead, ETHER_ADDR_LEN);
	if (verbose) {
	  fprintf(stderr,"ARP: Changed MAC addr for %#o\n", schad);
	  print_arp_table();
	}
      } else
	if (verbose) {
	  fprintf(stderr,"ARP: Updated age for %#o\n", schad);
	  print_arp_table();
	}
      break;
    }
  /* It's not in the list already, is there room? */
  if (!found && charp_len < CHARP_MAX) {
    if (verbose) printf("ARP: Adding new entry for Chaos %#o\n", schad);
    charp_list[charp_len].charp_chaddr = schad;
    charp_list[charp_len].charp_age = time(NULL);
    memcpy(&charp_list[charp_len++].charp_eaddr, sead, ETHER_ADDR_LEN);
    if (verbose) print_arp_table();
  }
  PTUNLOCK(charp_lock);
}

static void arp_input(int arpfd, u_char *data, int dlen) {
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
#endif // COLLECT_STATS
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
	struct chroute *srcrt = find_in_routing_table(srcaddr, 0, 0);
	forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			  srcrt != NULL ? srcrt->rt_type : RT_DIRECT,
			  srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
			  (u_char *)&data, len, LINK_ETHER);  /* forward to appropriate links */
      }
    }
  }
}

void
forward_on_ether(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  if (debug) fprintf(stderr,"Forward ether from %#o to %#o\n", schad, dchad);
  // Skip Chaos trailer on Ether, nobody uses it, it's redundant given Ethernet header/trailer
  dlen -= CHAOS_HW_TRAILERSIZE;
  htons_buf((u_short *)ch, (u_short *)ch, dlen);
  if (dchad == 0) {		/* broadcast */
    if (debug) fprintf(stderr,"Forward: Broadcasting on ether from %#o\n", schad);
    send_packet(chfd, ETHERTYPE_CHAOS, eth_brd, ETHER_ADDR_LEN, data, dlen);
  } else {
    if (rt->rt_type == RT_BRIDGE)
      // the bridge is on Ether, but the dest might not be
      dchad = rt->rt_braddr;
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
}

void
print_config_ether() 
{
  int i;
  printf("Using Ethernet interface %s, ether address ", ifname);
  for (i = 0; i < ETHER_ADDR_LEN-1; i++)
    printf("%02X:",myea[i]);
  printf("%02X\n",myea[i]);
}

// module initialization
void init_chaos_ether() 
{
  get_my_ea();
  if ((arpfd = get_packet_socket(ETHERTYPE_ARP, ifname)) < 0)
    exit(1);
  if ((chfd = get_packet_socket(ETHERTYPE_CHAOS, ifname)) < 0)
    exit(1);
}
