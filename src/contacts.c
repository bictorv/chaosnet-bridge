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

#include <sys/types.h>
#include <sys/socket.h>
#include "cbridge.h"

extern time_t boottime;
extern char myname[32];
#if CHAOS_TLS
extern int do_tls_server;
#endif

// RFC handler struct (the contacts this process handles)
struct rfc_handler {
  char *contact;
  void (*handler)(u_char *, int);
};

// declare some handlers
void status_responder(u_char *, int);
void lastcn_responder(u_char *, int);
void dump_routing_table_responder(u_char *, int);
void uptime_responder(u_char *, int);
void time_responder(u_char *, int);
#if CHAOS_DNS
void dns_responder(u_char *, int);
#endif

// the contacts and their handler function
static struct rfc_handler mycontacts[] = {
  { "STATUS", &status_responder },
  { "LASTCN", &lastcn_responder },
  { "DUMP-ROUTING-TABLE", &dump_routing_table_responder },
  { "UPTIME", &uptime_responder },
  { "TIME", &time_responder },
#if CHAOS_DNS
  { "DNS", &dns_responder },
#endif
  { NULL, NULL}			/* end marker */
};


// Return the "best" response address for a BRD request
static u_short 
brd_response_addr(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short dst, src = ch_srcaddr(ch);

  if (nchaddr == 1)		// There can be only one!
    return mychaddr[0];

  // Initial attempt: find the one closest to the sender
  if (len >= CHAOS_HEADERSIZE + ch_nbytes(ch) + CHAOS_HW_TRAILERSIZE) {
    // If there is a trailer, use it - we'll most likely send the response in that direction
    struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)(rfc+len-CHAOS_HW_TRAILERSIZE);
    dst = find_my_closest_addr(htons(tr->ch_hw_srcaddr));
  } else
    dst = find_my_closest_addr(src);

  if (ch_opcode(ch) != CHOP_BRD) // only BRD has mask
    return dst;

  // Now for the overkill: check if we can find one that is "more friendly" to the recipient.
  // This is just to make displays of BRD responses for specific subnets easier to read/understand.
  u_int masksize = ch_ackno(ch)*8;
  u_char mask[32];
  // broadcast mask (unswapped)
  htons_buf((u_short *)&rfc[CHAOS_HEADERSIZE], (u_short *)mask, ch_ackno(ch));
  // If "my closest addr" is not on a requested subnet,
  // but I have an address on a/the requested one, use that instead
  return myaddr_for_subnet_mask(dst, mask, masksize);
}

// Make a RUT pkt for someone (dest), filtering out its own subnet and nets it is the bridge for already.
int
make_routing_table_pkt(u_short dest, u_char *pkt, int pklen)
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_char *data = &pkt[CHAOS_HEADERSIZE];
  int i, cost, nroutes = 0;
  // there is a subnet link to the subnet we're constructing a RUT pkt to, and we have a direct link to it
  int directdestp = RT_PATHP(&rttbl_net[dest>>8]) && RT_DIRECT(&rttbl_net[dest>>8]);
  int maxroutes = (pklen-CHAOS_HEADERSIZE)/4;  /* that fit in this pkt, max 122 */
  if (maxroutes > 122)
    maxroutes = 122;

  memset(pkt, 0, pklen);
  set_ch_opcode(cha, CHOP_RUT);

  PTLOCKN(rttbl_lock,"rttbl_lock");
  for (i = 0; (i < 0xff) && (nroutes <= maxroutes); i++) {
    struct chroute *hostpath = NULL;
    if (RT_PATHP(&rttbl_net[i])
	// don't send routes which are already stale
	&& (rttbl_net[i].rt_cost < RTCOST_HIGH)
	// don't send a subnet route to the subnet itself (but to individual hosts)
	&& (! (((dest & 0xff) == 0) && (i == (dest>>8))))
	// and not to the bridge itself
	&& (rttbl_net[i].rt_braddr != dest)
	// don't include routes which are reachable through the dest
	&& (! (((dest & 0xff) == 0) // subnet dest, and 
	       // someone else is the bridge and it's not a broadcast/direct route
	       && RT_BRIDGED(&rttbl_net[i]) && (!is_mychaddr(rttbl_net[i].rt_braddr))
	       // route for this subnet route is through a host on the dest subnet
	       // and this subnet route is direct and the bridge has a host route
	       && (((rttbl_net[i].rt_braddr >> 8) == (dest >> 8)) &&
		   !directdestp &&
		   // and we have a host route to the bridge
		   (((hostpath = find_in_routing_table(rttbl_net[i].rt_braddr, 1, 0)) == NULL)
		    || (hostpath->rt_dest == 0))) // which is connected
	       ))
	) {
      if (is_private_subnet(i)) {
	// Don't advertise route to this subnet
	if (debug || verbose)
	  fprintf(stderr," NOT including private subnet %#o\n", i);
	continue;
      }
      data[nroutes*4+1] = i;
      cost = rttbl_net[i].rt_cost;
      data[nroutes*4+2] = (cost >> 8);
      data[nroutes*4+3] = (cost & 0xff);
      if (debug) fprintf(stderr," including net %#o cost %d\n", i, cost);
      nroutes++;
    } else if (debug && (rttbl_net[i].rt_type != RT_NOPATH)) {
      if (i == (dest >> 8))
	fprintf(stderr, " NOT including net %#o for dest %#o (same subnet)\n", i, dest);
      else if (rttbl_net[i].rt_braddr == dest) 
	fprintf(stderr, " NOT including net %#o (bridge %#o) for dest %#o\n", i, rttbl_net[i].rt_braddr, dest);
      else if (((rttbl_net[i].rt_braddr >> 8) == (dest >> 8)) && directdestp && (hostpath != NULL))
	fprintf(stderr, " NOT including net %#o (bridge %#o is on dest subnet %#o, direct, have host path)\n", i, rttbl_net[i].rt_braddr, dest>>8);
      else 
	// extra debug
	fprintf(stderr, " NOT including net %#o bridge %#o dest %#o %s path %p cost %d (anyway)\n", 
		i, rttbl_net[i].rt_braddr, dest, directdestp ? "direct" : "indirect", hostpath, rttbl_net[i].rt_cost);
    }
  }
  PTUNLOCKN(rttbl_lock,"rttbl_lock");
  set_ch_destaddr(cha, 0);	/* RUT pkts must be sent to dest 0 */
  set_ch_nbytes(cha,nroutes*4);
  if (ch_nbytes(cha) > 0)
    return ch_nbytes(cha)+CHAOS_HEADERSIZE;
  else
    return 0;
}

// Implement DUMP-ROUTING-TABLE for bridge, 
// so CHAOS:SHOW-ROUTING-PATH (LMI) and CHAOS:PRINT-ROUTING-TABLE (Symbolics) could work.
// See SYS:NETWORK.CHAOS;CHSNCP LISP
// ;;; Routing table format: for N subnets, N*4 bytes of data, holding N*2 words
// ;;; For subnet n, pkt[2n] has the method; if this is less than 400 (octal), it's
// ;;; an interface number; otherwise, it's a host which will forward packets to that
// ;;; subnet.  pkt[2n+1] has the host's idea of the cost.
// (Stupid format, can only handle subnets up to decimal #122 - RUT
// handles 122 subnets regardless of their actual subnet number.)
// Note: thus no need to filter out PRIVATE_CHAOS_SUBNET. Unless it would fit.

static int
make_dump_routing_table_pkt(u_char *pkt, int pklen)
{
  u_short *data = (u_short *)&pkt[CHAOS_HEADERSIZE];
  int sub, cost, nroutes = 0;
  int maxroutes = (pklen-CHAOS_HEADERSIZE)/4;  /* that fit in this pkt, max 122 */
  if (maxroutes > 122)
    maxroutes = 122;

  memset(data, 0, pklen-CHAOS_HEADERSIZE);

  PTLOCKN(rttbl_lock,"rttbl_lock");
  for (sub = 0; (sub < 0xff) && (sub <= maxroutes); sub++) {
    struct chroute *hostr, *rt = &rttbl_net[sub];
    if (is_private_subnet(sub)) {
      if (debug || verbose) 
	fprintf(stderr," NOT adding routing for private subnet %#o\n", sub);
      continue;
    }
    if ((rt->rt_type != RT_NOPATH) &&
#if CHAOS_TLS
	(rt->rt_type == RT_STATIC) && (rt->rt_link == LINK_TLS) // manually configured TLS route
	? ((rt->rt_braddr != 0) // using a bridge 
	   // with a host route which is up/connected
	   && ((hostr = find_in_routing_table(rt->rt_braddr,1,0)) != 0) && (hostr->rt_dest != 0)) : 
#endif
	 1) {
      // Method: if < 0400: interface number; otherwise next hop address
      if (RT_DIRECT(rt) || (is_mychaddr(rt->rt_braddr))) {
	// interface nr - use link type
	data[sub*2] = htons(rt->rt_link);
      } else {
	data[sub*2] = htons(rt->rt_braddr);
      }
      cost = rt->rt_cost;
      data[sub*2+1] = htons(cost);
      if (debug) fprintf(stderr," Adding routing for subnet %#o (meth %#o, cost %d)\n",
			 sub, data[sub*2], cost);
      nroutes = sub;
    }
  }
  PTUNLOCKN(rttbl_lock,"rttbl_lock");
#if CHAOS_TLS
  // Now check if we're a tls server and have active tls links to us, for a subnet we didn't already note above
  if (do_tls_server) {
    PTLOCKN(tlsdest_lock,"tlsdest_lock");
    for (int i = 0; i < tlsdest_len; i++) {
      struct tls_dest *td = &tlsdest[i];
      sub = (td->tls_addr >> 8);
      if (sub >= maxroutes)
	continue;		// skip it if it doesn't fit
      if ((td->tls_serverp == 1) && (td->tls_addr != 0) && (data[sub*2] == 0)) {
	if (debug) fprintf(stderr," Adding TLS server subnet %#o\n", sub);
	data[sub*2] = htons(LINK_TLS); // method: interface number
	data[sub*2+1] = htons(RTCOST_ASYNCH); // cost: asynch
	if (sub > nroutes)
	  nroutes = sub;
      }
    }
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
  }
#endif

  if (debug) fprintf(stderr," Max net in pkt %#o, i.e. %d bytes data\n", nroutes, (nroutes+1)*4);
  return (nroutes+1)*4;
}

void 
dump_routing_table_responder(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short src = ch_srcaddr(ch);
  u_short dst = ch_destaddr(ch);
  u_char ans[CH_PK_MAXLEN];
  struct chaos_header *ap = (struct chaos_header *)&ans;
  int i;

  if (verbose || debug) {
    fprintf(stderr,"Handling DUMP-ROUTING-TABLE from %#o to %#o\n",
	    src, dst);
    print_routing_table();
  }  

  memset(ans, 0, sizeof(ans));
  set_ch_opcode(ap, CHOP_ANS);
  set_ch_destaddr(ap, src);
  set_ch_destindex(ap, ch_srcindex(ch));
  if (dst == 0)
    // broadcast
    dst = brd_response_addr(rfc, len);
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  i = make_dump_routing_table_pkt((u_char *)ap, sizeof(ans));
  if (verbose || debug) {
    fprintf(stderr,"Responding to DUMP-ROUTING-TABLE with %d bytes\n", i);
  }
  set_ch_nbytes(ap, i);

  send_chaos_pkt((u_char *)ap, ch_nbytes(ap)+CHAOS_HEADERSIZE);
}

static int
make_time_pkt(u_char *pkt, int pklen, time_t t)
{
  u_char *data = (u_char *)&pkt[CHAOS_HEADERSIZE];
  // LSB first (see MIT AIM 628) and in 11 order
  data[1] = t & 0xff;
  data[0] = (t>>8) & 0xff;
  data[3] = (t>>16) & 0xff;
  data[2] = (t>>24) & 0xff;
  if (debug)
    fprintf(stderr,"Time pkt: %#lx => %02x %02x %02x %02x\n",
	    t, data[0], data[1], data[2], data[3]);
  return 4;
}

// @@@@ lots of copy-paste here, generalize
void
uptime_responder(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short src = ch_srcaddr(ch);
  u_short dst = ch_destaddr(ch);
  u_char ans[CH_PK_MAXLEN];
  struct chaos_header *ap = (struct chaos_header *)&ans;
  int i;

  if (verbose || debug) {
    fprintf(stderr,"Handling UPTIME from %#o to %#o\n",
	    src, dst);
  }  

  memset(ans, 0, sizeof(ans));
  set_ch_opcode(ap, CHOP_ANS);
  set_ch_destaddr(ap, src);
  set_ch_destindex(ap, ch_srcindex(ch));
  if (dst == 0)
    // broadcast
    dst = brd_response_addr(rfc, len);
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  time_t now = time(NULL);
  i = make_time_pkt((u_char *)ap, sizeof(ans), (now-boottime)*60);
  if (verbose || debug) {
    fprintf(stderr,"Responding to UPTIME with %d bytes\n", i);
  }
  set_ch_nbytes(ap, i);

  send_chaos_pkt((u_char *)ap, ch_nbytes(ap)+CHAOS_HEADERSIZE);
}

void
time_responder(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short src = ch_srcaddr(ch);
  u_short dst = ch_destaddr(ch);
  u_char ans[CH_PK_MAXLEN];
  struct chaos_header *ap = (struct chaos_header *)&ans;
  int i;

  if (verbose || debug) {
    fprintf(stderr,"Handling TIME from %#o to %#o\n",
	    src, dst);
  }  

  memset(ans, 0, sizeof(ans));
  set_ch_opcode(ap, CHOP_ANS);
  set_ch_destaddr(ap, src);
  set_ch_destindex(ap, ch_srcindex(ch));
  if (dst == 0)
    // broadcast
    dst = brd_response_addr(rfc, len);
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  time_t now = time(NULL);
  i = make_time_pkt((u_char *)ap, sizeof(ans), now+2208988800UL);  /* see RFC 868 */
  if (verbose || debug) {
    fprintf(stderr,"Responding to TIME with %d bytes\n", i);
  }
  set_ch_nbytes(ap, i);

  send_chaos_pkt((u_char *)ap, ch_nbytes(ap)+CHAOS_HEADERSIZE);
}

void 
status_responder(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short src = ch_srcaddr(ch);
  u_short dst = ch_destaddr(ch);
  u_char ans[CH_PK_MAXLEN];
  struct chaos_header *ap = (struct chaos_header *)&ans;
  int i;

  memset(ans, 0, sizeof(ans));
  set_ch_opcode(ap, CHOP_ANS);
  set_ch_destaddr(ap, src);
  set_ch_destindex(ap, ch_srcindex(ch));
  if (dst == 0)
    // broadcast
    dst = brd_response_addr(rfc, len);
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  u_short *dp = (u_short *)&ans[CHAOS_HEADERSIZE];

  // First 32 bytes contain the name of the node, padded on the right with zero bytes.
  ch_11_puts((u_char *)dp, (u_char *)myname);	/* this rounds up to 16-bit border */
  dp += strlen((char *)myname)/2+1;
  for (i = strlen((char *)myname)/2+1; i < 32/2; i++)
    *dp++ = 0;

  int maxentries = 12;		// max 244 words in a Chaos pkt, 16 for Node name, 18 per entry below
  // Low-order half of 32-bit word comes first
  // By the way: There is no subnet 0.
  for (i = 1; i < 256 && maxentries > 0; i++) {
    if ((linktab[i].pkt_in != 0) || (linktab[i].pkt_out != 0) || (linktab[i].pkt_crcerr != 0)
	 || (linktab[i].pkt_aborted != 0) || (linktab[i].pkt_lost != 0)) {
      if ((i != (src>>8)) &&
	  ((is_private_subnet(i) && !is_private_subnet(src>>8)) ||
	   (!is_private_subnet(i) && is_private_subnet(src>>8)))) {
	// Don't leak between private/public subnets
	if (debug || verbose)
	  fprintf(stderr,"STATUS: NOT including subnet %#o to dest %#o\n", i, src);
	continue;
      }
      maxentries--;
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


void 
lastcn_responder(u_char *rfc, int len)
{
  struct chaos_header *ch = (struct chaos_header *)rfc;
  u_short src = ch_srcaddr(ch);
  u_short dst = ch_destaddr(ch);
  u_char ans[CH_PK_MAXLEN];
  struct chaos_header *ap = (struct chaos_header *)&ans;
  int i, n;

  memset(ans, 0, sizeof(ans));
  set_ch_opcode(ap, CHOP_ANS);
  set_ch_destaddr(ap, src);
  set_ch_destindex(ap, ch_srcindex(ch));
  if (dst == 0)
    // broadcast
    dst = brd_response_addr(rfc, len);
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  u_short *dp = (u_short *)&ans[CHAOS_HEADERSIZE];

  int words_per_entry = 8;	// see below
  int maxentries = 244/words_per_entry;
  // Low-order half of 32-bit word comes first
  time_t now = time(NULL);
  for (n = 0; n < 256 && maxentries > 0; n++) {
    struct hostat *he = hosttab[n];
    if (he != NULL) {
      for (i = 0; i < 256 && maxentries > 0; i++) {
	if (he[i].hst_in != 0 || he[i].hst_last_hop != 0 || he[i].hst_last_seen != 0) {
	  *dp++ = htons(words_per_entry); /* length in 16-bit words */
	  *dp++ = htons((n << 8) | i);	/* host addr */
	  *dp++ = htons(he[i].hst_in & 0xffff);	 /* input pkts from it */
	  *dp++ = htons(he[i].hst_in>>16);
	  *dp++ = htons(he[i].hst_last_hop);  /* last seen from this router */
	  u_int when = he[i].hst_last_seen > 0 ? now - he[i].hst_last_seen : 0;
	  *dp++ = htons(when & 0xffff);	 /* how many seconds ago */
	  *dp++ = htons(when >> 16);
	  *dp++ = htons(he[i].hst_last_fc); /* forwarding count last time seen */
	  maxentries--;
	}
      }
    }
  }
  if (maxentries == 0)
    fprintf(stderr,"WARNING: your hosttab contains too many addesses,\n"
	    " %d of them do not fit in LASTCN pkt\n",
	    maxentries);
  set_ch_nbytes(ap, (dp-(u_short *)&ans[CHAOS_HEADERSIZE])*2);

  send_chaos_pkt((u_char *)ap, ch_nbytes(ap)+CHAOS_HEADERSIZE);
}

int
handle_rfc(struct chaos_header *ch, u_char *data, int dlen)
{
  int i;
  char cname[CH_PK_MAX_DATALEN];
  int datalen = ch_nbytes(ch);
  if (datalen > CH_PK_MAX_DATALEN) {
    fprintf(stderr,"NCP (handle_rfc): Data too long (%d, dlen %d) in %s pkt from <%#o,%#x> to <%#o,%#x>\n",
	    datalen, dlen, ch_opcode_name(ch_opcode(ch)), 
	    ch_srcaddr(ch), ch_srcindex(ch), ch_destaddr(ch), ch_destindex(ch));
    return 0;
  }
  get_packet_string(ch, (u_char *)cname, sizeof(cname));
  char *space = index(cname, ' ');
  if (space) *space = '\0'; // look only for contact name, not args
  if (debug) fprintf(stderr,"Looking for handler of \"%s\"\n", cname);
  for (i = 0; mycontacts[i].contact != NULL; i++) {
    if ((strncmp(cname, mycontacts[i].contact, strlen(mycontacts[i].contact)) == 0)
	&& (strlen(cname) == strlen(mycontacts[i].contact))
	) {
      if (verbose) fprintf(stderr,"%s for %s received, responding\n", 
			   ch_opcode_name(ch_opcode(ch)), mycontacts[i].contact);
      // call the handler
      (*mycontacts[i].handler)(data, dlen);
      // Signal that it was handled
      return 1;
    } 
  }
  // it wasn't handled
  return 0;
}
