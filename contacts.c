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
#include <sys/socket.h>
#include "cbridge.h"

extern time_t boottime;
extern char myname[32];

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

// the contacts and their handler function
static struct rfc_handler mycontacts[] = {
  { "STATUS", &status_responder },
  { "LASTCN", &lastcn_responder },
  { "DUMP-ROUTING-TABLE", &dump_routing_table_responder },
  { "UPTIME", &uptime_responder },
  { "TIME", &time_responder }
};
// KEEP THIS IN SYNC WITH LENGTH OF mycontacts
#define MAX_CONTACT 5

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

// Implement DUMP-ROUTING-TABLE for bridge, 
// so CHAOS:SHOW-ROUTING-PATH (LMI) and CHAOS:PRINT-ROUTING-TABLE (Symbolics) could work.
// See SYS:NETWORK.CHAOS;CHSNCP LISP
// ;;; Routing table format: for N subnets, N*4 bytes of data, holding N*2 words
// ;;; For subnet n, pkt[2n] has the method; if this is less than 400 (octal), it's
// ;;; an interface number; otherwise, it's a host which will forward packets to that
// ;;; subnet.  pkt[2n+1] has the host's idea of the cost.
// (Stupid format, can only handle subnets up to decimal #122 - RUT
// handles 122 subnets regardless of their actual subnet number.)

static int
make_dump_routing_table_pkt(u_char *pkt, int pklen)
{
  struct chaos_header *cha = (struct chaos_header *)pkt;
  u_short *data = (u_short *)&pkt[CHAOS_HEADERSIZE];
  int sub, cost, nroutes = 0;
  int maxroutes = (pklen-CHAOS_HEADERSIZE)/4;  /* that fit in this pkt, max 122 */
  if (maxroutes > 122)
    maxroutes = 122;

  memset(data, 0, pklen-CHAOS_HEADERSIZE);

  PTLOCK(rttbl_lock);
  for (sub = 0; (sub < 0xff) && (sub <= maxroutes); sub++) {
    if (rttbl_net[sub].rt_type != RT_NOPATH) {
      // Method: if < 0400: interface number; otherwise next hop address
      if ((rttbl_net[sub].rt_type == RT_DIRECT) || (is_mychaddr(rttbl_net[sub].rt_braddr))) {
	// interface nr - use link type
	if (rttbl_net[sub].rt_link == LINK_INDIRECT)
	  data[sub*2] = htons(LINK_CHUDP);  /* assume this */
	else
	  data[sub*2] = htons(rttbl_net[sub].rt_link);
      } else {
	data[sub*2] = htons(rttbl_net[sub].rt_braddr);
      }
      cost = rttbl_net[sub].rt_cost;
      data[sub*2+1] = htons(cost);
      if (debug) fprintf(stderr," Adding routing for subnet %#o (meth %#o, cost %d)\n",
			 sub, data[sub*2], cost);
      nroutes = sub;
    }
  }
  PTUNLOCK(rttbl_lock);

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
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  time_t now = time(NULL);
  i = make_time_pkt((u_char *)ap, sizeof(ans), now+2208988800L);  /* see RFC 868 */
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
  for (i = 0; i < 256 && maxentries > 0; i++) {
    if ((linktab[i].pkt_in != 0) || (linktab[i].pkt_out != 0) || (linktab[i].pkt_crcerr != 0)
	 || (linktab[i].pkt_aborted != 0) || (linktab[i].pkt_lost != 0)) {
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
  set_ch_srcaddr(ap, dst);
  set_ch_srcindex(ap, ch_destindex(ch));

  u_short *dp = (u_short *)&ans[CHAOS_HEADERSIZE];

  int words_per_entry = 7;	// see below
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

void
handle_rfc(struct chaos_header *ch, u_char *data, int dlen)
{
  int i;
  u_char *cname = (u_char *)calloc(ch_nbytes(ch)+1, sizeof(u_char));
  ch_11_gets(&data[CHAOS_HEADERSIZE], cname, ch_nbytes(ch));
  for (i = 0; i < MAX_CONTACT; i++) {
    if ((strncmp((char *)cname, (char *)mycontacts[i].contact, strlen(mycontacts[i].contact)) == 0)
	&& (ch_nbytes(ch) == strlen(mycontacts[i].contact))) {
      if (verbose) fprintf(stderr,"RFC for %s received, responding\n", mycontacts[i].contact);
      // call the handler
      (*mycontacts[i].handler)(data, dlen);
      break;
    }
  }
}
