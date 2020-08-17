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

unsigned int
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

char *
ip46_ntoa(struct sockaddr *sa, char *buf, int buflen)
{
  if (inet_ntop(sa->sa_family, sa->sa_family == AF_INET ?
		(void *)&((struct sockaddr_in *)sa)->sin_addr :
		(void *)&((struct sockaddr_in6 *)sa)->sin6_addr,
		buf, buflen) == NULL)
    strerror_r(errno,buf,buflen);
  return buf;
}

// **** Debug stuff
static char **datnames = NULL;
static char **dwdnames = NULL;

char *
ch_opcode_name(int op)
  {
    if (op == 0)
      return "bogus0";
    else if (op <= CHOP_BRD && op > 0)
      return ch_opc[op];
    else if (op == CHOP_ACK)
      // Note: extension for the NCP Packet socket
      return "ACK";
    else if ((op >= CHOP_DAT) && (op < CHOP_DWD)) {
      if (op == CHOP_DAT)
	return "DAT";
      else {
	if (datnames == NULL)
	  datnames = calloc(128,sizeof(char *));
	if (datnames[op-CHOP_DAT] == NULL) {
	  datnames[op-CHOP_DAT] = malloc(7*sizeof(char));
	  sprintf(datnames[op-CHOP_DAT],"DAT%d", op-CHOP_DAT);
	}
	return datnames[op-CHOP_DAT];
      }
    } else if (op >= CHOP_DWD) {
      if (op == CHOP_DWD)
	return "DWD";
      else {
	if (dwdnames == NULL)
	  dwdnames = calloc(128,sizeof(char *));
	if (dwdnames[op-CHOP_DWD] == NULL) {
	  dwdnames[op-CHOP_DWD] = malloc(7*sizeof(char));
	  sprintf(dwdnames[op-CHOP_DWD],"DWD%d", op-CHOP_DWD);
	}
	return dwdnames[op-CHOP_DWD];
      }
    } else
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
static char *
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

int
ch_11_puts(unsigned char *out, unsigned char *in) 
{
  int i, x = ((strlen((char *)in)+1)/2)*2;
  for (i = 0; i < x; i++) {
    if (i % 2 == 1)
      out[i-1] = in[i];
    else
      out[i+1] = in[i];
  }
  return x;
}

int
ch_11_gets(unsigned char *in, unsigned char *out, int nbytes)
{
  int i;
  // round up because the last byte might be in the lsb of the last word
  if (nbytes % 2) nbytes++;
  for (i = 0; i < nbytes; i++) {
    if (i % 2 == 1)
      out[i] = in[i-1];
    else
      out[i] = in[i+1];
  }
  out[i] = '\0';
  return i-1;
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

void print_buf(u_char *ucp, int len) 
{
  int row, i;
  char b1[3],b2[3];

  for (row = 0; row*8 < len; row++) {
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
}

void
ch_dumpkt(unsigned char *ucp, int cnt)
{
  int i, row, len, mlen;
  char b1[3],b2[3];
  struct chaos_header *ch = (struct chaos_header *)ucp;
  struct chaos_hw_trailer *tr;
  unsigned char *data = malloc(ch_nbytes(ch)+1);

  fprintf(stderr,"Opcode: %#o (%s), unused: %o\r\nFC: %o, Nbytes %d.\r\n",
	  ch_opcode(ch), ch_opcode_name(ch_opcode(ch)),
	  ch->ch_opcode_u.ch_opcode_s.ch_unused,
	  ch_fc(ch), ch_nbytes(ch));
  fprintf(stderr,"Dest host: %#o, index %#o (%#x)\r\nSource host: %#o, index %#o (%#x)\r\n",
	  ch_destaddr(ch), ch_destindex(ch), ch_destindex(ch), ch_srcaddr(ch), ch_srcindex(ch), ch_srcindex(ch));
  fprintf(stderr,"Packet %#o (%#x)\r\nAck %#o (%#x)\r\n",
	  ch_packetno(ch), ch_packetno(ch), ch_ackno(ch), ch_ackno(ch));

  fprintf(stderr,"Data:\r\n");

  len = ch_nbytes(ch);
  tr = (struct chaos_hw_trailer *)&ucp[cnt-6];

  /* Skip headers */
  ucp += CHAOS_HEADERSIZE;

  switch (ch_opcode(ch)) {
  case CHOP_BRD:
    // show bitmask, then fall through
    mlen = ch_ackno(ch);
    fprintf(stderr," Broadcast to %d*8 subnets ", ch_ackno(ch));
    for (i = 0; i < mlen; i++) {
      int x;
      fprintf(stderr, "%#x ", ucp[i]);
#if 0
      for (x = 0; x < 8; x++) {
	if (ucp[i] & (1<<x))
	  fprintf(stderr, "%#o, ", i*8+x);
      }
#endif
    }
    fprintf(stderr,"\n");
    ch_11_gets(ucp+mlen, data, (ch_nbytes(ch)+1)-mlen);
    fprintf(stderr,"[Contact: \"%s\"]\n", data);
    break;
    
  case CHOP_RFC:
    ch_11_gets(ucp, data, ((ch_nbytes(ch)+1)/2)*2);
    fprintf(stderr,"[Contact: \"%s\"]\n", data);
    break;

  case CHOP_OPN:
  case CHOP_STS:
    {
      unsigned short rcpt, winsz;
      rcpt = WORD16(ucp);
      winsz = WORD16(ucp+2);
      fprintf(stderr,"[Received up to and including %#o (%#x), window size %d]\n",
	      rcpt, rcpt, winsz);
      break;
    }
  case CHOP_CLS:
  case CHOP_LOS:
    ch_11_gets(ucp, data, ((ch_nbytes(ch)+1)/2)*2);
    fprintf(stderr,"[Reason: \"%s\"]\n", data);
    break;

  case CHOP_FWD:
    ch_11_gets(ucp, data, ((ch_nbytes(ch)+1)/2)*2);
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
  if (len+CHAOS_HEADERSIZE > cnt)
    fprintf(stderr,"... (header length field %d > buf len %d)\n", len, cnt);

  /* Now show trailer */
  if (len % 2)
    len++;			/* Align */
  if (cnt == len+CHAOS_HEADERSIZE)
    fprintf(stderr,"[No trailer]\n");
  else if (cnt < len+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE)
    fprintf(stderr,"[Incomplete trailer: pkt size %d < (header + len + trailer size) = %lu]\n",
	    cnt, len+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE);
  else {
    u_int cks = ch_checksum((u_char *)ch, len);
    fprintf(stderr,"HW trailer:\r\n  Dest: %o\r\n  Source: %o\r\n  Checksum: %#x (%#x)\r\n",
	    ntohs(tr->ch_hw_destaddr), ntohs(tr->ch_hw_srcaddr), ntohs(tr->ch_hw_checksum),
	    cks);
  }
}

