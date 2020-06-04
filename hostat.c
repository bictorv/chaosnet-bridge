/* Copyright © 2020 Björn Victor (bjorn@victor.se) */
/* Simple demonstration program for 
   NCP (Network Control Program) implementing Chaosnet transport layer
   for cbridge, the bridge program for various Chaosnet implementations. */
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "cbridge-chaos.h"

void usage(char *s) 
{
  fprintf(stderr,"usage: %s host [contact]\n"
	  " Handles \"simple\" connectionless Chaosnet protocols.\n"
	  " Contact defaults to STATUS. Try also TIME, UPTIME, DUMP-ROUTING-TABLE. (Not case sensitive.)\n",
	  s);
  exit(1);
}

char chaos_socket_directory[] = "/tmp";

static int
connect_to_named_socket(int socktype, char *path)
{
  int sock, slen;
  struct sockaddr_un local, server;
  
  local.sun_family = AF_UNIX;
  sprintf(local.sun_path, "%s/%s_%d", chaos_socket_directory, path, getpid());
  if (unlink(local.sun_path) < 0) {
    //perror("unlink(chaos_sockfile)");
  } 
  
  if ((sock = socket(AF_UNIX, socktype, 0)) < 0) {
    perror("socket(AF_UNIX)");
    exit(1);
  }
  slen = strlen(local.sun_path)+ 1 + sizeof(local.sun_family);
  if (bind(sock, (struct sockaddr *)&local, slen) < 0) {
    perror("bind(local)");
    exit(1);
  }
  if (chmod(local.sun_path, 0777) < 0)
    perror("chmod(local, 0777)");
  
  server.sun_family = AF_UNIX;
  sprintf(server.sun_path, "%s/%s", chaos_socket_directory, path);
  slen = strlen(server.sun_path)+ 1 + sizeof(server.sun_family);

  if (connect(sock, (struct sockaddr *)&server, slen) < 0) {
    perror("connect(server)");
    exit(1);
  }
  return sock;
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

void print_buf(u_char *ucp, int len) 
{
  int row, i;
  char b1[3],b2[3];

  printf("Read %d bytes:\n", len);
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

// ;;; Routing table format: for N subnets, N*4 bytes of data, holding N*2 words
// ;;; For subnet n, pkt[2n] has the method; if this is less than 400 (octal), it's
// ;;; an interface number; otherwise, it's a host which will forward packets to that
// ;;; subnet.  pkt[2n+1] has the host's idea of the cost.
void print_routing_table(u_char *bp, int len)
{
  u_short *ep, *dp = (u_short *)bp;
  int i, sub, maxroutes = len/4;

  printf("%-8s %-8s %s\n", "Subnet", "Method", "Cost");
  for (sub = 0; sub < maxroutes; sub++) {
    if (dp[sub*2] != 0) {
      printf("%#-8o %#-8o %-8d\n",
	     sub, ntohs(dp[sub*2]), ntohs(dp[sub*2+1]));
    }
  }
}

void print_time(u_char *bp, int len)
{
  u_short *dp = (u_short *)bp;
  char tbuf[64];

  if (len != 4) { printf("Bad time length %d (expected 4)\n", len); exit(1); }

  time_t t = (u_short)ntohs(*dp++); t |= (u_long) ((u_short)ntohs(*dp)<<16);
#if __APPLE__
  // imagine this
  t &= 0xffffffff;
#endif
  if (t > 2208988800UL) {  /* see RFC 868 */
    t -= 2208988800UL;
    strftime(tbuf, sizeof(tbuf), "%F %T", localtime(&t));
    printf("%s\n", tbuf);
  } else 
    printf("Unexpected time value %ld <= %ld\n", t, 2208988800UL);
}

char *seconds_as_interval(u_int t)
{
  char tbuf[64], *tp = tbuf;
  
  if (t == 0)
    return strdup("now");

  if (t > 60*60*24*7) {
    int w = t/(60*60*24*7);
    sprintf(tp, "%d week%s ", w, w == 1 ? "" : "s");
    t %= 60*60*24*7;
    tp += strlen(tp);
  }
  if (t > 60*60*24) {
    int d = t/(60*60*24);
    sprintf(tp, "%d day%s ", d, d == 1 ? "" : "s");
    t %= (60*60*24);
    tp = &tbuf[strlen(tbuf)];
  }
  if (t > 60*60) {
    int h = t/(60*60);
    sprintf(tp, "%d hour%s ", h, h == 1 ? "" : "s");
    t %= 60*60;
    tp = &tbuf[strlen(tbuf)];
  }
  if (t > 60)
    sprintf(tp, "%dm %ds", (t/60), t % 60);
  else
    sprintf(tp, "%d s", t);
  return strdup(tbuf);
}

void print_uptime(u_char *bp, int len)
{
  u_short *dp = (u_short *)bp;

  if (len != 4) { printf("Bad time length %d (expected 4)\n", len); exit(1); }

  u_int t = (u_short)ntohs(*dp++); t |= (u_long) ((u_short)ntohs(*dp)<<16);

  t /= 60;
  printf("%s\n", seconds_as_interval(t));
}

void print_lastcn(u_char *bp, int len)
{
  u_short *dp = (u_short *)bp;
  int i;
  
  // @@@@ prettyprint age, host?
  printf("%-8s %-8s %-8s %s\n", "Host","#in","Via","Age(s)");
  for (i = 0; i < len/2/7; i++) {
    u_short wpe = ntohs(*dp++);
    if (wpe != 7) { printf("Unexpected WPE of LASTCN: %d should be 7\n", wpe); exit(1); }
    u_short addr = ntohs(*dp++);
    u_short in = ntohs(*dp++); in |= (ntohs(*dp++)<<16);
    u_short last = ntohs(*dp++);
    u_short age = ntohs(*dp++); age |= (ntohs(*dp++)<<16);
    printf("%#-8o %-8d %#-8o %s\n", addr, in, last, seconds_as_interval(age));
  }
}

void print_status(u_char *bp, int len)
{
  u_char hname[32];
  u_short *dp;
  int i;

  // First 32 bytes contain the name of the node, padded on the right with zero bytes.
  ch_11_gets(bp, hname, sizeof(hname));
  printf("Hostat for host %s\n", hname);
  bp += 32;

  dp = (u_short *)bp;
  u_short *ep = (u_short *)(bp+(len - 32));

  printf("%s \t%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
	 "Net", "In", "Out", "Abort", "Lost", "crcerr", "ram", "Badlen", "Rejected");
  for (i = 0; dp < ep; i++) {
    u_short subnet = ntohs(*dp++);
    if ((subnet - 0400) < 0) { printf("Unexpected format of subnet: %#o (%#x)\n", subnet, subnet); exit(1); }
    subnet -= 0400;
    u_short elen = ntohs(*dp++);
    u_int in = ntohs(*dp++); in |= (ntohs(*dp++)<<16);
    u_int out = ntohs(*dp++); out |= (ntohs(*dp++)<<16);
    u_int aborted = ntohs(*dp++); aborted |= (ntohs(*dp++)<<16);
    u_int lost = ntohs(*dp++); lost |= (ntohs(*dp++)<<16);
    u_int crcerr = ntohs(*dp++); crcerr |= (ntohs(*dp++)<<16);
    u_int crcerr_post = ntohs(*dp++); crcerr_post |= (ntohs(*dp++)<<16);
    u_int badlen = ntohs(*dp++); badlen |= (ntohs(*dp++)<<16);
    u_int rejected = 0;
    if (elen == 16) {
      rejected = ntohs(*dp++); rejected |= (ntohs(*dp++)<<16);
    }
    printf("%#o \t%-8d %-8d %-8d %-8d %-8d %-8d %-8d %-8d\n",
	   subnet, in, out, aborted, lost, crcerr, crcerr_post, badlen, rejected);
  }
}

int
main(int argc, char *argv[])
{
  signed char c;
  char *host, *contact = "STATUS", *pname;
  char buf[CH_PK_MAXLEN];
  char *nl, *bp;
  int i, cnt, sock, anslen, ncnt;

  pname = argv[0];

  if (argc < 2) 
    usage(pname);

  host = argv[1];
  if (argc > 2)
    contact = argv[2];

  sock = connect_to_named_socket(SOCK_STREAM, "chaos_stream");
  
  // printf("Trying %s %s...\n", host, contact);
  dprintf(sock,"RFC %s %s\r\n", host, contact);

  if ((cnt = recv(sock, buf, sizeof(buf), 0)) < 0) {
    perror("recv"); exit(1);
  }
  nl = index((char *)buf, '\n');
  if (nl != NULL) {
    *nl = '\0';
    nl++;
  }

  if (strncmp(buf, "ANS ", 4) != 0) {
    if (nl != NULL) *nl = '\0';
    fprintf(stderr,"Unexpected reply from %s: %s\n", host, buf);
    exit(1);
  }
  if (sscanf(&buf[4], "%d", &anslen) != 1) {
    fprintf(stderr, "Cannot parse ANS length: %s\n", buf);
    exit(1);
  }
  for (bp = nl+cnt; bp-nl < anslen; ncnt = recv(sock, bp, sizeof(buf)-(bp-buf), 0)) {
    cnt += ncnt;
    bp += ncnt;
  }
  if (strcasecmp(contact, "STATUS") == 0)
    print_status((u_char *)nl, anslen);
  else if (strcasecmp(contact, "TIME") == 0)
    print_time((u_char *)nl, anslen);
  else if (strcasecmp(contact, "UPTIME") == 0)
    print_uptime((u_char *)nl, anslen);
  else if (strcasecmp(contact, "DUMP-ROUTING-TABLE") == 0)
    print_routing_table((u_char *)nl, anslen);
  else if (strcasecmp(contact, "LASTCN") == 0)
    print_lastcn((u_char *)nl, anslen);
  else
    print_buf((u_char *)nl, anslen);
}
