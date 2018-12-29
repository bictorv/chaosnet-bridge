/* Copyright © 2005, 2017, 2018 Björn Victor (bjorn@victor.se) */
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

#include <sys/un.h>
#include <sys/stat.h>

#include "chaosd.h"		/* chaos-over-unix-sockets */
#include "cbridge.h"

/* **** Chaos-over-Unix-Sockets functions **** */
// Based on code by Brad Parker (brad@heeltoe.com), see http://www.unlambda.com/cadr/

int fd;
extern int unixsock;

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

void * unix_input(void *v)
{
  /* Unix -> others thread */
  u_char data[CH_PK_MAXLEN];
  int len, blen = sizeof(data);
  u_char *pkt = data;

  u_char us_subnet = 0;		/* unix socket subnet */
  int i;
  for (i = 0; i < *rttbl_host_len; i++) {
    if (rttbl_host[i].rt_link == LINK_UNIXSOCK) {
      us_subnet = rttbl_host[i].rt_dest >> 8;
      break;
    }
  }

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
      // check where it's coming from, prefer trailer info
      u_short srcaddr;
      if (len > (ch_nbytes(ch) + CHAOS_HEADERSIZE)) {
	struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
	srcaddr = tr->ch_hw_srcaddr;
      } else
	srcaddr = ch_srcaddr(ch);
      if (is_mychaddr(srcaddr)) {
	// Unix socket server/chaosd echoes everything to everyone
	// (This is checked also in forward_chaos_pkt, but optimize a little?)
	if (debug) fprintf(stderr,"unix_input: dropping echoed pkt from self\n");
	continue;
      }
      struct chroute *srcrt = find_in_routing_table(srcaddr, 0, 0);
      forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			srcrt != NULL ? srcrt->rt_type : RT_DIRECT,
			srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
			pkt, len, LINK_UNIXSOCK);
    }
  }
}

void
forward_on_usocket(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  // There can be only one?
  htons_buf((u_short *)ch, (u_short *)ch, dlen);
  if (unixsock > 0) {
    if (debug) fprintf(stderr,"Forward: Sending on unix from %#o to %#o\n", schad, dchad);
    u_send_chaos(unixsock, data, dlen);
  }
}
