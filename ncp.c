/* Copyright © 2020 Björn Victor (bjorn@victor.se) */
/*  NCP (Network Control Program) implementing Chaosnet transport layer
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

// TODO:
// - Decide/structure/clean up/make sure/document who changes the state
// - Document it better
//
// add statistics struct, for (new) PEEK protocol to report
// write client library (but see named.py for how simple it is, not needed really?)

#include <stdlib.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <assert.h>

#include "cbridge.h"
#include "pkqueue.h"

#ifndef USE_CHAOS_SIMPLE
// NYI
#define USE_CHAOS_SIMPLE 0
#endif

#include "ncp.h"

#if CHAOS_DNS
#include <resolv.h>
#endif

// ms to wait for ack of final EOF
#define EOF_WAIT_TIMEOUT (3*DEFAULT_RETRANSMISSION_INTERVAL)
// ms to wait for conn to become Open from RFC_Received before closing it down
#define FINISH_WAIT_TIMEOUT 5000

#define MAX_CONTACT_NAME_LENGTH CH_PK_MAX_DATALEN

// configurable stuff
int ncp_enabled = 0;
// chaos socket directory
#define DEFAULT_CHAOS_SOCKET_DIRECTORY "/tmp/"
static char chaos_socket_directory[PATH_MAX];
// default domain for host lookups
#if CHAOS_DNS
#define DEFAULT_CHAOS_DOMAIN "chaosnet.net"
static char **chaos_domains = NULL;
static int number_of_chaos_domains = 0;
#endif
// default retransmission interval
static int default_retransmission_interval = DEFAULT_RETRANSMISSION_INTERVAL;
// default window size
static int default_window_size = DEFAULT_WINSIZE;
// default EOF wait timeout
static int eof_wait_timeout = EOF_WAIT_TIMEOUT;
// finish wait timeout
static int finish_wait_timeout = FINISH_WAIT_TIMEOUT;
// transparently follow FWD
static int forward_transparently = 0;
// debug/trace
static int ncp_debug = 0;
static int ncp_trace = 0;

// list of registered listeners
struct listener *registered_listeners;
// list of active conns
struct conn_list *conn_list;

static void print_conn(char *leader, struct conn *conn, int alsostate);
static void start_conn(struct conn *conn);
static void add_output_pkt(struct conn *c, struct chaos_header *pkt);
static void socket_closed_for_simple_conn(struct conn *conn);
static void retransmit_controlled_packets(struct conn *conn);
static void user_socket_los(struct conn *conn, char *fmt, ...);
static int receive_or_die(struct conn *conn, u_char *buf, int buflen);
static void send_to_user_socket(struct conn *conn, struct chaos_header *pkt, u_char *buf, int len);

// parse a configuration file line:
// ncp socketdir /var/run debug on domain ams.chaosnet.net trace on
int
parse_ncp_config_line()
{
  char *tok = NULL;
  int val = 0;

  strcpy(chaos_socket_directory,DEFAULT_CHAOS_SOCKET_DIRECTORY); // default
  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    val = 0;
    if (strcmp(tok,"socketdir") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no socket directory specified\n"); return -1; }
      strncpy(chaos_socket_directory, tok, sizeof(chaos_socket_directory));
      if ((strlen(chaos_socket_directory) < sizeof(chaos_socket_directory)) && 
	  (chaos_socket_directory[strlen(chaos_socket_directory)-1] != '/')) {
	fprintf(stderr,"ncp: fixing socketdir to add slash to \"%s\"\n", chaos_socket_directory);
	strcat(chaos_socket_directory, "/");
      }
#if CHAOS_DNS
    } else if ((strcmp(tok,"domain") == 0) || (strcmp(tok,"domains") == 0)) {
      char *sp, *ep;
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no domain specified\n"); return -1; }
      for (sp = tok, ep = index(tok, ','); ep != NULL; sp = ep+1, ep = index(ep+1, ',')) {
	// look for comma-separated domain list
	chaos_domains = realloc(chaos_domains, (number_of_chaos_domains+1) * sizeof(char *));
	if (chaos_domains == NULL) { perror("realloc(chaos_domains)"); exit(1); }
	*ep = '\0';
	if (strlen(sp) == 0) {
	  fprintf(stderr,"Syntax error in \"domain\" setting - empty domain\n");
	  return -1;
	}
	chaos_domains[number_of_chaos_domains++] = strdup(sp);
      }
      // add the single one, or the last one
      if (strlen(sp) == 0) {
	fprintf(stderr,"Syntax error in \"domain\" setting - empty domain\n");
	return -1;
      }
      chaos_domains = realloc(chaos_domains, (number_of_chaos_domains+1) * sizeof(char *));
      if (chaos_domains == NULL) { perror("realloc(chaos_domains)"); exit(1); }
      chaos_domains[number_of_chaos_domains++] = strdup(sp);
#endif
    } else if (strcmp(tok,"retrans") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no retrans value specified\n"); return -1; }
      if (sscanf(tok, "%d", &val) != 1) { fprintf(stderr,"ncp: bad retrans value specified: %s\n", tok); return -1; }
      if (val < 1) { fprintf(stderr,"ncp: bad retrans value specified: %d\n", val); return -1; }
      // @@@@ at least #define limits?
      if ((val < 100) || (val > 15*1000)) { fprintf(stderr,"ncp: very short or long retrans value specified: %d\n", val); return -1; }
      else default_retransmission_interval = val;
    } else if (strcmp(tok,"eofwait") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no eofwait value specified\n"); return -1; }
      if (sscanf(tok, "%d", &val) != 1) { fprintf(stderr,"ncp: bad eofwait value specified: %s\n", tok); return -1; }
      if (val < 1) { fprintf(stderr,"ncp: bad eofwait value specified: %d\n", val); return -1; }
      // @@@@ at least #define limits?
      if ((val < 100) || (val > 3*60*1000)) { fprintf(stderr,"ncp: very short or long eofwait value specified: %d\n", val); return -1; }
      else eof_wait_timeout = val;
    } else if (strcmp(tok,"finishwait") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no finishwait value specified\n"); return -1; }
      if (sscanf(tok, "%d", &val) != 1) { fprintf(stderr,"ncp: bad finishwait value specified: %s\n", tok); return -1; }
      if (val < 1) { fprintf(stderr,"ncp: bad finishwait value specified: %d\n", val); return -1; }
      // @@@@ at least #define limits?
      if ((val < 100) || (val > 15*60*1000)) { fprintf(stderr,"ncp: very short or long finishwait value specified: %d\n", val); return -1; }
      else finish_wait_timeout = val;
    } else if (strcmp(tok,"window") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no window value specified\n"); return -1; }
      // allow any base: 0x for hex, 012 for octal, otherwise decimal
      if (sscanf(tok, "%i", &val) != 1) { fprintf(stderr,"ncp: bad window value specified: %s\n", tok); return -1; }
      if ((val < 1) || (val > MAX_WINSIZE)) { fprintf(stderr,"ncp: bad window value specified: %d\n", val); return -1; }
      else default_window_size = val;
    } else if (strcmp(tok, "follow_forward") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0)) {
	forward_transparently = 1;
      } else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0)) {
	forward_transparently = 0;
      } else {
	fprintf(stderr,"ncp: bad 'follow_forward' arg %s specified\n", tok);
	return -1;
      }
    } else if (strcmp(tok, "debug") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0)) {
	ncp_debug = 1;
      } else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0)) {
	ncp_debug = 0;
      } else if ((sscanf(tok, "%d", &val) == 1) && (val >= 0)) {
	// allow decimal values too
	ncp_debug = val;
      } else {
	fprintf(stderr,"ncp: bad 'debug' arg %s specified\n", tok);
	return -1;
      }
    } else if (strcmp(tok, "trace") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0)) {
	ncp_trace = 1;
      } else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0)) {
	ncp_trace = 0;
      } else if ((sscanf(tok, "%d", &val) == 1) && (val >= 0)) {
	// allow decimal values too
	ncp_trace = val;
      } else {
	fprintf(stderr,"ncp: bad 'trace' arg %s specified\n", tok);
	return -1;
      }
    } else if (strcmp(tok, "enabled") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0)) {
	ncp_enabled = 1;
      } else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0)) {
	ncp_enabled = 0;
      } else {
	fprintf(stderr,"ncp: bad 'enabled' arg %s specified\n", tok);
	return -1;
      }
    } else {
      fprintf(stderr,"bad ncp keyword %s\n", tok);
      return -1;
    }
  }
#if CHAOS_DNS
  if (number_of_chaos_domains == 0) {
    // add default domain
    chaos_domains = malloc(sizeof(char *));
    if (chaos_domains != NULL) 
      chaos_domains[number_of_chaos_domains++] = DEFAULT_CHAOS_DOMAIN;
  }
#endif
  if (verbose || ncp_debug) {
    printf("NCP is %s. Socket directory \"%s\", retrans %d, window %d, eofwait %d, finishwait %d, follow_forward %s, debug %d %s, trace %d %s\n", 
	   ncp_enabled ? "enabled" : "disabled",
	   chaos_socket_directory, 
	   default_retransmission_interval, default_window_size,
	   eof_wait_timeout, finish_wait_timeout,
	   forward_transparently > 0 ? "on" : "off",
	   ncp_debug, (ncp_debug > 0) ? "on" : "off",
	   ncp_trace, (ncp_trace > 0) ? "on" : "off");
#if CHAOS_DNS
    if (number_of_chaos_domains > 0) {
      int i;
      printf(" %d configured domain%s: ", number_of_chaos_domains, number_of_chaos_domains == 1 ? "" : "s");
      for (i = 0; i < number_of_chaos_domains; i++)
	printf("%s%s", chaos_domains[i], i < number_of_chaos_domains-1 ? ", " : "");
      printf("\n");
    }
#endif
  }
  return 0;
}

static void
trace_conn(char *leader, struct conn *conn)
{
  char tbuf[128], buf[256];
  if (ncp_trace) {
    time_t now = time(NULL);
    strftime(tbuf, sizeof(tbuf), "%T", localtime(&now));
    sprintf(buf, "%s %s", tbuf, leader);
    print_conn(buf, conn, 0);
  }
}

char *
conn_thread_name(struct conn *conn)
{
  if (pthread_equal(conn->conn_to_net_thread, pthread_self()))
    return "conn_to_net";
  else if (pthread_equal(conn->conn_to_sock_thread, pthread_self()))
    return "conn_to_sock";
  else if (pthread_equal(conn->conn_from_sock_thread, pthread_self()))
    return "conn_from_sock";
  else
    return "(not conn thread)";
}

//////////////// utility

static int
opcode_uncontrolled(int opc)
{
  if ((opc == CHOP_RFC) || (opc == CHOP_OPN) || (opc == CHOP_EOF) || (opc == CHOP_BRD)
      || (opc >= CHOP_DAT))
    // controlled
    return 0;
  else
    // uncontrolled
    return 1;
}

static int
packet_uncontrolled(struct chaos_header *pkt)
{
  return opcode_uncontrolled(ch_opcode(pkt));
}

// make an unsigned short random value
static u_short
make_u_short_random(void)
{
  // call srandom() in ncp_user_server
  return random() % (1<<16);
}

static pthread_mutex_t indexindexlock = PTHREAD_MUTEX_INITIALIZER;
#define INDEXINDEXMAX 0x10000
static u_short indexindex[INDEXINDEXMAX];
static int indexindexindex = 0;
static u_short
make_fresh_index(void)
{
  int i, found = 1;
  u_short new;
  PTLOCKN(indexindexlock,"indexindexlock");
  if (indexindexindex > (INDEXINDEXMAX>>4)) {
    if (ncp_debug) printf("GC of indexes, have %#x\n", indexindexindex);
    // gc old indexes @@@@ could check if they are in use, of course...
    memmove(&indexindex[0], &indexindex[INDEXINDEXMAX>>8], sizeof(u_short)*(INDEXINDEXMAX>>8));
    indexindexindex = INDEXINDEXMAX>>8;
  }
  if (ncp_debug > 1) printf("Making new index, now have %d in use\n", indexindexindex);
  while (found) {
    new = make_u_short_random();
    found = 0;
    // if (ncp_debug) printf(" trying %#x\n", new);
    for (i = 0; i < indexindexindex; i++)
      if (indexindex[i] == new) {
	found = 1;
	break;
      }
  }
  if (ncp_debug > 1) printf(" Using %#x\n", new);
  indexindex[++indexindexindex] = new;
  PTUNLOCKN(indexindexlock,"indexindexlock");
  return new;
}

//////// packet numbers, modulo 2^16 - see section 3.4 in MIT AIM 628

int pktnum_less(u_short a, u_short b)
{
  return (((int)a-(int)b) & 0100000) != 0;
}
int pktnum_equal(u_short a, u_short b)
{
  // assumes using pktnum_1plus so no overflow
  return a==b;
}
static int pktnum_diff(u_short a, u_short b)
{
  signed int x = (int)a-(int)b;
  if (x < 0)
    return x+0200000;
  else
    return x;
}
static int pktnum_1plus(u_short a)
{
  return ((int)a+1) & 0177777;
}
static int pktnum_1minus(u_short a)
{
  return pktnum_diff(a, 1);
}

//////// named sockets

static int
make_named_socket(int socktype, char *path)
{
  int sock, slen;
  struct sockaddr_un local;
  struct stat stb;
  
  local.sun_family = AF_UNIX;
  strcpy(local.sun_path, chaos_socket_directory);
  strcat(local.sun_path, path);
  slen = strlen(local.sun_path)+ 1 + sizeof(local.sun_family);

  // if the socket file exists, try connecting to it, and if it succeeds, complain and terminate
  if (stat(local.sun_path, &stb) == 0) {
    if ((stb.st_mode & S_IFMT) == S_IFSOCK) {
      if (ncp_debug) fprintf(stderr,"stat(%s) successful, trying to connect\n", local.sun_path);
      if ((sock = socket(AF_UNIX, socktype, 0)) < 0) {
	perror("socktype(AF_UNIX)");
	exit(1);
      }
      if (connect(sock, (struct sockaddr *)&local, slen) == 0) {
	fprintf(stderr,"?? Warning: server socket \"%s\" already exists and is active - avoid running two cbridge processes!\n",
		local.sun_path);
	exit(1);
      } else if (ncp_debug) {
	fprintf(stderr,"Info: connect to \"%s\": %s\n", local.sun_path, strerror(errno));
      }
      // don't need this anymore
      close(sock);
    } else 
      fprintf(stderr,"%% socket file %s exists but is not a socket (mode %#o), removing it\n",
	      local.sun_path, (stb.st_mode & S_IFMT));
    // it didn't respond, try removing it
    if (unlink(local.sun_path) < 0) {
      fprintf(stderr,"?? failed to unlink \"%s\": %s\n", local.sun_path, strerror(errno));
      exit(1);
    } else if (ncp_debug) 
      fprintf(stderr,"NCP unlinked old socket file %s\n", local.sun_path);
  } else if (ncp_debug)
    fprintf(stderr,"Info: failed to stat \"%s\": %s\n", local.sun_path, strerror(errno));
  // it doesn't exist at this point
  
  if ((sock = socket(AF_UNIX, socktype, 0)) < 0) {
    perror("?? socket(AF_UNIX)");
    exit(1);
  }
  slen = strlen(local.sun_path)+ 1 + sizeof(local.sun_family);
  if (bind(sock, (struct sockaddr *)&local, slen) < 0) {
    perror("?? bind(local)");
    exit(1);
  }
  if (chmod(local.sun_path, 0777) < 0)
    perror("?? chmod(local, 0777)"); // @@@@ configurable?
  if (socktype == SOCK_STREAM) {
    if (listen(sock, 25) < 0) {	// @@@@ random limit
      perror("?? listen(local)");
      exit(1);
    }
  }
  // no signal, just error, please!
#ifdef F_SETNOSIGPIPE
  if (fcntl(sock, F_SETNOSIGPIPE, 1) == -1)  { perror("fcntl(pipe)"); exit(1); }
#else
#ifdef SO_NOSIGPIPE
  int set = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int)) < 0) { perror("setsockopt(pipe)"); exit(1); }
#else
#ifndef MSG_NOSIGNAL
  #warn No way to disable SIGPIPE
#endif
#endif
#endif
  return sock;
}

//////////////// datatypes

//////// conns

static char *
state_name(connstate_t s)
{
  switch (s) {
  case CS_Inactive: return "Inactive";
  case CS_Answered: return "Answered";
  case CS_CLS_Received: return "CLS_Received";
  case CS_Listening: return "Listening";
  case CS_RFC_Received: return "RFC_Received";
  case CS_RFC_Sent: return "RFC_Sent";
  case CS_Open_Sent: return "Open_Sent";
  case CS_Open: return "Open";
  case CS_LOS_Received: return "LOS_Received";
  case CS_Host_Down: return "Host_Down";
  case CS_Foreign: return "Foreign";
  case CS_BRD_Sent: return "BRD_Sent";
  case CS_Finishing: return "Finishing";
  }
}

static char *
conn_state_name(struct conn *conn)
{
  return state_name(conn->conn_state->state);
}

static char *
conn_type_type_name(conntype_t ct)
{
  switch (ct) {
  case CT_Stream: return "Stream";
  case CT_Simple: return "Simple";
  case CT_Packet: return "Packet";
  }
}

static char *
conn_type_name(struct conn *conn)
{
  return conn_type_type_name(conn->conn_type);
}

static char *
conn_sockaddr_path(struct conn *c)
{
  return c->conn_sockaddr.sun_path;
}

static void
print_conn(char *leader, struct conn *conn, int alsostate)
{
  time_t now = time(NULL);
  printf("%s conn %p %s contact \"%s\" remote <%#o,%#x> local <%#o,%#x> state %s age %ld t/o %d ff %d sock %d %s\n",
	 leader,
	 conn, conn_type_name(conn),
	 conn->conn_contact,
	 conn->conn_rhost, conn->conn_ridx,
	 conn->conn_lhost, conn->conn_lidx,
	 conn_state_name(conn), now - conn->conn_created, conn->rfc_timeout,
	 conn->follow_forward,
	 conn->conn_sock, conn->conn_sockaddr.sun_path);
  if (alsostate) {
    struct conn_state *cs = conn->conn_state;
    printf("%s made %#x fwin %d avail %d, read %d contr %d ooo %d, ack %#x rec %#x, send %d high %#x ack %#x last rec %ld probe %ld\n",
	   leader, cs->pktnum_made_highest,
	   cs->foreign_winsize, cs->window_available, pkqueue_length(cs->read_pkts), cs->read_pkts_controlled,
	   pkqueue_length(cs->received_pkts_ooo), 
	   cs->pktnum_read_highest, cs->pktnum_received_highest, 
	   pkqueue_length(cs->send_pkts), cs->pktnum_sent_highest, cs->pktnum_sent_acked,
	   cs->time_last_received > 0 ? now - cs->time_last_received : -1,
	   cs->time_last_probed > 0 ? now - cs->time_last_probed : -1);
  }
}

void
set_conn_state(struct conn *c, connstate_t old, connstate_t new, int havelock)
{
  struct conn_state *cs = c->conn_state;
  // Warn if asked to change from a state we're no longer in
  if (cs->state != old) {
    if (cs->state != new)
      // don't complain if we're already in the new state
      if (ncp_debug) printf("%%%% Conn %p told to change from %s to %s but now in %s - NOT CHANGING STATE\n",
			    c, state_name(old), state_name(new), state_name(cs->state));
    return;
  }
  if (!havelock) PTLOCKN(cs->conn_state_lock,"conn_state_lock");
  if (ncp_debug) printf("Conn %p changing from %s to %s\n", c, conn_state_name(c), state_name(new));
  cs->state = new;
  if (pthread_cond_broadcast(&cs->conn_state_cond) != 0) perror("?? pthread_cond_broadcast(conn_state_cond)");
  if (!havelock) PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
}

connstate_t
await_conn_state(struct conn *c, connstate_t new, int timeout_ms)
{
  int timedout;
  struct timespec to;
  struct timeval tv;
  struct conn_state *cs = c->conn_state;
  
  PTLOCKN(cs->conn_state_lock,"conn_state_lock");

  gettimeofday(&tv, NULL);
  tv.tv_usec += timeout_ms*1000;
  while (tv.tv_usec > 1000000) {
    tv.tv_sec++; tv.tv_usec -= 1000000;
  }
  to.tv_sec = tv.tv_sec + 0;
  to.tv_nsec = tv.tv_usec * 1000;

  timedout = 0;

  while ((timedout == 0) && (cs->state != new)) {
    if (timeout_ms > 0) {
      if (ncp_debug) printf("NCP in %s await %s for %d ms\n", 
			    conn_state_name(c), state_name(new), timeout_ms);
      timedout = pthread_cond_timedwait(&cs->conn_state_cond, &cs->conn_state_lock, &to);
    }
    else
      pthread_cond_wait(&cs->conn_state_cond, &cs->conn_state_lock);
  }
  PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
  if (timedout == ETIMEDOUT)
    return -1;
  else if (timedout < 0)
    perror("?? pthread_cond_timedwait");

  return cs->state;
}

static struct conn *
make_conn(conntype_t ctype, int sock, struct sockaddr_un *sa, int sa_len)
{
  // mutable conn state
  struct conn_state *cs = (struct conn_state *)calloc(1, sizeof(struct conn_state));

  struct pkqueue *read_pkts = make_pkqueue();
  struct pkqueue *received_pkts_ooo = make_pkqueue();
  struct pkqueue *send_pkts = make_pkqueue();

  if (ncp_debug) printf("Creating %s conn\n", conn_type_type_name(ctype));

  if ((cs == NULL)||(read_pkts == NULL)||(received_pkts_ooo==NULL)||(send_pkts==NULL)) {
    perror("?? malloc(make_conn)");
    exit(1);
  }

  cs->read_pkts = read_pkts;
  cs->read_pkts_controlled = 0;
  cs->received_pkts_ooo = received_pkts_ooo;
  cs->received_pkts_ooo_width = 0;
  cs->send_pkts = send_pkts;
  cs->state = CS_Inactive;
  cs->local_winsize = DEFAULT_WINSIZE;
  cs->foreign_winsize = DEFAULT_WINSIZE;
  cs->window_available = DEFAULT_WINSIZE;
  cs->pktnum_sent_highest = make_fresh_index(); // initialize
  cs->pktnum_made_highest = cs->pktnum_sent_highest;
  cs->time_last_received = 0;
  cs->time_last_probed = 0;

  // condition vars, locks
  if (pthread_mutex_init(&cs->conn_state_lock, NULL) != 0)
    perror("?? pthread_mutex_init(conn_state_lock)");
  if (pthread_cond_init(&cs->conn_state_cond, NULL) != 0)
    perror("?? pthread_cond_init(conn_state_cond)");
  if (pthread_mutex_init(&cs->read_mutex, NULL) != 0)
    perror("?? pthread_mutex_init(read_mutex)");
  if (pthread_cond_init(&cs->read_cond, NULL) != 0)
    perror("?? pthread_cond_init(read_cond)");
  if (pthread_mutex_init(&cs->received_ooo_mutex, NULL) != 0)
    perror("?? pthread_mutex_init(received_ooo_mutex)");
  if (pthread_mutex_init(&cs->send_mutex, NULL) != 0)
    perror("?? pthread_mutex_init(send_mutex)");
  if (pthread_cond_init(&cs->send_cond, NULL) != 0)
    perror("?? pthread_cond_init(send_cond)");
  if (pthread_mutex_init(&cs->window_mutex, NULL) != 0)
    perror("?? pthread_mutex_init(window_mutex)");
  if (pthread_cond_init(&cs->window_cond, NULL) != 0)
    perror("?? pthread_cond_init(window_cond)");


  // the conn itself
  struct conn *conn = (struct conn *)calloc(1, sizeof(struct conn));

  conn->conn_type = ctype;
  if (pthread_mutex_init(&conn->conn_lock, NULL) != 0)
    perror("?? pthread_mutex_init(conn_lock)");
  conn->conn_sock = sock;

  if (sa != NULL)
    memcpy(&conn->conn_sockaddr, sa, (sa_len > sizeof(conn->conn_sockaddr) ? sizeof(conn->conn_sockaddr) : sa_len));
  conn->conn_state = cs;
  conn->retransmission_interval = default_retransmission_interval;
  conn->follow_forward = forward_transparently;
  conn->rfc_timeout = CONNECTION_TIMEOUT;
  conn->conn_created = time(NULL);

  if (ncp_debug) print_conn("Made new", conn, 1);
  return conn;
}

static struct conn *
make_temp_conn_from_pkt(struct chaos_header *ch)
{
  struct conn *conn = make_conn(CT_Simple, 0, NULL, 0);
  // no locking needed, not accessible from outside yet
  conn->conn_rhost = ch_srcaddr(ch);
  conn->conn_ridx = ch_srcindex(ch);
  conn->conn_lhost = ch_destaddr(ch);
  conn->conn_lidx = ch_destindex(ch);
  return conn;
}

static void
free_conn(struct conn *conn)
{
  int x;
  struct conn_state *cs = conn->conn_state;

  PTLOCKN(cs->read_mutex,"read_mutex");
  if (ncp_debug) printf("free_pkqeue(read_pkts)\n");
  free_pkqueue(cs->read_pkts);
  PTUNLOCKN(cs->read_mutex,"read_mutex");

  PTLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
  if (ncp_debug) printf("free_pkqeue(received_pkts_ooo)\n");
  free_pkqueue(cs->received_pkts_ooo);
  PTUNLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");

  PTLOCKN(cs->send_mutex,"send_mutex");
  if (ncp_debug) printf("free_pkqeue(send_pkts)\n");
  free_pkqueue(cs->send_pkts);
  PTUNLOCKN(cs->send_mutex,"send_mutex");

  if (conn->conn_contact != NULL)
    free(conn->conn_contact);
  if (conn->conn_contact_args != NULL)
    free(conn->conn_contact_args);

  if ((x = pthread_mutex_destroy(&conn->conn_lock)) != 0) 
    fprintf(stderr,"pthread_mutex_destroy(conn_lock): %s\n", strerror(x));
  if ((x = pthread_mutex_destroy(&cs->conn_state_lock)) != 0) 
    fprintf(stderr,"pthread_mutex_destroy(conn_state_lock): %s\n", strerror(x));
  if ((x = pthread_cond_destroy(&cs->conn_state_cond)) != 0) 
    fprintf(stderr,"pthread_cond_destroy(conn_state_cond): %s\n", strerror(x));
  if ((x = pthread_mutex_destroy(&cs->read_mutex)) != 0) 
    fprintf(stderr,"pthread_mutex_destroy(read_mutex): %s\n", strerror(x));
  if ((x = pthread_cond_destroy(&cs->read_cond)) != 0) 
    fprintf(stderr,"pthread_cond_destroy(read_cond): %s\n", strerror(x));
  if ((x = pthread_mutex_destroy(&cs->received_ooo_mutex)) != 0) 
    fprintf(stderr,"pthread_mutex_destroy(received_ooo_mutex): %s\n", strerror(x));
  if ((x = pthread_mutex_destroy(&cs->send_mutex)) != 0) 
    fprintf(stderr,"pthread_mutex_destroy(send_mutex): %s\n", strerror(x));
  if ((x = pthread_cond_destroy(&cs->send_cond)) != 0) 
    fprintf(stderr,"pthread_cond_destroy(send_cond): %s\n", strerror(x));
  if ((x = pthread_mutex_destroy(&cs->window_mutex)) != 0) 
    fprintf(stderr,"pthread_mutex_destroy(window_mutex): %s\n", strerror(x));
  if ((x = pthread_cond_destroy(&cs->window_cond)) != 0) 
    fprintf(stderr,"pthread_cond_destroy(window_cond): %s\n", strerror(x));

  if (ncp_debug) printf("NCP freeing conn_state for %p\n", conn);
  free(cs);
  if (ncp_debug) printf("NCP freeing conn %p\n", conn);
  free(conn);
}

static pthread_mutex_t connlist_lock = PTHREAD_MUTEX_INITIALIZER;
static struct conn_list *
add_active_conn(struct conn *c)
{
  int x, cstate;
  struct conn_list *new = (struct conn_list *)malloc(sizeof(struct conn_list));

  new->conn_conn = c;
  if (ncp_debug) print_conn("Adding active",c,0);

  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(connlist_lock,"connlist_lock");
  new->conn_next = conn_list;
  new->conn_prev = NULL;
  if (conn_list != NULL)
    conn_list->conn_prev = new;
  conn_list = new;
  PTUNLOCKN(connlist_lock,"connlist_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();

  if (ncp_debug > 1) print_conn("Added active",c,0);
  return conn_list;
}

// find c on conn_list, remove from conn_list, and free the element from conn_list
// c is also freed!
static void
remove_active_conn(struct conn *c, int dolock, int dofree)
{
  int x, cstate;
  struct conn_list *cl;

  if (ncp_debug) printf("NCP removing conn %p\n", c);
  if (dolock) {
    // protect against cancellation while holding global lock
    if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
      fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

    PTLOCKN(connlist_lock,"connlist_lock");
  }
  for (cl = conn_list; cl != NULL; cl = cl->conn_next) {
    struct conn *cn = cl->conn_conn;
    if ((cn == c) ||
	((c->conn_rhost == cn->conn_rhost) &&
	 (c->conn_ridx == cn->conn_ridx) &&
	 (c->conn_lhost == cn->conn_lhost) &&
	 (c->conn_lidx == cn->conn_lidx))) {
      int lastone = 0;
      if (ncp_debug) printf("Removing conn %p from conn_list %p prev %p next %p\n", 
			    c, cl, cl->conn_prev, cl->conn_next);
      if (cl->conn_prev != NULL)
	cl->conn_prev->conn_next = cl->conn_next;
      else
	// if prev was null, this is the first element, so conn_list needs updating
	conn_list = cl->conn_next;

      if (cl->conn_next != NULL)
	cl->conn_next->conn_prev = cl->conn_prev;
      if ((cl->conn_prev == NULL) && (cl->conn_next == NULL))
	lastone = 1;
      if (ncp_debug) printf("NCP freeing conn_list entry %p for %p\n", cl, c);
      free(cl);
      if (lastone)
	conn_list = NULL;
      if (dofree) {
	if (ncp_debug) printf("NCP freeing conn %p\n", c);
	free_conn(c);
      }
      break;
    }
  }
  if (dolock) {
    PTUNLOCKN(connlist_lock,"connlist_lock");

    if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
      fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
    // see if we were cancelled?
    pthread_testcancel();
  }
}

// find a conn on conn_list which matches the (incoming) packet
static struct conn *
find_existing_conn(struct chaos_header *ch)
{
  int x, cstate;
  struct conn_list *cl;
  struct conn *val = NULL;

    // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(connlist_lock,"connlist_lock");
  for (cl = conn_list; (cl != NULL) && (val == NULL); cl = cl->conn_next) {
    struct conn *c = cl->conn_conn;
    if ((c->conn_rhost == ch_srcaddr(ch)) &&
	((c->conn_ridx == ch_srcindex(ch)) || // properly existing conn
	 (((ch_opcode(ch) == CHOP_RFC) || (ch_opcode(ch) == CHOP_OPN) || (ch_opcode(ch) == CHOP_ANS) || 
	   (ch_opcode(ch) == CHOP_FWD) || (ch_opcode(ch) == CHOP_CLS))
	  // half-existing conn where we don't know the remote index yet
	  && (c->conn_ridx == 0))
	 // uncontrolled pkt doesn't necessarily have a non-zero index, e.g. LOS for non-existing conn
	 // || (opcode_uncontrolled(ch_opcode(ch)) && (ch_srcindex(ch) == 0))
	 )
	&&
	(c->conn_lhost == ch_destaddr(ch)) &&
	((c->conn_lidx == ch_destindex(ch)) 
	 // when receiving RFC, dest index is not specified
	 || ((c->conn_state->state != CS_Inactive) && (ch_opcode(ch) == CHOP_RFC) && (ch_destindex(ch) == 0)))) {
      val = c;
      break;
    }
  }
  if (ncp_debug && (val == NULL) && ((ch_opcode(ch) == CHOP_RFC) || (ch_opcode(ch) == CHOP_LOS))) {
    u_char contact[CH_PK_MAX_DATALEN];
    get_packet_string(ch, contact, sizeof(contact));
    printf("NCP: no conn found for %s %#x from src <%#o,%#x> for dest <%#o,%#x>, data (len %d) \"%s\"\n", 
	   ch_opcode_name(ch_opcode(ch)), ch_packetno(ch),
	   ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch), ch_nbytes(ch), contact);
    if (ch_opcode(ch) == CHOP_RFC) {
      printf("NCP: conn list length%s\n", conn_list == NULL ? " empty" : ":");
      struct conn_list *c = conn_list;
      while (c) {
	print_conn(">", c->conn_conn, 1);
	c = c->conn_next;
      }
    }
  }
  PTUNLOCKN(connlist_lock,"connlist_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();

  return val;
}

//////// listeners

static void
print_listener(char *leader, struct listener *l)
{
  printf("%s listener %p for \"%s\" conn %p next %p prev %p\n",
	 leader, l, l->lsn_contact, l->lsn_conn, l->lsn_next, l->lsn_prev);
}

static struct listener *
make_listener(struct conn *c, u_char *contact)
{
  struct listener *l = (struct listener *)malloc(sizeof(struct listener));
  if (l == NULL) {
    perror("?? malloc(make_listener)");
    exit(1);
  }
  int len = strlen((char *)contact);
  if (len > MAX_CONTACT_NAME_LENGTH) len = MAX_CONTACT_NAME_LENGTH;
  l->lsn_contact = calloc(1,len+1);
  strncpy((char *)l->lsn_contact, (char *)contact, len);
  l->lsn_conn = c;
  l->lsn_next = NULL;
  l->lsn_prev = NULL;

  return l;
}

static void
free_listener(struct listener *lsn)
{
  // assert(not on the registered_listeners list)
  if (lsn->lsn_contact != NULL)
    free(lsn->lsn_contact);
  if (ncp_debug) printf("NCP freeing listener %p\n", lsn);
  free(lsn);
}

static pthread_mutex_t listener_lock = PTHREAD_MUTEX_INITIALIZER;

static void
unlink_listener(struct listener *ll, int dolock)
{
  int x, cstate;

  if (dolock) {
    // protect against cancellation while holding global lock
    if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
      fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

    PTLOCKN(listener_lock,"listener_lock");
  }
  if (ll->lsn_prev == NULL) {
    if (registered_listeners != NULL)
      registered_listeners->lsn_prev = ll;
    registered_listeners = ll->lsn_next;
  } else {
    ll->lsn_prev->lsn_next = ll->lsn_next;
    if (ll->lsn_next != NULL)
      ll->lsn_next->lsn_prev = ll->lsn_prev;
  }
  if (dolock) {
    PTUNLOCKN(listener_lock,"listener_lock");

    if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
      fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
    // see if we were cancelled?
    pthread_testcancel();
  }
 }

static void
remove_listener_for_conn(struct conn *conn)
{
  int x, cstate;
  struct listener *ll;

  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(listener_lock,"listener_lock");
  for (ll = registered_listeners; ll != NULL; ll = ll->lsn_next) {
    if (ll->lsn_conn == conn) {
      unlink_listener(ll, 0);
      free_listener(ll);
      break;
    }
  }
  PTUNLOCKN(listener_lock,"listener_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();
}

static void
remove_listener_for_contact(u_char *contact)
{
  int x, cstate;
  struct listener *ll;

  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(listener_lock,"listener_lock");
  for (ll = registered_listeners; ll != NULL; ll = ll->lsn_next) {
    if (strcmp((char *)ll->lsn_contact, (char *)contact) == 0) {
      unlink_listener(ll, 0);
      free_listener(ll);
      break;
    }
  }
  PTUNLOCKN(listener_lock,"listener_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();
  return;
}

struct listener *
add_listener(struct conn *c, u_char *contact)
{
  int x, cstate;

  // make listener, add to registered_listeners 
  struct listener *new = make_listener(c, contact);
  if (ncp_debug) print_listener("Adding",new);

  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(listener_lock,"listener_lock");
  new->lsn_next = registered_listeners;
  // assert(registered_listeners->lsn_prev == NULL) always
  if (registered_listeners != NULL)
    registered_listeners->lsn_prev = new;
  registered_listeners = new;
  PTUNLOCKN(listener_lock,"listener_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();

  set_conn_state(c, CS_Inactive, CS_Listening, 0);
  return registered_listeners;
}

// find a listener for the RFC received
struct conn *
find_matching_listener(struct chaos_header *ch)
{
  int x, cstate;
  struct listener *ll;
  struct conn *val = NULL;
  u_char *contact = (u_char *)calloc(1, ch_nbytes(ch)+3);

  get_packet_string(ch, contact, ch_nbytes(ch)+2);
  char *space = index((char *)contact, ' ');
  if (space) // ignore args
    *space = '\0';

  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(listener_lock,"listener_lock");
  for (ll = registered_listeners; ll != NULL; ll = ll->lsn_next) {
    if (strcmp((char *)contact, (char *)ll->lsn_contact) == 0) {
      if (space) // undo
	*space = ' ';
      val = ll->lsn_conn;
      break;
    } else if (ncp_debug)
      printf("NCP checking listener \"%s\" against RFC \"%s\" - mismatch\n", ll->lsn_contact, contact);
  }
  PTUNLOCKN(listener_lock,"listener_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();
  return val;
}

//////////////// packets

// call this with conn_state_lock held
static int
make_pkt_from_conn(int opcode, struct conn *c, u_char *pkt)
{
  struct conn_state *cs = c->conn_state;
  int pklen = 0;
  struct chaos_header *ch = (struct chaos_header *)pkt;
  u_char *data = &pkt[CHAOS_HEADERSIZE];
  u_short *dataw = (u_short *)data; // as 16-bit words

  memset(pkt, 0, CHAOS_HEADERSIZE);
  set_ch_opcode(ch, opcode);
  set_ch_destaddr(ch, c->conn_rhost);
  set_ch_destindex(ch, c->conn_ridx);
  set_ch_srcaddr(ch, c->conn_lhost);
  set_ch_srcindex(ch, c->conn_lidx);
  set_ch_ackno(ch, cs->pktnum_read_highest);
  cs->pktnum_acked = cs->pktnum_read_highest; // record the sent ack

  if (opcode_uncontrolled(opcode))
    set_ch_packetno(ch, 0);
  else {
    set_ch_packetno(ch, pktnum_1plus(cs->pktnum_made_highest));
    cs->pktnum_made_highest = pktnum_1plus(cs->pktnum_made_highest);
  }

  switch (opcode) {
  case CHOP_RFC:
      if (c->conn_contact_args != NULL) {
	u_char rfcwithargs[MAX_CONTACT_NAME_LENGTH];
	sprintf((char *)rfcwithargs, "%s %s", c->conn_contact, c->conn_contact_args);
	pklen = ch_11_puts(data, rfcwithargs);
      } else
	pklen = ch_11_puts(data, c->conn_contact);
    break;
  case CHOP_SNS:
    // no data
    break;
  case CHOP_OPN: // same data as for STS
  case CHOP_STS:
    {
      u_short winz = cs->local_winsize;
      u_short receipt = cs->pktnum_received_highest; // note: different from ackno
      dataw[0] = htons(receipt);
      dataw[1] = htons(winz);
      pklen = 4;
    }
    break;
  case CHOP_LSN:
    fprintf(stderr,"making LSN packet doesn't make sense\n");
    exit(1);
  }
  set_ch_nbytes(ch, pklen);

  pklen += CHAOS_HEADERSIZE;
  if (pklen % 2)
    pklen++;
  return pklen;
}

static int
send_basic_pkt_with_data(struct conn *c, int opcode, u_char *data, int len)
{
  u_char pkt[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)pkt;
  u_char *datao = &pkt[CHAOS_HEADERSIZE];
  int pklen;

  PTLOCK(c->conn_state->conn_state_lock);
  // construct pkt from conn
  pklen = make_pkt_from_conn(opcode, c, (u_char *)&pkt);
  PTUNLOCK(c->conn_state->conn_state_lock);
  if ((data != NULL) && (len > 0)) {
    switch (opcode) {
    case CHOP_RFC: case CHOP_CLS: case CHOP_LOS: case CHOP_ANS:
      htons_buf((u_short *)data, (u_short *)datao, len);
      break;
    case CHOP_FWD:
      // yes, this is cheating
      set_ch_ackno(ch, data[0] | (data[1] << 8));
      len = 0;
      break;
    default:
      if (opcode >= CHOP_DAT)
	htons_buf((u_short *)data, (u_short *)datao, len);
      else
	memcpy(datao, data, len);
    }
    pklen += len;
    set_ch_nbytes(ch, len);
  }

  if (opcode_uncontrolled(opcode)) {
    if (ncp_debug) {
      printf("NCP sending uncontrolled pkt %#x (%s) len %d remote <%#o,%#x> local <%#o,%#x> in state %s\n", 
	     ch_packetno(ch), ch_opcode_name(ch_opcode(ch)), pklen, 
	     c->conn_rhost, c->conn_ridx, c->conn_lhost, c->conn_lidx, conn_state_name(c));
    }
    send_chaos_pkt(pkt, pklen);
  } else 
    add_output_pkt(c, ch);

  return ch_packetno(ch);
}

static int
send_basic_pkt(struct conn *c, int opcode)
{
  return send_basic_pkt_with_data(c, opcode, NULL, 0);
}

static void
send_sts_pkt(struct conn *c)
{
  send_basic_pkt(c, CHOP_STS);
}

static void
send_sns_pkt(struct conn *c)
{
  send_basic_pkt(c, CHOP_SNS);
}

static int
send_eof_pkt(struct conn *c)
{
  if (ncp_debug)
    print_conn("Sending EOF for", c, 1);
  return send_basic_pkt(c, CHOP_EOF);
}


// initialize local haddr, index, winsize
static void
send_first_pkt(struct conn *c, int opcode, connstate_t newstate)
{
  struct conn_state *cs = c->conn_state;
  u_char pkt[CH_PK_MAXLEN];
  int pklen;

  if (ncp_debug > 1) printf("NCP: about to make %s pkt\n", ch_opcode_name(opcode));

  PTLOCKN(c->conn_lock,"conn_lock");
  c->conn_lhost = find_my_closest_addr(c->conn_rhost);
  if (ncp_debug) printf("NCP: my closest addr to %#o (%#x) is %#o (%#x)\n",
			c->conn_rhost, c->conn_rhost, c->conn_lhost, c->conn_lhost);
  c->conn_lidx = make_fresh_index();
  PTUNLOCKN(c->conn_lock,"conn_lock");
  if (ncp_debug > 1) print_conn("Updated", c, 0);

  PTLOCKN(cs->conn_state_lock,"conn_state_lock");
  cs->local_winsize = default_window_size;

  // initial pkt nr random, make sure we don't think it's acked
  // ITS starts at 1, but random is better against hijacks.
  cs->pktnum_made_highest = make_u_short_random();
  cs->pktnum_sent_acked = c->conn_state->pktnum_made_highest;
  cs->pktnum_sent_highest = c->conn_state->pktnum_made_highest;

  // construct pkt from conn
  pklen = make_pkt_from_conn(opcode, c, (u_char *)&pkt);

  set_conn_state(c, cs->state, newstate, 1);
  PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");

  if ((c->conn_type == CT_Simple) || opcode_uncontrolled(opcode)) {
    if (ncp_debug) printf("NCP sending simple/uncontrolled pkt %#x (%s)\n", 
			  ch_packetno((struct chaos_header *)pkt), ch_opcode_name(ch_opcode((struct chaos_header *)pkt)));
    send_chaos_pkt(pkt, pklen);
  } else {
    if (ncp_debug > 1) printf("NCP: adding pkt to output for conn\n");
    add_output_pkt(c, (struct chaos_header *)pkt);
    if (ncp_debug > 1) printf("NCP send queue now %d\n", pkqueue_length(c->conn_state->send_pkts));
  }
}

static void
send_rfc_pkt(struct conn *c)
{
  // count it as created when we send the first RFC pkt (for timeout handling)
  c->conn_created = time(NULL);
  send_first_pkt(c, CHOP_RFC, CS_RFC_Sent);
}


static void
send_opn_pkt(struct conn *c)
{
  // don't declare it open until STS arrives
  send_first_pkt(c, CHOP_OPN, CS_Open_Sent);
}


static void
send_ans_pkt(struct conn *c, u_char *ans, int len)
{
  send_basic_pkt_with_data(c, CHOP_ANS, ans, len);
  // ANS is uncontrolled, so just terminate
  socket_closed_for_simple_conn(c);
}

static void
send_fwd_pkt(struct conn *c, u_short addr)
{
  // this is abusing the args to send_basic_pkt_with_data...
  u_char buf[2];
  buf[0] = addr & 0xff;
  buf[1] = addr >> 8;
  if (ncp_debug) printf("NCP sending FWD to %#o\n", addr);
  send_basic_pkt_with_data(c, CHOP_FWD, buf, 2);
  // FWD is uncontrolled, so just terminate
  socket_closed_for_simple_conn(c);
}

// i.e LOS or CLS
static void
send_text_response_pkt(struct conn *c, int opcode, u_char *msg)
{
  u_char txt[CH_PK_MAX_DATALEN];
  int len = strlen((char *)msg);
  if (len < sizeof(txt))
    ch_11_puts(txt,msg);
  else 
    fprintf(stderr,"%%%% NCP: bad text response length %d, %s\n", len, msg);
  send_basic_pkt_with_data(c, opcode, msg, len);
}

static void
send_los_pkt(struct conn *c, char *reason)
{
  send_text_response_pkt(c, CHOP_LOS, (u_char *)reason);
}

static void
send_cls_pkt(struct conn *c, char *msg)
{
  send_text_response_pkt(c, CHOP_CLS, (u_char *)msg);
}

static void 
wait_for_ack_of_pkt(struct conn *conn, int pknum) 
{
  struct conn_state *cs = conn->conn_state;
  int timedout;
  struct timespec to;
  struct timeval tv, tn, ts;

  // Use window updates from discard_received_pkts_from_send_list to check for acked pkts - this is a hack
  PTLOCKN(cs->window_mutex,"window_mutex");

  gettimeofday(&tv, NULL);
  memcpy(&ts, &tv, sizeof(ts));
  tv.tv_usec += eof_wait_timeout*1000;
  while (tv.tv_usec > 1000000) {
    tv.tv_sec++; tv.tv_usec -= 1000000;
  }
  to.tv_sec = tv.tv_sec + 0;
  to.tv_nsec = tv.tv_usec * 1000;

  timedout = 0;

  while ((timedout == 0) && pktnum_less(cs->pktnum_sent_acked, pknum))
    timedout = pthread_cond_timedwait(&cs->window_cond, &cs->window_mutex, &to);
  if ((timedout < 0) && (timedout != ETIMEDOUT))
    perror("?? pthread_cond_timedwait");
  PTUNLOCKN(cs->window_mutex,"window_mutex");

  if (ncp_debug) {
    gettimeofday(&tn, NULL);
    tn.tv_sec -= ts.tv_sec;
    tn.tv_usec -= ts.tv_usec;
    while (tn.tv_usec < 0) {
      tn.tv_sec--; 
      tn.tv_usec += 1000000;
    }
    printf("NCP %s for %p done waiting for EOF ack %#x (%s after %ld.%03d)\n", conn_thread_name(conn), conn, pknum,
	   timedout != 0 ? "timed out" : "acked", tn.tv_sec, tn.tv_usec/1000);
  }
}


//// packet conn stuff

static void
packet_conn_header_from_pkt(struct conn *conn, int opc, u_char *out, int len)
{
  if (conn->conn_type != CT_Packet) {
    fprintf(stderr,"packet_conn_header_from_pkt called with bad conn %p type %s\n", conn, conn_type_name(conn));
    abort();
  }
  out[0] = opc;
  out[1] = 0;
  // lsb
  out[2] = len & 0xff;
  // msb
  out[3] = len >> 8;
  if (ncp_debug) printf("NCP Packet: made header %#o (%s) %d %#x %#x (nbytes %#x)\n", 
			out[0], ch_opcode_name(out[0]), out[1], out[2], out[3], len);
}

static int
packet_conn_parse_and_send_bytes(struct conn *conn, u_char *buf, int cnt) 
{
  u_char *bp = buf;
  int opc, zero, len = 0;
  while (cnt > 0) {
    opc = bp[0];
    zero = bp[1];
    len = bp[2];
    len |= bp[3]<<8;
    if ((opc == 0) || ((opc > CHOP_BRD) && (opc < CHOP_DAT)) || (zero != 0) || (len > CH_PK_MAX_DATALEN)) {
      if (ncp_debug) printf("%%%% NCP socket_to_conn_packet_handler: bad opc %#o, zero nonzero (%d), or len too big (%d)\n", opc, zero, len);
      user_socket_los(conn,"Bad packet format (%#o %d %d)", opc, zero, len);
      return -1;
    }
    if (cnt-4 < len) {
      if (ncp_debug) printf("NCP Packet: read from socket didn't get a full packet (opcode %s len %d have %d)\n", 
			    ch_opcode_name(opc), len, cnt);
      // move what we have, so there is space
      if (ncp_debug) printf("NCP Packet: moving %d bytes from %p to %p (diff %ld)\n", 
			    cnt, bp, buf, bp-buf);
      memmove(buf, bp, cnt);
      bp = buf;
      // read just what we need
      if (ncp_debug) printf("NCP Packet: reading %d more bytes to get a full 4+%d chunk at %p (diff %ld)\n", 
			    (len+4)-cnt, len, &buf[cnt], &buf[cnt]-buf);
      cnt += receive_or_die(conn, &buf[cnt], (len+4)-cnt);
      // go back and try parsing it again
      continue;
    } else {
      if ((opc == CHOP_EOF) || (opc == CHOP_LOS) || (opc == CHOP_UNC) || (opc >= CHOP_DAT)) {
	int pknum, dowait = 0;
	if (ncp_debug) printf("NCP Packet: parsed opcode %#o (%s) len %d\n", opc, ch_opcode_name(opc), len);
	if (opc == CHOP_EOF) {
	  if ((len > 0) && (strncasecmp((char *)(bp+4), "wait", 4) == 0)) 
	    dowait = 1;
	// EOF pkts always have zero length
	  pknum = send_basic_pkt_with_data(conn, opc, bp+4, 0);
	} else
	  pknum = send_basic_pkt_with_data(conn, opc, bp+4, len);
	if (dowait) {
	  if (ncp_debug) printf("NCP Packet waiting for ACK of EOF %#x\n", pknum);
	  wait_for_ack_of_pkt(conn, pknum);
	  // @@@@ invent an ACK pkt to send to the socket?
	  u_char ackpkt[CHAOS_HEADERSIZE];
	  struct chaos_header *pkt = (struct chaos_header *)ackpkt;
	  set_ch_opcode(pkt, CHOP_ACK);
	  set_ch_nbytes(pkt, 0);
	  send_to_user_socket(conn, pkt, ackpkt, 0);
	}
      } else
	user_socket_los(conn,"Bad opcode %s in state %s, only LOS UNC DAT..DWD are OK", 
			ch_opcode_name(opc), conn_state_name(conn));
    }
    cnt -= (4+len);
    bp += (4+len);
  }
  return 1;
}

//// stream conn stuff
static void 
stream_conn_send_data_chunks(struct conn *conn, u_char *bp, int cnt) 
{
  // Just plain data, pack it up and send it. OK if Open_Sent, just queue the data for output.
  // Break it up in packet chunks if necessary
  while (cnt > CH_PK_MAX_DATALEN) {
    if (ncp_debug) printf("NCP sending max data chunk: %.10s ...\n", bp);
    send_basic_pkt_with_data(conn, CHOP_DAT, bp, CH_PK_MAX_DATALEN);
    bp += CH_PK_MAX_DATALEN;
    cnt -= CH_PK_MAX_DATALEN;
  }
  if (cnt > 0) {
    if (ncp_debug) printf("NCP sending remaining data chunk (%d): %.10s ...\n", cnt, bp);
    send_basic_pkt_with_data(conn, CHOP_DAT, bp, cnt);
  }
}


//////////////// shutting things down

static void
cancel_conn_threads(struct conn *conn)
{
  struct conn_state *cs = conn->conn_state;
  char *tn = conn_thread_name(conn);
  int x, y;
  void *jv;

  if (ncp_debug) printf("cancelling threads for %p (this is %s)\n", conn, tn);

  if (conn->conn_sock != -1) {
    if (ncp_debug) printf("%%%% Terminating conn %p but conn_sock non-negative (%d) - fixing that\n", 
			  conn, conn->conn_sock);
    close(conn->conn_sock);
    conn->conn_sock = -1;
  }
  if (pthread_equal(conn->conn_to_net_thread, pthread_self()) ||
      pthread_equal(conn->conn_from_sock_thread, pthread_self())) {
    // conn_to_sock is the main thread, which waits for the others to join - they just exit.
    if (ncp_debug) printf("%%%% Conn %p thread %p (%s) terminating\n", conn, pthread_self(), conn_thread_name(conn));
    // make sure conn_to_sock also knows
    PTLOCKN(cs->read_mutex,"read_mutex");
    if ((x = pthread_cond_signal(&cs->read_cond) != 0)) 
      fprintf(stderr,"?? pthread_cond_signal(read_cond): %s", strerror(x));
    PTUNLOCKN(cs->read_mutex,"read_mutex");
    pthread_exit(NULL);
  } else if (pthread_equal(conn->conn_to_sock_thread, pthread_self())) {
    if (ncp_debug) printf("%%%% Conn %p thread %p (%s) waiting for %p and %p to join\n",
			  conn, pthread_self(), conn_thread_name(conn), 
			  conn->conn_to_net_thread, conn->conn_from_sock_thread);
    if ((x = pthread_join(conn->conn_to_net_thread,(void *) &jv)) < 0) {
      if (ncp_debug) fprintf(stderr,"pthread_join (c_t_n): %s\n", strerror(x));
    }
    if ((y = pthread_join(conn->conn_from_sock_thread,(void *) &jv)) < 0) {
      if (ncp_debug) fprintf(stderr,"pthread_join (c_f_s): %s\n", strerror(y));
    }
    // and NOW free all storage
    if ((x == 0) && (y == 0)) {
      if (ncp_debug) printf("%%%% Other threads joined %s, now freeing conn %p\n", conn_thread_name(conn), conn);
      remove_active_conn(conn, 1, 1);
    }
    if (ncp_debug) printf("%%%%%%%% NCP %s for %p terminating\n", conn_thread_name(conn), conn);
    pthread_exit(NULL);
  } else {
    // other thread (i.e. cbridge): make conn_to_sock_thread find out
    if (ncp_debug) printf("Conn %p asked to cancel everything\n", conn);
    close(conn->conn_sock);
    conn->conn_sock = -1;
    PTLOCKN(cs->read_mutex,"read_mutex");
    if ((x = pthread_cond_signal(&cs->read_cond) != 0)) 
      fprintf(stderr,"?? pthread_cond_signal(read_cond): %s", strerror(x));
    PTUNLOCKN(cs->read_mutex,"read_mutex");
  }
}


static void
finish_stream_conn(struct conn *conn, int send_eof)
{
  struct conn_state *cs = conn->conn_state;
  int wait_eof_ack = send_eof;
  u_short eofpktnum = 0;

  if (ncp_debug) printf("NCP conn %p (%s) finishing\n", conn, conn_thread_name(conn));
  if (conn->conn_state->state == CS_Inactive) { // || (conn->conn_sock == -1)
    //trace_conn("Already finished", conn);
    if (ncp_debug) print_conn("Already finished", conn, 1);
    cancel_conn_threads(conn);
    return;
  }
  trace_conn("Finishing", conn);
  if (ncp_debug) print_conn("Finishing", conn, 0);

  if (cs->state == CS_Open_Sent) { // ((cs->state == CS_RFC_Received) || (cs->state == CS_Open_Sent)) 
    // Wait a while for conn to open so pkts can get through
    int to;
    if (ncp_debug) printf("NCP %s Finishing in state %s, waiting for Open\n", 
			  conn_thread_name(conn), conn_state_name(conn));
    to = await_conn_state(conn, CS_Open, finish_wait_timeout);
    if (ncp_debug) printf("NCP Finished waiting %s, state %s now\n", 
			  to < 0 ? "TIMED OUT" : "no timeout", conn_state_name(conn));
  }
  if (cs->state == CS_Open) {
    // finish conn: send eof, wait for it to be acked.
    if (ncp_debug) printf("NCP %s finishing in state %s, retransmitting\n", 
			  conn_thread_name(conn), conn_state_name(conn));
    set_conn_state(conn, CS_Open, CS_Finishing, 1);
    // try retransmission first, in anything remains
    retransmit_controlled_packets(conn);
    // Also when eof has been sent already
    if (!send_eof) {
      PTLOCKN(cs->send_mutex,"send_mutex");
      struct chaos_header *last = pkqueue_peek_last(cs->send_pkts);
      if ((last != NULL) && (ch_opcode(last) == CHOP_EOF)) {
	wait_eof_ack = 1;
	eofpktnum = ch_packetno(last);
	if (ncp_debug) printf("NCP %s finds last sent pkt is EOF %#x\n", conn_thread_name(conn), eofpktnum);
      }
      PTUNLOCKN(cs->send_mutex,"send_mutex");
    }
    if (wait_eof_ack) {
      if (ncp_debug) printf("NCP %s%s sending EOF, waiting for its ack\n",
			    conn_thread_name(conn), send_eof ? "" : " not");
      if (send_eof)
	eofpktnum = send_eof_pkt(conn);
      // now wait.
      wait_for_ack_of_pkt(conn, eofpktnum);
    }
    if (cs->state != CS_CLS_Received) {
      // unless CLS received, send a CLS
      send_cls_pkt(conn,"Bye bye");
    }
  }
  PTLOCKN(conn->conn_lock, "conn_lock");
  int s = conn->conn_sock;
  // this signals to all (other) threads it's time to go home
  if (ncp_debug) printf("NCP %s for %p setting conn_sock to -1\n", conn_thread_name(conn), conn);
  conn->conn_sock = -1;
  close(s);
  if ((strlen(conn->conn_sockaddr.sun_path) > 0) && (unlink(conn->conn_sockaddr.sun_path) != 0)) {
    if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", conn->conn_sockaddr.sun_path, strerror(errno));
  }
  set_conn_state(conn, cs->state, CS_Inactive, 0);
  PTUNLOCKN(conn->conn_lock, "conn_lock");
  // and terminate
  cancel_conn_threads(conn);
}

// !!!! note: this is used (cf send_ans_pkt), although CT_Simple is not fully implemented
static void 
socket_closed_for_simple_conn(struct conn *conn)
{
  if (ncp_debug) print_conn("Socket closed for", conn, 0);
  if (conn->conn_state->state == CS_Listening) {
    remove_listener_for_conn(conn);
  }
  // leave the conn around for tracing/statistics
  set_conn_state(conn, conn->conn_state->state, CS_Inactive, 0);
  close(conn->conn_sock);
  conn->conn_sock = -1;
  if ((strlen(conn->conn_sockaddr.sun_path) > 0) && (unlink(conn->conn_sockaddr.sun_path) != 0)) {
    if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", conn->conn_sockaddr.sun_path, strerror(errno));
  }
  cancel_conn_threads(conn);
  // does not get here unless it's called by cbridge/packet_to_conn_handler
}

static void 
socket_closed_for_stream_conn(struct conn *conn)
{
  if (ncp_debug) print_conn("Socket closed for", conn, 0);
  if (conn->conn_state->state == CS_Listening) {
    remove_listener_for_conn(conn);
  }
  // Only send EOF automatically for Stream conns - Packet conns have their own responsibility to handle them.
  finish_stream_conn(conn, conn->conn_type == CT_Stream ? 1 : 0);
}

static void 
socket_closed_for_conn(struct conn *conn)
{
  if (conn->conn_type == CT_Simple)
    socket_closed_for_simple_conn(conn);
  else
    socket_closed_for_stream_conn(conn);
}

static void 
user_socket_los(struct conn *conn, char *fmt, ...)
{
  u_char data[CH_PK_MAX_DATALEN];
  char *dp;
  va_list args;

  if (conn->conn_type == CT_Stream)
    dp = (char *)data;
  else if (conn->conn_type == CT_Packet)
    dp = (char *)&data[4];

  va_start(args, fmt);
  vsprintf(dp, fmt, args);
  va_end(args);

  if (conn->conn_type == CT_Stream)
    dprintf(conn->conn_sock,"LOS %s\r\n", data);
  else if (conn->conn_type == CT_Packet) {
    // prepend data with a LOS "simple header"
    int len = strlen(dp);
    if (len > CH_PK_MAX_DATALEN) len = CH_PK_MAX_DATALEN;
    data[0] = CHOP_LOS; data[1] = 0;
    data[2] = len & 0xff; data[3] = len >> 8;
    if (
#ifdef MSG_NOSIGNAL
	send(conn->conn_sock, data, len+4, MSG_NOSIGNAL)
#else
	write(conn->conn_sock, data, len+4)
#endif
	< 0) {
      // never mind, at this stage, since we're closing down
      if ((ncp_debug) && !((errno == ECONNRESET) || (errno == EPIPE) || (errno == EBADF))) {
        perror("write(user_socket_los)");
      }
    }
  }
  close(conn->conn_sock);
  conn->conn_sock = -1;
  if ((strlen(conn->conn_sockaddr.sun_path) > 0) && (unlink(conn->conn_sockaddr.sun_path) != 0)) {
    if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", conn->conn_sockaddr.sun_path, strerror(errno));
  }
  cancel_conn_threads(conn);
}

//////////////// parsing rfcs

#if CHAOS_DNS
static u_short 
dns_closest_address_or_los(struct conn *conn, u_char *hname) 
{
  u_char dname[NS_MAXDNAME];
  u_short haddrs[4];
  int naddrs = 0;
    
  if (strlen((char *)hname) >= sizeof(dname)) {
    user_socket_los(conn, "Too long hostname: %lu", strlen((char *)hname));
    return 0;
  }
  // chaos_domains is a list, iterate until match
  strcpy((char *)dname, (char *)hname);
  int hlen = strlen((char *)hname);
  char *eoh = (char *)dname+hlen;
  if (index((char *)hname, '.') == NULL) {
    int i;
    // add a period
    *eoh++ = '.';
    for (i = 0; i < number_of_chaos_domains; i++) {
      // make sure it's terminated
      dname[sizeof(dname)-1] = '\0';
      strncpy(eoh, chaos_domains[i], sizeof(dname)-hlen-1-1);
      if (ncp_debug) printf("NCP DNS trying \"%s\"\n", dname);
      if ((naddrs = dns_addrs_of_name(dname, (u_short *)&haddrs, 4)) > 0) {
	if (ncp_debug) printf("NCP DNS found %d addrs\n", naddrs);
	break;
      }
    }
  } else 
    naddrs = dns_addrs_of_name(dname, (u_short *)&haddrs, 4);
  if (naddrs <= 0) {
    user_socket_los(conn, "No addrs of name \"%s\" found", hname);
    return 0;
  } else {
    // Pick one which is closest, if one is
    return find_closest_addr((u_short *)&haddrs, naddrs);
  }
}
#endif // CHAOS_DNS


// Read contact name from in, return a malloc()ed null-terminated copy
u_char *
parse_contact_name(u_char *in)
{
  u_char *copy;
  int i = 0;
  while (in[i] != '\0' && !(isspace(in[i]))) {
    if (islower(in[i])) in[i] = toupper(in[i]);
    i++;
  }
  copy = calloc(1, i+1);
  if (copy == NULL) { fprintf(stderr,"calloc failed (parse_contact_name)\n"); exit(1); }
  strncpy((char *)copy, (char *)in, i);
  return copy;
}

u_char * 
parse_contact_args(u_char *data, u_char *contact) 
{
  if (strlen((char *)data) > strlen((char *)contact)) {
    int i, j = strlen((char *)data) - strlen((char *)contact);
    u_char *e, *p = &data[strlen((char *)contact)];
    // skip spaces
    while (*p == ' ') p++;
    // find end of printable stuff (or string)
    for (i = 0, e = p; i < j && isprint(*e); e++, i++);
    // terminate (e.g. CRLF)
    *e = '\0';
    if (e == p)
      return NULL;
    else
      return (u_char *)strdup((char *)p);
  } else
    return NULL;
}


static void
initiate_conn_from_rfc_pkt(struct conn *conn, struct chaos_header *ch, u_char *data)
{
  u_char contact[MAX_CONTACT_NAME_LENGTH];

  get_packet_string(ch, contact, sizeof(contact));

  PTLOCKN(conn->conn_lock,"conn_lock");
  conn->conn_contact = parse_contact_name(contact);
  conn->conn_contact_args = parse_contact_args(contact, conn->conn_contact);
  conn->conn_rhost = ch_srcaddr(ch);
  conn->conn_ridx = ch_srcindex(ch);
  conn->conn_lhost = ch_destaddr(ch);
  conn->conn_lidx = make_fresh_index();
  conn->conn_state->pktnum_received_highest = ch_packetno(ch);
  conn->conn_created = time(NULL);
  // conn->conn_state->state = CS_RFC_Received;
  PTUNLOCKN(conn->conn_lock,"conn_lock");
  if (ncp_debug) print_conn("Initiated from RFC pkt:", conn, 0);
  add_active_conn(conn);
}


static void
handle_option(struct conn *c, char *optname, char *val)
{
  if (ncp_debug) printf("NCP parsing RFC option \"%s\" value \"%s\"\n", optname, val);
  if (strcasecmp(optname, "timeout") == 0) {
    int to = 0;
    if ((sscanf(val, "%d", &to) == 1) && (to > 0)) {
      if (ncp_debug) printf(" setting rfc_timeout to %d\n", to);
      c->rfc_timeout = to;
    } else {
      if (ncp_debug) printf(" bad value, not a positive int");
      user_socket_los(c, "Bad timeout value \"%s\" in RFC options", val);
      return;
    }
  // @@@@ add more options as needed, maybe windowsize, retrans, etc?
  } else if (strcasecmp(optname, "follow_forward") == 0) {
    if ((strlen(val) == 0) || (strcasecmp(val,"yes") == 0) || (strcasecmp(val,"on") == 0)) {
      if (ncp_debug) printf(" setting 1\n");
      c->follow_forward = 1;
    } else if ((strcasecmp(val,"off") == 0) || (strcasecmp(val,"no") == 0)) {
      if (ncp_debug) printf(" setting 0\n");
      c->follow_forward = 0;
    } else {
      if (ncp_debug) printf("Bad follow_forward value \"%s\"\n", val);
      user_socket_los(c, "Bad follow_forward value \"%s\" in RFC options", val);
      return;
    }
  } else {
    if (ncp_debug) printf(" unknown option, LOSing\n");
    user_socket_los(c, "Unknown option \"%s\" in RFC line", optname);
  }
}

static void 
parse_rfc_line_options(struct conn *conn, char *beg, char *end) 
{
  char *eql = NULL, *comma = NULL, *vp = NULL;
  // now parse the options=value
  do {
    if (comma != NULL) beg = comma+1; // not the first option
    if ((eql = index(beg, '=')) != NULL) {
      *eql = '\0';
      vp = eql+1;
      handle_option(conn, beg, vp);
    } else
      handle_option(conn, beg, "on");
  } while ((comma = index(end, ',')) != NULL);
}

static void
initiate_conn_from_rfc_line(struct conn *conn, u_char *buf, int buflen)  
{
  u_short haddr = 0;
  u_char *cname, *hname = buf;

  u_char *space = (u_char *)index((char *)hname,' ');
  if (space == NULL) {
    // return a LOS to the user: no contact given
    user_socket_los(conn, "No contact name given in RFC line");
    return;
  }
  if (hname[0] == '[') {
    // beginning of options
    char *beg = (char *)&hname[1], *end = index((char *)hname, ']');
    if (end == NULL) {
      user_socket_los(conn, "Syntax error in option parsing (%s)", &hname[1]);
      return;
    }
    *end = '\0';
    if (ncp_debug) printf("NCP about to parse options: \"%s\"\n", beg);
    hname = (u_char *)(end+1);		     // skip options part
    while (isspace(*hname)) hname++; // skip whitespace
    space = (u_char *)index((char *)hname, ' ');
    if (space == NULL) {
      user_socket_los(conn, "No contact name given in RFC line (%s)", hname);
      return;
    }
    parse_rfc_line_options(conn, beg, end);
  }
  *space = '\0';

  cname = &space[1];

  if ((sscanf((char *)hname, "%ho", &haddr) != 1) || !valid_chaos_host_address(haddr)) {
#if CHAOS_DNS
    haddr = dns_closest_address_or_los(conn, hname);
#else
    // return a LOS to the user: bad host name '%s'
    user_socket_los(conn, "Bad host name \"%s\"", hname);
    return;
#endif
  } 
  PTLOCKN(conn->conn_lock,"conn_lock");
  conn->conn_contact = parse_contact_name(cname);
  conn->conn_contact_args = parse_contact_args(cname, conn->conn_contact);
  conn->conn_rhost = haddr;
  if (ncp_debug) printf("NCP parsed RFC line: host %#o contact \"%s\" args \"%s\"\n",
			haddr, conn->conn_contact, conn->conn_contact_args);
  PTUNLOCKN(conn->conn_lock,"conn_lock");
  if (ncp_debug) print_conn("Initiated from RFC line:", conn, 0);
  add_active_conn(conn);
  send_rfc_pkt(conn);
}


////////////////

// NCP user server thread.
// Creates unix socket (socket, bind, listen),
// waits for connections (accept),
// and reads LSN/RFC requests ("LSN contact" or "RFC [host] [contact+args]") from it.
// For LSN, add to list, create conn, let user await RFC (handled in packet_to_conn_handler).
// For RFC, create conn, send off RFC pkt.
// Args: none - create all three sockets, and select on them for reading input
void *
ncp_user_server(void *v)
{
  int simplesock, streamsock;
  fd_set rfd;
  int i, len, sval, maxfd, fd;
  int *fds;
  struct slist { int socktype; char *sockname; conntype_t sockconn; }
  socklist[] = {
#if USE_CHAOS_SIMPLE
    { SOCK_DGRAM,"chaos_simple", CT_Simple },
#endif
    { SOCK_STREAM,"chaos_stream", CT_Stream },
    { SOCK_STREAM, "chaos_packet", CT_Packet }, // SOCK_SEQPACKET doesn't seem to be what I really want
    {0, NULL, 0}};

#if __APPLE__
  srandomdev();
#else
  srandom(time(NULL));
#endif

  if (ncp_debug) printf("NCP user server thread is %p\n", pthread_self());

  maxfd = 0;

  for (i = 0; socklist[i].sockname != NULL; i++);
  fds = malloc(i * sizeof(int));
  if (fds == NULL) { perror("malloc(fds)"); exit(1); }

  for (i = 0; socklist[i].sockname != NULL; i++) {
    fds[i] = make_named_socket(socklist[i].socktype, socklist[i].sockname);
    if (fds[i] > maxfd) maxfd = fds[i];
  }

  // accept, select etc
  while (1) {
    // select waiting for one of them to be readable
    FD_ZERO(&rfd);
    for (i = 0; socklist[i].sockname != NULL; i++) 
      FD_SET(fds[i], &rfd);

    if ((sval = select(maxfd+1, &rfd, NULL, NULL, NULL)) < 0) {
      fprintf(stderr,"select(ncp user server)");
      sleep(1);
      continue;
    } else if (sval > 0) {
      for (i = 0; socklist[i].sockname != NULL; i++) {
	if (FD_ISSET(fds[i], &rfd)) {
	  struct sockaddr_storage caddr;
	  u_int clen = sizeof(caddr);
	  struct sockaddr *sa = (struct sockaddr *)&caddr;
	  if ((fd = accept(fds[i], sa, &clen)) < 0) {
	    perror("?? accept(simplesock)");
	    // @@@@ what could go wrong? lots
	    exit(1);
	  }
	  if (ncp_debug) printf("accepted socket \"%s\"\n", ((struct sockaddr_un *)sa)->sun_path);
	  struct conn *c = make_conn(socklist[i].sockconn, fd, (struct sockaddr_un *)sa, clen);
	  if (ncp_debug) print_conn("Starting new",c,0);
	  start_conn(c);
	}
      }
    } else
      fprintf(stderr,"select: no FD_ISSET\n");
  }
}

static void
forward_conn_transparently(struct conn *conn, u_short fw) 
{
  struct conn_state *cs = conn->conn_state;
  PTLOCKN(conn->conn_lock,"conn_lock");
  if (ncp_debug) printf("NCP transparent FWD to %#o\n", fw);
  PTLOCKN(cs->send_mutex,"send_mutex");
  struct pkt_elem *pk;
  for (pk = pkqueue_first_elem(cs->send_pkts); pk != NULL; pk = pkqueue_next_elem(pk)) {
    struct chaos_header *p = pkqueue_elem_pkt(pk);
    if (ch_destaddr(p) == conn->conn_rhost) {
      set_ch_destaddr(p,fw);
    } else if (ncp_debug) 
      printf("NCP FWD to %#x found unexpected destaddr %#x expected %#x\n",
	     fw, ch_destaddr(p), conn->conn_rhost);
  }
  PTUNLOCKN(cs->send_mutex, "send_mutex");
  // note: after this, any retransmissions of the FWD are discarded
  // since they no longer match this conn.
  conn->conn_rhost = fw;
  PTUNLOCKN(conn->conn_lock,"conn_lock");
}

static void
clear_send_pkts(struct conn *c)
{
  struct chaos_header *p;
  struct conn_state *cs = c->conn_state;
  int npkts = 0;

  PTLOCKN(cs->window_mutex,"window_mutex");
  PTLOCKN(cs->send_mutex,"send_mutex");
  while ((p = pkqueue_get_first(cs->send_pkts)) != NULL) {
    npkts++;
    if (!packet_uncontrolled(p))
      cs->window_available++;
    free(p);
  }
  if (ncp_debug) printf("NCP cleared %d pkts from send_pkts\n", npkts);
  PTUNLOCKN(cs->send_mutex,"send_mutex");
  PTUNLOCKN(cs->window_mutex,"window_mutex");
}

static void
discard_received_pkts_from_send_list(struct conn *conn, u_short receipt)
{
  // discard pkts from send_pkts with number <= receipt
  struct conn_state *cs = conn->conn_state;
  struct chaos_header *p;
  int wsize;


  if (receipt == 0) // typically an uninitialized ack value from an RFC etc,
    return;	    // we'll get this with the next packet?

  // window lock around send_pkts lock
  PTLOCKN(cs->window_mutex,"window_mutex");
  PTLOCKN(cs->send_mutex,"send_mutex");
  wsize = cs->window_available;
  p = pkqueue_peek_first(cs->send_pkts);
  while ((p != NULL) && !packet_uncontrolled(p) && 
	 (pktnum_less(ch_packetno(p), receipt) || pktnum_equal(ch_packetno(p), receipt))) {
    // discard and increase space in window
    if (ncp_debug > 1) printf("Discarding pkt %#x receipt %#x opcode %s\n",
			      ch_packetno(p), receipt, ch_opcode_name(ch_opcode(p)));
    if (ncp_debug > 1) print_pkqueue(cs->send_pkts);
    p = pkqueue_get_first(cs->send_pkts);
    if (ncp_debug > 1) print_pkqueue(cs->send_pkts);
    if (!packet_uncontrolled(p))
      cs->window_available++;
    // malloc:ed in add_output_pkt
    free(p);
    p = pkqueue_peek_first(cs->send_pkts);
  }
  PTUNLOCKN(cs->send_mutex,"send_mutex");
  if (ncp_debug && (wsize != cs->window_available)) {
    printf("Discarded pkts: window changed from %d to %d\n", wsize, cs->window_available);
  }
  // Notify everyone (might be more than one!)
  if (pthread_cond_broadcast(&cs->window_cond) != 0) perror("?? pthread_cond_broadcast(window_cond)");
  PTUNLOCKN(cs->window_mutex,"window_mutex");
}

static struct chaos_header *
get_input_pkt(struct conn *c)
{
  struct conn_state *cs = c->conn_state;
  struct chaos_header *pkt;

  PTLOCKN(cs->read_mutex,"read_mutex");
  while ((pkqueue_length(cs->read_pkts) == 0) && (c->conn_sock != -1))
    if (pthread_cond_wait(&cs->read_cond, &cs->read_mutex) != 0) perror("?? pthread_cond_wait(read_cond)");
  if (c->conn_sock == -1) {
    // time to die
    if (ncp_debug) printf("%%%%%%%% NCP conn %p (%s) detected conn_sock is -1, cancelling all\n",
			  c, conn_thread_name(c));
    PTUNLOCKN(cs->read_mutex,"read_mutex");
    cancel_conn_threads(c);
    // just in case...
    return NULL;
  }
  // get a packet
  if (ncp_debug > 1) {
    printf("NCP get_input_pkt: read_pkts follows:\n");
    print_pkqueue(cs->read_pkts);
  }
  pkt = pkqueue_get_first(cs->read_pkts);
  if (!packet_uncontrolled(pkt))
    cs->read_pkts_controlled--;
  PTUNLOCKN(cs->read_mutex,"read_mutex");

  return pkt;
}

static void
add_input_pkt(struct conn *c, struct chaos_header *pkt)
{
  struct conn_state *cs = c->conn_state;
  int pklen = ch_nbytes(pkt)+CHAOS_HEADERSIZE;

  if (pklen % 2) pklen++;
  struct chaos_header *saved = (struct chaos_header *)malloc(pklen);
  // save a copy since the pkt comes from cbridge
  memcpy(saved, pkt, pklen);

  // lock it
  PTLOCKN(cs->read_mutex,"read_mutex");
  // add pkt
  pkqueue_add(saved, cs->read_pkts);
  if (!packet_uncontrolled(pkt))
    cs->read_pkts_controlled++;
  // let consumer know there is stuff to send to user
  if (pthread_cond_signal(&cs->read_cond) != 0) perror("?? pthread_cond_signal(read_cond)");
  PTUNLOCKN(cs->read_mutex,"read_mutex");
}

static void
add_ooo_pkt(struct conn *c, struct chaos_header *pkt)
{
  struct conn_state *cs = c->conn_state;
  int pklen = ch_nbytes(pkt)+CHAOS_HEADERSIZE;

  if (pklen % 2) pklen++;
  struct chaos_header *saved = (struct chaos_header *)malloc(pklen);
  // save a copy since the pkt comes from cbridge
  memcpy(saved, pkt, pklen);

  // lock it
  PTLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
  // add pkt
  pkqueue_insert_by_packetno(saved, cs->received_pkts_ooo);
  cs->received_pkts_ooo_width = 1+pktnum_diff(ch_packetno(pkqueue_peek_last(cs->received_pkts_ooo)), 
					      ch_packetno(pkqueue_peek_first(cs->received_pkts_ooo)));
  PTUNLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
}

struct chaos_header *
get_ooo_pkt(struct conn *c, int dolock)
{
  struct conn_state *cs = c->conn_state;
  struct chaos_header *pkt;
  if (dolock)
    PTLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
  pkt = pkqueue_get_first(cs->received_pkts_ooo);
  if (pkqueue_length(cs->received_pkts_ooo) > 0) {
    cs->received_pkts_ooo_width = 1+pktnum_diff(ch_packetno(pkqueue_peek_last(cs->received_pkts_ooo)), 
						ch_packetno(pkqueue_peek_first(cs->received_pkts_ooo)));
  } else
    cs->received_pkts_ooo_width = 0;
  if (dolock)
    PTUNLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
  return pkt;
}

static void
add_output_pkt(struct conn *c, struct chaos_header *pkt)
{
  int pklen = ch_nbytes(pkt)+CHAOS_HEADERSIZE;
  // round up, e.g. because of 11-format text. (A single char is in the second byte, not the first.)
  if (pklen % 2)
    pklen++;

  struct conn_state *cs = c->conn_state;

  if (ncp_debug) {
    char buf[128];
    sprintf(buf, "Adding %s %#x to", ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt));
    print_conn(buf,c,1);
    if (pkt == NULL) {
      printf("NCP: NULL packet to send!\n");
      return;
    }       
  }

  if (!packet_uncontrolled(pkt)) {
    if ((pkqueue_length(cs->send_pkts) > 0) &&
	!pktnum_less(cs->send_pkts_pktnum_highest, ch_packetno(pkt))) {
      if (ncp_debug) printf("NCP: already added pkt %#x for output\n", ch_packetno(pkt));
      return;
    }
  } 
  if (ncp_debug) printf("NCP: adding %s pkt %#x nbytes %d for output\n",
			ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt), ch_nbytes(pkt));

  struct chaos_header *saved = (struct chaos_header *)malloc(pklen);
  // save a copy
  if (saved == NULL) {
    perror("?? malloc(saved, add_output_pkt)");
    exit(1);
  }
  memcpy(saved, pkt, pklen);

  // make sure there is room in the window first
  // window lock around send_pkts lock
  PTLOCKN(cs->window_mutex,"window_mutex");
  if (!packet_uncontrolled(pkt)) {
    while (cs->window_available <= 0)
      if (pthread_cond_wait(&cs->window_cond, &cs->window_mutex) != 0) perror("?? pthread_cond_wait(window_cond)");
  }
  // lock it
  PTLOCKN(cs->send_mutex,"send_mutex");
  // add pkt
  pkqueue_add(saved, cs->send_pkts);
  if (ncp_debug > 1) printf("Added pkt to send_pkts len %d\n", pkqueue_length(cs->send_pkts));
  // already checked above that it's higher
  cs->send_pkts_pktnum_highest = ch_packetno(pkt);

  // let consumer know there is stuff to send to network
  if (pthread_cond_signal(&c->conn_state->send_cond) != 0) perror("?? pthread_cond_signal(send_cond)");
  PTUNLOCKN(cs->send_mutex,"send_mutex");

  PTUNLOCKN(cs->window_mutex,"window_mutex");
}

//////////////// conn-to-packet (network)

static void
retransmit_controlled_packets(struct conn *conn)
{
  struct conn_state *cs = conn->conn_state;
  struct chaos_header *pkt;
  struct pkt_elem *q;
  int nsent = 0;
  int npkts = 0;
  int pklen;
  u_char tempkt[CH_PK_MAXLEN];

  // make sure.
  discard_received_pkts_from_send_list(conn, cs->pktnum_sent_acked);

  PTLOCKN(cs->send_mutex,"send_mutex");
  if ((npkts = pkqueue_length(cs->send_pkts)) > 0) {
    for (q = pkqueue_first_elem(cs->send_pkts); q != NULL; q = pkqueue_next_elem(q)) {
      pkt = pkqueue_elem_pkt(q); 
      pklen = ch_nbytes(pkt)+CHAOS_HEADERSIZE;
      if (pklen % 2) pklen++;
      if (pkt != NULL) {
	    // don't retransmit OPN when we're already open
	if ((ch_opcode(pkt) == CHOP_OPN) && ((cs->state == CS_Open) || (cs->state == CS_Finishing))) {
	  if (ncp_debug) printf("%%%% Retrans %s %#x with acked %#x in state %s\n",
				ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt), 
				cs->pktnum_sent_acked, state_name(cs->state));
	}
	if ((ch_opcode(pkt) == CHOP_RFC) && (conn->rfc_timeout > 0)
	    && (time(NULL) - conn->conn_created > conn->rfc_timeout)) {
	  // Note: more than rfc_timeout has passed. This is better than >= I think.
	  if (ncp_debug) printf("NCP: RFC timeout (%ld > %d)\n", time(NULL) - conn->conn_created, conn->rfc_timeout);
	  PTUNLOCKN(cs->send_mutex,"send_mutex");
	  // this also cancels the conn
	  user_socket_los(conn, "Connection timed out (after %d s), host %#o not responding",
			  conn->rfc_timeout, conn->conn_rhost);
	}
	if (!packet_uncontrolled(pkt)
	    // don't retransmit OPN when we're already open
	    //&& !((ch_opcode(pkt) == CHOP_OPN) || (cs->state == CS_Open) || (cs->state == CS_Finishing))
	    // don't retransmit DAT until CS_Open
	    && ((ch_opcode(pkt) < CHOP_DAT) || (cs->state == CS_Open) || (cs->state == CS_Finishing))) {
	  // @@@@ unless sent within 1/30 s
	  nsent++;
	  // protect against swapping - send a copy
	  if (pklen <= sizeof(tempkt)) {
	    // update ack field
	    set_ch_ackno(pkt, cs->pktnum_read_highest);
	    cs->pktnum_acked = cs->pktnum_read_highest; // record the sent ack
	    memcpy(tempkt, (u_char *)pkt, pklen);
	    if (ncp_debug) printf("NCP local %#x retransmitting controlled pkt %#x (%s), ack %#x\n",
				  conn->conn_lidx,
				  ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), ch_ackno(pkt));
	    send_chaos_pkt(tempkt, pklen);
	  } else if (ncp_debug) printf("NCP: packet too long (%d > %lu)\n", pklen, sizeof(tempkt));
	}
      }
    }
  }
  if (ncp_debug && (nsent != npkts)) {
    printf("Retransmitted %d controlled packets, expected %d (qlen), thread %p\n", 
	   nsent, npkts, pthread_self());
    print_pkqueue(cs->send_pkts);
  }
  PTUNLOCKN(cs->send_mutex,"send_mutex");
}

// call with a fresh copy of a pkt (no swapping protection here)
static int
send_packet_when_window_open(struct conn_state *cs, struct chaos_header *pkt, int pklen) 
{
  if (packet_uncontrolled(pkt)) {
    // just send it
    if (ncp_debug) printf("Sending uncontrolled pkt %#x (%s len %d)\n", 
			  ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), ch_nbytes(pkt));
    send_chaos_pkt((u_char *)pkt, pklen);
    return 1;
  }
  if (!((ch_opcode(pkt) >= CHOP_DAT) && (cs->state != CS_Open)) && // don't send DAT until Open
      pktnum_less(cs->pktnum_sent_highest, ch_packetno(pkt)) && // we haven't already sent it
      pktnum_less(cs->pktnum_sent_acked, ch_packetno(pkt))) {  // and we haven't gotten an ack for it
    if (ncp_debug > 1) printf("Want to send controlled pkt %#x, window now %d, q len %d\n", ch_packetno(pkt),
			  cs->window_available, pkqueue_length(cs->send_pkts));
    PTLOCKN(cs->window_mutex,"window_mutex");
    while (cs->window_available <= 0)
      if (pthread_cond_wait(&cs->window_cond, &cs->window_mutex) != 0) perror("?? pthread_cond_wait(window_cond)");

    PTLOCKN(cs->conn_state_lock,"conn_state_lock");
    cs->pktnum_sent_highest = ch_packetno(pkt);
    cs->window_available--;
    PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
    if (ncp_debug) printf("NCP: Sending controlled pkt %#x, window now %d, q len %d, ack %#x\n", ch_packetno(pkt),
			  cs->window_available, pkqueue_length(cs->send_pkts), ch_ackno(pkt));
    PTUNLOCKN(cs->window_mutex,"window_mutex");
    // update ack field
    set_ch_ackno(pkt, cs->pktnum_read_highest);
    cs->pktnum_acked = cs->pktnum_read_highest; // record the sent ack

    if (ncp_debug) printf("NCP sending controlled pkt %#x (%s) ack %#x\n", 
			  ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), ch_ackno(pkt));
    send_chaos_pkt((u_char *)pkt, pklen);
    return 1;
  } else {
    // already acked, so ignore it
  }
  return 0;
}

static void
probe_connection(struct conn *conn) 
{
  struct conn_state *cs = conn->conn_state;
  if (ncp_debug > 1) print_conn("Probing", conn, 1);

  // - if timeout,
  // -- every DEFAULT_RETRANSMISSION_INTERVAL msec, retransmission: all pkts not receipted (except sent within 1/30s) resent
  // -- every PROBE_INTERVAL sec, probe:
  // --- if conn->time_last_received > HOST_DOWN_INTERVAL, declare conn host-down [deallocate everything, close socket]
  // --- if conn->conn_state->window_available < conn->conn_state->foreign_winsize, send SNS
  // --- if conn->time_last_received > LONG_PROBE_INTERVAL, send SNS
  struct timespec now;
  timespec_get(&now, TIME_UTC);
  retransmit_controlled_packets(conn);
  if ((cs->time_last_received != 0) && (now.tv_sec - cs->time_last_received > HOST_DOWN_INTERVAL)) {
    // haven't received for a long time, despite probing
    if (ncp_debug) printf("conn %p (%s) hasn't received in %ld seconds, host down!\n", 
			  conn, conn_state_name(conn),
			  now.tv_sec - cs->time_last_received);
    set_conn_state(conn, CS_Open, CS_Host_Down, 0);
    // close and die
    user_socket_los(conn, "Host %#o down - no reception for %ld seconds", conn->conn_rhost,
		    now.tv_sec - cs->time_last_received);
  } else if ((cs->state != CS_Open) && (cs->state != CS_Finishing)) {
    // don't send SNS unless conn is open
  } else if ((cs->time_last_received != 0) 
	     && (now.tv_sec - cs->time_last_received > LONG_PROBE_INTERVAL)
	     && (now.tv_sec - cs->time_last_probed > LONG_PROBE_INTERVAL)) {
    // haven't received for quite some time, send a SNS probe
    if ((cs->state == CS_Open) || (cs->state == CS_Finishing)) {
      // don't probe all the time
      cs->time_last_probed = now.tv_sec;
      if (ncp_debug) printf("conn %p (%s) hasn't received in %ld seconds, sending SNS\n",
			    conn, conn_state_name(conn),
			    now.tv_sec - cs->time_last_received);
      // Could also detect if there is no route to the destination anymore?
      // Let send_chaos_pkt return fail/success, and handle it here?
      // But the routing tables take about half an hour to get outdated (to RTCOST_HIGH), so no point.
      send_sns_pkt(conn);
    }
  } else if (pktnum_less(cs->pktnum_sent_acked, cs->pktnum_sent_highest)) {
    // still have outstanding acks, ask for ack confirmation
    if ((cs->state == CS_Open) || (cs->state == CS_Finishing)) {
      if (ncp_debug) printf("conn %p (%s) has %d outstanding acks (acked %#x sent %#x), sending SNS\n",
			    conn, conn_state_name(conn),
			    pktnum_diff(cs->pktnum_sent_highest, cs->pktnum_sent_acked),
			    cs->pktnum_sent_acked, cs->pktnum_sent_highest);
      send_sns_pkt(conn);
    }
  }
}

// Gets packets from the send queue and transmits them on the net.
// Also manages probing, and thus retransmissions.
// (This handles both "stream" and "packet" connections, just the same.)
static void *
conn_to_packet_stream_handler(void *v)
{
  struct conn *conn = (struct conn *)v;
  struct conn_state *cs = conn->conn_state;
  struct chaos_header *pkt;
  struct timespec retrans, lastsent, now;
  struct timeval tv;
  int timedout = 0;
  int qlen = 0;
  int npkts = 0;
  u_char tempkt[CH_PK_MAXLEN];
  int pklen;

  if ((conn->conn_type != CT_Stream) && (conn->conn_type != CT_Packet)) {
    fprintf(stderr,"%%%% Bug: conn_to_packet_stream_handler running with non-stream conn\n");
    exit(1);
  }
  timespec_get(&lastsent, TIME_UTC);
  while (1) {
    if (conn->conn_sock == -1) {
      // should have exited already
      // pthread_exit(NULL);
      if (ncp_debug) printf("%%%%%%%% NCP %s for %p terminating\n", conn_thread_name(conn), conn);
      return NULL;
    }
    // Wait for input to be available to send to network
    PTLOCKN(cs->send_mutex,"send_mutex");

    gettimeofday(&tv, NULL);
    tv.tv_usec += (conn->retransmission_interval)*1000;
    while (tv.tv_usec > 1000000) {
      tv.tv_sec++; tv.tv_usec -= 1000000;
    }
    retrans.tv_sec = tv.tv_sec + 0;
    retrans.tv_nsec = tv.tv_usec * 1000;

    timedout = 0;
    npkts = 0;

    while ((timedout == 0) && ((qlen = pkqueue_length(cs->send_pkts)) == 0))
      timedout = pthread_cond_timedwait(&cs->send_cond, &cs->send_mutex, &retrans);
    
    if (conn->conn_sock == -1) {
      if (ncp_debug) printf("%%%%%%%% NCP %p (%s) found conn_sock == -1, exiting\n", conn, conn_thread_name(conn));
      PTUNLOCKN(cs->send_mutex, "send_mutex");
      return NULL;
    }

    if (timedout == 0) {
      // get a packet - the last one added
      pkt = pkqueue_peek_last(cs->send_pkts);
      if (pkt != NULL) {
	// make a copy, to protect against (1) swapping when sending, and (2) pkt being freed after lock is released
	pklen = ch_nbytes(pkt)+CHAOS_HEADERSIZE;
	if (pklen % 2) pklen++;
	memcpy(tempkt, (u_char *)pkt, pklen);
	pkt = (struct chaos_header *)tempkt;
	PTUNLOCKN(cs->send_mutex,"send_mutex");

	npkts += send_packet_when_window_open(cs, pkt, pklen);
      } else {
	PTUNLOCKN(cs->send_mutex,"send_mutex");
	if (ncp_debug) printf("%%%% NCP: c_t_p triggered w/o timeout (qlen %d) but no pkt?\n", qlen);
      }
      timespec_get(&now, TIME_UTC);
      if (npkts == 0) {
	// we didn't send anything, and retransmission interval passed since last time
	if ((now.tv_sec*1000 + now.tv_nsec/1000000) - (lastsent.tv_sec*1000 + lastsent.tv_nsec/1000000) > conn->retransmission_interval) {
	  if (ncp_debug > 1) printf("NCP nothing sent for %ld msec, probing\n",
				(now.tv_sec*1000 + now.tv_nsec/1000000) - (lastsent.tv_sec*1000 + lastsent.tv_nsec/1000000));
	  // probe connection, but don't do it again until time passes again
	  probe_connection(conn);
	  lastsent.tv_sec = now.tv_sec;
	  lastsent.tv_nsec = now.tv_nsec;
	}
      } else {
	// we sent something
	lastsent.tv_sec = now.tv_sec;
	lastsent.tv_nsec = now.tv_nsec;
      }
    } else if (timedout == ETIMEDOUT) {
      PTUNLOCKN(cs->send_mutex,"send_mutex");
      probe_connection(conn);
    } else {
      perror("?? pthread_cond_timedwait(conn_to_packet_stream_handler)");
      PTUNLOCKN(cs->send_mutex,"send_mutex");
    }
    // go back wait for another pkt to send
    if ((ncp_debug > 1) && (npkts == 0) && (qlen > 0))
      printf("NCP: tried to send no packets although queue len is %d\n", qlen);
  }
}

//////////////// packet-to-conn network-to-conn
// Gets packets from the network and passes them to the conn

static void 
receive_data_for_conn(int opcode, struct conn *conn, struct chaos_header *pkt)
{
  u_char *data = (u_char *)pkt;
  u_short *dataw = (u_short *)pkt;
  struct conn_state *cs = conn->conn_state;

  if (packet_uncontrolled(pkt)) {
    // uncontrolled pkts always fit the window
    // @@@@ well, keep a lid on it
    if (ncp_debug) printf("Receive uncontrolled pkt (%s)\n", ch_opcode_name(ch_opcode(pkt)));
    add_input_pkt(conn, pkt);
    return;
  }
  if (opcode == CHOP_OPN) {
    // initial response, pktnum dealt with elsewhere
    if (ncp_debug) printf("Receive %s pkt (%#x)\n", ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt));
    add_input_pkt(conn, pkt);
    return;
  }
  if (opcode == CHOP_FWD) {
    if (ncp_debug) printf("Receive %s pkt (%#x)\n", ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt));
    add_input_pkt(conn, pkt);
  }
  if ((cs->read_pkts_controlled + cs->received_pkts_ooo_width) < cs->local_winsize) {
    // it fits in the window
    if (ncp_debug) printf("Receive %s pkt %#x with %d room in window\n",
			  ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt),
			  cs->local_winsize - (cs->read_pkts_controlled + cs->received_pkts_ooo_width));
    // Check if it has already been received
    if (pktnum_less(ch_packetno(pkt), cs->pktnum_received_highest) || 
	pktnum_equal(ch_packetno(pkt), cs->pktnum_received_highest)) {
      // Evidence of unnecessary retransmisson, keep other end informed
      if (ncp_debug) printf("Pkt %#x already received (highest %#x)\n", ch_packetno(pkt), cs->pktnum_received_highest);
      if ((cs->state == CS_Open) || (cs->state == CS_Finishing))
	send_sts_pkt(conn);
      return;
    }
    // add it to read_pkts if it's the next one in order, and collect in-order pkts from received_pkts_ooo
    if (pktnum_equal(ch_packetno(pkt), pktnum_1plus(cs->pktnum_received_highest))) {
      // it was the next expected packet, so add it to the read_pkts
      add_input_pkt(conn, pkt);	// this also updates read_pkts_controlled
      cs->pktnum_received_highest = ch_packetno(pkt);

      // now pick pkts from received_pkts_ooo as long as they are in order.
      // (Need the lock since we're peeking the queue.)
      PTLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
      int expected = pktnum_1plus(ch_packetno(pkt));
      struct chaos_header *p = pkqueue_peek_first(cs->received_pkts_ooo);
      while ((p != NULL) && (pktnum_equal(ch_packetno(p), expected))) {
	// this is the pkt we wanted, so get it from the queue
	p = get_ooo_pkt(conn, 0);
	expected = pktnum_1plus(ch_packetno(p));
	if (ncp_debug) printf(" moving pkt %#x from OOO to ordered list\n", ch_packetno(p));
	add_input_pkt(conn, p);
	// update the highest received in order pkt for STS
	cs->pktnum_received_highest = ch_packetno(p);
	// add_input_pkt made a copy, so free this one
	free(p);
	// peek the next one
	p = pkqueue_peek_first(cs->received_pkts_ooo);
      }
      PTUNLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
    } else {
      // it wasn't the next pkt expected, so put it in the right place in received_pkts_ooo
      if (ncp_debug) printf(" pkt %#x is OOO (highest is %#x)\n", ch_packetno(pkt), cs->pktnum_received_highest);
      add_ooo_pkt(conn, pkt);
    }
  } else {
    // window full, send STS to inform the other end about the window and acks and receipts etc
    if (ncp_debug) printf("Window is full for pkt %#x, sending STS\n", ch_packetno(pkt));
    send_sts_pkt(conn);
  }
}

// @@@@ This could do with some structuring/modularization etc
static void
packet_to_conn_stream_handler(struct conn *conn, struct chaos_header *ch)
{
  u_char *data = &((u_char *)ch)[CHAOS_HEADERSIZE];
  u_short *dataw = (u_short *)data;
  struct conn_state *cs = conn->conn_state;

  if (ncp_debug) 
    printf("NCP <<< in state %s: got %s pkt %#x from <%#o,%#x> to <%#o,%#x> ack %#x nbytes %d\n",
	   state_name(cs->state), ch_opcode_name(ch_opcode(ch)), ch_packetno(ch),
	   ch_srcaddr(ch), ch_srcindex(ch), ch_destaddr(ch), ch_destindex(ch),
	   ch_ackno(ch), ch_nbytes(ch));
  if (cs->state == CS_Inactive) {
    if (ncp_debug) printf("NCP: inactive conn, ignoring pkt\n");
    return;
  }

  if ((ch_ackno(ch) != 0) && (ch_opcode(ch) != CHOP_FWD) && (pktnum_less(cs->pktnum_sent_acked, ch_ackno(ch)))) {
    // we got an ack update
    cs->pktnum_sent_acked = ch_ackno(ch);
    // clear out acked pkts from send_pkts
    discard_received_pkts_from_send_list(conn, ch_ackno(ch));
  }
  if ((cs->time_last_received == 0) && (ch_opcode(ch) != CHOP_FWD)) {
    // if this is the first, make sure we realize we haven't already received it
    // mmm, but if pkts arrive out-of-order? the first for a conn should always be RFC or OPN.
    cs->pktnum_received_highest = pktnum_1minus(ch_packetno(ch));
    cs->pktnum_read_highest = cs->pktnum_received_highest;
    if (ncp_debug) print_conn("First pkt for", conn, 1);
  }
  cs->time_last_received = time(NULL);

  // Handle STS and SNS 
  if (ch_opcode(ch) == CHOP_STS) {
    u_short receipt = ntohs(dataw[0]);
    u_short winz = ntohs(dataw[1]);
    if (ncp_debug)
      printf("NCP: got %s ack %#x rec %#x win %d\n", ch_opcode_name(ch_opcode(ch)), ch_ackno(ch), receipt, winz);
    // validate reasonable value
    if (winz <= MAX_WINSIZE) {
      if (winz != cs->foreign_winsize) {
	// adjust also window_available
	if (ncp_debug) printf("NCP: adjusting available window from %d to %d\n", cs->window_available, 
			      cs->window_available + (winz - cs->foreign_winsize));
	cs->window_available += winz - cs->foreign_winsize;
      }
      cs->foreign_winsize = winz;
    }
    // clear out send_pkts based on receipt - also updates window_available and window_cond
    discard_received_pkts_from_send_list(conn, receipt);
    if (cs->state == CS_Open_Sent) {
      // We have got an RFC and sent an OPN, so we were waiting for this STS.
      // Now we are ready to send data!
      set_conn_state(conn, CS_Open_Sent, CS_Open, 0);
      if (ncp_debug) print_conn("STS opening", conn, 1);
      trace_conn("Opened", conn);
    }
    retransmit_controlled_packets(conn);
    return;
  } else if (ch_opcode(ch) == CHOP_SNS) {
    if ((cs->state == CS_Open) || (cs->state == CS_Finishing)) 	// ignore SNS if not open
      send_sts_pkt(conn);
    return;
  } else if (ch_opcode(ch) == CHOP_CLS) {
    if (ncp_debug) printf("CLS received, clearing send_pkts\n");
    // don't retransmit anything - the other end has gone
    clear_send_pkts(conn);
    // socket end will finish the conn when the CLS pkt reaches it
  }

  // Dispatch based on state and opcode
  switch (cs->state) {
  case CS_Listening: {
    if (ch_opcode(ch) == CHOP_RFC) {
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      // conn_to_socket changes state
      // set_conn_state(conn, CS_Listening, CS_RFC_Received, 0);
    } else if (ch_opcode(ch) == CHOP_BRD) {
      // @@@@ do something
      fprintf(stderr,"NYI: BRD received, but not implemented yet\n");
    } else
      // ignore all other pkts
      return;
    break;
  }
  case CS_BRD_Sent:
    // @@@@ do something?
  case CS_RFC_Sent:
    switch (ch_opcode(ch)) {
    case CHOP_CLS:
      // let user read the reason for close, and nothing more
      set_conn_state(conn, cs->state, CS_CLS_Received, 0);
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      break;
    case CHOP_FWD:
      if (conn->follow_forward)
	forward_conn_transparently(conn, ch_ackno(ch));
      else 
	receive_data_for_conn(ch_opcode(ch), conn, ch);
      break;
    case CHOP_ANS:
      // let user read the answer, and nothing more
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      break;
    case CHOP_OPN: {
      // server accepted our RFC, send back an STS
      u_short rec, winz;
      rec = ntohs(dataw[0]);
      winz = ntohs(dataw[1]);
      if (ncp_debug) {
	int pklen = ch_nbytes(ch)+CHAOS_HEADERSIZE;
	if (pklen % 2) pklen++;
	printf("NCP: got %s pkt %#x from <%#o,%#x> to <%#o,%#x> rec %#x win %d\n",
	       ch_opcode_name(ch_opcode(ch)), ch_packetno(ch),
	       ch_srcaddr(ch), ch_srcindex(ch), ch_destaddr(ch), ch_destindex(ch), 
	       rec, winz);
	print_conn("Opening", conn, 1);
      }
      trace_conn("Opening", conn);
      // note these
      conn->conn_ridx = ch_srcindex(ch);
      // although it isn't put on read_pkts, must record it
      cs->pktnum_received_highest = ch_packetno(ch);
      cs->foreign_winsize = winz;
      cs->window_available = winz;
      send_sts_pkt(conn);
      set_conn_state(conn, CS_RFC_Sent, CS_Open, 0);
      if (ncp_debug) print_conn("Opened", conn, 1);
      receive_data_for_conn(ch_opcode(ch), conn, ch);
    }
      break;
    }
    // All other than CLS, ANS, OPN fall through here
    break;
  case CS_Open:
    // In the Open state, only EOF, LOS, CLS and the DAT pkts are OK
    if (ch_opcode(ch) == CHOP_OPN) {
      // maybe the STS went missing, so resend it - doesn't hurt
      send_sts_pkt(conn);
      break;
    } else if ((ch_opcode(ch) != CHOP_EOF) && (ch_opcode(ch) != CHOP_LOS) 
	&& (ch_opcode(ch) != CHOP_CLS) && (ch_opcode(ch) < CHOP_DAT)) {
      // note error (we handle STS SNS above)
      if (ncp_debug) printf("%%%% %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
      break;
    }
    // Check window, maybe send an STS if it's full, store data in read_pkts or received_pkts_ooo
    receive_data_for_conn(ch_opcode(ch), conn, ch);
    break;
  case CS_Finishing:
    // Just waiting for an ACK of our EOF
    if ((ch_opcode(ch) == CHOP_CLS) || (ch_opcode(ch) == CHOP_EOF))
      // expected
      return;
    else if (ncp_debug)
      printf("%%%% p_t_c_stream_h %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    break;
  case CS_Foreign:
    // @@@@ completely untested - should probably accept CLS/EOF too
    if (ch_opcode(ch) == CHOP_UNC) {
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      break;
    } else {
      // complain
      if (ncp_debug) printf("%%%% %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
      break;
    }
  case CS_Inactive:
    if (ch_opcode(ch) == CHOP_RFC) {
      send_los_pkt(conn, "No such index exists");
      return;
    }
    // fall through
  case CS_CLS_Received:
  case CS_LOS_Received:
  case CS_Host_Down:
  case CS_Open_Sent:	       // Should only happen for the STS above
  case CS_RFC_Received:	       // Should only get retransmitted RFCs
  case CS_Answered: // should not get pkts (other than retransmitted ANS?)
    if (!((cs->state == CS_RFC_Received) && (ch_opcode(ch) != CHOP_RFC)) &&
	!((cs->state == CS_Answered) && (ch_opcode(ch) != CHOP_ANS))) {
      if (ncp_debug) printf("%%%% p_t_c_stream_h %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    }
    if (ncp_debug && (ch_opcode(ch) == CHOP_LOS)) {
      u_char buf[CH_PK_MAX_DATALEN];
      get_packet_string(ch, buf, sizeof(buf));
      printf("%%%% LOS: %s\n", buf);
      break;
    }
    break;
  }
#if 0
  if (packet_uncontrolled(ch)) { // controlled pkts must fit in window to count
    // Amber: "The packet number field contains sequential numbers in
    // controlled packets; in uncontrolled packets it contains the same
    // number as the next controlled packet will contain."
    // 
    // Clearly not the case, I'd say, given experimental evidence from ITS 1648.
    // Instead, it seems to be vaguely related to the ack field, OR to an old pkt that has been sent already.
    // is it the next in order? then update highest received
    if (pktnum_equal(ch_packetno(ch), pktnum_1plus(cs->pktnum_received_highest)))
      cs->pktnum_received_highest = ch_packetno(ch);
  }
#endif
  return;
}


// Packet received for unknown conn - see if there is a listener, else send LOS or CLS
static struct conn *
packet_to_unknown_conn_handler(u_char *pkt, int len, struct chaos_header *ch, u_char *data) 
{
  struct conn *conn = NULL;
  if (ch_opcode(ch) == CHOP_RFC) {
    u_char contact[CH_PK_MAX_DATALEN];
    get_packet_string(ch, contact, sizeof(contact));
    if (ncp_debug) printf("NCP p_t_c_h: Got %s %#x from <%#o,%#x> for <%#o,%#x>, contact \"%s\"\n", 
			  ch_opcode_name(ch_opcode(ch)), ch_packetno(ch),
			  ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch), contact);
    // go look for a matching listener
    conn = find_matching_listener(ch);
    if (conn) {
      // if we got one, initiate it from the conn and data (contact args)
      // don't accept a new one
      remove_listener_for_conn(conn);
      // fill in
      initiate_conn_from_rfc_pkt(conn, ch, data);
      add_input_pkt(conn, ch);
      if (ncp_debug) print_conn("Found listener for", conn, 0);
    } else {
      // CLS: No listener for this contact
      if (ncp_debug) printf("No listener found for RFC \"%s\"\n", contact);
      send_cls_pkt(make_temp_conn_from_pkt(ch), "No server for this contact name");
    }
  } else if ((ch_opcode(ch) >= CHOP_DAT) || (ch_opcode(ch) == CHOP_OPN) 
	     || (ch_opcode(ch) == CHOP_STS) || (ch_opcode(ch) == CHOP_SNS)) {
    // don't send LOS for someone who doesn't know who they are talking to
    if (ch_destindex(ch) == 0)
      return NULL;
    // send LOS: No such connection at this host
    if (ncp_debug) printf("No conn found for %s %#x from <%#o,%#x> for <%#o,%#x>\n",
			  ch_opcode_name(ch_opcode(ch)), ch_packetno(ch),
			  ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch));
    send_los_pkt(make_temp_conn_from_pkt(ch),"No such index exists");
  } else if (ch_opcode(ch) == CHOP_LOS) {
    // LOS for unknown conn - try to figure out why?
    if (ncp_debug) {
      u_char buf[CH_PK_MAX_DATALEN];
      get_packet_string(ch, buf, sizeof(buf));
      printf("NCP p_t_c_h: Got LOS from <%#o,%#x> for <%#o,%#x> - ignoring: %s\n",
	     ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch),
	     buf);
    }
  } else {
    //@@@@ hmm.
    if (ncp_debug) printf("Got unexpected %s from <%#o,%#x> for <%#o,%#x> with no conn\n", ch_opcode_name(ch_opcode(ch)),
			  ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch));
  }
  return conn;
}

// NCP packet handler, packets coming from network for a local address.
// Called from cbridge (handle_pkt_for_me)
void 
packet_to_conn_handler(u_char *pkt, int len)
{
  struct conn *conn = NULL;
  struct chaos_header *ch = (struct chaos_header *)pkt;
  u_char *data = &((u_char *)pkt)[CHAOS_HEADERSIZE];

  // find existing conn based on rhost/ridx/lhost/lidx
  conn = find_existing_conn(ch);
  
  // if we didn't find one, do the right thing
  if (conn == NULL) {
    conn = packet_to_unknown_conn_handler(pkt, len, ch, data);
    if (conn == NULL)
      return;
 }
  // else conn is known
  else if ((conn->conn_state->state == CS_Inactive) &&  // but not active, not about to start or just lost
	   (ch_opcode(ch) != CHOP_RFC) && (ch_opcode(ch) != CHOP_LOS)) {
    if (ncp_debug) printf("Got %s from <%#o,%#x> for <%#o,%#x> in state %s\n", ch_opcode_name(ch_opcode(ch)),
			  ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch),
			  conn_state_name(conn));
    send_los_pkt(conn, "No such index exists");
    return;
  }

  if (ch_nbytes(ch) > CH_PK_MAX_DATALEN) {
    if (ncp_debug) print_conn("Data too long for", conn, 1);
    send_los_pkt(conn,"Data too long");
    return;
  }
  if ((ch_opcode(ch) > CHOP_BRD) && (ch_opcode(ch) < CHOP_DAT)) {
    if (ncp_debug) print_conn("Illegal opcode for", conn, 1);
    send_los_pkt(conn,"Illegal opcode");
    return;
  }

  if (conn->conn_type == CT_Simple) {
    // packet_to_conn_simple_handler(conn, ch);
    fprintf(stderr,"%%%%%%%% NCP mega-lose - packet_to_conn_simple_handler doesn't exist.\n");
    abort();
    return;
  } else if ((conn->conn_type == CT_Stream) || (conn->conn_type == CT_Packet)) {
    packet_to_conn_stream_handler(conn, ch);
    return;
  }
}

//////////////// socket-to-conn

static int 
receive_or_die(struct conn *conn, u_char *buf, int buflen) 
{
  int cnt, sval = 0, sock = conn->conn_sock;
  fd_set fds;
  struct timeval timeout;

  // need to read with timeout in order to discover that the socket closes, apparently
  while (((sock = conn->conn_sock) != -1) && (sval == 0)) {
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    // @@@@ well, some interval? The longer, more time until socket closure is discovered
    timeout.tv_sec = 0;
    timeout.tv_usec = conn->retransmission_interval*1000;
    while (timeout.tv_usec > 1000000) {
      timeout.tv_sec++; timeout.tv_usec -= 1000000;
    }

    if ((sval = select(sock+1, &fds, NULL, NULL, &timeout)) < 0) {
      if (sval == EINTR) {
	// timed out, try again
	sval = 0;
      }
    }
  }
  cnt = sval;
  if ((conn->conn_sock != -1) && (sval > 0) && FD_ISSET(sock, &fds) && ((cnt = recv(conn->conn_sock, buf, buflen, 0)) < 0)) {
    if ((errno == EBADF) || (errno == ECONNRESET) || (errno == ETIMEDOUT)) {
      socket_closed_for_conn(conn);
      return -1;
    } else {
      perror("?? recv(receive_or_die)");
      exit(1);
    }
  } else if ((conn->conn_sock == -1) || (sval == 0) || (cnt == 0)) {
    if (ncp_debug > 1) printf("== receive_or_die (%s, %s): sock %d select %d, read %d bytes, assuming closed\n", 
			      conn_thread_name(conn), conn_type_name(conn), conn->conn_sock, sval, cnt);
    socket_closed_for_conn(conn);
    return -1;
  } else if (ncp_debug > 1) printf("== receive_or_die read %d bytes (buflen %d)\n", cnt, buflen);
  return cnt;
}

static int 
get_ans_bytes_and_send(struct conn *conn, int anslen, u_char *buf, int buflen, int cnt) 
{
  if (cnt >= anslen) {
    // the buffer holds the whole ANS data
    send_ans_pkt(conn, buf, anslen);
    return anslen;
  } else {
    // read more bytes
    int ncnt = 0;
    u_char *bp = buf+cnt;
    while (cnt < anslen) {
      ncnt = receive_or_die(conn, bp, buflen-cnt);
      if (ncnt < 0)
	return ncnt;
      cnt += ncnt;
      bp += ncnt;
    }
    // read all the rest, use it
    send_ans_pkt(conn, buf, anslen);
    return anslen;
  }
}

static int
get_ans_string_and_send(struct conn *conn, int anslen, u_char *buf, int buflen, int cnt)
{
  u_char *nl = (u_char *)index((char *)buf, '\n');
  if (nl != NULL) {
    nl++; // skip \n
    return get_ans_bytes_and_send(conn, anslen, buf, buflen, cnt);
  } else {
    user_socket_los(conn, "No newline after ANS length?");
    set_conn_state(conn, conn->conn_state->state, CS_Inactive, 0);
    return -1;
  }
}

// return
// >0 for success, go on
// =0 for done, finished
// <0 for error
static int
socket_to_conn_stream_handler(struct conn *conn)
{
  struct conn_state *cs = conn->conn_state;
  int cnt;
  u_char *cname, buf[CH_PK_MAXLEN], pkt[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)pkt;

  memset(buf, 0, CH_PK_MAXLEN);

  cnt = receive_or_die(conn, (u_char *)buf, sizeof(buf));
  if (ncp_debug) printf("socket_to_conn_stream_handler: read %d bytes from %s\n", cnt, conn_sockaddr_path(conn));
  if (cnt <= 0)
    return cnt;

  if (cs->state == CS_Inactive) {
    // In inactive state, the first thing from the user socket is a "string command" (RFC or LSN)
    if (strncasecmp((char *)buf,"LSN ", 4) == 0) {
      cname = parse_contact_name(&buf[4]);
      if (ncp_debug) printf("Stream \"LSN %s\", adding listener\n", cname);
      add_listener(conn, cname);	// also changes state
    } else if (strncasecmp((char *)buf,"RFC ", 4) == 0) {
      // create conn and send off an RFC pkt
      if (ncp_debug) printf("Stream \"%s\"\n", buf);
      initiate_conn_from_rfc_line(conn,&buf[4],cnt-4);
    }
  }
  else if (cs->state == CS_RFC_Received) {
    // After receiving RFC, the first thing from the user socket is in "string command" form
    if ((strncasecmp((char *)buf,"OPN ", 4) == 0) 
	   || ((strncasecmp((char *)buf,"OPN", 3) == 0) && ((buf[3] == '\r') || (buf[3] == '\n')))) {
      char *nl = index((char *)buf,'\n');
      int dlen = 0;
      if ((nl != NULL) && (nl-(char *)buf < cnt-1)) { 
	// there was a \n and it's not the last byte
	*nl++ = '\0';
	dlen = cnt-strlen(nl)-1;
      }
      if (ncp_debug) printf("Stream cmd \"%s\"\n", buf);
      send_opn_pkt(conn);
      if (dlen > 0) {
	if (ncp_debug) printf("Adding extra DATa length %d: \"%.8s\"...\n", dlen, nl);
	// just use the data as is
	send_basic_pkt_with_data(conn, CHOP_DAT, (u_char *)nl, dlen);
      }
    }
    else if (strncasecmp((char *)buf,"CLS ", 4) == 0) {
      char *eol = index((char *)&buf[4],'\r');
      if (eol == NULL) eol = index((char *)&buf[4], '\n');
      if (eol != NULL) *eol = '\0';
      if (ncp_debug) printf("Stream cmd \"%s\"\n", buf);
      send_cls_pkt(conn, (char *)&buf[4]);
      // done here
      return 0;
    }
    else if (strncasecmp((char *)buf,"FWD ", 4) == 0) {
      u_short haddr;
      char *eol = index((char *)&buf[4],'\r');
      if (eol == NULL) eol = index((char *)&buf[4], '\n');
      if (eol != NULL) *eol = '\0';
      if (ncp_debug) printf("Stream cmd \"%s\"\n", buf);
      if ((sscanf((char *)&buf[4],"%ho", &haddr) != 1) || !valid_chaos_host_address(haddr)) {
#if CHAOS_DNS
	haddr = dns_closest_address_or_los(conn, &buf[4]);
#else
	// return a LOS to the user: bad host name '%s'
	user_socket_los(conn, "Bad host name \"%s\"", hname);
	return;
#endif
      }
      send_fwd_pkt(conn, haddr);
      return 0;
    }
    else if  ((strncasecmp((char *)buf,"ANS ", 4) == 0) 
	      || ((strncasecmp((char *)buf,"ANS", 3) == 0) && ((buf[3] == '\r') || (buf[3] == '\n')))) {
      int anslen = 0;
      if (ncp_debug) printf("Stream cmd \"%s\"\n", buf);
      if (sscanf((char *)&buf[4], "%d", &anslen) == 1) {
	if ((anslen >= 0) && (anslen <= CH_PK_MAX_DATALEN)) {
	  if (get_ans_string_and_send(conn, anslen, buf, sizeof(buf), cnt) < 0)
	    return -1;
	  else
	    // finished by sending ANS
	    return 0;
	} else {
	  user_socket_los(conn, "Bad ANS length %d (should be positive and max %d)", anslen, CH_PK_MAX_DATALEN);
	  set_conn_state(conn, cs->state, CS_Inactive, 0);
	  return -1;
	}
      } 
      else {
	user_socket_los(conn,"No length specified in ANS");
	return -1;
      }
    }
  }
  else if ((cs->state == CS_Open) || (cs->state == CS_Open_Sent)) {
    stream_conn_send_data_chunks(conn, buf, cnt);
  }
#if 1
  // @@@@ shit happens - but debug this!
  else if ((cnt == 2) && (strncmp((char *)buf,"\r\n",2) == 0)) {
    // ignore
    fprintf(stderr,"@@@@ NCP shit happened: CRLF read, ignoring\n");
    print_conn("@@ ", conn, 1);
    ;
  }
#endif
  else if (cs->state != CS_Inactive) {
    char errbuf[512];
    sprintf(errbuf, "Bad request len %d from stream user in state %s: not RFC, LSN, OPN, CLS, ANS, or wrong state: %.12s...", 
	    cnt, conn_state_name(conn), buf);
    fprintf(stderr,"%s\n", errbuf);
    send_los_pkt(conn,"Local error. We apologize for the incovenience.");
    // return a LOS to the user: bad request - not RFC or LSN
    user_socket_los(conn, "%s", errbuf);
    set_conn_state(conn, cs->state, CS_Inactive, 0);
    return -1;
  }
  // success
  return 1;
}

static int
socket_to_conn_packet_handler(struct conn *conn)
{
  struct conn_state *cs = conn->conn_state;
  int cnt;
  u_char *cname, *buf, sbuf[CH_PK_MAXLEN], pkt[CH_PK_MAXLEN];
  int buflen = sizeof(sbuf);
  struct chaos_header *ch = (struct chaos_header *)pkt;

  memset(sbuf, 0, CH_PK_MAXLEN);
  buf = sbuf;

  cnt = receive_or_die(conn, buf, buflen);
  if (ncp_debug) printf("socket_to_conn_packet_handler: read %d bytes from %s\n", cnt, conn_sockaddr_path(conn));

  while (cnt > 0) {
    int opc = buf[0], zero = buf[1];
    int len = buf[2] | (buf[3]<<8);
    if ((opc == 0) || ((opc > CHOP_BRD) && (opc < CHOP_DAT)) || (zero != 0) || (len > CH_PK_MAX_DATALEN)) {
      if (ncp_debug) printf("NCP socket_to_conn_packet_handler: bad opc %#o, zero nonzero (%d), or len too big (%d)\n", opc, zero, len);
      user_socket_los(conn,"Bad packet format (%#o %d %d)", opc, zero, len);
      return -1;
    }
    if (len+4 > cnt) {
      if (ncp_debug) printf("NCP Packet: read from socket didn't get a full packet (opcode %s len %d have %d)\n", 
			    ch_opcode_name(opc), len, cnt);
      // get some more input, but only what we need
      memmove(sbuf, buf, cnt);
      if (ncp_debug) printf("NCP Packet: reading %d more bytes to get a full 4+%d chunk at %p (diff %ld)\n", 
			    (len+4)-cnt, len, &buf[cnt], &buf[cnt]-buf);
      cnt += receive_or_die(conn, buf+cnt, (len+4)-cnt);
    }
    if (cs->state == CS_Inactive) {
      // In inactive state, the first thing from the user socket is RFC or LSN
      if (opc == CHOP_LSN) {
	u_char argbuf[MAX_CONTACT_NAME_LENGTH];
	memcpy(argbuf, &buf[4], len);
	argbuf[len] = '\0';
	cname = parse_contact_name(argbuf);
	if (ncp_debug) printf("Packet \"LSN %s\", adding listener\n", cname);
	add_listener(conn, cname);	// also changes state
      } else if (opc == CHOP_RFC) {
	u_char argbuf[MAX_CONTACT_NAME_LENGTH];
	memcpy(argbuf, &buf[4], len);
	argbuf[len] = '\0';
	if (ncp_debug) printf("Packet \"RFC %s\"\n", argbuf);
	initiate_conn_from_rfc_line(conn,argbuf,len);
      }
    }
    else if (cs->state == CS_RFC_Received) {
      // After receiving RFC, the first thing from the user socket is in "string command" form
      if (opc == CHOP_OPN) {
	if (ncp_debug) printf("Packet OPN len %d\n", len);
	send_opn_pkt(conn);
      }
      else if (opc == CHOP_CLS) {
	u_char argbuf[MAX_CONTACT_NAME_LENGTH];
	memcpy(argbuf, &buf[4], len);
	argbuf[len] = '\0';
	if (ncp_debug) printf("Packet cmd \"CLS %s\"\n", argbuf);
	send_cls_pkt(conn, (char *)argbuf);
	// done here
	return 0;
      }
      else if (opc == CHOP_FWD) {
	if (len == 2) {
	  u_short haddr = buf[4] | (buf[5]<<8);
	  send_fwd_pkt(conn, haddr);
	  // done
	  return 0;
	} else {
	  user_socket_los(conn, "Bad FWD length %d, expected 2", len);
	  return -1;
	}
      }
      else if (opc == CHOP_ANS) {
	if (ncp_debug) printf("Packet cmd \"ANS\"\n");
	if (get_ans_bytes_and_send(conn, len, &buf[4], sizeof(buf)-4, cnt-4) < 0)
	  return -1;
	else
	  // finished by sending ANS
	  return 0;
      }
    }
    else if ((cs->state == CS_Open) || (cs->state == CS_Open_Sent)) {
      // parse 4byte headers and send corresponding packets (LOS UNC DAT DWD EOF)
      return packet_conn_parse_and_send_bytes(conn, buf, cnt);
    }
    else if (cs->state != CS_Inactive) {
      char errbuf[512];
      sprintf(errbuf, "Bad request len %d from stream user in state %s: not RFC, LSN, OPN, CLS, ANS, or wrong state: %s", 
	      cnt, conn_state_name(conn), ch_opcode_name(buf[0]));
      fprintf(stderr,"%s\n", errbuf);
      send_los_pkt(conn,"Local error. We apologize for the incovenience.");
      // return a LOS to the user: bad request - not RFC or LSN
      user_socket_los(conn, "%s", errbuf);
      set_conn_state(conn, cs->state, CS_Inactive, 0);
      return -1;
    }
    // consumed some buffer
    cnt -= len+4;
    buf += len+4;
  }
  // success
  return 1;
}

// Handle conn user writes, for conn given as arg
static void *
socket_to_conn_handler(void *arg)
{
  struct conn *conn = (struct conn *)arg;
  struct conn_state *cs = conn->conn_state;

  switch (conn->conn_type) {
  case CT_Simple:
    // for simple:
    //  use socket_to_conn_simple_handler. If ANS/LOS/CLS, close and cancel/exit thread, if LSN/RFC continue.
    fprintf(stderr,"%%%% About to call socket_to_conn_simple_handler which isn't implemented\n");
    abort();
    break;
  case CT_Stream:
  case CT_Packet:
    while (1) {
      int v;
      if (conn->conn_type == CT_Stream)
	v = socket_to_conn_stream_handler(conn);
      else
	v = socket_to_conn_packet_handler(conn);
      if (v == 0) {
	if (ncp_debug) print_conn("Conn done",conn,1);
	// Only send EOF automatically for Stream conns - Packet conns have their own responsibility to handle them.
	finish_stream_conn(conn, conn->conn_type == CT_Stream);
      } else if (v < 0) {
	if (ncp_debug) print_conn("Conn error",conn,1);
	if (ncp_debug) printf("%%%%%%%% NCP %p (%s) exiting\n", conn, conn_thread_name(conn));
	return NULL;
      }
      // else loop
    }
    break;
  }
}

//////////////// conn-to-socket

static void
send_to_user_socket(struct conn *conn, struct chaos_header *pkt, u_char *buf, int len) 
{
  int opc = ch_opcode(pkt);
  u_char obuf[CH_PK_MAXLEN+128];
  if (conn->conn_type == CT_Stream) {
    // add text line, unless data
    int olen;
    switch (opc) {
    case CHOP_ANS:
      sprintf((char *)obuf,"ANS %d\r\n", len);
      olen = strlen((char *)obuf);
      memcpy(&obuf[olen], buf, len);
      len += olen+2;
      break;
    case CHOP_RFC:
      sprintf((char *)obuf,"RFC %s\r\n", buf);
      len += 4+2;
      break;
    case CHOP_OPN:
      sprintf((char *)obuf,"OPN Connection to host %#o opened\r\n", ch_srcaddr(pkt));
      len = strlen((char *)obuf);
      break;
    case CHOP_LOS: case CHOP_CLS:
      sprintf((char *)obuf, "%s ", ch_opcode_name(opc));
      strncpy((char *)&obuf[4], (char *)buf, len);
      strcpy((char *)&obuf[len+4], "\r\n");
      len += 4+2;
      break;
    case CHOP_FWD: {
#if CHAOS_DNS
      char fhost[NS_MAXDNAME];
#else
      char fhost[32];
#endif
#if CHAOS_DNS
      if (dns_name_of_addr(ch_ackno(pkt), (u_char *)fhost, sizeof(fhost)) < 0)
#endif
	sprintf((char *)fhost, "%#o", ch_ackno(pkt));
      sprintf((char *)obuf, "FWD %s", fhost);
      len = strlen((char *)obuf);
    }
      break;
    default:
      memcpy(obuf, buf, len);
    }
  } else if (conn->conn_type == CT_Packet) {
    // add 4-byte header
    packet_conn_header_from_pkt(conn, opc, (u_char *)obuf, len);
    memcpy(&obuf[4], buf, len);
    len += 4;
  }
  if (
#ifdef MSG_NOSIGNAL
      send(conn->conn_sock, obuf, len, MSG_NOSIGNAL)
#else
      write(conn->conn_sock, obuf, len)
#endif
      < 0) {
    if ((errno == ECONNRESET) || (errno == EPIPE) || (errno == EBADF)) {
      socket_closed_for_conn(conn);
    } else {
      perror("?? write(conn_to_socket_pkt_handler)");
      exit(1);
    }
  }
}

static void
conn_to_socket_pkt_handler(struct conn *conn, struct chaos_header *pkt)
{
  struct conn_state *cs = conn->conn_state;
  u_char *pk = (u_char *)pkt;
  u_char *data = &pk[CHAOS_HEADERSIZE];
  char buf[CH_PK_MAXLEN+256];
  int i, opc, len = 0;

  opc = ch_opcode(pkt);
  PTLOCKN(cs->conn_state_lock,"conn_state_lock");

  if (conn->conn_type != CT_Simple) {
    // Update state
    if (!packet_uncontrolled(pkt)) {
      if (pktnum_less(cs->pktnum_read_highest, ch_packetno(pkt)))
	cs->pktnum_read_highest = ch_packetno(pkt);
      else if (pktnum_equal(cs->pktnum_read_highest, ch_packetno(pkt))) {
	if (ncp_debug) printf("NCP conn_to_socket_pkt_handler: retransmission of pkt %#x received (highest %#x) - ignoring\n", 
			      ch_packetno(pkt), cs->pktnum_read_highest);
	PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
	return;
      } else
	fprintf(stderr,"%%%% Read pkt from read_pkts with unexpected number: highest was %#x, pkt is %#x\n", 
		cs->pktnum_read_highest, ch_packetno(pkt));
    }
  }

  if ((cs->state == CS_Listening) && (opc == CHOP_RFC)) {
#if CHAOS_DNS
    char fhost[NS_MAXDNAME];
#else
    char fhost[32];
#endif
    char args[MAX_CONTACT_NAME_LENGTH], *space;
    len = ch_nbytes(pkt);
#if CHAOS_DNS
    if (dns_name_of_addr(ch_srcaddr(pkt), (u_char *)fhost, sizeof(fhost)) < 0)
#endif
      sprintf((char *)fhost, "%#o", ch_srcaddr(pkt));
    // skip contact (listener knows that), just get args
    get_packet_string(pkt, (u_char *)args, sizeof(args));
    if (ncp_debug) printf("NCP rfc data: \"%s\"\n", args);
    if ((space = index(args, ' ')) != NULL) 
      sprintf(buf, "%s%s", fhost, space);
    else
      sprintf(buf, "%s", fhost);
    len = strlen(buf);
    if (ncp_debug) printf("To socket %s (%d bytes): [RFC] %s\n", conn_sockaddr_path(conn), len, buf);
    set_conn_state(conn, CS_Listening, CS_RFC_Received, 1);
  } else if ((cs->state == CS_RFC_Sent) && (ch_opcode(pkt) == CHOP_ANS)) {
    trace_conn("Answered", conn);
    len = ch_nbytes(pkt);
    // might be non-string data
    ntohs_buf((u_short *)data, (u_short *)buf, len);
    if (ncp_debug) printf("To socket %s (%d bytes): [ANS]\n", conn_sockaddr_path(conn), len);
    set_conn_state(conn, CS_RFC_Sent, CS_Answered, 1);
  } else if ((cs->state == CS_RFC_Sent) && (ch_opcode(pkt) == CHOP_FWD)) {
    trace_conn("Forwarded", conn);
    buf[0] = ch_ackno(pkt) & 0xff;
    buf[1] = ch_ackno(pkt) >> 8;
    len = 2;
  } else if (((cs->state == CS_RFC_Sent) || (cs->state == CS_Open))
	     && (opc == CHOP_OPN)) {
#if CHAOS_DNS
    if (dns_name_of_addr(ch_srcaddr(pkt), (u_char *)buf, NS_MAXDNAME > CH_PK_MAX_DATALEN ? CH_PK_MAX_DATALEN : NS_MAXDNAME) < 0)
#endif
      sprintf((char *)buf, "%#o", ch_srcaddr(pkt));
    len = strlen(buf);
    if (ncp_debug) printf("To socket %s (%d bytes): [OPN] %s", conn_sockaddr_path(conn), len, buf);
  } else if ((opc == CHOP_LOS) || (opc == CHOP_CLS)) {
    if (ncp_debug > 1) printf("NCP conn_to_socket_pkt_handler state %s: CLS/LOS data length %d\n", 
			      conn_state_name(conn), ch_nbytes(pkt));
    get_packet_string(pkt, (u_char *)buf, sizeof(buf)-4-3);
    len = ch_nbytes(pkt);
    if (ncp_debug) printf("To socket %s (len %d): [%s] %.12s...\n", conn_sockaddr_path(conn), len, 
			  ch_opcode_name(opc), buf);
    if (ch_opcode(pkt) == CHOP_LOS)
      set_conn_state(conn, cs->state, CS_LOS_Received, 1);
    else if (ch_opcode(pkt) == CHOP_CLS) {
      if ((cs->state == CS_Open) && (conn->conn_type == CT_Stream)) { // this is the expected way to close
	if (ncp_debug) printf("CLS received in Open state, no message to user socket\n");
	len = -1;
      }
      set_conn_state(conn, cs->state, CS_CLS_Received, 1);
    }
  } else if ((opc == CHOP_EOF) && (cs->state == CS_Open)) {
    // we received an EOF - just ack it and pass to user (for CT_Packet)
    // When the other end gets the ACK, they might CLS the conn.
    if (ncp_debug)
      printf("EOF %#x received, sending STS. Highest rec %#x, read %#x\n", 
	     ch_packetno(pkt), cs->pktnum_received_highest, cs->pktnum_read_highest);
    PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
    send_sts_pkt(conn);
    PTLOCKN(cs->conn_state_lock,"conn_state_lock");
    if (conn->conn_type == CT_Packet)
      len = 1;			// fake marker, to make the message go to the socket
  } else if (((cs->state == CS_Open) || (cs->state == CS_Finishing))
	     && (opc >= CHOP_DAT)) {
    if (ncp_debug > 1) printf("NCP conn_to_socket_pkt_handler: got %s for conn type %s\n", 
			      ch_opcode_name(ch_opcode(pkt)), conn_type_name(conn));
    ntohs_buf((u_short *)data, (u_short *)buf, ch_nbytes(pkt));
    len = ch_nbytes(pkt);
  } else {
    fprintf(stderr,"%%%% Bad pkt in conn_to_socket_pkt_handler: pkt %#x opcode %s in state %s, highest %#x\n",
	    ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), state_name(cs->state),
	    cs->pktnum_received_highest);
    print_conn("%% ", conn, 1);
  }

  PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");

  if ((len > 0) || (conn->conn_type == CT_Packet)) {	     // Something to write to the user socket?
    if (opc == CHOP_EOF) len = 0; // fake len given
    if (len >= 0)
      send_to_user_socket(conn, pkt, (u_char *)buf, len);
  }
  // free the packet, which was malloc:ed in add_input_pkt
  free(pkt);
}


// Handle conn user reads, for conn given as arg
static void *
conn_to_socket_handler(void *arg)
{
  struct conn *conn = (struct conn *)arg;
  struct conn_state *cs = conn->conn_state;
  struct chaos_header *pkt;

  while (1) {
    // Wait for input to be available from network
    pkt = get_input_pkt(conn);

    if (pkt == NULL) {
      fprintf(stderr,"%%%% Disaster: null pkt read from read_pkts\n");
      exit(1);
    }

    // handle it
    switch (conn->conn_type) {
    case CT_Simple:
      conn_to_socket_pkt_handler(conn, pkt);
      break;
    case CT_Stream:
    case CT_Packet:
      conn_to_socket_pkt_handler(conn, pkt);
      if (!packet_uncontrolled(pkt) &&
	  ((cs->state == CS_Open) || (cs->state == CS_Finishing)) &&
	  // more than a third of the window is un-acked
	  (pktnum_diff(cs->pktnum_read_highest, cs->pktnum_acked) > cs->local_winsize/3)) {
	// Then send explict STS
	send_sts_pkt(conn);
      }
      if ((cs->state == CS_CLS_Received) || (cs->state == CS_Host_Down) ||
	  (cs->state == CS_LOS_Received) || (cs->state == CS_Answered)) {
	if (ncp_debug) printf("NCP c_t_s connection finishing, state %s\n", state_name(cs->state));
	// Don't send EOF, we're already pretty closed.
	finish_stream_conn(conn, 0);
      }
      break;
    }
  }
}

//////////////// utility

static void 
start_conn(struct conn *conn)
{
  if (pthread_create(&conn->conn_to_sock_thread, NULL, &conn_to_socket_handler, conn) < 0) {
    perror("?? pthread_create(conn user read handler)");
    exit(1);
  }
  if (pthread_create(&conn->conn_from_sock_thread, NULL, &socket_to_conn_handler, conn) < 0) {
    perror("?? pthread_create(conn user write handler)");
    exit(1);
  }
  if (conn->conn_type != CT_Simple) {
    if (pthread_create(&conn->conn_to_net_thread, NULL, &conn_to_packet_stream_handler, conn) < 0) {
      perror("?? pthread_create(conn_to_packet_stream_handler)");
      exit(1);
    }
  }
}

void
print_ncp_stats()
{
  int x, cstate, cslocked, llocked;

  if (!ncp_enabled) {
    printf("NCP disabled\n");
    return;
  }
#if 0
  printf("NCP: %d indexes used\n", indexindexindex);
#endif
  // debugging...
  if ((cslocked = pthread_mutex_trylock(&connlist_lock)) != 0) {
    if (cslocked == EBUSY)
      printf("%%%% NCP: connlist lock is already locked\n");
    else
      fprintf(stderr,"pthread_mutex_trylock(connlist_lock): %s\n", strerror(cslocked));
  } else PTUNLOCKN(connlist_lock,"connlist_lock");
  if ((llocked = pthread_mutex_trylock(&listener_lock)) != 0) {
    if (llocked == EBUSY)
      printf("%%%% NCP: listener lock is already locked\n");
    else
      fprintf(stderr,"pthread_mutex_trylock(listener_lock): %s\n", strerror(llocked));
  } else PTUNLOCKN(listener_lock,"listener_lock");


  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(connlist_lock,"connlist_lock");
  printf("NCP: conn list length%s\n", conn_list == NULL ? " empty" : ":");
  struct conn_list *c = conn_list;
  while (c) {
    print_conn(">", c->conn_conn, 1);
    c = c->conn_next;
  }
  PTUNLOCKN(connlist_lock,"connlist_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();

  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));
  PTLOCKN(listener_lock,"listener_lock");
  printf("NCP: listener list%s\n", registered_listeners == NULL ? " empty" : ":");
  struct listener *ll = registered_listeners;
  while (ll) {
    print_listener(">", ll);
    ll = ll->lsn_next;
  }
  PTUNLOCKN(listener_lock,"listener_lock");
  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();

}
