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
// - GC of inactive connections - note garbage_collect_idle_conns doesn't quite work yet
// - handle local address (including cbridge "built-in" handlers, e.g. STATUS)
// - Decide/structure/clean up/document who changes the state
// - Document it better
//
// add statistics struct, for (new) PEEK protocol to report
// domain search list config - here or in dns?
// write client library

#include <stdlib.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>

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

// ms to wait for ack of EOF
#define EOF_WAIT_TIMEOUT 1000

#define MAX_CONTACT_NAME_LENGTH CH_PK_MAX_DATALEN

// configurable stuff
int ncp_enabled = 0;
// chaos socket directory
#define DEFAULT_CHAOS_SOCKET_DIRECTORY "/tmp/"
static char chaos_socket_directory[PATH_MAX];
// default domain for host lookups
#define DEFAULT_CHAOS_DOMAIN "chaosnet.net"
static char default_chaos_domain[NS_MAXDNAME];
// default retransmission interval
static int default_retransmission_interval = DEFAULT_RETRANSMISSION_INTERVAL;
// default window size
static int default_window_size = DEFAULT_WINSIZE;
// default EOF wait timeout
static int eof_wait_timeout = EOF_WAIT_TIMEOUT;
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

// parse a configuration file line:
// ncp socketdir /var/run debug on domain ams.chaosnet.net trace on
int
parse_ncp_config_line()
{
  char *tok = NULL;
  int val = 0;

  strcpy(chaos_socket_directory,DEFAULT_CHAOS_SOCKET_DIRECTORY); // default
  strcpy(default_chaos_domain,DEFAULT_CHAOS_DOMAIN); // default
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
    } else if (strcmp(tok,"domain") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no domain specified\n"); return -1; }
      strncpy(default_chaos_domain, tok, sizeof(default_chaos_domain));
      if ((strlen(default_chaos_domain) < sizeof(default_chaos_domain)) &&
	  (default_chaos_domain[strlen(default_chaos_domain)-1] == '.')) {
	fprintf(stderr,"ncp: fixing domain to remove final '%c' from \"%s\"\n", 
		default_chaos_domain[strlen(default_chaos_domain)-1], default_chaos_domain);
	default_chaos_domain[strlen(default_chaos_domain)-1] = '\0';
      }
    } else if (strcmp(tok,"retrans") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no retrans value specified\n"); return -1; }
      if (sscanf(tok, "%d", &val) != 1) { fprintf(stderr,"ncp: bad retrans value specified: %s\n", tok); return -1; }
      if (val < 1) { fprintf(stderr,"ncp: bad retrans value specified: %d\n", val); return -1; }
      if ((val < 100) || (val > 15*1000)) { fprintf(stderr,"ncp: very short or long retrans value specified: %d\n", val); return -1; }
      else default_retransmission_interval = val;
    } else if (strcmp(tok,"eofwait") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no eofwait value specified\n"); return -1; }
      if (sscanf(tok, "%d", &val) != 1) { fprintf(stderr,"ncp: bad eofwait value specified: %s\n", tok); return -1; }
      if (val < 1) { fprintf(stderr,"ncp: bad eofwait value specified: %d\n", val); return -1; }
      if ((val < 100) || (val > 15*1000)) { fprintf(stderr,"ncp: very short or long eofwait value specified: %d\n", val); return -1; }
      else eof_wait_timeout = val;
    } else if (strcmp(tok,"window") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"ncp: no window value specified\n"); return -1; }
      // allow any base: 0x for hex, 012 for octal, otherwise decimal
      if (sscanf(tok, "%i", &val) != 1) { fprintf(stderr,"ncp: bad window value specified: %s\n", tok); return -1; }
      if ((val < 1) || (val > MAX_WINSIZE)) { fprintf(stderr,"ncp: bad window value specified: %d\n", val); return -1; }
      else default_window_size = val;
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
  if (verbose || ncp_debug) {
    printf("NCP is %s. Socket directory \"%s\", default domain \"%s\", retrans %d, window %d, eofwait %d, debug %d %s, trace %d %s\n", 
	   ncp_enabled ? "enabled" : "disabled",
	   chaos_socket_directory, default_chaos_domain, default_retransmission_interval, default_window_size,
	   eof_wait_timeout,
	   ncp_debug, (ncp_debug > 0) ? "on" : "off",
	   ncp_trace, (ncp_trace > 0) ? "on" : "off");
  }
  return 0;
}

static void
trace_conn(char *leader, struct conn *conn)
{
  char tbuf[128], buf[256];
  time_t now = time(NULL);
  if (ncp_trace) {
    strftime(tbuf, sizeof(tbuf), "%T", localtime(&now));
    sprintf(buf, "%s %s", tbuf, leader);
    print_conn(buf, conn, 0);
  }
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
  
  local.sun_family = AF_UNIX;
  strcpy(local.sun_path, chaos_socket_directory);
  strcat(local.sun_path, path);
  if (unlink(local.sun_path) < 0) {
    if (ncp_debug) perror("unlink(chaos_sockfile)");
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
    perror("chmod(local, 0777)"); // @@@@ configurable?
  if (socktype == SOCK_STREAM) {
    if (listen(sock, 25) < 0) {	// @@@@ random limit
      perror("listen(local)");
      exit(1);
    }
  }
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
conn_type_name(struct conn *conn)
{
  switch (conn->conn_type) {
  case CT_Stream: return "Stream";
  case CT_Simple: return "Simple";
  }
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
  printf("%s conn %p %s contact \"%s\" remote <%#o,%#x> local <%#o,%#x> state %s age %ld %s\n",
	 leader,
	 conn, conn_type_name(conn),
	 conn->conn_contact,
	 conn->conn_rhost, conn->conn_ridx,
	 conn->conn_lhost, conn->conn_lidx,
	 conn_state_name(conn), now - conn->conn_created,
	 conn->conn_sockaddr.sun_path);
  if (alsostate) {
    struct conn_state *cs = conn->conn_state;
    printf("%s made %#x fwin %d avail %d, read %d contr %d ooo %d, ack %#x rec %#x, send %d high %#x ack %#x last rec %ld\n",
	   leader, cs->pktnum_made_highest,
	   cs->foreign_winsize, cs->window_available, pkqueue_length(cs->read_pkts), cs->read_pkts_controlled,
	   pkqueue_length(cs->received_pkts_ooo), 
	   cs->pktnum_read_highest, cs->pktnum_received_highest, 
	   pkqueue_length(cs->send_pkts), cs->pktnum_sent_highest, cs->pktnum_sent_acked,
	   cs->time_last_received > 0 ? now - cs->time_last_received : -1);
  }
}

void
set_conn_state(struct conn *c, connstate_t new, int havelock)
{
  struct conn_state *cs = c->conn_state;
  if (!havelock) PTLOCKN(cs->conn_state_lock,"conn_state_lock");
  if (ncp_debug) printf("Conn %p changing from %s to %s\n", c, conn_state_name(c), state_name(new));
  cs->state = new;
  if (pthread_cond_broadcast(&cs->conn_state_cond) != 0) perror("pthread_cond_broadcast(conn_state_cond)");
  if (!havelock) PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
}

connstate_t
await_conn_state(struct conn *c, connstate_t new, int timeout_ms)
{
  int timedout;
  struct timespec to;
  struct conn_state *cs = c->conn_state;
  
  PTLOCKN(cs->conn_state_lock,"conn_state_lock");

  timespec_get(&to, TIME_UTC);
  to.tv_nsec += timeout_ms*1000000;
  while (to.tv_nsec > 1000000000) {
    to.tv_sec++; to.tv_nsec -= 1000000000;
  }
  timedout = 0;

  while ((timedout == 0) && (cs->state != new)) {
    if (timeout_ms > 0)
      timedout = pthread_cond_timedwait(&cs->conn_state_cond, &cs->conn_state_lock, &to);
    else
      pthread_cond_wait(&cs->conn_state_cond, &cs->conn_state_lock);
  }
  PTUNLOCKN(cs->conn_state_lock,"conn_state_lock");
  if (timedout != 0)
    return -1;
  else
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

  if (ncp_debug) printf("Creating %s conn\n", ctype == CT_Stream ? "Stream" : (ctype == CT_Simple ? "Simple" : "??"));

  if ((cs == NULL)||(read_pkts == NULL)||(received_pkts_ooo==NULL)||(send_pkts==NULL)) {
    perror("malloc(make_conn)");
    exit(1);
  }

  cs->read_pkts = read_pkts;
  cs->read_pkts_controlled = 0;
  cs->received_pkts_ooo = received_pkts_ooo;
  cs->send_pkts = send_pkts;
  cs->state = CS_Inactive;
  cs->local_winsize = DEFAULT_WINSIZE;
  cs->foreign_winsize = DEFAULT_WINSIZE;
  cs->window_available = DEFAULT_WINSIZE;
  cs->pktnum_sent_highest = make_fresh_index(); // initialize
  cs->pktnum_made_highest = cs->pktnum_sent_highest;

  // condition vars, locks
  if (pthread_mutex_init(&cs->conn_state_lock, NULL) != 0)
    perror("pthread_mutex_init(conn_state_lock)");
  if (pthread_cond_init(&cs->conn_state_cond, NULL) != 0)
    perror("pthread_cond_init(conn_state_cond)");
  if (pthread_mutex_init(&cs->read_mutex, NULL) != 0)
    perror("pthread_mutex_init(read_mutex)");
  if (pthread_cond_init(&cs->read_cond, NULL) != 0)
    perror("pthread_cond_init(read_cond)");
  if (pthread_mutex_init(&cs->received_ooo_mutex, NULL) != 0)
    perror("pthread_mutex_init(received_ooo_mutex)");
  if (pthread_mutex_init(&cs->send_mutex, NULL) != 0)
    perror("pthread_mutex_init(send_mutex)");
  if (pthread_cond_init(&cs->send_cond, NULL) != 0)
    perror("pthread_cond_init(send_cond)");
  if (pthread_mutex_init(&cs->window_mutex, NULL) != 0)
    perror("pthread_mutex_init(window_mutex)");
  if (pthread_cond_init(&cs->window_cond, NULL) != 0)
    perror("pthread_cond_init(window_cond)");


  // the conn itself
  struct conn *conn = (struct conn *)calloc(1, sizeof(struct conn));

  conn->conn_type = ctype;
  if (pthread_mutex_init(&conn->conn_lock, NULL) != 0)
    perror("pthread_mutex_init(conn_lock)");
  conn->conn_sock = sock;

  if (sa != NULL)
    memcpy(&conn->conn_sockaddr, sa, (sa_len > sizeof(conn->conn_sockaddr) ? sizeof(conn->conn_sockaddr) : sa_len));
  conn->conn_state = cs;
  conn->retransmission_interval = default_retransmission_interval;
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

  free(conn->conn_contact);
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

  free(cs);
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
remove_active_conn(struct conn *c, int dolock)
{
  int x, cstate;
  struct conn_list *cl;

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
      if (ncp_debug || ncp_trace) printf("Removing conn %p\n", c);
      if (cl->conn_prev != NULL)
	cl->conn_prev->conn_next = cl->conn_next;
      if (cl->conn_next != NULL)
	cl->conn_next->conn_prev = cl->conn_prev;
      free(cl);
      free_conn(c);
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
	 (((ch_opcode(ch) == CHOP_RFC) || (ch_opcode(ch) == CHOP_OPN) || (ch_opcode(ch) == CHOP_ANS))
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
    u_char *data = &((u_char *)ch)[CHAOS_HEADERSIZE];
    ch_11_gets(data, contact, ch_nbytes(ch));
    contact[ch_nbytes(ch)] = '\0';
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
    perror("malloc(make_listener)");
    exit(1);
  }
  int len = strlen((char *)contact);
  if (len > MAX_CONTACT_NAME_LENGTH) len = MAX_CONTACT_NAME_LENGTH;
  l->lsn_contact = malloc(len+1);
  strncpy((char *)l->lsn_contact, (char *)contact, len);
  l->lsn_conn = c;
  l->lsn_next = NULL;
  l->lsn_prev = NULL;

  return l;
}

static void
free_listener(struct listener *lsn)
{
  // @@@@ assert(not on the registered_listeners list)
  if (lsn->lsn_contact != NULL)
    free(lsn->lsn_contact);
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
    // @@@@ assert(registered_listeners == ll)
    if (registered_listeners != NULL)
      registered_listeners->lsn_prev = ll;
    registered_listeners = ll->lsn_next;
  } else {
    ll->lsn_prev->lsn_next = ll->lsn_next;
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
  // @@@@ assert(registered_listeners->lsn_prev == NULL) always
  if (registered_listeners != NULL)
    registered_listeners->lsn_prev = new;
  registered_listeners = new;
  PTUNLOCKN(listener_lock,"listener_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();

  set_conn_state(c, CS_Listening, 0);
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
  u_char *data = &((u_char *)ch)[CHAOS_HEADERSIZE];

  ch_11_gets(data, contact, ch_nbytes(ch));
  contact[ch_nbytes(ch)] = '\0';
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
    case CHOP_DAT: case CHOP_RFC: case CHOP_CLS: case CHOP_LOS: case CHOP_ANS:
      htons_buf((u_short *)data, (u_short *)datao, len);
      break;
    default:
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
  return send_basic_pkt(c, CHOP_EOF);
}


// initialize local haddr, index, winsize
static void
send_first_pkt(struct conn *c, int opcode, connstate_t newstate)
{
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

  PTLOCKN(c->conn_state->conn_state_lock,"conn_state_lock");
  c->conn_state->local_winsize = default_window_size;

  // initial pkt nr random, make sure we don't think it's acked
  // ITS starts at 1, but random is better against hijacks.
  c->conn_state->pktnum_made_highest = make_u_short_random();
  c->conn_state->pktnum_sent_acked = c->conn_state->pktnum_made_highest;
  c->conn_state->pktnum_sent_highest = c->conn_state->pktnum_made_highest;

  // construct pkt from conn
  pklen = make_pkt_from_conn(opcode, c, (u_char *)&pkt);

  set_conn_state(c, newstate, 1);
  PTUNLOCKN(c->conn_state->conn_state_lock,"conn_state_lock");

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
  send_first_pkt(c, CHOP_RFC, CS_RFC_Sent);
}


static void
send_opn_pkt(struct conn *c)
{
  // don't declare it open until STS arrives
  send_first_pkt(c, CHOP_OPN, CS_RFC_Received);
}


static void
send_ans_pkt(struct conn *c, u_char *ans, int len)
{
  send_basic_pkt_with_data(c, CHOP_ANS, ans, len);
  // ANS is uncontrolled, so just terminate
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


//////////////// shutting things down

static void
cancel_conn_threads(struct conn *conn)
{
  int x;

  if (ncp_debug) printf("cancelling threads for %p\n", conn);

  PTLOCKN(conn->conn_lock,"conn_lock");
  // cancel the other threads
  if (!pthread_equal(conn->conn_from_sock_thread, pthread_self())) {
    if (conn->conn_from_sock_thread == 0) {
      if (ncp_debug) printf("thread c_f_s already exited\n");
    } else if ((x = pthread_cancel(conn->conn_from_sock_thread)) != 0) {
      if (ncp_debug) fprintf(stderr,"pthread_cancel failed: %s\n", strerror(x));
    }
    if (ncp_debug) printf("cancelled c_f_s thread %p for %p\n", conn->conn_from_sock_thread, conn);
    conn->conn_from_sock_thread = 0;
  }
  if (!pthread_equal(conn->conn_to_sock_thread, pthread_self())) {
    if (conn->conn_to_sock_thread == 0) {
      if (ncp_debug) printf("thread c_t_s already exited\n");
    } else if ((x = pthread_cancel(conn->conn_to_sock_thread)) != 0) {
      if (ncp_debug) fprintf(stderr,"pthread_cancel failed: %s\n", strerror(x));
    }
    if (ncp_debug) printf("cancelled c_t_s thread %p for %p\n", conn->conn_to_sock_thread, conn);
    conn->conn_to_sock_thread = 0;
  }
  if (conn->conn_type != CT_Simple) {
    if (!pthread_equal(conn->conn_to_net_thread, pthread_self())) {
      if (conn->conn_to_net_thread == 0) {
	if (ncp_debug) printf("thread c_t_n already exited\n");
      } else if ((x = pthread_cancel(conn->conn_to_net_thread)) != 0) {
	if (ncp_debug) fprintf(stderr,"pthread_cancel failed: %s\n", strerror(x));
      }
      if (ncp_debug) printf("cancelled c_t_n thread %p for %p\n", conn->conn_to_net_thread, conn);
      conn->conn_to_net_thread = 0;
    }
  }
  // and exit this one if it's a conn thread
  if (pthread_equal(conn->conn_to_net_thread, pthread_self()) ||
      pthread_equal(conn->conn_to_sock_thread, pthread_self()) ||
      pthread_equal(conn->conn_from_sock_thread, pthread_self())) {
    if (ncp_debug) printf("exiting this thread %p for %p\n", pthread_self(), conn);
    PTUNLOCKN(conn->conn_lock,"conn_lock");
    pthread_exit(NULL);
  }
}

static void
finish_stream_conn(struct conn *conn)
{
  PTLOCKN(conn->conn_lock,"conn_lock");
  if ((conn->conn_state->state == CS_Inactive) || (conn->conn_sock == -1)) {
    trace_conn("Already finished", conn);
    PTUNLOCKN(conn->conn_lock, "conn_lock");
    cancel_conn_threads(conn);
    return;
  }
  trace_conn("Finishing", conn);
  if (ncp_debug) print_conn("Finishing", conn, 0);
  // The description of the EOF/EOF/CLS sequence doesn't seem to match the LISPM implementation.
  // Let's see if this works.
  struct conn_state *cs = conn->conn_state;
  u_short eofpktnum;
  int timedout;
  struct timespec to;

  if (cs->state == CS_RFC_Received) {
    // Wait a while for conn to open so pkts can get through
    int to;
    if (ncp_debug) printf("NCP Finishing in state %s, waiting for Open\n", conn_state_name(conn));
    // @@@@ configurable
    to = await_conn_state(conn, CS_Open, 2000);
    if (ncp_debug) printf("NCP Finished waiting %s, state %s now\n", 
			  to < 0 ? "TIMED OUT" : "no timeout", conn_state_name(conn));
  }
  if (cs->state == CS_Open) { //  || (cs->state == CS_CLS_Received)
    // finish conn: send eof, wait for it to be acked.
    set_conn_state(conn, CS_Finishing, 1);
    // try retransmission first, in anything remains
    retransmit_controlled_packets(conn);
    eofpktnum = send_eof_pkt(conn);
    // now wait.
    // Use window updates from discard_received_pkts_from_send_list to check for acked pkts - this is a hack
    PTLOCKN(cs->window_mutex,"window_mutex");

    timespec_get(&to, TIME_UTC);
    to.tv_nsec += eof_wait_timeout*1000000;
    while (to.tv_nsec > 1000000000) {
      to.tv_sec++; to.tv_nsec -= 1000000000;
    }
    timedout = 0;

    while ((timedout == 0) && pktnum_less(cs->pktnum_sent_acked, eofpktnum))
      timedout = pthread_cond_timedwait(&cs->window_cond, &cs->window_mutex, &to);
    PTUNLOCKN(cs->window_mutex,"window_mutex");

    if (cs->state != CS_CLS_Received) {
      // unless CLS received, send a CLS
      send_cls_pkt(conn,"Bye bye");
    }
  }
  close(conn->conn_sock);
  conn->conn_sock = -1;
  if ((strlen(conn->conn_sockaddr.sun_path) > 0) && (unlink(conn->conn_sockaddr.sun_path) != 0)) {
    if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", conn->conn_sockaddr.sun_path, strerror(errno));
  }
  set_conn_state(conn, CS_Inactive, 0);
  PTUNLOCKN(conn->conn_lock, "conn_lock");
  // and terminate
  cancel_conn_threads(conn);
}

static void 
socket_closed_for_simple_conn(struct conn *conn)
{
  if (ncp_debug) print_conn("Socket closed for", conn, 0);
  if (conn->conn_state->state == CS_Listening) {
    remove_listener_for_conn(conn);
  }
  // leave the conn around for tracing/statistics
  set_conn_state(conn, CS_Inactive, 0);
  close(conn->conn_sock);
  conn->conn_sock = -1;
  if ((strlen(conn->conn_sockaddr.sun_path) > 0) && (unlink(conn->conn_sockaddr.sun_path) != 0)) {
    if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", conn->conn_sockaddr.sun_path, strerror(errno));
  }
  cancel_conn_threads(conn);
  // does not get here
}

static void 
socket_closed_for_stream_conn(struct conn *conn)
{
  if (ncp_debug) print_conn("Socket closed for", conn, 0);
  if (conn->conn_state->state == CS_Listening) {
    remove_listener_for_conn(conn);
  }
  finish_stream_conn(conn);
}

static void 
user_socket_los(struct conn *conn, char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vdprintf(conn->conn_sock, fmt, args);
  va_end(args);
  close(conn->conn_sock);
  conn->conn_sock = -1;
  if ((strlen(conn->conn_sockaddr.sun_path) > 0) && (unlink(conn->conn_sockaddr.sun_path) != 0)) {
    if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", conn->conn_sockaddr.sun_path, strerror(errno));
  }
  cancel_conn_threads(conn);
}

//////////////// parsing rfcs
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

  ch_11_gets(data, contact, ch_nbytes(ch));
  contact[ch_nbytes(ch)] = '\0';
  PTLOCKN(conn->conn_lock,"conn_lock");
  conn->conn_contact = parse_contact_name(contact);
  conn->conn_contact_args = parse_contact_args(contact, conn->conn_contact);
  conn->conn_rhost = ch_srcaddr(ch);
  conn->conn_ridx = ch_srcindex(ch);
  conn->conn_lhost = ch_destaddr(ch);
  conn->conn_lidx = make_fresh_index();
  conn->conn_state->pktnum_received_highest = ch_packetno(ch);
  // conn->conn_state->state = CS_RFC_Received;
  PTUNLOCKN(conn->conn_lock,"conn_lock");
  if (ncp_debug) print_conn("Initiated from RFC pkt:", conn, 0);
  add_active_conn(conn);
}


static void
initiate_conn_from_rfc_line(struct conn *conn, u_char *buf, int buflen)  
{
  u_short haddr = 0;
  u_char *cname, *hname = &buf[4];

  u_char *space = (u_char *)index((char *)hname,' ');
  if (space == NULL) {
    // return a LOS to the user: no contact given
    user_socket_los(conn, "LOS No contact name given in RFC line");
    return;
  }
  *space = '\0';
  cname = &space[1];

  if ((sscanf((char *)hname, "%ho", &haddr) != 1) || (haddr <= 0x100) || (haddr > 0xfe00) || ((haddr & 0xff) == 0)) {
#if CHAOS_DNS
    u_char dname[NS_MAXDNAME];
    u_short haddrs[4];
    int naddrs = 0;
    
    if (strlen((char *)hname) >= sizeof(dname)) {
      user_socket_los(conn, "LOS Too long hostname in RFC line: %lu", strlen((char *)hname));
      return;
    }
    // @@@@ make default_chaos_domain a list, iterate until match
    strcpy((char *)dname, (char *)hname);
    if ((strlen((char *)dname)+strlen(default_chaos_domain)+1+1 < sizeof(dname)) &&
	(index((char *)dname, '.') == NULL)) {
      strcat((char *)dname, ".");
      strcat((char *)dname, default_chaos_domain);
    }
    if ((naddrs = dns_addrs_of_name(dname, (u_short *)&haddrs, 4)) <= 0) {
      user_socket_los(conn, "LOS no addrs of name \"%s\" found", dname);
      return;
    } else {
      // Pick one which is closest, if one is
      haddr = find_closest_addr((u_short *)&haddrs, naddrs);
    }
#else
    // return a LOS to the user: bad host name '%s'
    user_socket_los(conn, "LOS Bad host name \"%s\"", hname);
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

static void
garbage_collect_idle_conns()
{
  struct timespec now;
  int x, cstate;
  struct conn_list *cl;
  
  // protect against cancellation while holding global lock
  if ((x = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cstate)) != 0)
    fprintf(stderr,"pthread_setcancelstate(PTHREAD_CANCEL_DISABLE): %s\n", strerror(x));

  PTLOCKN(connlist_lock,"connlist_lock");

  timespec_get(&now, TIME_UTC);

  for (cl = conn_list; cl != NULL; cl = cl->conn_next) {
    struct conn *c = cl->conn_conn;
    if (((c->conn_state->state == CS_Inactive) || (c->conn_state->state == CS_Host_Down))
	&& (((c->conn_state->time_last_received != 0) 
	     && (now.tv_sec - c->conn_state->time_last_received > GARBAGE_CONN_AGE))
	    ||
	    // never received
	    ((c->conn_state->time_last_received == 0) && (now.tv_sec - c->conn_created > GARBAGE_CONN_AGE)))) {
      if (ncp_debug || ncp_trace)
	printf("NCP Garbage collecting conn: remote <%#o,%#x> local <%#o,%#x> state %s idle %lds created %ld ago\n",
	       c->conn_rhost, c->conn_ridx, c->conn_lhost, c->conn_ridx,
	       state_name(c->conn_state->state), now.tv_sec - c->conn_state->time_last_received,
	       now.tv_sec - c->conn_created);
      // cancel its threads
      cancel_conn_threads(c);
      // close its socket
      if (c->conn_sock != -1) {
	close(c->conn_sock);
	c->conn_sock = -1;
	if ((strlen(c->conn_sockaddr.sun_path) > 0) && (unlink(c->conn_sockaddr.sun_path) != 0)) {
	  if (ncp_debug) fprintf(stderr,"unlink %s: %s\n", c->conn_sockaddr.sun_path, strerror(errno));
	}
      }
      // remove it from the conn list and free the storage used
      remove_active_conn(c, 0);
    }
  }

  PTUNLOCKN(connlist_lock,"connlist_lock");

  if ((x = pthread_setcancelstate(cstate, NULL)) != 0) 
    fprintf(stderr,"pthread_setcancelstate(%d): %s\n", cstate, strerror(x));
  // see if we were cancelled?
  pthread_testcancel();
}


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
#define NCP_NUMSOCKS 2
  int fds[NCP_NUMSOCKS];
  struct slist { int socktype; char *sockname; conntype_t sockconn; }
  socklist[] = {
#if USE_CHAOS_SIMPLE
    {SOCK_DGRAM,"chaos_simple", CT_Simple},
#endif
    {SOCK_STREAM,"chaos_stream", CT_Stream},
    // SOCK_SEQPACKET, "chaos_binary", CT_Binary },
    {0, NULL, 0}};

#if __APPLE__
  srandomdev();
#else
  srandom(time(NULL));
#endif

  maxfd = 0;

  for (i = 0; socklist[i].sockname != NULL; i++) {
    fds[i] = make_named_socket(socklist[i].socktype, socklist[i].sockname);
    if (fds[i] > maxfd) maxfd = fds[i];
  }
  if (i >= NCP_NUMSOCKS) {
    fprintf(stderr,"not enough room for sockets - increase NCP_NUMSOCKS to %d\n", i);
    exit(1);
  }

  // accept, select etc
  while (1) {
    // check if any conns are too old
    // @@@@ not finished: 
    // garbage_collect_idle_conns();
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
	    perror("accept(simplesock)");
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
    if (ncp_debug) printf("Discarding pkt %#x receipt %#x opcode %s\n",
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
  if (pthread_cond_broadcast(&cs->window_cond) != 0) perror("pthread_cond_broadcast(window_cond)");
  PTUNLOCKN(cs->window_mutex,"window_mutex");
}

static struct chaos_header *
get_input_pkt(struct conn *c)
{
  struct conn_state *cs = c->conn_state;
  struct chaos_header *pkt;

  PTLOCKN(cs->read_mutex,"read_mutex");
  while (pkqueue_length(cs->read_pkts) == 0)
    if (pthread_cond_wait(&cs->read_cond, &cs->read_mutex) != 0) perror("pthread_cond_wait(read_cond)");
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
  if (pthread_cond_signal(&cs->read_cond) != 0) perror("pthread_cond_signal(read_cond)");
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
  PTUNLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
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
    perror("malloc(saved, add_output_pkt)");
    exit(1);
  }
  memcpy(saved, pkt, pklen);

  // make sure there is room in the window first
  // window lock around send_pkts lock
  PTLOCKN(cs->window_mutex,"window_mutex");
  if (!packet_uncontrolled(pkt)) {
    while (cs->window_available <= 0)
      if (pthread_cond_wait(&cs->window_cond, &cs->window_mutex) != 0) perror("pthread_cond_wait(window_cond)");
  }
  // lock it
  PTLOCKN(cs->send_mutex,"send_mutex");
  // add pkt
  pkqueue_add(saved, cs->send_pkts);
  if (ncp_debug > 1) printf("Added pkt to send_pkts len %d\n", pkqueue_length(cs->send_pkts));
  // already checked above that it's higher
  cs->send_pkts_pktnum_highest = ch_packetno(pkt);

  // let consumer know there is stuff to send to network
  if (pthread_cond_signal(&c->conn_state->send_cond) != 0) perror("pthread_cond_signal(send_cond)");
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
	if (!packet_uncontrolled(pkt)
	    // don't retransmit OPN when we're already open
	    //&& !((ch_opcode(pkt) == CHOP_OPN) || (cs->state == CS_Open) || (cs->state == CS_Finishing))
	    // don't retransmit DAT until CS_Open
	    && ((ch_opcode(pkt) != CHOP_DAT) || (cs->state == CS_Open) || (cs->state == CS_Finishing))) {
	  // @@@@ unless sent within 1/30 s
	  nsent++;
	  // protect against swapping - send a copy
	  if (pklen <= sizeof(tempkt)) {
	    // update ack field
	    set_ch_ackno(pkt, cs->pktnum_read_highest);
	    cs->pktnum_acked = cs->pktnum_read_highest; // record the sent ack
	    memcpy(tempkt, (u_char *)pkt, pklen);
	    if (ncp_debug) printf("NCP retransmitting controlled pkt %#x (%s), ack %#x\n",
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

static int
send_packet_when_window_open(struct conn_state *cs, struct chaos_header *pkt) 
{
  u_char tempkt[CH_PK_MAXLEN];
  int pklen = ch_nbytes(pkt)+CHAOS_HEADERSIZE;
  if (pklen % 2) pklen++;

  if (packet_uncontrolled(pkt)) {
    // just send it
    if (ncp_debug) printf("Sending uncontrolled pkt %#x (%s len %d)\n", 
			  ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), ch_nbytes(pkt));
    send_chaos_pkt((u_char *)pkt, pklen);
    return 1;
  }
  if (!((ch_opcode(pkt) == CHOP_DAT) && (cs->state != CS_Open)) && // don't send DAT until Open
      pktnum_less(cs->pktnum_sent_highest, ch_packetno(pkt)) && // we haven't already sent it
      pktnum_less(cs->pktnum_sent_acked, ch_packetno(pkt))) {  // and we haven't gotten an ack for it
    if (ncp_debug > 1) printf("Want to send controlled pkt %#x, window now %d, q len %d\n", ch_packetno(pkt),
			  cs->window_available, pkqueue_length(cs->send_pkts));
    PTLOCKN(cs->window_mutex,"window_mutex");
    while (cs->window_available <= 0)
      if (pthread_cond_wait(&cs->window_cond, &cs->window_mutex) != 0) perror("pthread_cond_wait(window_cond)");

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
    // protect against swapping
    if (pklen <= sizeof(tempkt)) {
      memcpy(tempkt, (u_char *)pkt, pklen);
      if (ncp_debug) printf("NCP sending controlled pkt %#x (%s) ack %#x\n", 
			    ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), ch_ackno(pkt));
      send_chaos_pkt(tempkt, pklen);
      return 1;
    } else if (ncp_debug)
      printf("NCP: packet too long (%d > %lu)\n", pklen, sizeof(tempkt));
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
    set_conn_state(conn, CS_Host_Down, 0);
    // close and die
    user_socket_los(conn, "LOS Host %#o down - no reception for %ld seconds", conn->conn_rhost,
		    now.tv_sec - cs->time_last_received);
  } else if ((cs->state != CS_Open) && (cs->state != CS_Finishing)) {
    // don't send SNS unless conn is open
  } else if ((cs->time_last_received != 0) && (now.tv_sec - cs->time_last_received > LONG_PROBE_INTERVAL)) {
    // haven't received for quite some time, send a SNS probe
    if ((cs->state == CS_Open) || (cs->state == CS_Finishing)) {
      if (ncp_debug) printf("conn %p (%s) hasn't received in %ld seconds, sending SNS\n",
			    conn, conn_state_name(conn),
			    now.tv_sec - cs->time_last_received);
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

static void *
conn_to_packet_stream_handler(void *v)
{
  struct conn *conn = (struct conn *)v;
  struct conn_state *cs = conn->conn_state;
  struct chaos_header *pkt;
  struct timespec retrans, lastsent, now;
  int timedout = 0;
  int qlen = 0;
  int npkts = 0;

  if (conn->conn_type != CT_Stream) {
    fprintf(stderr,"%%%% Bug: conn_to_packet_stream_handler running with non-stream conn\n");
    exit(1);
  }
  timespec_get(&lastsent, TIME_UTC);
  while (1) {
    if (conn->conn_sock == -1) {
      // should have exited already
      // pthread_exit(NULL);
      return NULL;
    }
    // Wait for input to be available to send to network
    PTLOCKN(cs->send_mutex,"send_mutex");
    timespec_get(&retrans, TIME_UTC);
    retrans.tv_nsec += (conn->retransmission_interval)*1000000;
    while (retrans.tv_nsec > 1000000000) {
      retrans.tv_sec++; retrans.tv_nsec -= 1000000000;
    }
    timedout = 0;
    npkts = 0;

    while ((timedout == 0) && ((qlen = pkqueue_length(cs->send_pkts)) == 0))
      timedout = pthread_cond_timedwait(&cs->send_cond, &cs->send_mutex, &retrans);
    
    if (timedout == 0) {
      // get a packet
      pkt = pkqueue_peek_last(cs->send_pkts);
      if (pkt == NULL) pkt = pkqueue_peek_first(cs->send_pkts);
      PTUNLOCKN(cs->send_mutex,"send_mutex");

      if (pkt != NULL) {
	npkts += send_packet_when_window_open(cs, pkt);
      } else if (ncp_debug) {
	printf("NCP: c_t_p triggered w/o timeout (qlen %d) but no pkt?\n", qlen);
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
      perror("pthread_cond_timedwait(conn_to_packet_stream_handler)");
      PTUNLOCKN(cs->send_mutex,"send_mutex");
    }
    // go back wait for another pkt to send
    if ((ncp_debug > 1) && (npkts == 0) && (qlen > 0))
      printf("NCP: tried to send no packets although queue len is %d\n", qlen);
  }
}

//////////////// packet-to-conn network-to-conn

static void
packet_to_conn_simple_handler(struct conn *conn, struct chaos_header *ch)
{
  struct conn_state *cs = conn->conn_state;

  cs->time_last_received = time(NULL);

  // for simple conns, this is quite simple
  fprintf(stderr,"NYI packet_to_conn_simple_handler not really tested.\n");
  exit(1);

  if ((cs->state == CS_Listening) && (ch_opcode(ch) == CHOP_RFC)) {
    // someone wants an answer
    set_conn_state(conn, CS_RFC_Received, 0);
    add_input_pkt(conn, ch);
  } else if ((cs->state == CS_RFC_Sent) && (ch_opcode(ch) == CHOP_ANS)) {
    // this is the answer we wanted
    set_conn_state(conn, CS_Answered, 0);
    add_input_pkt(conn, ch);
  } else if ((cs->state == CS_RFC_Sent) && (ch_opcode(ch) == CHOP_CLS)) {
    set_conn_state(conn, CS_CLS_Received, 0);
    add_input_pkt(conn, ch);
  } else if (ch_opcode(ch) == CHOP_LOS) {
    set_conn_state(conn, CS_LOS_Received, 0);
    add_input_pkt(conn, ch);
  } else {
    // garbage, ignore, complain, log it
    fprintf(stderr,"%%%% Bad pkt in packet_to_conn_simple_handler: opcode %d (%s)\n", ch_opcode(ch), ch_opcode_name(ch_opcode(ch)));
  }
}

// For streams, it's more complex.
// Data for stream has arrived from network (might be DAT, ANS, CLS, UNC, EOF)
// Check window, maybe send an STS if it's full, store data in read_pkts or received_pkts_ooo
// EOF: no data, needs special treatment (see 4.4 end-of-data, but this isn't really what happens)
static void 
receive_data_for_conn(int opcode, struct conn *conn, struct chaos_header *pkt)
{
  u_char *data = (u_char *)pkt;
  u_short *dataw = (u_short *)pkt;
  struct conn_state *cs = conn->conn_state;

  if (packet_uncontrolled(pkt)) {
    // uncontrolled pkts always fit
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
  if ((cs->read_pkts_controlled + pkqueue_length(cs->received_pkts_ooo)) < cs->local_winsize) {
    // it fits
    if (ncp_debug) printf("Receive %s pkt %#x with %d room in window\n",
			  ch_opcode_name(ch_opcode(pkt)), ch_packetno(pkt),
			  cs->local_winsize - (cs->read_pkts_controlled + pkqueue_length(cs->received_pkts_ooo)));
    // Check if it has already been received
    if (pktnum_less(ch_packetno(pkt), cs->pktnum_received_highest) || 
	pktnum_equal(ch_packetno(pkt), cs->pktnum_received_highest)) {
      // Evidence of unnecessary retransmisson, keep other end informed
      if (ncp_debug) printf("Pkt %#x already received (highest %#x)\n", ch_packetno(pkt), cs->pktnum_received_highest);
      if ((cs->state == CS_Open) || (cs->state == CS_Finishing))
	send_sts_pkt(conn);
      return;
    }
    // - add it to read_pkts if it's the next one in order, and collect in-order pkts from received_pkts_ooo
    if (pktnum_equal(ch_packetno(pkt), pktnum_1plus(cs->pktnum_received_highest))) {
      // it was the next expected packet, so add it to the read_pkts
      add_input_pkt(conn, pkt);	// this also updates read_pkts_controlled
      cs->pktnum_received_highest = ch_packetno(pkt);

      // now pick pkts from received_pkts_ooo as long as they are in order
      PTLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
      int expected = pktnum_1plus(ch_packetno(pkt));
      struct chaos_header *p = pkqueue_peek_first(cs->received_pkts_ooo);
      while ((p != NULL) && (pktnum_equal(ch_packetno(p), expected))) {
	p = pkqueue_get_first(cs->received_pkts_ooo);
	expected = pktnum_1plus(ch_packetno(p));
	if (ncp_debug) printf(" moving pkt %#x from OOO to ordered list\n", ch_packetno(p));
	add_input_pkt(conn, p);
	// update the highest received in order pkt for STS
	cs->pktnum_received_highest = ch_packetno(p);
	// add_input_pkt makes a copy, so free this one
	free(p);
	p = pkqueue_peek_first(cs->received_pkts_ooo);
      }
      PTUNLOCKN(cs->received_ooo_mutex,"received_ooo_mutex");
    } else {
      // - or put it in the right place in received_pkts_ooo
      if (ncp_debug) printf(" pkt %#x is OOO (highest is %#x)\n", ch_packetno(pkt), cs->pktnum_received_highest);
      add_ooo_pkt(conn, pkt);
    }
  } else {
    // window full, send STS
    if (ncp_debug) printf("Window is full for pkt %#x, sending STS\n", ch_packetno(pkt));
    send_sts_pkt(conn);
  }
}

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

  if ((ch_ackno(ch) != 0) && (pktnum_less(cs->pktnum_sent_acked, ch_ackno(ch)))) {
    cs->pktnum_sent_acked = ch_ackno(ch);
    // clear out acked pkts from send_pkts
    discard_received_pkts_from_send_list(conn, ch_ackno(ch));
  }
  if (cs->time_last_received == 0) {
    // if this is the first, make sure we realize we haven't already received it
    // @@@@ mmm, but if pkts arrive out-of-order? the first for a conn should always be RFC or OPN.
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
    if (cs->state == CS_RFC_Received) {
      // We got an RFC and sent an OPN, so waiting for this STS
      // - note this state doesn't quite match the homonymous LISPM state
      // Now we are ready to send data!
      set_conn_state(conn, CS_Open, 0);
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
    clear_send_pkts(conn);
    // socket end will finish the conn when pkt reaches it
  }

  // Dispatch based on state and opcode
  // @@@@ major cleanup needed
  switch (cs->state) {
  case CS_Inactive:
    if (ch_opcode(ch) == CHOP_RFC) {
      send_los_pkt(conn, "No such index exists");
      return;
    }
    // @@@@ should not happen
    if (ncp_debug) {
      printf("%%%% p_t_c_stream_h %s pkt received in %s state for %p!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn), conn);
      if (ch_opcode(ch) == CHOP_LOS) {
	u_char buf[CH_PK_MAX_DATALEN];
	if (ch_nbytes(ch) < sizeof(buf)) {
	  ch_11_gets(data, buf, ch_nbytes(ch));
	  buf[ch_nbytes(ch)] = '\0';
	  printf("%%%% LOS: %s\n", buf);
	}
	break;
      }
    }
  case CS_CLS_Received:
  case CS_LOS_Received:
  case CS_Host_Down:
    // @@@@ only allow user to read pkts from read_pkts
    if (ncp_debug) printf("%%%% p_t_c_stream_h %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    return;
  case CS_RFC_Received:				
    // Should only happen for the STS above
    // @@@@ complain
    if (ncp_debug) printf("%%%% p_t_c_stream_h %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    break;
  case CS_Answered:		// should not get pkts (other than retransmitted ANS?)
    if (ch_opcode(ch) != CHOP_ANS) {
      // @@@@ count it?
      if (ncp_debug) printf("%%%% p_t_c_stream_h %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    }
    break;
  case CS_Listening: {
    if (ch_opcode(ch) == CHOP_RFC) {
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      set_conn_state(conn, CS_RFC_Received, 0);
    } else if (ch_opcode(ch) == CHOP_BRD) {
      // @@@@ do something
      fprintf(stderr,"NYI: BRD received, but not implemented yet\n");
    } else
      return;			// ignore
    break;
  }
  case CS_Finishing:
    if ((ch_opcode(ch) == CHOP_CLS) || (ch_opcode(ch) == CHOP_EOF))
      // expected
      return;
    else if (ncp_debug)
      printf("%%%% p_t_c_stream_h %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    break;
  case CS_BRD_Sent:
  case CS_RFC_Sent:
    switch (ch_opcode(ch)) {
    case CHOP_CLS:
      // let user read the reason for close, and nothing more
      set_conn_state(conn, CS_CLS_Received, 0);
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      break;
    case CHOP_ANS:
      // let user read the answer, and nothing more
      // cs->state = CS_Answered;
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
      set_conn_state(conn, CS_Open, 0);
      if (ncp_debug) print_conn("Opened", conn, 1);
      receive_data_for_conn(ch_opcode(ch), conn, ch);
    }
      break;
    }
    break;
  case CS_Open:
    if ((ch_opcode(ch) != CHOP_EOF) && (ch_opcode(ch) != CHOP_LOS) 
	&& (ch_opcode(ch) != CHOP_CLS) && (ch_opcode(ch) < CHOP_DAT)) {
      // note error (we handle STS SNS above)
      if (ncp_debug) printf("%%%% %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
      break;
    }
    // Check window, maybe send an STS if it's full, store data in read_pkts or received_pkts_ooo
    receive_data_for_conn(ch_opcode(ch), conn, ch);
    break;
  case CS_Foreign:
    // @@@@ completely untested
    if (ch_opcode(ch) == CHOP_UNC) {
      receive_data_for_conn(ch_opcode(ch), conn, ch);
      break;
    } else {
      // complain
      if (ncp_debug) printf("%%%% %s pkt received in %s state!\n", ch_opcode_name(ch_opcode(ch)), conn_state_name(conn));
    }
  }
  if (packet_uncontrolled(ch)) { // controlled pkts must fit in window to count
    // Amber: "The packet number field contains sequential numbers in
    // controlled packets; in uncontrolled packets it contains the same
    // number as the next controlled packet will contain."
    // 
    // Clearly not the case, I'd say, given experimental evidence from ITS 1648.
    // Instead, it seems to be vaguely related to the ack field, OR to an old pkt that has been sent already.
#if 0
    // is it the next in order? then update highest received
    if (pktnum_equal(ch_packetno(ch), pktnum_1plus(cs->pktnum_received_highest)))
      cs->pktnum_received_highest = ch_packetno(ch);
#endif
  }
  return;
}


static struct conn *
packet_to_unknown_conn_handler(u_char *pkt, int len, struct chaos_header *ch, u_char *data) 
{
  struct conn *conn = NULL;
  if (ch_opcode(ch) == CHOP_RFC) {
    u_char contact[CH_PK_MAX_DATALEN];
    // @@@@ make a fun fur these two lines
    ch_11_gets(data, contact, ch_nbytes(ch));
    contact[ch_nbytes(ch)] = '\0';
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
    // send LOS: No such connection at this host
    if (ncp_debug) printf("No conn found for %s %#x from <%#o,%#x> for <%#o,%#x>\n",
			  ch_opcode_name(ch_opcode(ch)), ch_packetno(ch),
			  ch_srcaddr(ch),ch_srcindex(ch),ch_destaddr(ch),ch_destindex(ch));
    send_los_pkt(make_temp_conn_from_pkt(ch),"No such index exists");
  } else if (ch_opcode(ch) == CHOP_LOS) {
    // LOS for unknown conn - try to figure out why?
    if (ncp_debug) {
      u_char buf[CH_PK_MAX_DATALEN];
      buf[0] = '\0';
      if (ch_nbytes(ch) < sizeof(buf)) {
	ch_11_gets(data, buf, ch_nbytes(ch));
	buf[ch_nbytes(ch)] = '\0';
      }
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
    packet_to_conn_simple_handler(conn, ch);
    return;
  } else if (conn->conn_type == CT_Stream) {
    packet_to_conn_stream_handler(conn, ch);
    return;
  }
}

//////////////// socket-to-conn

static void
socket_to_conn_simple_handler(struct conn *conn)
{
  int sock = conn->conn_sock;
  int cnt;
  u_char *cname, buf[CH_PK_MAXLEN];

  fprintf(stderr, "NYI socket_to_conn_simple_handler not really tested.\n");
  exit(1);

  memset(buf, 0, CH_PK_MAXLEN);

  if ((cnt = recv(sock, (u_char *)&buf, sizeof(buf), 0)) < 0) {
    if ((errno == EBADF) || (errno == ECONNRESET) || (errno == ETIMEDOUT)) {
      socket_closed_for_simple_conn(conn);
    } else {
      perror("recv(socket_to_conn_simple_handler)");
      exit(1);
    }
  }
  if ((strncasecmp((char *)buf,"LSN ", 4) == 0) && (conn->conn_state->state == CS_Inactive)) {
    cname = parse_contact_name(&buf[4]);
    if (ncp_debug) printf("Simple \"LSN %s\", adding listener\n", cname);
    add_listener(conn, cname);	// also changes state
  } else if ((strncasecmp((char *)buf,"RFC ", 4) == 0) && (conn->conn_state->state == CS_Inactive)) {
    // create conn and send off an RFC pkt
    if (ncp_debug) printf("Simple \"%s\"\n", buf);
    initiate_conn_from_rfc_line(conn,buf,cnt);
  } else if ((strncasecmp((char *)buf, "ANS ", 4) == 0) && (conn->conn_state->state == CS_RFC_Received)) {
    int len = 0;
    u_char *data;
    if ((sscanf((char *)&buf[4],"%d", &len) == 1) && (len > 0)) {
      if (ncp_debug) printf("Simple ANS %d\n", len);
      data = (u_char *)index((char *)&buf[4], '\n');
      if ((data != NULL) && (len + (data-&buf[0]) <= cnt)) {
	data++; // skip newline
	send_ans_pkt(conn, data, len);
      } else {
	// @@@@ return a LOS: bad length
	if (ncp_debug) printf("Simple ANS: bad length %d cnt %d\n", len, cnt);
      }
    } else {
      // @@@@ return a LOS: bad length
      if (ncp_debug) printf("Simple ANS: bad length \"%s\"\n", &buf[4]);
    }
  } else {
    // @@@@ return a LOS to the user: bad request - not RFC or LSN
    fprintf(stderr,"Bad request len %d from simple user in state %s: not RFC, LSN or ANS: %s\n", 
	    cnt, conn_state_name(conn), buf);
    set_conn_state(conn, CS_Inactive, 0);
  }
}

static int 
receive_or_die(struct conn *conn, int sock, u_char *buf, int buflen) 
{
  int cnt;
  if ((cnt = recv(sock, buf, buflen, 0)) < 0) {
    if ((errno == EBADF) || (errno == ECONNRESET) || (errno == ETIMEDOUT)) {
      socket_closed_for_stream_conn(conn);
    } else {
      perror("recv(socket_to_conn_stream_handler)");
      exit(1);
    }
  } else if (cnt == 0) {
    if (ncp_debug) printf("socket_to_conn_stream_handler: read %d bytes, assuming closed\n", cnt);
    socket_closed_for_stream_conn(conn);
  }
  return cnt;
}

void 
get_ans_bytes_and_send(struct conn *conn, int anslen, u_char *buf, int buflen, int cnt)
{
  u_char *nl = (u_char *)index((char *)buf, '\n');
  if (nl != NULL) {
    nl++; // skip \n
    if (cnt-(nl-buf) >= anslen) {
      // the buffer holds the whole ANS data
      send_ans_pkt(conn, nl, anslen);
    } else {
      // read more bytes
      int ncnt = 0;
      u_char *bp = buf+cnt;
      while (cnt-(nl-buf) < anslen) {
	ncnt = receive_or_die(conn, conn->conn_sock, bp, buflen-cnt);
	cnt += ncnt;
	bp += ncnt;
      }
      // read all the rest, use it
      send_ans_pkt(conn, nl, anslen);
    }
  } else {
    user_socket_los(conn, "LOS No newline after ANS length?");
    set_conn_state(conn, CS_Inactive, 0);
  }
}

static void
socket_to_conn_stream_handler(struct conn *conn)
{
  struct conn_state *cs = conn->conn_state;
  int sock = conn->conn_sock;
  int cnt;
  u_char *cname, buf[CH_PK_MAXLEN], pkt[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)pkt;

  memset(buf, 0, CH_PK_MAXLEN);

  cnt = receive_or_die(conn, sock, (u_char *)buf, sizeof(buf));
  if (ncp_debug) printf("socket_to_conn_stream_handler: read %d bytes from %s\n", cnt, conn_sockaddr_path(conn));
  if (cnt < 0)
    return;

  if ((strncasecmp((char *)buf,"LSN ", 4) == 0) && (cs->state == CS_Inactive)) {
    cname = parse_contact_name(&buf[4]);
    if (ncp_debug) printf("Stream \"LSN %s\", adding listener\n", cname);
    add_listener(conn, cname);	// also changes state
  } else if ((strncasecmp((char *)buf,"RFC ", 4) == 0) && (cs->state == CS_Inactive)) {
    // create conn and send off an RFC pkt
    if (ncp_debug) printf("Stream \"%s\"\n", buf);
    initiate_conn_from_rfc_line(conn,buf,cnt);
  }
  else if (((strncasecmp((char *)buf,"OPN ", 4) == 0) 
	    || ((strncasecmp((char *)buf,"OPN", 3) == 0) && ((buf[3] == '\r') || (buf[3] == '\n'))))
	   && (cs->state == CS_RFC_Received)) {
    char *nl = index((char *)buf,'\n');
    int dlen = 0;
    if (nl != NULL) { 
      *nl++ = '\0';
      dlen = strlen(nl+1);
    }
    if (ncp_debug) printf("Stream cmd \"%s\"\n", buf);
    send_opn_pkt(conn);
    if (dlen > 0) {
      if (ncp_debug) printf("Adding extra DATa length %d: \"%.8s\"...\n", dlen, nl);
      send_basic_pkt_with_data(conn, CHOP_DAT, (u_char *)nl, dlen);
    }
  }
  else if ((strncasecmp((char *)buf,"CLS ", 4) == 0) && (cs->state == CS_RFC_Received)) {
    char *eol = index((char *)&buf[4],'\r');
    if (eol == NULL) eol = index((char *)&buf[4], '\n');
    if (eol != NULL) *eol = '\0';
    if (ncp_debug) printf("Stream cmd \"%s\"\n", buf);
    send_cls_pkt(conn, (char *)&buf[4]);
    if (conn->conn_type == CT_Stream)
      finish_stream_conn(conn);
    else
      socket_closed_for_simple_conn(conn);
  }
  else if (((strncasecmp((char *)buf,"ANS ", 4) == 0) 
	    || ((strncasecmp((char *)buf,"ANS", 3) == 0) && ((buf[3] == '\r') || (buf[3] == '\n'))))
	   && (cs->state == CS_RFC_Received)) {
    // @@@@ this is really a Simple protocol then, maybe switch type even if it sort of ends here anyway?
    // conn->conn_type = CT_Simple;
    int anslen = 0;
    if (ncp_debug) printf("Stream cmd \"%s\", switching to Simple\n", buf);
    if (sscanf((char *)&buf[4], "%d", &anslen) == 1) {
      if ((anslen >= 0) && (anslen <= CH_PK_MAX_DATALEN)) {
	get_ans_bytes_and_send(conn, anslen, buf, sizeof(buf), cnt);
      } else {
	user_socket_los(conn, "LOS Bad ANS length %d (should be positive and max %d)", anslen, CH_PK_MAX_DATALEN);
	set_conn_state(conn, CS_Inactive, 0);
      }
    } 
    else user_socket_los(conn,"LOS No length specified in ANS");
  }
  else if ((cs->state == CS_Open) || (cs->state == CS_RFC_Received)) {
    // Just plain data, pack it up and send it. OK if RFC_Received, just queue the data for output.
    // Break it up in packet chunks if necessary
    u_char *bp = buf;
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
#if 1
  // @@@@ shit happens
  else if ((cnt == 2) && (strncmp((char *)buf,"\r\n",2) == 0)) {
    // ignore
    ;
  }
#endif
  else if (cs->state != CS_Inactive) {
    char errbuf[512];
    sprintf(errbuf, "Bad request len %d from stream user in state %s: not RFC, LSN, OPN, CLS, ANS, or wrong state: %s\n", 
	    cnt, conn_state_name(conn), buf);
    fprintf(stderr,"%s\n", errbuf);
    send_los_pkt(conn,"Local error. We apologize for the incovenience.");
    // return a LOS to the user: bad request - not RFC or LSN
    user_socket_los(conn, "LOS %s", errbuf);
    set_conn_state(conn, CS_Inactive, 0);
  }
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
    while (1) {
      socket_to_conn_simple_handler(conn);
      if ((cs->state == CS_Answered) || (cs->state == CS_LOS_Received) || (cs->state == CS_CLS_Received)) {
	// our work is done
	if (ncp_debug) print_conn("Simple done",conn,0);
	// pthread_exit(NULL);
	return NULL;
      }
    }
    break;
  case CT_Stream:
    while (1) {
      socket_to_conn_stream_handler(conn);
      if (0 && (cs->state == CS_Inactive)) {
	if (ncp_debug) print_conn("Stream done",conn,1);
	return NULL;
	// pthread_exit(NULL);
      }
    }
    break;
    // case CT_Binary:
    // for SOCK_SEQPACKET, read actual packets and send them
    // while (1);
  }
}

//////////////// conn-to-socket

static void
conn_to_socket_pkt_handler(struct conn *conn, struct chaos_header *pkt)
{
  struct conn_state *cs = conn->conn_state;
  u_char *pk = (u_char *)pkt;
  u_char *data = &pk[CHAOS_HEADERSIZE];
  char buf[CH_PK_MAXLEN+256];
  int i, len = 0;

  if (conn->conn_type == CT_Stream) {
    // Update state
    if (!packet_uncontrolled(pkt)) {
      if (pktnum_less(cs->pktnum_read_highest, ch_packetno(pkt)))
	cs->pktnum_read_highest = ch_packetno(pkt);
      else if (pktnum_equal(cs->pktnum_read_highest, ch_packetno(pkt))) {
	if (ncp_debug) printf("NCP conn_to_socket_pkt_handler: retransmission of pkt %#x received (highest %#x) - ignoring\n", 
			      ch_packetno(pkt), cs->pktnum_read_highest);
	return;
      } else
	fprintf(stderr,"%%%% Read pkt from read_pkts with unexpected number: highest was %#x, pkt is %#x\n", 
		cs->pktnum_read_highest, ch_packetno(pkt));
    }
  }
  if (((cs->state == CS_Listening) || (cs->state == CS_RFC_Received))
      && (ch_opcode(pkt) == CHOP_RFC)) {
    char fhost[NS_MAXDNAME], args[MAX_CONTACT_NAME_LENGTH], *space;
    len = ch_nbytes(pkt);
    if (dns_name_of_addr(ch_srcaddr(pkt), (u_char *)fhost, sizeof(fhost)) < 0)
      sprintf((char *)fhost, "%#o", ch_srcaddr(pkt));
    // skip contact (listener knows that), just get args
    ch_11_gets(data, (u_char *)args, ch_nbytes(pkt));
    args[ch_nbytes(pkt)] = '\0';
    if (ncp_debug) printf("NCP rfc data: \"%s\"\n", args);
    if ((space = index(args, ' ')) != NULL) 
      sprintf(buf, "RFC %s%s\r\n", fhost, space);
    else
      sprintf(buf, "RFC %s\r\n", fhost);
    len = strlen(buf);
    if (ncp_debug) printf("To socket %s (%d bytes): %s", conn_sockaddr_path(conn), len, buf);
    set_conn_state(conn, CS_RFC_Received, 0);
  } else if ((cs->state == CS_RFC_Sent) && (ch_opcode(pkt) == CHOP_ANS)) {
    sprintf(buf, "ANS %d\r\n", ch_nbytes(pkt));
    if (ncp_debug) printf("To socket %s: %s", conn_sockaddr_path(conn), buf);
    len = strlen(buf);
    // might be non-string data
    ntohs_buf((u_short *)data, (u_short *)&buf[len], ch_nbytes(pkt));
    // memcpy(&buf[len], data, ch_nbytes(pkt));
    len += ch_nbytes(pkt);
    set_conn_state(conn, CS_Answered, 0);
  } else if (ch_opcode(pkt) == CHOP_OPN) {
    sprintf(buf, "OPN Connection to host %#o opened\r\n", ch_srcaddr(pkt));
    if (ncp_debug) printf("To socket %s: %s", conn_sockaddr_path(conn), buf);
    len = strlen(buf);
  } else if ((ch_opcode(pkt) == CHOP_LOS) || (ch_opcode(pkt) == CHOP_CLS)) {
    if (ncp_debug) printf("NCP conn_to_socket_pkt_handler state %s: CLS/LOS data length %d\n", 
			  conn_state_name(conn), ch_nbytes(pkt));
    sprintf(buf, "%s ", ch_opcode_name(ch_opcode(pkt)));
    ch_11_gets(data, (u_char *)&buf[4], ch_nbytes(pkt));
    buf[4+ch_nbytes(pkt)] = '\0';
    strcat(buf, "\r\n");
    len = 4+ch_nbytes(pkt)+2; // strlen(buf);
    if (ncp_debug) printf("To socket %s (len %d): %s\n", conn_sockaddr_path(conn), len, buf);
    if (ch_opcode(pkt) == CHOP_LOS) set_conn_state(conn, CS_LOS_Received, 0);
    else if (ch_opcode(pkt) == CHOP_CLS) {
      if (cs->state == CS_Open) { // this is the expected way to close
	if (ncp_debug) printf("CLS received in Open state, no message to user socket\n");
	len = 0;
      }
      set_conn_state(conn, CS_CLS_Received, 0);
    }
  } else if ((ch_opcode(pkt) == CHOP_EOF) && (cs->state == CS_Open)) {
    finish_stream_conn(conn);
  } else if ((ch_opcode(pkt) >= CHOP_DAT) && (ch_opcode(pkt) < CHOP_DWD)) {
    ntohs_buf((u_short *)data, (u_short *)buf, ch_nbytes(pkt));
    len = ch_nbytes(pkt);
    // @@@@ please also handle CHOP_DWD?
  } else {
    fprintf(stderr,"%%%% Bad pkt in conn_to_socket_pkt_handler: pkt %#x opcode %s in state %s, highest %#x\n",
	    ch_packetno(pkt), ch_opcode_name(ch_opcode(pkt)), state_name(cs->state),
	    cs->pktnum_received_highest);
    print_conn("%% ", conn, 1);
  }

  if (len > 0) {	     // Something to write to the user socket?
    if (write(conn->conn_sock, buf, len) < 0) {
      if ((errno == ECONNRESET) || (errno == EPIPE)) {
	if (conn->conn_type == CT_Simple)
	  socket_closed_for_simple_conn(conn);
	else if (conn->conn_type == CT_Stream)
	  socket_closed_for_stream_conn(conn);
      } else {
	perror("write(conn_to_socket_pkt_handler)");
	exit(1);
      }
    }
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
	finish_stream_conn(conn);
      }
      break;
      //case CT_Binary:
      // For SOCK_SEQPACKET, write actual packets
      // fprintf(stderr,"NYI binary streams\n");
    }
  }
}

//////////////// utility

static void 
start_conn(struct conn *conn)
{
  if (pthread_create(&conn->conn_to_sock_thread, NULL, &conn_to_socket_handler, conn) < 0) {
    perror("pthread_create(conn user read handler)");
    exit(1);
  }
  if (pthread_create(&conn->conn_from_sock_thread, NULL, &socket_to_conn_handler, conn) < 0) {
    perror("pthread_create(conn user write handler)");
    exit(1);
  }
  if (conn->conn_type == CT_Stream) {
    if (pthread_create(&conn->conn_to_net_thread, NULL, &conn_to_packet_stream_handler, conn) < 0) {
      perror("pthread_create(conn_to_packet_stream_handler)");
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
