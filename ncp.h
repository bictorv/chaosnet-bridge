/* Copyright © 2005, 2017-2020 Björn Victor (bjorn@victor.se) */
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

// Oh well, I guess we have to accept this in the name of Backwards Compatibilty
#define MAX_WINSIZE 0200	// 128 x 488 = 62464, i.e. 61k bytes
// Lambda value: should be configurable
#define DEFAULT_WINSIZE 015	// 6344b, just over 6k

#define CONNECTION_TIMEOUT 30  // seconds

// Lambda values: should be configurable
#define DEFAULT_RETRANSMISSION_INTERVAL 500 // ms
#define PROBE_INTERVAL 10 // s
#define LONG_PROBE_INTERVAL 60 // s
#define HOST_DOWN_INTERVAL 300 // s = 5 min

// Conn types
typedef enum conntype {
  CT_Simple,			/* RFC-ANS type */
  CT_Stream,			/* Unstructured stream */
  // NYI  CT_Binary,			/* Packet-oriented stream */
} conntype_t;

// Conn states
typedef enum connstate {
  CS_Inactive,
  CS_Answered,
  CS_CLS_Received,
  CS_Listening,
  CS_RFC_Received,
  CS_RFC_Sent,
  CS_Open,
  CS_LOS_Received,
  CS_Host_Down,
  CS_Foreign,
  CS_BRD_Sent,
  CS_Finishing, // not in Amber or Lispm code
} connstate_t;

// state parts of conn
struct conn_state {
  connstate_t state;
  pthread_mutex_t conn_state_lock;
  u_short pktnum_made_highest;

  u_short local_winsize;
  u_short foreign_winsize;
  u_short window_available; // for sending, before it's full
  pthread_mutex_t window_mutex; // make sure there is room in window before adding to send_pkts
  pthread_cond_t window_cond;

  struct pkqueue *read_pkts; // available for user to read
  int read_pkts_controlled;  // nr of controlled pkts in read_pkts, for window calculation
  pthread_mutex_t read_mutex; // to tell conn there are things in it
  pthread_cond_t read_cond;
  struct pkqueue *received_pkts_ooo; // received, out of order (need to add to read_pkts when preceding in-order pkt arrives)
  pthread_mutex_t received_ooo_mutex;
  u_short pktnum_read_highest; // given to user, next ack
  u_short pktnum_received_highest; // highest num on read_pkts, for STS
  u_short pktnum_acked; // actually acked
  struct pkqueue *send_pkts; // packets to send
  u_short send_pkts_pktnum_highest; // highest controlled pkt nr 
  pthread_mutex_t send_mutex; // to tell network there are things to send
  pthread_cond_t send_cond;
  u_short pktnum_sent_highest;
  u_short pktnum_sent_acked; // last we got ack for
  time_t time_last_received; // for probing
};

// static parts
struct conn {
  conntype_t conn_type;
  pthread_mutex_t conn_lock;
  time_t conn_created;
  int conn_sock; // unix socket
  struct sockaddr_un conn_sockaddr; // to sendto
  struct conn_state *conn_state;
  u_char *conn_contact;
  u_char *conn_contact_args;
  u_short conn_rhost;
  u_short conn_ridx;
  u_short conn_lhost;
  u_short conn_lidx;
  u_int retransmission_interval; // msec
  pthread_t conn_to_sock_thread;	 // conn_to_socket
  pthread_t conn_from_sock_thread;	 // socket_to_conn
  pthread_t conn_to_net_thread;	 // conn_to_packet (only for stream)
};

struct conn_list {
  struct conn *conn_conn;
  struct conn_list *conn_prev;
  struct conn_list *conn_next;
};

struct listener {
  u_char *lsn_contact;		// contact name
  struct conn *lsn_conn;	// conn to handle an RFC
  struct listener *lsn_prev;
  struct listener *lsn_next;
};
