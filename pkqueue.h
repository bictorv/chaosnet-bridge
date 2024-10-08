/* Copyright © 2020 Björn Victor (bjorn@victor.se) */
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

// Packet queue implementation

#include <pthread.h>
#include <time.h>

struct pkt_elem {
  struct chaos_header *pkt;
  struct timespec transmitted;		// when it was last transmitted
  struct pkt_elem *next;
};

struct pkqueue {
  pthread_mutex_t pkq_mutex;
  int pkq_len;
  struct pkt_elem *first;
  struct pkt_elem *last;
};

void print_pkqueue(struct pkqueue *q);
struct pkqueue *make_pkqueue(void);
void free_pkqueue(struct pkqueue *q);
struct pkt_elem *pkqueue_add(struct chaos_header *pkt, struct pkqueue *q);
int pkqueue_insert_by_packetno(struct chaos_header *pkt, struct pkqueue *q);
struct chaos_header *pkqueue_get_first(struct pkqueue *q);
struct chaos_header *pkqueue_peek_first(struct pkqueue *q);
struct pkt_elem *pkqueue_peek_first_elem(struct pkqueue *q);
struct chaos_header *pkqueue_peek_last(struct pkqueue *q);
struct pkt_elem *pkqueue_first_elem(struct pkqueue *q);
struct pkt_elem *pkqueue_next_elem(struct pkt_elem *e);
struct chaos_header *pkqueue_elem_pkt(struct pkt_elem *e);
struct timespec *pkqueue_elem_transmitted(struct pkt_elem *e);
void set_pkqueue_elem_transmitted(struct pkt_elem *e, struct timespec *ts);
int pkqueue_length(struct pkqueue *q);
struct pkt_elem *pkqueue_unlink_pkt_elem(struct pkt_elem *elem, struct pkt_elem *prev, struct pkqueue *queue);
