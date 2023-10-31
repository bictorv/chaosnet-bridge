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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

// ncp.c
int pktnum_less(u_short a, u_short b);
int pktnum_equal(u_short a, u_short b);

#include "cbridge.h"
#include "pkqueue.h"

// cf https://gist.github.com/diabloneo/9619917?permalink_comment_id=3364033#gistcomment-3364033
static inline void timespec_diff(struct timespec *a, struct timespec *b,
    struct timespec *result) {
    result->tv_sec  = a->tv_sec  - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

static void
print_pkqueue_holding_lock(struct pkqueue *q)
{
  struct pkt_elem *e;
  int nelem = 0;
  struct timespec now, diff;
  timespec_get(&now, TIME_UTC);

  if (q == NULL) { printf("#<pkq NULL>\n"); return; }
  printf("#<pkq %p len %d first %p last %p", q, q->pkq_len, q->first, q->last);
  
  for (e = q->first; e != NULL; e = e->next) {
    nelem++;
    printf("\n elem %p ", e);
    if (e->pkt != NULL) {
      timespec_diff(&now,&e->transmitted, &diff);
      printf("%s pkt %#x nbytes %d trans %f ago", ch_opcode_name(ch_opcode(e->pkt)), ch_packetno(e->pkt),
	     ch_nbytes(e->pkt), diff.tv_sec + (float)(diff.tv_nsec)/(float)1000000000);
    }
    else
      printf("NULL");
  }
  printf(">\n");
  if (nelem != q->pkq_len) {
    printf("PKQ: number of elements printed: %d differs from pkq_len %d\n",
	   nelem, q->pkq_len);
  }
}


void
print_pkqueue(struct pkqueue *q)
{
  PTLOCKN(q->pkq_mutex,"pkq_mutex");
  print_pkqueue_holding_lock(q);
  PTUNLOCKN(q->pkq_mutex,"pkq_mutex");
}

struct pkqueue *
make_pkqueue(void)
{
  struct pkqueue *q = (struct pkqueue *)malloc(sizeof(struct pkqueue));
  if (pthread_mutex_init(&q->pkq_mutex, NULL) != 0)
    perror("pthread_mutex_init(pkq_mutex)");
  q->pkq_len = 0;
  q->first = q->last = NULL;
  return q;
}

void
free_pkqueue(struct pkqueue *q)
{
  struct pkt_elem *p = NULL, *e;

  PTLOCKN(q->pkq_mutex,"pkq_mutex");
  
  for (e = q->first; e != NULL; e = e->next) {
    free(e->pkt);
    if (p != NULL) 
      free(p);
    p = e;
  }
  if (p != NULL)
    free(p);

  PTUNLOCKN(q->pkq_mutex,"pkq_mutex");
  pthread_mutex_destroy(&q->pkq_mutex);
  free(q);
}

int // returns new length
pkqueue_add(struct chaos_header *pkt, struct pkqueue *q)
{
  struct pkt_elem *ql = NULL, *nl;
  
  PTLOCKN(q->pkq_mutex,"pkq_mutex");

  ql = q->last;			// last in queue
  // consistency checks
  if (ql != NULL) {		// non-empty queue
    assert(ql->next == NULL);	// last elem has no cdr
  } else {
    assert(q->pkq_len == 0);	// empty: zero length
    assert(q->first == NULL);	// last NULL => first NULL
  }
  // make new element
  nl = (struct pkt_elem *)malloc(sizeof(struct pkt_elem)); // new last
  if (nl == NULL) {
    perror("malloc(pkt_elem)"); exit(1);
  }
  nl->pkt = pkt;
  nl->transmitted.tv_sec = 0;
  nl->transmitted.tv_nsec = 0;
  nl->next = NULL;

  if (ql != NULL)
    // append new element
    ql->next = nl;
  else {
    // queue was empty
    // assert((q->first == NULL) && (q->pkq_len == 0));
    // length 1: first and last the same
    q->first = nl;
  }
  // now put the new element last
  q->last = nl;
  // we added one
  q->pkq_len++;
  int len = q->pkq_len;
  PTUNLOCKN(q->pkq_mutex,"pkq_mutex");

  return len;
}
int // returns some interesting number
pkqueue_insert_by_packetno(struct chaos_header *pkt, struct pkqueue *q)
{
  struct pkt_elem *l, *ql = NULL, *nl, *pl;

  PTLOCKN(q->pkq_mutex,"pkq_mutex");

  nl = (struct pkt_elem *)malloc(sizeof(struct pkt_elem)); // new last
  if (nl == NULL) {
    perror("malloc(pkt_elem)"); exit(1);
  }
  nl->pkt = pkt;
  nl->transmitted.tv_sec = 0;
  nl->transmitted.tv_nsec = 0;
  nl->next = NULL;
  if (q->first == NULL) {
    // optimization: see if q was empty
    assert(q->last == NULL);
    assert(q->pkq_len == 0);
    q->first = nl; 
    q->last = nl;
    q->pkq_len = 1;
  } else if ((q->last != NULL) && (q->last->pkt != NULL) && (pktnum_less(ch_packetno(q->last->pkt), ch_packetno(pkt)))) {
  // optimization: see if it goes last
    // @@@@ add pkt last
    nl->next = NULL;
    ql = q->last;
    ql->next = nl;
    q->last = nl;
    q->pkq_len++;
  } else {
    // scan for the right place
    for (pl = NULL, l = q->first; (l != NULL) && (l->pkt != NULL) && (pktnum_less(ch_packetno(l->pkt), ch_packetno(pkt))); l = l->next) 
      // previous
      pl = l;
    if (pl == NULL) {
      // insert first
      nl->next = q->first;
      q->first = nl;
      q->pkq_len++;
    } else {
      // insert after previous
      // @@@@ assert(pl->next == l)
      nl->next = l;
      pl->next = nl;
      q->pkq_len++;
    }
  }

  int len = q->pkq_len;
  PTUNLOCKN(q->pkq_mutex,"pkq_mutex");

  return len;
}

// get and remove first
struct chaos_header *
pkqueue_get_first(struct pkqueue *q)
{
  if ((q == NULL) || (q->first == NULL))
    return NULL;
  PTLOCKN(q->pkq_mutex,"pkq_mutex");

  struct pkt_elem *f = q->first;
  struct chaos_header *p = f->pkt;
  q->first = f->next;
  q->pkq_len--;
  if (q->first == NULL) {
    q->last = NULL;
    // assert(q->pkq_len == 0);
    if (q->pkq_len != 0) {
      printf("PKQ: unexpected length %d\n", q->pkq_len);
      print_pkqueue_holding_lock(q);
      abort();
    }
  }
  free(f);
  PTUNLOCKN(q->pkq_mutex,"pkq_mutex");

  return p;
}
struct chaos_header *
pkqueue_peek_first(struct pkqueue *q)
{
  if ((q == NULL) || (q->first == NULL))
    return NULL;
  else
    return q->first->pkt;
}
struct pkt_elem *
pkqueue_peek_first_elem(struct pkqueue *q)
{
  if ((q == NULL) || (q->first == NULL))
    return NULL;
  else
    return q->first;
}
struct chaos_header *
pkqueue_peek_last(struct pkqueue *q)
{
  if ((q == NULL) || (q->last == NULL))
    return NULL;
  else
    return q->last->pkt;
}
struct chaos_header *
pkqueue_peek_next(struct pkqueue *q)
{
  if ((q == NULL) || (q->first == NULL))
    return NULL;
  else
    return q->first->next->pkt;
}
struct pkt_elem *
pkqueue_first_elem(struct pkqueue *q)
{
  if (q != NULL)
    return q->first;
  else
    return NULL;
}
struct pkt_elem *
pkqueue_next_elem(struct pkt_elem *e)
{
  if (e != NULL)
    return e->next;
  else
    return NULL;
}
struct chaos_header *
pkqueue_elem_pkt(struct pkt_elem *e)
{
  if (e != NULL)
    return e->pkt;
  else
    return NULL;
}
struct timespec *
pkqueue_elem_transmitted(struct pkt_elem *e)
{
  if (e != NULL)
    return &e->transmitted;
  else
    return NULL;
}
int
pkqueue_length(struct pkqueue *q)
{
  return q->pkq_len;
}
void
set_pkqueue_elem_transmitted(struct pkt_elem *e, struct timespec *ts)
{
  e->transmitted.tv_sec = ts->tv_sec;
  e->transmitted.tv_nsec = ts->tv_nsec;
}
