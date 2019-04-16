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

extern u_short tls_myaddr;
extern char tls_ca_file[];
extern char tls_key_file[];
extern char tls_cert_file[];
extern int do_tls_ipv6;
extern int tls_server_port;
extern int tls_debug;

static int tls_tcp_ursock;		/* ur-socket to listen on (for server end) */

static int tls_write_record(struct tls_dest *td, u_char *buf, int len);
static void tls_inform_tcp_is_open(struct tls_dest *td);
static void tls_wait_for_reconnect_signal(struct tls_dest *td);

// send an empty SNS packet, just to let the other (server) end know our Chaos address and set up the route
void
send_empty_sns(struct tls_dest *td)
{
  u_char pkt[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)pkt;
  u_short src = (tls_myaddr > 0 ? tls_myaddr : mychaddr[0]);  // default
  u_short dst = td->tls_addr;
  int i;

  struct chroute *rt = find_in_routing_table(dst, 1, 0);
  if (rt == NULL) {
    if (tls_debug) fprintf(stderr,"Can't send SNS to %#o - no route found!\n", dst);
    return;
  } else
    if (rt->rt_myaddr > 0)
      src = rt->rt_myaddr;

  if (verbose || debug || tls_debug) 
    fprintf(stderr,"Sending SNS from %#o to %#o\n", src, dst);

  memset(pkt, 0, sizeof(pkt));
  set_ch_opcode(ch, CHOP_SNS);
  set_ch_destaddr(ch, dst);
  set_ch_srcaddr(ch, src);
  set_ch_nbytes(ch, 0);

  send_chaos_pkt((u_char *)ch, ch_nbytes(ch)+CHAOS_HEADERSIZE);
}

// One server thread which listens for new connections,
// Client links: connect and wait for writers to ask for re-connection.
// One input thread which selects on all tls_sock fields.
// For input thread and for writers (through forward_on_link)
// - If error on client link, ask for re-connection
// - If error on server link, close/disable it (and wait for client to reconnect)
// @@@@ Probably tons of memory leaks in SSL library.
// @@@@ try mtrace()?

// See https://wiki.openssl.org/index.php/Simple_TLS_Server,
//     https://github.com/CloudFundoo/SSL-TLS-clientserver

void init_openssl()
{ 
  SSL_library_init();
  SSL_load_error_strings();	
  OpenSSL_add_ssl_algorithms();
}

// not used
static void cleanup_openssl()
{
    EVP_cleanup();
}

static u_char *
tls_get_cert_cn(X509 *cert)
{
  // see https://github.com/iSECPartners/ssl-conservatory/blob/master/openssl/openssl_hostname_validation.c
  int common_name_loc = -1, subj_alt_name_loc = -1;
  X509_NAME_ENTRY *common_name_entry = NULL, *subj_alt_name_entry = NULL;
  ASN1_STRING *common_name_asn1 = NULL, *subj_alt_name_asn1 = NULL;
  char *common_name_str = NULL, *subj_alt_name_str = NULL;

  // Find the position of the CN field in the Subject field of the certificate
  common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) cert), NID_commonName, -1);
  if (common_name_loc < 0) {
    if (tls_debug)
      fprintf(stderr,"TLS get_cert_cn: can't find CN");
    return NULL;
  }

  // Extract the CN field
  common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) cert), common_name_loc);
  if (common_name_entry == NULL) {
    if (tls_debug)
      fprintf(stderr,"TLS get_cert_cn: can't extract CN");
    return NULL;
  }

  // Convert the CN field to a C string
  common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
  if (common_name_asn1 == NULL) {
    if (tls_debug)
      fprintf(stderr,"TLS get_cert_cn: can't convert CN to C string");
    return NULL;
  }			
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  common_name_str = (char *) ASN1_STRING_data(common_name_asn1);
#else
  common_name_str = (char *) ASN1_STRING_get0_data(common_name_asn1);
#endif
  // Make sure there isn't an embedded NUL character in the CN
  if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
    if (tls_debug)
      fprintf(stderr,"TLS get_cert_cn: malformed CN (NUL in CN)\n");
    return NULL; // MalformedCertificate;
  }
  return (u_char *)common_name_str;
}

static SSL_CTX *tls_create_some_context(const SSL_METHOD *method)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

static SSL_CTX *tls_create_client_context()
{
  const SSL_METHOD *method;

    method = SSLv23_client_method();
    return tls_create_some_context(method);
}

static SSL_CTX *tls_create_server_context()
{
   const SSL_METHOD *method;
    method = SSLv23_server_method();
    return tls_create_some_context(method);
}

static void tls_configure_context(SSL_CTX *ctx)
{
  // Auto-select elliptic curve
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(ctx, 1);
#endif

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, tls_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, tls_key_file, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
    // Check key and cert
    if (SSL_CTX_check_private_key(ctx) != 1) {
      fprintf(stderr,"Private key and certificate do not match\n");
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    // Load CA cert chain
    if (!SSL_CTX_load_verify_locations(ctx, tls_ca_file, NULL)) {
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
    // Make sure to verify the peer (both server and client)
    // Consider adding a callback to validate CN/subjectAltName?
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // go up to "higher level CA"
    SSL_CTX_set_verify_depth(ctx, 2);
}


// Routes, tlsdest etc

void print_tlsdest_config()
{
  int i;
  char ip[INET6_ADDRSTRLEN];
  PTLOCK(tlsdest_lock);
  printf("TLS destination config: %d links\n", tlsdest_len);
  for (i = 0; i < tlsdest_len; i++) {
    if (tlsdest[i].tls_sa.tls_saddr.sa_family != 0) {
      ip46_ntoa(&tlsdest[i].tls_sa.tls_saddr, ip, sizeof(ip));
    } else
      strcpy(ip, "[none]");
    printf(" dest %#o, name %s, ",
	   tlsdest[i].tls_addr, 
	   tlsdest[i].tls_name);
    if (tlsdest[i].tls_serverp) printf("(server) ");
    printf("host %s port %d\n",
	   ip,
	   ntohs((tlsdest[i].tls_sa.tls_saddr.sa_family == AF_INET
		  ? tlsdest[i].tls_sa.tls_sin.sin_port
		  : tlsdest[i].tls_sa.tls_sin6.sin6_port)));
  }
  PTUNLOCK(tlsdest_lock);
}

// Should only be called by server (clients have their routes set up by config)
static struct chroute *
add_tls_route(int tindex, u_short srcaddr)
{
  struct chroute * srcrt = NULL;
  PTLOCK(rttbl_lock);
  // find any old entry (only host route, also nopath)
  srcrt = find_in_routing_table(srcaddr, 1, 1);
  if (srcrt != NULL) {
    // old route exists
    if (tls_debug) fprintf(stderr,"TLS: Old %s route to %#o found (type %s), updating to TLS Dynamic\n",
			   rt_linkname(srcrt->rt_link), srcaddr, rt_typename(srcrt->rt_type));
    // @@@@ tear down any other link?
    srcrt->rt_link = LINK_TLS;
    srcrt->rt_type = RT_DYNAMIC;
    srcrt->rt_cost = RTCOST_ASYNCH;
    srcrt->rt_cost_updated = time(NULL);
  } else {
    // make a routing entry for host srcaddr through tls link at tlsindex
    srcrt = add_to_routing_table(srcaddr, 0, tls_myaddr, RT_DYNAMIC, LINK_TLS, RTCOST_ASYNCH);
  }
  PTUNLOCK(rttbl_lock);
  PTLOCK(tlsdest_lock);
  if ((tlsdest[tindex].tls_addr != 0) && (tlsdest[tindex].tls_addr != srcaddr))
    fprintf(stderr,"%%%% TLS link %d chaos address already known (%#o) but route not found - updating to %#o\n",
	    tindex, tlsdest[tindex].tls_addr, srcaddr);
  if (tls_debug) fprintf(stderr,"TLS route addition updates tlsdest addr from %#o to %#o\n", tlsdest[tindex].tls_addr, srcaddr);
  tlsdest[tindex].tls_addr = srcaddr;
  PTUNLOCK(tlsdest_lock);
  return srcrt;
}

static void
close_tlsdest(struct tls_dest *td)
{
  PTLOCK(tlsdest_lock);
  if (td->tls_serverp) {
    // forget remote sockaddr
    memset((void *)&td->tls_sa.tls_saddr, 0, sizeof(td->tls_sa.tls_saddr));
    // forget remote chaos addr
    td->tls_addr = 0;
  }
  if (td->tls_ssl != NULL) {
    SSL_free(td->tls_ssl);
    td->tls_ssl = NULL;
  }
  if (td->tls_sock != 0) {
    close(td->tls_sock);
    td->tls_sock = 0;
  }
  PTUNLOCK(tlsdest_lock);
}

void
close_tls_route(struct chroute *rt) 
{
  int i;
  struct tls_dest *td = NULL;
  if ((rt->rt_link == LINK_TLS) && (rt->rt_type != RT_NOPATH)) {
    PTLOCK(tlsdest_lock);
    for (i = 0; i < tlsdest_len; i++) {
      if (tlsdest[i].tls_addr == rt->rt_braddr) {
	td = &tlsdest[i];
	break;
      }
    }
    PTUNLOCK(tlsdest_lock);
    if (td != NULL) {
      if (tls_debug) fprintf(stderr,"TLS: closing link to bridge addr %#o\n", rt->rt_braddr);
      close_tlsdest(td);
    } else if (tls_debug) fprintf(stderr,"%%%% TLS: can't find TLS link to bridge addr %#o to close\n", rt->rt_braddr);
  } else
    fprintf(stderr,"%%%% TLS: asked to close TLS link to bridge addr %#o which is link %s type %s\n", rt->rt_braddr,
	    rt_linkname(rt->rt_link), rt_typename(rt->rt_type));
}

static void
update_client_tlsdest(struct tls_dest *td, u_char *server_cn, int tsock, SSL *ssl)
{
  // defining the client link adds the tlsdest entry, but need to fill in and initialize mutex/conds

  // fill in tls_name, tls_sock, tls_ssl
  PTLOCK(tlsdest_lock);
#if 0
  // don't - we need the "IP name" of the server
  if (server_cn != NULL)
    strncpy(td->tls_name, (char *)server_cn, TLSDEST_NAME_LEN);
#endif
  td->tls_serverp = 0;
  td->tls_sock = tsock;
  td->tls_ssl = ssl;

  // initiate these
  if (pthread_mutex_init(&td->tcp_is_open_mutex, NULL) != 0)
    perror("pthread_mutex_init(update_client_tlsdest)");
  if (pthread_cond_init(&td->tcp_is_open_cond, NULL) != 0)
    perror("pthread_cond_init(update_client_tlsdest)");
  if (pthread_mutex_init(&td->tcp_reconnect_mutex, NULL) != 0)
    perror("pthread_mutex_init(update_client_tlsdest)");
  if (pthread_cond_init(&td->tcp_reconnect_cond, NULL) != 0)
    perror("pthread_cond_init(update_client_tlsdest)");
  
  PTUNLOCK(tlsdest_lock);
}


static void
add_server_tlsdest(u_char *name, int sock, SSL *ssl, struct sockaddr *sa, int sa_len, u_short chaddr)
{
  // no tlsdest exists for server end, until it is connected
  struct tls_dest *td = NULL;

  PTLOCK(tlsdest_lock);
  // look for name in tlsdest and reuse entry if it is closed
  int i;
  for (i = 0; i < tlsdest_len; i++) {
    if ((tlsdest[i].tls_name[0] != '\0') && tlsdest[i].tls_serverp && (strncmp(tlsdest[i].tls_name, (char *)name, TLSDEST_NAME_LEN) == 0)) {
      td = &tlsdest[i];
      break;
    }
  }
  if (td != NULL) {
    if (tls_debug) fprintf(stderr,"Reusing tlsdest for %s\n", name);
    // update sock and ssl
    td->tls_sock = sock;
    td->tls_ssl = ssl;
    // get sockaddr
    memcpy((void *)&td->tls_sa.tls_saddr, sa, sa_len);
  } else {
    // crete a new entry
    if (tlsdest_len >= TLSDEST_MAX) {
      PTUNLOCK(tlsdest_lock);
      fprintf(stderr,"%%%% tlsdest is full! Increase TLSDEST_MAX\n");
      return;
    }
    if (tls_debug) {
      char ip6[INET6_ADDRSTRLEN];
      fprintf(stderr,"Adding new TLS destination %s from %s port %d chaddr %#o\n", name,
	      ip46_ntoa(sa, ip6, sizeof(ip6)),
	      ntohs((sa->sa_family == AF_INET
		     ? ((struct sockaddr_in *)sa)->sin_port
		     : ((struct sockaddr_in6 *)sa)->sin6_port)),
	      chaddr);
    }

    memset(&tlsdest[tlsdest_len], 0, sizeof(struct tls_dest));
    // get sockaddr
    memcpy(&tlsdest[tlsdest_len].tls_sa, sa, sa_len);
    if (name != NULL)
      strncpy((char *)&tlsdest[tlsdest_len].tls_name, (char *)name, TLSDEST_NAME_LEN);
    tlsdest[tlsdest_len].tls_serverp = 1;
    tlsdest[tlsdest_len].tls_sock = sock;
    tlsdest[tlsdest_len].tls_ssl = ssl;
    tlsdest[tlsdest_len].tls_addr = chaddr;

    tlsdest_len++;
  }
  PTUNLOCK(tlsdest_lock);
  if (verbose) print_tlsdest_config();

  // add route when first pkt comes in, see tls_input
}

// TCP low-level things
static int tcp_server_accept(int sock, struct sockaddr_storage *saddr, u_int *sa_len)
{
  struct sockaddr_storage caddr;
  int fd;
  u_int clen = sizeof(caddr);
  u_int *slen = &clen;
  struct sockaddr *sa = (struct sockaddr *)&caddr;

  if ((saddr != NULL) && (*sa_len != 0)) {
    // fill in sockaddr
    sa = (struct sockaddr *)saddr;
    slen = sa_len;
  }


  if ((fd = accept(sock, (struct sockaddr *)sa, slen)) < 0) {
    perror("accept");
    fprintf(stderr,"errno = %d\n", errno);
    // @@@@ better error handling, back off and try again? what could go wrong here?
    exit(1);
  }
  // @@@@ log stuff about the connection?
  if (tls_debug) {
    char ip6[INET6_ADDRSTRLEN];
    fprintf(stderr,"TCP accept connection from %s port %d\n", ip46_ntoa(sa, ip6, sizeof(ip6)),
	    ntohs((sa->sa_family == AF_INET
		   ? ((struct sockaddr_in *)sa)->sin_port
		   : ((struct sockaddr_in6 *)sa)->sin6_port)));
  }
  return fd;
}

static int tcp_bind_socket(int type, u_short port) 
{
  int sock;

  if ((sock = socket(do_tls_ipv6 ? AF_INET6 : AF_INET, type, 0)) < 0) {
    perror("socket (TCP) failed");
    exit(1);
  }
  // @@@@ SO_REUSEADDR or SO_REUSEPORT
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
    perror("setsockopt(SO_REUSEADDR)");

  if (tls_debug)
    fprintf(stderr,"binding socket type %d (%s), %s, to port %d\n", 
	     type, (type == SOCK_DGRAM ? "dgram" : (type == SOCK_STREAM ? "stream" : "?")),
	    do_tls_ipv6 ? "IPv6" : "IPv4",
	     port);
  if (do_tls_ipv6) {
    struct sockaddr_in6 sin6;
#if 0
    // For TLS, allow both IPv4 and IPv6
    int one = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0)
      perror("setsockopt(IPV6_V6ONLY)");
#endif
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    memcpy(&sin6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
    if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
      perror("bind(v6) failed");
      exit(1);
    }
  } else {
    struct sockaddr_in sin;
    memset(&sin,0,sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock,(struct sockaddr *)&sin, sizeof(sin)) < 0) {
      perror("bind() failed");
      exit(1);
    }
  }
  return sock;
}

// TCP connector, with backoff
static int tcp_client_connect(struct sockaddr *sin)
{
  int sock, unlucky = 1, foo;
  
  while (unlucky) {
    if (tls_debug) fprintf(stderr,"TCP connect: socket family %d (%s)\n",
			   sin->sa_family,
			   (sin->sa_family == AF_INET ? "IPv4" :
			    (sin->sa_family == AF_INET6 ? "IPv6" : "??")));
    if ((sock = socket(sin->sa_family, SOCK_STREAM, 0)) < 0) {
      perror("socket(tcp)");
      exit(1);
    }

    if (tls_debug) {
      char ip[INET6_ADDRSTRLEN];
      fprintf(stderr,"TCP connect: connecting to %s port %d\n", ip46_ntoa(sin, ip, sizeof(ip)),
	      ntohs((sin->sa_family == AF_INET
		     ? ((struct sockaddr_in *)sin)->sin_port
		     : ((struct sockaddr_in6 *)sin)->sin6_port)));
    }

    if (connect(sock, sin, (sin->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) < 0) {
      if (tls_debug) {
	perror("connect (tcp)");
	fprintf(stderr,"connect errno %d\n", errno);
      }
      // back off and try again - the other end might be down
      if (tls_debug)
	fprintf(stderr,"TCP connect: trying again in %d s\n", unlucky);
      if ((foo = sleep(unlucky)) != 0) {
	fprintf(stderr,"TCP connect: sleep returned %d\n", foo);
      }
      // Backoff: increase sleep until 30s, then go back to 10s
      unlucky++;
      if (unlucky > 30) unlucky /= 3;
      if (close(sock) < 0)
	perror("close(tcp_client_connect)");
      continue;
    }
    else
      unlucky = 0;
  }
  // log stuff about the connection
  if (tls_debug) {
    char ip[INET6_ADDRSTRLEN];
    fprintf(stderr,"TCP connect: connected to %s port %d\n", ip46_ntoa(sin, ip, sizeof(ip)),
	    ntohs((sin->sa_family == AF_INET
		   ? ((struct sockaddr_in *)sin)->sin_port
		   : ((struct sockaddr_in6 *)sin)->sin6_port)));
  }
  return sock;  
}

// TLS level things.

// TLS client connector thread.
// Take struct tls_dest *td
// Create a client context, connect to server, make TLS connection, fill in td, (add route?)
// and wait for others to ask for reconnection.
// Iterate.
void *tls_connector(void *arg)
{
  struct tls_dest *td = (struct tls_dest *)arg;

  SSL *ssl;
  SSL_CTX *ctx = tls_create_client_context();
  tls_configure_context(ctx);

  while (1) {
    // @@@@ re-parse tlsdest?
    if (tls_debug) {
      char ip[INET6_ADDRSTRLEN];
      fprintf(stderr,"TLS client: connecting to %s port %d\n",
	      ip46_ntoa(&td->tls_sa.tls_saddr, ip, sizeof(ip)),
	      ntohs((td->tls_sa.tls_saddr.sa_family == AF_INET
		     ? ((struct sockaddr_in *)&td->tls_sa.tls_sin)->sin_port
		     : ((struct sockaddr_in6 *)&td->tls_sa.tls_sin6)->sin6_port)));
    }
    // connect to server
    int tsock = tcp_client_connect((struct sockaddr *)(td->tls_sa.tls_saddr.sa_family == AF_INET ? (void *)&td->tls_sa.tls_sin : (void *)&td->tls_sa.tls_sin6));

    if (tls_debug)
      fprintf(stderr,"TLS client: connected\n");

    if ((ssl = SSL_new(ctx)) == NULL) {
      fprintf(stderr,"tls_connector: SSL_new failed");
      ERR_print_errors_fp(stderr);
      close(tsock);
      continue; // try again
    }
    SSL_set_fd(ssl, tsock);
    int v = 0;
    if ((v = SSL_connect(ssl)) <= 0) {
      fprintf(stderr,"%%%% Fatal error: TLS connect (%s) failed (probably cert problem?)\n", td->tls_name);
      int err = SSL_get_error(ssl, v);
      ERR_print_errors_fp(stderr);
      close(tsock);
      SSL_free(ssl);
      // just sleep and retry - maybe conn was dropped between connect and SSL_connect
      sleep(3);
      continue;
#if 0
      // or just let this thread die?
      pthread_exit(&(int){ 1 });
      exit(1);
      // don't just keep trying!
      // continue;
#endif
    }

    X509 *ssl_server_cert = SSL_get_peer_certificate(ssl);

    if(ssl_server_cert) {
	long verifyresult;

	verifyresult = SSL_get_verify_result(ssl);
	if(verifyresult != X509_V_OK) {
	  X509_free(ssl_server_cert);				
	  SSL_free(ssl);
	  close(tsock);
	  continue;
	}
	u_char *server_cn = tls_get_cert_cn(ssl_server_cert);
#if CHAOS_DNS
	if (server_cn) {
	  u_short claddrs[4];
	  int i, naddrs = dns_addrs_of_name(server_cn, (u_short *)&claddrs, 4);
	  if (tls_debug) {
	    fprintf(stderr, "TLS server CN %s has %d Chaos address(es): ", server_cn, naddrs);
	    for (i = 0; i < naddrs; i++)
	      fprintf(stderr,"%#o ", claddrs[i]);
	    fprintf(stderr,"\n");
	  }
	  int found = 0;
	  for (i = 0; i < naddrs; i++) {
	    if (claddrs[i] == td->tls_addr) {
	      found = 1;
	      break;
	    }
	  }
	  if (!found) {
	    if (tls_debug || verbose || debug) {
	      fprintf(stderr, "%% Warning: TLS server CN %s doesn't match Chaos address in TLS dest (%#o)\n", server_cn, td->tls_addr);
	      // one day, do something
	    }
	  }
	}
#endif
	// create tlsdest, fill in stuff
	update_client_tlsdest(td, server_cn, tsock, ssl);

	// tell others about it
	tls_inform_tcp_is_open(td);

	// Send a SNS pkt to get route initiated (tell server about our Chaos address)
	// SNS is supposed to be only for existing connections, but we
	// can abuse it since the recipient is a cbridge - we handle it.
	send_empty_sns(td);

	// wait for someone to ask us to reconnect
	tls_wait_for_reconnect_signal(td);
	// close the old, go back and open new
	close_tlsdest(td);
    } else {
      fprintf(stderr,"%%%% Fatal error: TLS client: no server cert (%s), closing\n", td->tls_name);
      SSL_free(ssl);
      close(tsock);
      pthread_exit(&(int){ 1 });
      exit(1);
      // continue;
    }
  }
}

// signalling stuff

static void tls_please_reopen_tcp(struct tls_dest *td, int inputp)
// called by tls_write_record, tls_read_record on failure
{
  u_short chaddr = td->tls_addr;

  // Count this as a lost/aborted pkt.
  // Lost (on input):
  //  "The number of incoming packets from this subnet lost because the
  //  host had not yet read a previous packet out of the interface and
  //  consequently the interface could not capture the packet"
  // Aborted (on output):
  //  "The number of transmissions to this subnet aborted by
  //  collisions or because the receiver was busy."
  PTLOCK(linktab_lock);
  if (inputp)
    linktab[chaddr>>8].pkt_lost++;
  else
    linktab[chaddr>>8].pkt_aborted++;
  PTUNLOCK(linktab_lock);

  if (td->tls_serverp) {
    // no signalling to do, just close/free stuff
    close_tlsdest(td);    
    PTLOCK(rttbl_lock);
    // also disable routing entry
    struct chroute *rt = find_in_routing_table(chaddr, 1, 1);
    if (rt != NULL) {
      if (rt->rt_type != RT_NOPATH)
	rt->rt_cost_updated = time(NULL); // cost isn't updated, but keep track of state change
      rt->rt_type = RT_NOPATH;
    }
    else if (tls_debug) fprintf(stderr,"TLS please reopen: can't find route for %#o to disable!\n", td->tls_addr);
    // need to also disable network routes this is a bridge for
    int i;
    for (i = 0; i < 0xff; i++) {
      if ((rttbl_net[i].rt_link == LINK_TLS) && (rttbl_net[i].rt_braddr == chaddr))
	rttbl_net[i].rt_type = RT_NOPATH;
    }
    PTUNLOCK(rttbl_lock);
  } else {
    // let connector thread do the closing/freeing
    if (tls_debug)
      fprintf(stderr,"TLS_please_reopen_tcp (%s)\n",td->tls_name);
    // signal the connection thread - don't care if nobody's waiting (already working on it, probably)
    if (pthread_mutex_lock(&td->tcp_reconnect_mutex) < 0)
      perror("pthread_mutex_lock(reconnect)");
    if (pthread_cond_signal(&td->tcp_reconnect_cond) < 0) {
      perror("tls_please_reopen_tcp(cond)\n");
      exit(1);
    } 
    if (pthread_mutex_unlock(&td->tcp_reconnect_mutex) < 0)
      perror("pthread_mutex_unlock(reconnect)");
  }
}
static void tls_wait_for_reconnect_signal(struct tls_dest *td)
// called by tls_connector, tls_listener
{
  /* wait for someone to ask for reconnection, typically after an error in read/write */
  if (tls_debug)
    fprintf(stderr,"TLS wait_for_reconnect_signal (%s)...\n", td->tls_name);

  pthread_mutex_lock(&td->tcp_reconnect_mutex);
  if (pthread_cond_wait(&td->tcp_reconnect_cond, &td->tcp_reconnect_mutex) < 0) {
    perror("tls_wait_for_reconnect_signal(cond)");
    exit(1);
  }
  if (pthread_mutex_unlock(&td->tcp_reconnect_mutex) < 0)  {
    perror("tls_wait_for_reconnect_signal(unlock)");
    exit(1);
  }
  if (tls_debug)
    fprintf(stderr,"wait_for_reconnect_signal done\n");
}

static void tls_inform_tcp_is_open(struct tls_dest *td)
{
  if (tls_debug)
    fprintf(stderr,"tls_inform_tcp_is_open (%s)\n", td->tls_name);
  if (pthread_mutex_lock(&td->tcp_is_open_mutex) < 0)
    perror("pthread_mutex_lock(tcp_is_open)");
  /* wake everyone waiting on this */
  if (pthread_cond_broadcast(&td->tcp_is_open_cond) < 0) {
    perror("tls_inform_tcp_is_open(cond)");
    exit(1);
  }
  if (pthread_mutex_unlock(&td->tcp_is_open_mutex) < 0)
    perror("pthread_mutex_unlock(tcp_is_open)");
}
static void tls_wait_for_tcp_open(struct tls_dest *td)
{
  /* wait for tcp_is_open, and get a mutex lock */

  if (tls_debug)
    fprintf(stderr,"wait_for_tcp_open (%s)...\n", td->tls_name);

  pthread_mutex_lock(&td->tcp_is_open_mutex);
  if (tls_debug)
    fprintf(stderr,"wait_for_tcp_open got lock, waiting...\n");
  if (pthread_cond_wait(&td->tcp_is_open_cond, &td->tcp_is_open_mutex) < 0) {
    perror("wait_for_tcp_open(wait)");
    exit(1);
  }
  if (tls_debug)
    fprintf(stderr,"wait_for_tcp_open got signal\n");

  if (pthread_mutex_unlock(&td->tcp_is_open_mutex) < 0)  {
    perror("wait_for_tcp_open(unlock)");
    exit(1);
  }
  if (tls_debug)
    fprintf(stderr,"wait_for_tcp_open done\n");
}


// write a record length (two bytes MSB first) and that many bytes
static int tls_write_record(struct tls_dest *td, u_char *buf, int len)
{
  int wrote;
  SSL *ssl;

  if (len > 0xffff) {
    fprintf(stderr,"tls_write_record: too long: %#x  > 0xffff\n", len);
    exit(1);
  }
  if (len > CBRIDGE_TCP_MAXLEN) {
    fprintf(stderr,"tcp_write_record: too long: %#x > %#x\n", len, (u_int)CBRIDGE_TCP_MAXLEN);
    exit(1);
  }

  u_char obuf[CBRIDGE_TCP_MAXLEN+2];

  obuf[0] = (len >> 8) & 0xff;
  obuf[1] = len & 0xff;
  memcpy(obuf+2, buf, len);

  PTLOCK(tlsdest_lock);
  if ((ssl = td->tls_ssl) == NULL) {
    PTUNLOCK(tlsdest_lock);
    if (tls_debug) fprintf(stderr,"TLS write record: SSL is null, please reopen\n");
    tls_please_reopen_tcp(td, 0);
    return -1;
  }
  if ((wrote = SSL_write(ssl, obuf, 2+len)) <= 0) {
    int err = SSL_get_error(ssl, wrote);
    // punt;
    fprintf(stderr,"SSL_write error %d\n", err);
    if (tls_debug)
      ERR_print_errors_fp(stderr);
    PTUNLOCK(tlsdest_lock);
    // close/free etc
    tls_please_reopen_tcp(td, 0);
    return wrote;
  }
  else if (wrote != len+2)
    fprintf(stderr,"tcp_write_record: wrote %d bytes != %d\n", wrote, len+2);
  else if (tls_debug)
    fprintf(stderr,"TLS write record: sent %d bytes (reclen %d)\n", wrote, len);
  PTUNLOCK(tlsdest_lock);

  return wrote;
}

// read a record length (two bytes MSB first) and that many bytes
static int 
tls_read_record(struct tls_dest *td, u_char *buf, int blen)
{
  int cnt, rlen, actual;
  u_char reclen[2];

  // don't go SSL_free in some other thread please
  PTLOCK(tlsdest_lock);
  SSL *ssl = td->tls_ssl;

  if (ssl == NULL) {
    PTUNLOCK(tlsdest_lock);
    if (tls_debug) fprintf(stderr,"TLS read record: SSL is null, please reopen\n");
    tls_please_reopen_tcp(td, 1);
    return 0;
  }

  // read record length
  cnt = SSL_read(ssl, reclen, 2);
  PTUNLOCK(tlsdest_lock);

  if (cnt < 0) {
    if (tls_debug) perror("read record length");
    tls_please_reopen_tcp(td, 1);
    return -1;
  }
  if (cnt == 0) {
    // EOF
    if (tls_debug)
      fprintf(stderr,"TLS read record: record len: 0 bytes read - please reopen\n");
    tls_please_reopen_tcp(td, 1);
    return 0;
  } else if (cnt != 2) {
    if (tls_debug)
      fprintf(stderr,"TLS read record: record len not 2: %d\n", cnt);
    return 0;
  }
  rlen = reclen[0] << 8 | reclen[1]; //ntohs(reclen[0] << 8 || reclen[1]);
  if (rlen == 0) {
    if (tls_debug)
      fprintf(stderr,"TLS read record: MARK read (no data)\n");
    return 0;
  }
  if (tls_debug)
    fprintf(stderr,"TLS read record: record len %d\n", rlen);
  if (rlen > blen) {
    fprintf(stderr,"TLS read record: record too long for buffer: %d > %d\n", rlen, blen);
    tls_please_reopen_tcp(td, 1);
    return -1;
  }

  PTLOCK(tlsdest_lock);
  if ((ssl = td->tls_ssl) == NULL) {
    PTUNLOCK(tlsdest_lock);
    if (tls_debug) fprintf(stderr,"TLS read record: SSL is null, please reopen\n");
    tls_please_reopen_tcp(td, 1);
    return 0;
  }
  actual = SSL_read(ssl, buf, rlen);
  PTUNLOCK(tlsdest_lock);

  if (actual < 0) {
    perror("read record");
    tls_please_reopen_tcp(td, 1);
    return -1;
  }
  if (actual < rlen) {
    if (tls_debug)
      fprintf(stderr,"TLS read record: read less than record: %d < %d\n", actual, rlen);
    // read the remaining data
    int p = actual;
    while (rlen - p > 0) {
      PTLOCK(tlsdest_lock);
      if ((ssl = td->tls_ssl) == NULL) {
	PTUNLOCK(tlsdest_lock);
	if (tls_debug) fprintf(stderr,"TLS read record: SSL is null, please reopen\n");
	tls_please_reopen_tcp(td, 1);
	return 0;
      }
      actual = SSL_read(ssl, &buf[p], rlen-p);
      PTUNLOCK(tlsdest_lock);
      if (actual < 0) {
	perror("re-read record");
	tls_please_reopen_tcp(td, 1);
	return -1;
      }
      if (tls_debug)
	fprintf(stderr,"TLS read record: read %d more bytes\n", actual);
      if (actual == 0) {
	tls_please_reopen_tcp(td, 1);
	return -1;
      }
      p += actual;
    }
    actual = p;
  }
  if (tls_debug)
    fprintf(stderr,"TLS read record: read %d bytes total\n", actual);

  return actual;
}

// TLS server thread.
// Bind a socket, listen, and loop accepting valid TLS connections.
void * 
tls_server(void *v)
{
  // listen to the specified server port
  tls_tcp_ursock = tcp_bind_socket(SOCK_STREAM, tls_server_port);
  if (listen(tls_tcp_ursock, 42) < 0) {
    perror("listen (TLS server)");
    exit(1);
  }

  // make sure other threads are waiting
  sleep(1);

  SSL *ssl;
  SSL_CTX *ctx = tls_create_server_context();
  tls_configure_context(ctx);

  while (1) {
    struct sockaddr_storage caddr;
    u_int clen = sizeof(caddr);
    int tsock;

    if ((tsock = tcp_server_accept(tls_tcp_ursock, &caddr, &clen)) < 0) {
      perror("accept (TLS server)");
      // @@@@ what could go wrong here?
      exit(1);
    }
    if ((ssl = SSL_new(ctx)) == NULL) {
      fprintf(stderr,"SSL_new failed: ");
      ERR_print_errors_fp(stderr);
      close(tsock);
      continue;
    }
    SSL_set_fd(ssl, tsock);
    int v = 0;
    if ((v = SSL_accept(ssl)) <= 0) {
      // this already catches verification - client end gets "SSL alert number 48"?
      int err = SSL_get_error(ssl, v);
      if (err != SSL_ERROR_SSL) {
	if (tls_debug) ERR_print_errors_fp(stderr);
      }
      close(tsock);
      SSL_free(ssl);
      continue;
    }      

    X509 *ssl_client_cert = SSL_get_peer_certificate(ssl);

    if(ssl_client_cert) {
	long verifyresult;

	verifyresult = SSL_get_verify_result(ssl);
	if (verifyresult != X509_V_OK) {
	  X509_free(ssl_client_cert);				
	  SSL_free(ssl);
	  close(tsock);
	  continue;
	}
	u_char *client_cn = tls_get_cert_cn(ssl_client_cert);
	u_short client_chaddr = 0;
#if CHAOS_DNS
	if (client_cn) {
	  u_short claddrs[4];
	  int i, naddrs = dns_addrs_of_name(client_cn, (u_short *)&claddrs, 4);
	  if (tls_debug) {
	    fprintf(stderr, "TLS server client CN %s has %d Chaos address(es): ", client_cn, naddrs);
	    for (i = 0; i < naddrs; i++)
	      fprintf(stderr,"%#o ", claddrs[i]);
	    fprintf(stderr,"\n");
	  }
	  // if there is just one address, use it
	  // @@@@ search for address on my subnet
	  if (naddrs == 1)
	    client_chaddr = claddrs[0];
	}
#endif
	// create tlsdest, fill in stuff
	add_server_tlsdest(client_cn, tsock, ssl, (struct sockaddr *)&caddr, clen, client_chaddr);
    } else {
      // no cert
      if (tls_debug) fprintf(stderr,"TLS server: no client cert, closing\n");
      SSL_free(ssl);
      close(tsock);
      continue;
    }
  }
}

// TLS input thread.
// Reads from open (accepted) TLS sockets, passes input on to where it should go.
// Adds routing table entries if the source chaos address was new.
void * tls_input(void *v)
{
  /* TLS -> others thread */
  fd_set rfd;
  int len, sval, maxfd, i, j, tindex;
  u_char data[CH_PK_MAXLEN];
  struct timeval timeout;
  struct chaos_header *cha = (struct chaos_header *)&data;

  // @@@@ random number - parameter, or remove?
  sleep(2); // wait for things to settle, connection to open

  while (1) {
    FD_ZERO(&rfd);
    PTLOCK(tlsdest_lock);
    // collect all tls_sock:ets
    maxfd = -1;
    for (i = 0; i < tlsdest_len; i++) {
      if (tlsdest[i].tls_sock > 0) {
	FD_SET(tlsdest[i].tls_sock, &rfd);
	maxfd = (maxfd > tlsdest[i].tls_sock ? maxfd : tlsdest[i].tls_sock);
      }
    }
    PTUNLOCK(tlsdest_lock);
    maxfd++;			/* plus 1 */

    if (maxfd == 0) {
      // if (tls_debug) fprintf(stderr,"TLS input: nothing to see, sleep+retry\n");
      sleep(TLS_INPUT_RETRY_TIMEOUT);
      continue;
    }

    // if (tls_debug) fprintf(stderr,"TLS input: select maxfd %d\n", maxfd);

    // Must have timeout, in order to find new connections to select on
    timeout.tv_sec = TLS_INPUT_RETRY_TIMEOUT;
    timeout.tv_usec = 0;
    if ((sval = select(maxfd, &rfd, NULL, NULL, &timeout)) == EINTR) {
      if (tls_debug) fprintf(stderr,"TLS input timeout, retrying\n");
      continue;
    } else if (sval < 0)
      perror("select(tls)");
    else if (sval > 0) {
      for (j = 0; j < maxfd; j++) {
	if (FD_ISSET(j, &rfd)) {
	  tindex = -1;		/* don't know tlsdest index */
	  // find tlsdest index
	  PTLOCK(tlsdest_lock);
	  for (i = 0; i < tlsdest_len; i++) {
	    if (tlsdest[i].tls_sock == j) {
	      tindex = i;
	      break;
	    }
	  }
	  PTUNLOCK(tlsdest_lock);
	  if (tls_debug) fprintf(stderr,"TLS input: fd %d => tlsdest %d\n", j, tindex);
	  if (tindex >= 0) {
	    int serverp = tlsdest[tindex].tls_serverp;
	    bzero(data,sizeof(data));  /* clear data */
	    if ((len = tls_read_record(&tlsdest[tindex], data, sizeof(data))) < 0) {
	      // error handled by tls_read_record
	      if (tls_debug) perror("tls_read_record");
	      continue; // to next fd
	    } else if (len == 0) {
	      // just a mark
	      if (tls_debug) fprintf(stderr,"TLS input: read MARK\n");
	      continue; // to next fd
	    }
	    // got data!
	    ntohs_buf((u_short *)cha, (u_short *)cha, len);
	    if (debug) ch_dumpkt((u_char *)&data, len);
	    // check where it's coming from
	    // pkt should include trailer
	    u_short srcaddr;
	    if (len > (ch_nbytes(cha) + CHAOS_HEADERSIZE)) {
	      struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
	      srcaddr = ntohs(tr->ch_hw_srcaddr);
	      if (tls_debug) fprintf(stderr,"TLS input %s: Using source addr from trailer: %#o\n",
				     ch_opcode_name(ch_opcode(cha)), srcaddr);
	    } else {
	      srcaddr = ch_srcaddr(cha);
	      if (verbose || tls_debug || debug)
		fprintf(stderr,"%%%% TLS input: no trailer in pkt from %#o\n", srcaddr);
	      if (tls_debug) fprintf(stderr,"TLS input %s: Using source addr from header: %#o\n",
				     ch_opcode_name(ch_opcode(cha)), srcaddr);
	    }
	    // find the route to where from
	    struct chroute *srcrt = find_in_routing_table(srcaddr, 0, 0);

	    if (srcrt == NULL) {
	      // add route
	      if (tls_debug) fprintf(stderr,"TLS: No route found to source %#o for tlsdest %d - adding it\n", srcaddr, tindex);
#if CHAOS_DNS
	      if (tls_debug) {
		u_char hname[256];  /* random size limit */
		if (dns_name_of_addr(srcaddr, hname, sizeof(hname)) < 0)
		  fprintf(stderr,"TLS: no host name found for source %#o (TLS name '%s')\n", srcaddr, tlsdest[tindex].tls_name);
		else 
		  fprintf(stderr,"TLS: source %#o has DNS host name '%s' (TLS name '%s')\n", srcaddr, hname, tlsdest[tindex].tls_name);
	      }
#endif
	      if (!serverp)
		fprintf(stderr,"TLS: No source route found for incoming data, but we are a client?? (source %#o, tlsdest %d)\n",
			srcaddr, tindex);
	      srcrt = add_tls_route(tindex, srcaddr);
	    } else
	      if (tls_debug) fprintf(stderr,"TLS: Route found to source %#o for tlsdest %d: dest %#o\n",
				     srcaddr, tindex, srcrt->rt_dest);

	    // forward to destination
	    forward_chaos_pkt(srcrt != NULL ? srcrt->rt_dest : -1,
			      srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
			      (u_char *)&data, len, LINK_TLS);  /* forward to appropriate links */
	  } else {
	    // could happen under race conditions (closed while selecting?)
	    if (tls_debug) fprintf(stderr,"%%%% tls_input: received pkt from unknown socket %d\n", j);
	  }
	}
      }
    }
  }
}


void
forward_on_tls(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  int i;

  // send it in network order, with trailer
  if (debug) fprintf(stderr,"Forward: Sending on TLS from %#o to %#o via %#o/%#o (%d bytes)\n", schad, dchad, rt->rt_dest, rt->rt_braddr, dlen);

  struct tls_dest *td = NULL;
  PTLOCK(tlsdest_lock);
  for (i = 0; i < tlsdest_len; i++) {
    if (
	/* direct link to destination */
	(tlsdest[i].tls_addr == dchad)
	/* route to bridge */
	|| 
	(tlsdest[i].tls_addr == rt->rt_braddr)
	/* route to dest */
	|| 
	(rt->rt_braddr == 0 && (tlsdest[i].tls_addr == rt->rt_dest))
	) {
      if (verbose || debug) fprintf(stderr,"Forward TLS to dest %#o over %#o (%s)\n", dchad, tlsdest[i].tls_addr, tlsdest[i].tls_name);
      td = &tlsdest[i];
      break;
    }
  }
  PTUNLOCK(tlsdest_lock);
  if (td != NULL) {
    htons_buf((u_short *)ch, (u_short *)ch, dlen);
    tls_write_record(td, data, dlen);
  }
  if (td == NULL && (verbose || debug))
    fprintf(stderr, "Can't find TLS link to %#o via %#o/%#o\n",
	    dchad, rt->rt_dest, rt->rt_braddr);
}

// module initialization
void init_chaos_tls()
{
  init_openssl();
}
