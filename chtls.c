/* Copyright © 2005, 2017-2023 Björn Victor (bjorn@victor.se) */
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
#include <openssl/x509v3.h>

// when to start warning about approaching cert expiry
#define TLS_CERT_EXPIRY_WARNING_DAYS 90
static int tls_cert_expiry_warning_days = TLS_CERT_EXPIRY_WARNING_DAYS;

extern u_short tls_myaddrs[];
extern int tls_n_myaddrs;
extern char tls_ca_file[];
extern char tls_key_file[];
extern char tls_cert_file[];
extern char tls_crl_file[];
extern int do_tls_ipv6;
extern int do_tls_server;
extern int tls_server_port;
extern int tls_debug;

static int tls_tcp_ursock;		/* ur-socket to listen on (for server end) */

static int tls_write_record(struct tls_dest *td, u_char *buf, int len);
static void tls_wait_for_reconnect_signal(struct tls_dest *td);

// Find the tls_myaddrs matching the other address
static u_short my_tls_myaddr(u_short other)
{
  for (int i = 0; i < tls_n_myaddrs; i++) {
    if ((tls_myaddrs[i] & 0xff00) == (other & 0xff00))
      return tls_myaddrs[i];
  }
  return 0;
}

int
parse_tls_config_line()
{
  char *tok = NULL;
  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strncmp(tok,"key",sizeof("key")) == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"tls: no key file specified\n"); return -1; }
      strncpy(tls_key_file, tok, PATH_MAX);
    } else if (strncmp(tok,"cert",sizeof("cert")) == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"tls: no cert file specified\n"); return -1; }
      strncpy(tls_cert_file, tok, PATH_MAX);
    } else if (strncmp(tok,"ca-chain",sizeof("ca-chain")) == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"tls: no ca-chain file specified\n"); return -1; }
      strncpy(tls_ca_file, tok, PATH_MAX);
    } else if (strncmp(tok,"crl",sizeof("crl")) == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"tls: no crl file specified\n"); return -1; }
      strncpy(tls_crl_file, tok, PATH_MAX);
    } else if (strcmp(tok,"expirywarn") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"tls: no value for expirywarn specified\n"); return -1; }
      if ((sscanf(tok, "%d", &tls_cert_expiry_warning_days) != 1) || 
	  (tls_cert_expiry_warning_days < 0) || (tls_cert_expiry_warning_days > 730)) {
	fprintf(stderr,"tls: bad value %s for expirywarn specified\n", tok);
	return -1;
      }
    } else if ((strncmp(tok,"myaddr",sizeof("myaddr")) == 0) ||
	       (strncmp(tok,"myaddrs",sizeof("myaddrs")) == 0)) {
      tok = strtok(NULL, " \t\r\n");
      if (tok == NULL) { fprintf(stderr,"tls: no address for myaddrs specified\n"); return -1; }
      char *sp, *ep;
      for (sp = tok, ep = index(tok, ','); ep != NULL; sp = ep+1, ep = index(ep+1, ',')) {
	if (tls_n_myaddrs > TLSDEST_MAX) {
	  fprintf(stderr,"Error in tls \"myaddrs\" setting - too many addresses listed, max %d\n", TLSDEST_MAX);
	  return -1;
	}
	*ep = '\0';		// zap comma
	if (strlen(sp) == 0) {
	  fprintf(stderr,"Syntax error in tls \"myaddrs\" setting - empty address?\n");
	  return -1;
	}
	if ((sscanf(sp, "%ho", &tls_myaddrs[tls_n_myaddrs]) != 1) || !valid_chaos_host_address(tls_myaddrs[tls_n_myaddrs])) {
	  fprintf(stderr,"tls: bad octal value %s for myaddrs specified\n", sp);
	  return -1;
	}
	tls_n_myaddrs++;
      }
      // add the single/last one
      if (strlen(sp) == 0) {
	fprintf(stderr,"Syntax error in tls \"myaddrs\" setting - empty address?\n");
	return -1;
      } else if ((sscanf(sp, "%ho", &tls_myaddrs[tls_n_myaddrs]) != 1) || !valid_chaos_host_address(tls_myaddrs[tls_n_myaddrs])) {
	fprintf(stderr,"tls: bad octal value %s for myaddrs specified\n", sp);
	return -1;
      }
      tls_n_myaddrs++;
    }
    else if (strncmp(tok,"server",sizeof("server")) == 0) {
      tok = strtok(NULL, " \t\r\n");
      if (tok != NULL)
	tls_server_port = atoi(tok);
      do_tls_server = 1;
    } else if (strncmp(tok,"ipv6",sizeof("ipv6")) == 0) {
      do_tls_ipv6 = 1;
    } else if (strcasecmp(tok, "debug") == 0) {
      tok = strtok(NULL, " \t\r\n");
      if ((tok == NULL) || (strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0))
	tls_debug = 1;
      else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0))
	tls_debug = 0;
      else {
	fprintf(stderr,"tls: bad 'debug' arg %s specified\n", tok);
	return -1;
      }
    } else {
      fprintf(stderr,"bad tls keyword %s\n", tok);
      return -1;
    }
  }
  if ((tls_n_myaddrs == 0) && (mychaddr[0] != 0)) {
    if (do_tls_server)
      fprintf(stderr,"tls: server, but no myaddr parameter - defaulting to %#o\n", mychaddr[0]);
    // default - see send_empty_sns below
    tls_myaddrs[tls_n_myaddrs++] = mychaddr[0];
  }
  if (verbose) {
    printf("Using TLS myaddrs %#o",tls_myaddrs[0]);
    for (int i = 1; i < tls_n_myaddrs; i++)
      printf(",%#o", tls_myaddrs[i]);
    printf(", keyfile \"%s\", certfile \"%s\", ca-chain \"%s\"\n", tls_key_file, tls_cert_file, tls_ca_file);
    if (do_tls_server)
      printf(" and starting TLS server at port %d (%s)\n", tls_server_port, do_tls_ipv6 ? "IPv6+IPv4" : "IPv4");
  }
  return 0;
}

// send an empty SNS packet, just to let the other (server) end know our Chaos address and set up the route
void
send_empty_sns(struct tls_dest *td, u_short onbehalfof)
{
  u_char pkt[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)pkt;
  // use correct source for this link
  u_short src = td->tls_myaddr > 0 ? td->tls_myaddr : my_tls_myaddr(td->tls_addr);
  u_short dst = td->tls_addr;

  struct chroute *rt = find_in_routing_table(dst, 1, 0);
  if (rt == NULL) {
    if (tls_debug) fprintf(stderr,"Can't send SNS to %#o - no route found!\n", dst);
    return;
  } else if (onbehalfof != 0) {
    src = onbehalfof;
  } else
    if (rt->rt_myaddr > 0)
      src = rt->rt_myaddr;

  if (verbose || debug || tls_debug) 
    fprintf(stderr,"Sending SNS from %#o (obh %#o) to %#o\n", src, onbehalfof, dst);

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

#if 0
// not used
static void cleanup_openssl()
{
    EVP_cleanup();
}
#endif

static u_char *
tls_get_cert_cn(X509 *cert)
{
  // see https://github.com/iSECPartners/ssl-conservatory/blob/master/openssl/openssl_hostname_validation.c
  int common_name_loc = -1;
  X509_NAME_ENTRY *common_name_entry = NULL;
  ASN1_STRING *common_name_asn1 = NULL;
  char *common_name_str = NULL;

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

static char *
get_dp_url(DIST_POINT *dp)
{
  GENERAL_NAMES *gens;
  GENERAL_NAME *gen;
  int i, gtype;
  ASN1_STRING *uri;
  if (!dp->distpoint || dp->distpoint->type != 0)
    return NULL;
  gens = dp->distpoint->name.fullname;
  for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
    gen = sk_GENERAL_NAME_value(gens, i);
    uri = (ASN1_STRING *)GENERAL_NAME_get0_value(gen, &gtype);
    if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      char *uptr = (char *)ASN1_STRING_get0_data(uri);
#else
      char *uptr = (char *)ASN1_STRING_data(uri);
#endif
      return uptr;
    }
  }
  return NULL;
}

static char *
get_cert_crl_dp(X509 *cert)
{
  STACK_OF(DIST_POINT) *crldp;
  char *urlptr;

  crldp = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
  if (crldp == NULL) {
    if (tls_debug) fprintf(stderr,"%s: no crl distribution points in cert\n", __func__);
    return NULL;
  }

  int i;
  for (i = 0; i < sk_DIST_POINT_num(crldp); i++) { 
    DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
    urlptr = get_dp_url(dp);
    if (urlptr != NULL) {
      return urlptr;
    }
  }
  if (tls_debug) fprintf(stderr,"%s: found no crl distribution point in cert?\n", __func__);
  return NULL;
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
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // go up to "higher level CA"
    SSL_CTX_set_verify_depth(ctx, 2);

    // Set up for CRL checking
    if (strlen(tls_crl_file) > 0) {
      // Make a new store with X509_STORE_new to get stuff initialized properly.
      // X509_STORE *store = SSL_CTX_get_cert_store(ctx);
      X509_STORE *store = X509_STORE_new();
      // This means we need to reload locations set up above
      if (X509_STORE_load_locations(store, tls_ca_file, NULL) == 0) {
	fprintf(stderr,"Failed to load CA file %s\n", tls_ca_file);
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
      FILE *crl_fd = fopen(tls_crl_file,"r");
      if (crl_fd == NULL) {
	// This should already be checked in main()
	fprintf(stderr,"%%%% Can not open CRL file %s\n", tls_crl_file);
	perror("fopen");
	exit(EXIT_FAILURE);
      } 
      // Read the crl data
      X509_CRL *crl = PEM_read_X509_CRL(crl_fd, NULL, NULL, NULL);
      fclose(crl_fd);
      if (crl == NULL) {
	fprintf(stderr,"%s: Failed to read CRL from file %s\n", __func__, tls_crl_file);
	exit(EXIT_FAILURE);
      }
      if (X509_STORE_add_crl(store, crl) == 0) {
	fprintf(stderr,"%%%% %s: Failed to add CRL to store\n", __func__);
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
      X509_STORE_set_get_issuer(store, X509_STORE_CTX_get1_issuer);
      // Verify the leaf cert against CRL
      X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
      // Update the SSL CTX store
      SSL_CTX_set_cert_store(ctx, store);
      // Now set up the verification params
      if (SSL_CTX_set_purpose(ctx, X509_PURPOSE_ANY) == 0) { // @@@@ sloppy: server or client, depending
	fprintf(stderr,"%%%% %s: Failed to set purpose\n", __func__);
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
    }
}


// Routes, tlsdest etc

void print_tlsdest_config()
{
  int i, j;
  char ip[INET6_ADDRSTRLEN];
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  printf("TLS destination config: %d links\n", tlsdest_len);
  for (i = 0; i < tlsdest_len; i++) {
    if (tlsdest[i].tls_sa.tls_saddr.sa_family != 0) {
      ip46_ntoa(&tlsdest[i].tls_sa.tls_saddr, ip, sizeof(ip));
    } else
      strcpy(ip, "[none]");
    printf(" dest %#o, name %s, myaddr %#o, ",
	   tlsdest[i].tls_addr, 
	   tlsdest[i].tls_name,
	   tlsdest[i].tls_myaddr);
    if (tlsdest[i].tls_serverp) printf("(server) ");
    printf("host %s port %d",
	   ip,
	   ntohs((tlsdest[i].tls_sa.tls_saddr.sa_family == AF_INET
		  ? tlsdest[i].tls_sa.tls_sin.sin_port
		  : tlsdest[i].tls_sa.tls_sin6.sin6_port)));
    if (tlsdest[i].tls_muxed[0] != 0) {
      printf(" mux %o",tlsdest[i].tls_muxed[0]);
      for (j = 1; j < CHTLS_MAXMUX && tlsdest[i].tls_muxed[j] != 0; j++)
	printf(",%o", tlsdest[i].tls_muxed[j]);
    }
    printf("\n");
  }
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
}

// Should only be called by server (clients have their routes set up by config)
static struct chroute *
add_tls_route(int tindex, u_short srcaddr)
{
  struct chroute * rt = NULL;
  if (!tlsdest[tindex].tls_serverp) {
    fprintf(stderr,"%%%% TLS: add_tls_route called by client code for index %d\n",
	    tindex);
    abort();
  }
  PTLOCKN(rttbl_lock,"rttbl_lock");
  // find any old entry (only host route, also nopath)
  rt = find_in_routing_table(srcaddr, 1, 1);
  if (rt != NULL) {
    // old route exists
    if (((rt->rt_link != LINK_TLS) || (rt->rt_type == RT_NOPATH)) && (rt->rt_type != RT_STATIC)) {
      // @@@@ only if configured to switch link types
      if (tls_debug || debug)
	fprintf(stderr,"TLS: Old %s route to %#o found (type %s), updating to TLS Dynamic\n",
		rt_linkname(rt->rt_link), srcaddr, rt_typename(rt->rt_type));
      rt->rt_link = LINK_TLS;
      rt->rt_type = RT_DYNAMIC;
      rt->rt_cost = RTCOST_ASYNCH;
      rt->rt_cost_updated = time(NULL);
    } else if ((rt->rt_type == RT_STATIC) && (tls_debug || debug)) {
      fprintf(stderr,"TLS: not updating static route to %#o via %#o (%s)\n",
	      srcaddr, rt->rt_braddr, rt_linkname(rt->rt_link));
    }
  } else if ((srcaddr & 0xff00) == (tlsdest[tindex].tls_myaddr & 0xff00)) {
    // make a routing entry for host srcaddr through tls link at tlsindex
    rt = add_to_routing_table(srcaddr, 0, tlsdest[tindex].tls_myaddr, RT_DYNAMIC, LINK_TLS, RTCOST_ASYNCH);
  } else if (my_tls_myaddr(srcaddr) != 0) {
    // Not same subnet as existing route, or new
    u_short new = my_tls_myaddr(srcaddr);
    if (tls_debug) fprintf(stderr,"TLS: adding NEW route using myaddr %#o for index %d\n", new, tindex);
    rt = add_to_routing_table(srcaddr, 0, new, RT_DYNAMIC, LINK_TLS, RTCOST_ASYNCH);
  } else {
    if (1 || tls_debug) 
      fprintf(stderr,"%%%% TLS: asked to add route to %#o but wrong subnet (not matching tls_myaddrs) - not updating\n", srcaddr);
  }
  PTUNLOCKN(rttbl_lock,"rttbl_lock");
  // Done with routing, now work on tlsdest
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  if (tlsdest[tindex].tls_addr == 0) {
    if (tls_debug) fprintf(stderr,"TLS route addition updates tlsdest addr from %#o to %#o and myaddr from %#o to %#o\n",
			   tlsdest[tindex].tls_addr, srcaddr, tlsdest[tindex].tls_myaddr, my_tls_myaddr(srcaddr));
    tlsdest[tindex].tls_addr = srcaddr;
    tlsdest[tindex].tls_myaddr = my_tls_myaddr(srcaddr); // matching myaddr
  }
  else if (((tlsdest[tindex].tls_addr >> 8) == (srcaddr >> 8)) && (tlsdest[tindex].tls_addr != srcaddr)) {
    // add multiplexed dest @@@@ maybe let this be configurable?
    int j;
    for (j = 0; j < CHTLS_MAXMUX && tlsdest[tindex].tls_muxed[j] != 0; j++);
    if (j < CHTLS_MAXMUX) {
      if (tls_debug) fprintf(stderr,"Adding %#o to mux list %d of tlsdest %d\n", srcaddr, j, tindex);
      tlsdest[tindex].tls_muxed[j] = srcaddr;
      tlsdest[tindex].tls_myaddr = my_tls_myaddr(srcaddr); // make sure myaddr matches
    } else
      fprintf(stderr,"%%%% Warning: Can not add %#o to mux list of tlsdest %d - list full, increase CHTLS_MAXMUX?\n", srcaddr, tindex);
  } else if ((tlsdest[tindex].tls_addr != 0) && (tlsdest[tindex].tls_addr != srcaddr)) {
    char ip[INET6_ADDRSTRLEN];
    fprintf(stderr,"%%%% TLS link %d %s (%s) chaos address already known but route not found - updating from %#o to %#o\n",
	    tindex, tlsdest[tindex].tls_name, ip46_ntoa(&tlsdest[tindex].tls_sa.tls_saddr, ip, sizeof(ip)),
	    tlsdest[tindex].tls_addr, srcaddr);
    // This is OK. Use the most recent.
    tlsdest[tindex].tls_addr = srcaddr;
    tlsdest[tindex].tls_myaddr = my_tls_myaddr(srcaddr); // matching myaddr
  } else {
    // nothing
  }
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
  return rt;
}

static void
close_tlsdest(struct tls_dest *td)
{
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  if (td->tls_serverp) {
    // forget remote sockaddr
    memset((void *)&td->tls_sa.tls_saddr, 0, sizeof(td->tls_sa.tls_saddr));
    // forget remote chaos addr
    td->tls_addr = 0;
    // forget any mux list
    memset((void *)&td->tls_muxed, 0, sizeof(td->tls_muxed));
  }
  if (td->tls_ssl != NULL) {
    SSL_free(td->tls_ssl);
    td->tls_ssl = NULL;
  }
  if (td->tls_sock != 0) {
    close(td->tls_sock);
    td->tls_sock = 0;
  }
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
}

void
close_tls_route(struct chroute *rt) 
{
  int i;
  struct tls_dest *td = NULL;
  if ((rt->rt_link == LINK_TLS) && (rt->rt_type != RT_NOPATH)) {
    PTLOCKN(tlsdest_lock,"tlsdest_lock");
    for (i = 0; i < tlsdest_len; i++) {
      if (tlsdest[i].tls_addr == rt->rt_braddr) {
	td = &tlsdest[i];
	break;
      }
    }
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
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
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
#if 0
  // don't - we need the "IP name" of the server
  if (server_cn != NULL)
    strncpy(td->tls_name, (char *)server_cn, TLSDEST_NAME_LEN);
#endif
  td->tls_serverp = 0;
  td->tls_sock = tsock;
  td->tls_ssl = ssl;

  // initiate these
  if (pthread_mutex_init(&td->tcp_reconnect_mutex, NULL) != 0)
    perror("pthread_mutex_init(update_client_tlsdest)");
  if (pthread_cond_init(&td->tcp_reconnect_cond, NULL) != 0)
    perror("pthread_cond_init(update_client_tlsdest)");
  
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
}


static void
add_server_tlsdest(u_char *name, int sock, SSL *ssl, struct sockaddr *sa, int sa_len, u_short chaddr)
{
  // no tlsdest exists for server end, until it is connected
  struct tls_dest *td = NULL;

  PTLOCKN(tlsdest_lock,"tlsdest_lock");
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
      PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
      fprintf(stderr,"%%%% tlsdest is full! Increase TLSDEST_MAX\n");
      return;
    }
    if (tls_debug) {
      char ip6[INET6_ADDRSTRLEN];
      fprintf(stderr,"Adding new TLS destination %s from %s port %d chaddr %#o myaddr %#o\n", name,
	      ip46_ntoa(sa, ip6, sizeof(ip6)),
	      ntohs((sa->sa_family == AF_INET
		     ? ((struct sockaddr_in *)sa)->sin_port
		     : ((struct sockaddr_in6 *)sa)->sin6_port)),
	      chaddr, my_tls_myaddr(chaddr));
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
    tlsdest[tlsdest_len].tls_myaddr = my_tls_myaddr(chaddr);
    tlsdest_len++;
  }
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
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
  u_long ntimes = 0;
  char ip[INET6_ADDRSTRLEN];
  
  (void)ip46_ntoa(sin, ip, sizeof(ip));

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
      fprintf(stderr,"TCP connect: connecting to %s port %d\n", ip,
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
      else if (ntimes == 3)
	fprintf(stderr,"%%%% TLS: connection to %s failed %lu times, trying again in %d s\n", ip, ntimes, unlucky);
      if ((foo = sleep(unlucky)) != 0) {
	fprintf(stderr,"TCP connect: sleep returned %d\n", foo);
      }
      // Backoff: increase sleep until 30s, then go back to 10s
      unlucky++;
      ntimes++;
      if (unlucky > 30) {
	unlucky /= 3;
	// This happens the first time after sleeping 465 seconds + connection timeouts
	// then every 275 seconds + timeouts
	fprintf(stderr,"%%%% TLS: connection to %s failed %lu times, but still retrying - is the server up?\n",
		ip, ntimes);
      }
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
    fprintf(stderr,"TCP connect: connected to %s port %d\n", ip,
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

    if (tls_debug) {
      char ip[INET6_ADDRSTRLEN];
      fprintf(stderr,"TLS client: connected to %s (%s port %d)\n", td->tls_name,
	      ip46_ntoa(&td->tls_sa.tls_saddr, ip, sizeof(ip)),
	      ntohs((td->tls_sa.tls_saddr.sa_family == AF_INET
		     ? ((struct sockaddr_in *)&td->tls_sa.tls_sin)->sin_port
		     : ((struct sockaddr_in6 *)&td->tls_sa.tls_sin6)->sin6_port)));
    }

    if ((ssl = SSL_new(ctx)) == NULL) {
      fprintf(stderr,"tls_connector: SSL_new failed");
      ERR_print_errors_fp(stderr);
      close(tsock);
      continue; // try again
    }
    SSL_set_fd(ssl, tsock);
    int v = 0;
    if ((v = SSL_connect(ssl)) <= 0) {
      fprintf(stderr,"%%%% Error: TLS connect (%s) failed (probably cert problem?)\n", td->tls_name);
      ERR_print_errors_fp(stderr);
      close(tsock);
      SSL_free(ssl);
      // just sleep and retry - maybe conn was dropped between connect and SSL_connect
      // @@@@ count the number of times, and warn occasionally
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
	  // @@@@ warn?
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
	      if (naddrs < -1) 
		fprintf(stderr,"%%%% TLS: DNS error while looking up server CN:\n");
	      fprintf(stderr, "%% Warning: TLS server CN %s doesn't match Chaos address in TLS dest (%#o)\n", server_cn, td->tls_addr);
	      // one day, do something
	    }
	    // just sleep and retry - maybe temporary DNS failure?
	    // @@@@ count the number of times, and warn occasionally
	    sleep(15);
	    continue;
#if 0
	    // close and terminate
	    SSL_free(ssl);
	    close(tsock);
	    pthread_exit(&(int){ 1 });
#endif
	  }
	} else {
	  if (1 || tls_debug || verbose || debug) {
	    fprintf(stderr, "%%%% Error: TLS server has no CN in cert, for TLS dest %#o\n", td->tls_addr);
	  }
	  // close and terminate
	  SSL_free(ssl);
	  close(tsock);
	  pthread_exit(&(int){ 1 });
	}
#endif
	// create tlsdest, fill in stuff
	update_client_tlsdest(td, server_cn, tsock, ssl);

	// Send a SNS pkt to get route initiated (tell server about our Chaos address)
	// SNS is supposed to be only for existing connections, but we
	// can abuse it since the recipient is a cbridge - we handle it.
	send_empty_sns(td, 0);
	if (td->tls_muxed[0] != 0) {
	  // also send a SNS on behalf of all the muxed addresses, to add them to the tls routes of the server end
	  send_empty_sns(td, td->tls_muxed[0]);
	  int j;
	  for (j = 1; j < CHTLS_MAXMUX && td->tls_muxed[j] != 0; j++)
	    send_empty_sns(td, td->tls_muxed[j]);
	}
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

  // Remove the tls_ssl as soon as possible, to avoid other breakage
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  if (td->tls_ssl != NULL) {
    SSL_free(td->tls_ssl);
    td->tls_ssl = NULL;
  }
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");

  // Count this as a lost/aborted pkt.
  // Lost (on input):
  //  "The number of incoming packets from this subnet lost because the
  //  host had not yet read a previous packet out of the interface and
  //  consequently the interface could not capture the packet"
  // Aborted (on output):
  //  "The number of transmissions to this subnet aborted by
  //  collisions or because the receiver was busy."
  if ((chaddr >> 8) == 0) {
    if (1 || tls_debug) {
      fprintf(stderr,"TLS: bad call to tls_please_reopen_tcp: td %p tls_addr %#o (%#x), inputp %d, name \"%s\"\n",
	      td, chaddr, chaddr, inputp, td->tls_name);
      print_tlsdest_config();
    }
    return;
  } else {
    PTLOCKN(linktab_lock,"linktab_lock");
    if (inputp)
      linktab[chaddr>>8].pkt_lost++;
    else
      linktab[chaddr>>8].pkt_aborted++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
  }

  if (td->tls_serverp) {
    // no signalling to do, just close/free stuff
    int i;
    struct chroute *rt;
    // disable routing entries
    PTLOCKN(rttbl_lock, "rttbl_lock");
    rt = find_in_routing_table(chaddr, 1, 1);
    if (rt != NULL) {
      if (rt->rt_type != RT_NOPATH)
	rt->rt_cost_updated = time(NULL); // cost isn't updated, but keep track of state change
      rt->rt_type = RT_NOPATH;
    }
    else if (tls_debug) fprintf(stderr,"TLS please reopen: can't find route for %#o to disable!\n", td->tls_addr);
    // need to also disable network routes this is a bridge for
    for (i = 0; i < 0xff; i++) {
      if ((rttbl_net[i].rt_link == LINK_TLS) && (rttbl_net[i].rt_braddr == chaddr))
	rttbl_net[i].rt_type = RT_NOPATH;
    }
    // and multiplexed routes
    for (i = 0; i < CHTLS_MAXMUX && td->tls_muxed[i] != 0; i++) {
      if ((rt = find_in_routing_table(td->tls_muxed[i], 1, 1)) != NULL) {
	rt->rt_type = RT_NOPATH;
      }
    }
    PTUNLOCKN(rttbl_lock,"rttbl_lock");
    close_tlsdest(td);    
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

  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  if ((ssl = td->tls_ssl) == NULL) {
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
    if (tls_debug) fprintf(stderr,"TLS write record: SSL is null, please reopen\n");
    tls_please_reopen_tcp(td, 0);
    return -1;
  }
  if ((wrote = SSL_write(ssl, obuf, 2+len)) <= 0) {
    int err = SSL_get_error(ssl, wrote);
    // @@@@ Check the error, and if it is SSL_ERROR_SYSCALL,
    // @@@@ find the syscall error and report it.
    // @@@@ For now:
    // punt;
    fprintf(stderr,"SSL_write error %d\n", err);
    if (tls_debug)
      ERR_print_errors_fp(stderr);
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
    // close/free etc
    tls_please_reopen_tcp(td, 0);
    return wrote;
  }
  else if (wrote != len+2)
    fprintf(stderr,"tcp_write_record: wrote %d bytes != %d\n", wrote, len+2);
  else if (tls_debug > 1)
    fprintf(stderr,"TLS write record: sent %d bytes (reclen %d)\n", wrote, len);
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");

  return wrote;
}

// read a record length (two bytes MSB first) and that many bytes
static int 
tls_read_record(struct tls_dest *td, u_char *buf, int blen)
{
  int cnt, rlen, actual;
  u_char reclen[2];

  // don't go SSL_free in some other thread please
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  SSL *ssl = td->tls_ssl;

  if (ssl == NULL) {
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
    if (tls_debug) fprintf(stderr,"TLS read record: SSL is null, please reopen\n");
    tls_please_reopen_tcp(td, 1);
    return 0;
  }

  // read record length
  cnt = SSL_read(ssl, reclen, 2);
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");

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
  if (tls_debug > 1)
    fprintf(stderr,"TLS read record: record len %d\n", rlen);
  if (rlen > blen) {
    fprintf(stderr,"TLS read record: record too long for buffer: %d > %d\n", rlen, blen);
    tls_please_reopen_tcp(td, 1);
    return -1;
  }

  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  if ((ssl = td->tls_ssl) == NULL) {
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
    if (tls_debug) fprintf(stderr,"TLS read record: SSL is null, please reopen\n");
    tls_please_reopen_tcp(td, 1);
    return 0;
  }
  actual = SSL_read(ssl, buf, rlen);
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");

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
      PTLOCKN(tlsdest_lock,"tlsdest_lock");
      if ((ssl = td->tls_ssl) == NULL) {
	PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
	if (tls_debug) fprintf(stderr,"TLS read record: SSL is null, please reopen\n");
	tls_please_reopen_tcp(td, 1);
	return 0;
      }
      actual = SSL_read(ssl, &buf[p], rlen-p);
      PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
      if (actual < 0) {
	perror("re-read record");
	tls_please_reopen_tcp(td, 1);
	return -1;
      }
      if (tls_debug > 1)
	fprintf(stderr,"TLS read record: read %d more bytes\n", actual);
      if (actual == 0) {
	tls_please_reopen_tcp(td, 1);
	return -1;
      }
      p += actual;
    }
    actual = p;
  }
  if (tls_debug > 1)
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
    ERR_clear_error();		/* try to get the latest error below, not some old */
    if ((v = SSL_accept(ssl)) <= 0) {
      // this already catches verification - client end gets "SSL alert number 48"?
      int err = SSL_get_error(ssl, v);
      if (err != SSL_ERROR_SSL) {
	if (tls_debug) ERR_print_errors_fp(stderr);
#if 0
      } else {
	// @@@@ Experiment: what errors do we get in various situations?
	int rr = ERR_get_error();
	// Note: Applications should not make control flow decisions based on specific error codes.
	int libno = ERR_GET_LIB(rr);
	int rsn = ERR_GET_REASON(rr);
	// And here it shows why - apparently library def of ERR_LIB_X509V3 differs from include file.
	fprintf(stderr,"%%%% SSL error: lib %d (X509v3 %d), reason %d (vfy failed %d): %s\n", libno, ERR_LIB_X509V3, rsn, SSL_R_CERTIFICATE_VERIFY_FAILED, ERR_error_string(rr, NULL));
	// @@@@ This would be nice to have working, though!
	if ((libno == ERR_LIB_X509V3) && (rsn == SSL_R_CERTIFICATE_VERIFY_FAILED)) {
	  char ip[INET6_ADDRSTRLEN];
	  fprintf(stderr,"%%%% TLS server: client at %s failed cert verification, closing\n",
		    ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)));
	}
#endif
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
	  if (naddrs == 1)
	    client_chaddr = claddrs[0];
	  else {
	    // search for address on my subnet
	    int i;
	    for (i = 0; i < naddrs; i++) {
	      if (mychaddr_on_net(claddrs[i]) != 0) {
		client_chaddr = claddrs[i];
		break;
	      }
	    }
	  }
	  if (client_chaddr == 0) {
	    // @@@@ should limit the frequency of warnings?
	    char ip[INET6_ADDRSTRLEN];
	    if (naddrs < -1)
	      fprintf(stderr,"%%%% TLS: DNS error while looking up client CN %s at %s, rejecting\n",
		      client_cn, ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)));
	    else if (naddrs > 0) 
	      fprintf(stderr,"%%%% TLS server: client at %s presents cert CN %s with no Chaos addresses on my subnets, rejecting\n",
		      ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)), client_cn);
	    else
	      fprintf(stderr,"%%%% TLS server: client at %s presents cert CN %s with no Chaos addresses, rejecting\n",
		      ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)), client_cn);
	    SSL_free(ssl);
	    close(tsock);
	    continue;
	  }
	} else {
	  if (tls_debug) {
	    char ip[INET6_ADDRSTRLEN];
	    fprintf(stderr,"%%%% TLS server: client at %s has no CN in cert, closing\n",
		    ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)));
	  }
	  // close and wait for more
	  SSL_free(ssl);
	  close(tsock);
	  continue;
	}
#endif
	// Get serial
	const ASN1_INTEGER *serialp = X509_get0_serialNumber(ssl_client_cert);
	if (serialp != NULL) {
	  u_long serial = ASN1_INTEGER_get(serialp);
	  char ip[INET6_ADDRSTRLEN];
	  // @@@@ only do this once per client/serial
	  fprintf(stderr,"TLS client connecting: serial %6lX at IP %s, CN %s\n", serial, 
		  ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)), client_cn);
	}
	// create tlsdest, fill in stuff
	add_server_tlsdest(client_cn, tsock, ssl, (struct sockaddr *)&caddr, clen, client_chaddr);
    } else {
      // no cert
      if (tls_debug) {
	char ip[INET6_ADDRSTRLEN];
	fprintf(stderr,"%%%% TLS server: client at %s has no cert, closing\n",
		ip46_ntoa((struct sockaddr *)&caddr, ip, sizeof(ip)));
      }
      SSL_free(ssl);
      close(tsock);
      continue;
    }
  }
}

static void
print_tls_warning(int tindex, struct chaos_header *cha, char *header)
{
  char ip[INET6_ADDRSTRLEN];
  u_char *data = (u_char *)cha;
  int len = ch_nbytes(cha) + CHAOS_HEADERSIZE;
  len += (len % 2);
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)(data+len);
  u_short srcaddr = ntohs(tr->ch_hw_srcaddr);

  fprintf(stderr,"%%%% TLS: %s for %s from <%#o,%#x> hw %#o on tlsdest %d %s %s addr %#o myadd %#o\n",
	  header, ch_opcode_name(ch_opcode(cha)), ch_srcaddr(cha), ch_srcindex(cha), 
	  srcaddr, 
	  tindex, tlsdest[tindex].tls_name, ip46_ntoa(&tlsdest[tindex].tls_sa.tls_saddr, ip, sizeof(ip)),
	  tlsdest[tindex].tls_addr, tlsdest[tindex].tls_myaddr);
}

static void
handle_tls_input(int tindex)
{
  u_char data[CH_PK_MAXLEN];
  struct chaos_header *cha = (struct chaos_header *)&data;
  u_short srcaddr;
  int len, serverp = tlsdest[tindex].tls_serverp;

  bzero(data,sizeof(data));  /* clear data */
  if ((len = tls_read_record(&tlsdest[tindex], data, sizeof(data))) < 0) {
    // error handled by tls_read_record
    if (tls_debug) perror("tls_read_record");
    return;
  } else if (len == 0) {
    // just a mark
    if (tls_debug) fprintf(stderr,"TLS input: read MARK\n");
    return;
  }
  // got data!
  ntohs_buf((u_short *)cha, (u_short *)cha, len);
  if (debug) ch_dumpkt((u_char *)&data, len);
  // pkt should include trailer
  if (len != ch_nbytes(cha) + (ch_nbytes(cha)%2) + CHAOS_HEADERSIZE + CHAOS_HW_TRAILERSIZE) {
    // bad length: close socket
    if (1 || verbose || tls_debug || debug) print_tls_warning(tindex, cha, "no trailer");
    PTLOCKN(linktab_lock,"linktab_lock");
    srcaddr = ch_srcaddr(cha);
    if (srcaddr > 0xff)
      linktab[srcaddr>>8].pkt_badlen++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
    close_tlsdest(&tlsdest[tindex]);
    return;
  }

  // check where it's coming from
  struct chaos_hw_trailer *tr = (struct chaos_hw_trailer *)&data[len-CHAOS_HW_TRAILERSIZE];
  srcaddr = ntohs(tr->ch_hw_srcaddr);
  // verify it is on tls_myaddr subnet
  if ((srcaddr == 0) || ((srcaddr & 0xff00) != (tlsdest[tindex].tls_myaddr & 0xff00))) {
    if (tls_debug) print_tls_warning(tindex, cha, "hw source address not on my net");
    else if (verbose) fprintf(stderr,"TLS: Hardware source address %#o is not on my net %#o\n", srcaddr, (tlsdest[tindex].tls_myaddr & 0xff00)>>8);
    PTLOCKN(linktab_lock,"linktab_lock");
    srcaddr = ch_srcaddr(cha);
    if (srcaddr > 0xff)
      linktab[srcaddr>>8].pkt_rejected++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
    close_tlsdest(&tlsdest[tindex]);
    return;
  }
  if (tls_debug > 1) fprintf(stderr,"TLS input %s: Using source addr from trailer: %#o\n",
			     ch_opcode_name(ch_opcode(cha)), srcaddr);
  int cks;
  if ((cks = ch_checksum((u_char *)&data, len)) != 0) {
    // "This can't possibly happen!" - really!
    if (1 || tls_debug) print_tls_warning(tindex, cha, "BAD CHECKSUM");
    PTLOCKN(linktab_lock,"linktab_lock");
    srcaddr = ch_srcaddr(cha);
    if (srcaddr > 0xff)
      linktab[srcaddr>>8].pkt_crcerr++;
    PTUNLOCKN(linktab_lock,"linktab_lock");
    close_tlsdest(&tlsdest[tindex]);
    return;
  }

  // find the route to where from
  if (serverp && (ch_opcode(cha) == CHOP_SNS) && (ch_srcindex(cha) == 0) && (ch_destindex(cha) == 0)
      && (srcaddr != ch_srcaddr(cha)) && (srcaddr >> 8) == (ch_srcaddr(cha) >> 8)) {
    if (tls_debug) print_tls_warning(tindex, cha, "Using header source");
    srcaddr = ch_srcaddr(cha);
  }
  struct chroute *srcrt = find_in_routing_table(srcaddr, 1, 0);

  if (tls_debug && serverp && (ch_opcode(cha) == CHOP_SNS) && (ch_srcindex(cha) == 0) && (ch_destindex(cha) == 0)) {
    if (srcrt == NULL)
      print_tls_warning(tindex, cha, "NEW empty SNS");
    else
      print_tls_warning(tindex, cha, "Empty SNS but host route exists");
    if (srcrt != NULL) {
      struct chroute *rt = srcrt;
      fprintf(stderr,"Found host route to dest %#o: %s dest %#o %s bridge %#o myaddr %#o\n", srcaddr,
			 rt_linkname(rt->rt_link), rt->rt_dest, rt_typename(rt->rt_type), rt->rt_braddr, rt->rt_myaddr);
    }
  }
  // @@@@ use config for whether to allow switching link types
  if ((srcrt == NULL) || (srcrt->rt_link != LINK_TLS)) {
    // add route?
    if ((srcrt == NULL) && serverp) {
      if ((ch_opcode(cha) != CHOP_RUT) &&
	  !((ch_opcode(cha) == CHOP_SNS) && (ch_srcindex(cha) == 0) && (ch_destindex(cha) == 0))) {
	// not the expected start packet, ignore it.
	if (tls_debug) print_tls_warning(tindex, cha, "No source route and not a SNS/RUT");
	// ignore pkt
	close_tlsdest(&tlsdest[tindex]);
	return;
      }
    } else if (srcrt == NULL) {
      print_tls_warning(tindex, cha, "No source route found for incoming data, but we are a client");
      close_tlsdest(&tlsdest[tindex]);
      return;
    }
    else if ((srcrt->rt_link != LINK_TLS) && (1 || tls_debug))
      // @@@@ only switch links if configured to do it
      fprintf(stderr,"%%%% TLS: Old route found to source %#o for tlsdest %d of type %s - updating it\n", srcaddr, tindex, rt_linkname(srcrt->rt_link));

#if CHAOS_DNS
    u_char hname[256];  /* random size limit */
    if (dns_name_of_addr(srcaddr, hname, sizeof(hname)) < 0)
      print_tls_warning(tindex, cha, "no DNS host name found");
    else if (tls_debug) 
      fprintf(stderr,"TLS: source addr %#o has DNS host name '%s' (TLS name '%s')\n", srcaddr, hname, tlsdest[tindex].tls_name);
#endif
    srcrt = add_tls_route(tindex, srcaddr);
  } 
#if 0
  else if (tls_debug) fprintf(stderr,"TLS: Route found to source %#o for tlsdest %d: dest %#o\n",
			      srcaddr, tindex, srcrt->rt_dest);
#endif

  // forward to destination
  forward_chaos_pkt(srcrt, srcrt != NULL ? srcrt->rt_cost : RTCOST_DIRECT,
		    (u_char *)&data, len, LINK_TLS);  /* forward to appropriate links */
}


// TLS input thread.
// Reads from open (accepted) TLS sockets, passes input on to where it should go.
// Adds routing table entries if the source chaos address was new.
void * tls_input(void *v)
{
  /* TLS -> others thread */
  fd_set rfd;
  int sval, maxfd, i, j, tindex;
  struct timeval timeout;

  // @@@@ random number - parameter, or remove?
  sleep(2); // wait for things to settle, connection to open

  while (1) {
    FD_ZERO(&rfd);
    PTLOCKN(tlsdest_lock,"tlsdest_lock");
    // collect all tls_sock:ets
    maxfd = -1;
    for (i = 0; i < tlsdest_len; i++) {
      if (tlsdest[i].tls_sock > 0) {
	FD_SET(tlsdest[i].tls_sock, &rfd);
	maxfd = (maxfd > tlsdest[i].tls_sock ? maxfd : tlsdest[i].tls_sock);
      }
    }
    PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
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
    } else if (sval < 0) {
      perror("select(tls)");
      // @@@@ crash? sleep?
      sleep(TLS_INPUT_RETRY_TIMEOUT);
    } else if (sval > 0) {
      for (j = 0; j < maxfd; j++) {
	if (FD_ISSET(j, &rfd)) {
	  tindex = -1;		/* don't know tlsdest index */
	  // find tlsdest index
	  PTLOCKN(tlsdest_lock,"tlsdest_lock");
	  for (i = 0; i < tlsdest_len; i++) {
	    if (tlsdest[i].tls_sock == j) {
	      tindex = i;
	      break;
	    }
	  }
	  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
	  if (tindex < 0) {
	    // could happen under race conditions (closed while selecting?)
	    if (tls_debug) fprintf(stderr,"%%%% tls_input: received pkt from unknown socket %d\n", j);
	    continue;
	  }
	  if (tls_debug > 1) fprintf(stderr,"TLS input: fd %d => tlsdest %d\n", j, tindex);
	  handle_tls_input(tindex);
 	}
      }
    }
  }
}


static int
is_in_mux_list(u_short addr, u_short *list)
{
  int i;
  for (i = 0; i < CHTLS_MAXMUX && list[i] != 0; i++) {
    if (list[i] == addr)
      return 1;
  }
  return 0;
}

// @@@@ consider running this in a separate (perhaps ephemeral) thread,
// since it might hang on output due to TCP/TLS communication (and the other end having issues)
void
forward_on_tls(struct chroute *rt, u_short schad, u_short dchad, struct chaos_header *ch, u_char *data, int dlen)
{
  int i;

  // send it in network order, with trailer
  if (debug) fprintf(stderr,"Forward: Sending on TLS from %#o to %#o via %#o/%#o (%d bytes)\n", schad, dchad, rt->rt_dest, rt->rt_braddr, dlen);

  struct tls_dest *td = NULL;
  PTLOCKN(tlsdest_lock,"tlsdest_lock");
  for (i = 0; i < tlsdest_len; i++) {
    if ((tlsdest[i].tls_addr != 0) &&
	(
	 /* direct link to destination */
	 (tlsdest[i].tls_addr == dchad)
	 /* route to bridge */
	 || 
	 (tlsdest[i].tls_addr == rt->rt_braddr)
	 /* route to dest */
	 || 
	 (rt->rt_braddr == 0 && (tlsdest[i].tls_addr == rt->rt_dest))
	 ||
	 // multiplexed
	 is_in_mux_list(dchad, tlsdest[i].tls_muxed)
	 )) {
      if (verbose || debug) fprintf(stderr,"Forward TLS to dest %#o over %#o (%s)\n", dchad, tlsdest[i].tls_addr, tlsdest[i].tls_name);
      td = &tlsdest[i];
      break;
    }
  }
  PTUNLOCKN(tlsdest_lock,"tlsdest_lock");
  if (td != NULL) {
    htons_buf((u_short *)ch, (u_short *)ch, dlen);
    tls_write_record(td, data, dlen);
  }
  if (td == NULL && (verbose || debug))
    fprintf(stderr, "Can't find TLS link to %#o via %#o/%#o\n",
	    dchad, rt->rt_dest, rt->rt_braddr);
}

static int
days_until_expiry(const ASN1_TIME *x)
{
  // find out how many days until expiry
  ASN1_TIME *now;
  if ((now = ASN1_TIME_set(NULL, time(NULL))) == NULL) {
    perror("ASN1 error");
    abort();
  }
  int days, secs;
  if (ASN1_TIME_diff(&days, &secs, now, x) == 0) {
    perror("ASN1 error");
    abort();
  }
  return days;
}

static int
validate_cert_vs_crl(X509 *cert, char *fname)
{
  // Ideally, read the crl from the dist_point in the cert
  FILE *f = fopen(tls_crl_file,"r");
  if (f == NULL) {
    perror("crl fopen");
    return -1;
  }
  X509_CRL *crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);
  if (crl == NULL) {
    perror("PEM_read_X509_CRL");
    ERR_print_errors_fp(stderr);
    fclose(f);
    return -1;
  }
  
  // Check if it should be updated
  const ASN1_TIME *nupdate = X509_CRL_get0_nextUpdate(crl);
  if (nupdate != NULL) {
    int days = days_until_expiry(nupdate);
    if (days < 2) {
      BIO *b = BIO_new_fp(stderr, BIO_NOCLOSE);
      BIO_printf(b, "%%%% Warning: CRL file %s should %s updated ", tls_crl_file, days < 0 ? "have been" : "be");
      ASN1_TIME_print(b, nupdate);
      BIO_printf(b, days < 0 ? " (%d days ago)" : " (in %d days)\n", days < 0 ? -days : days);
      BIO_free(b);
      char *url = get_cert_crl_dp(cert);
      if (url != NULL)
	fprintf(stderr,"%%%%  Download a new CRL from %s\n", url);
    }
  }
  X509_STORE *store = X509_STORE_new();
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  // Why not validate the chain as well
  if (X509_STORE_load_locations(store, tls_ca_file, NULL) == 0) {
    perror("X509_STORE_load_locations");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  // First set the flag for the store: verify the leaf cert only
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
  // Use this CRL
  X509_STORE_add_crl(store, crl);
  // Init the ctx so it has the store and cert
  X509_STORE_CTX_init(ctx, store, cert, NULL);
  // We're verifying it to be a client cert
  X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT);

  // Now check the cert!
  int r = X509_verify_cert(ctx);
  if (r != 1) {
    int err = X509_STORE_CTX_get_error(ctx);
    fprintf(stderr,"%%%% Warning: the cert %s failed verification: %s\n", fname, X509_verify_cert_error_string(err));
    return err;
  }
  return X509_V_OK;
}

// Return 1 for server cert, otherwise 0
static int
server_cert_p(X509 *cert)
{
  int i;
  EXTENDED_KEY_USAGE *extusage = X509_get_ext_d2i(cert, NID_ext_key_usage, &i, NULL);
  if (extusage == NULL) {
    fprintf(stderr,"%%%% Could not find extended key usage for cert\n");
    ERR_print_errors_fp(stderr);
  } else {
    for (i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
      switch (OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage, i))) {
      case NID_server_auth:
	if (tls_debug) fprintf(stderr,"Server cert\n");
	return 1;
      /* case NID_client_auth: */
      /* 	fprintf(stderr,"Client cert\n"); */
      /* 	break; */
      }
    }
  }
  return 0;
}

static int
validate_cert_file(char *fname)
{
  FILE *f = fopen(fname,"r");
  u_char *client_cn;
  X509 *cert;

  if (f == NULL) {
    perror(fname);
    return -1;
  }
  if ((cert = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
    fprintf(stderr,"TLS: Unable to read X509 cert %s\n", fname);
    ERR_print_errors_fp(stderr);
    fclose(f);
    return -1;
  }
  fclose(f);

  // Check approaching expiration
  const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
  if (notAfter == NULL) {
    fprintf(stderr,"%%%% TLS: can't find expiration of cert %s\n", fname);
    return -1;
  } else {
    if (tls_debug) {
      BIO *b = BIO_new_fp(stderr, BIO_NOCLOSE);
      int days = days_until_expiry(notAfter);
      BIO_printf(b, "TLS: certificate %s expires in %d days, on ", fname, days);
      ASN1_TIME_print(b, notAfter);
      BIO_printf(b, "\n");
      BIO_free(b);
    }
    int cmp;
    time_t ptime = time(NULL) + (tls_cert_expiry_warning_days*24*60*60);
    if ((cmp = X509_cmp_time(notAfter, &ptime)) == 0) {
      perror("%%%% TLS: failed to compare expiration time");
      return -1;
    } else if (cmp < 0) {
      int days = days_until_expiry(notAfter);
      BIO *b = BIO_new_fp(stderr, BIO_NOCLOSE);
      if (days == 0)
	BIO_printf(b, "%%%% TLS: certificate %s expires TODAY: ", fname);
      else if (days < 0)
	BIO_printf(b, "%%%% TLS: certificate %s EXPIRED %d days ago: ", fname, -days);
      else 
	BIO_printf(b, "%%%% TLS: certificate %s expiring in %d days: ", fname, days);
      ASN1_TIME_print(b, notAfter);
      BIO_printf(b, "\n%%%% check https://github.com/bictorv/chaosnet-bridge/blob/master/TLS.md for how to renew it!\n");
      BIO_free(b);
      if (days <= 0)
	// Make sure to do something about it, like terminate
	return -1;
    }
  }

  // Check there is a CN
  client_cn = tls_get_cert_cn(cert);
  if (client_cn == NULL) {
    fprintf(stderr,"%%%% TLS: no CN found for cert in %s\n", fname);
    // Make sure to do something about it, like terminate
    return -1;
  } else if (tls_debug) 
    fprintf(stderr,"TLS certificate %s has CN %s\n", fname, client_cn);

#if CHAOS_DNS
  // Check the addresses of the CN
  u_short claddrs[4];
  int i, j, naddrs = dns_addrs_of_name(client_cn, (u_short *)&claddrs, 4);
  if (naddrs < -1) {
    fprintf(stderr,"%%%% TLS: DNS error when getting addresses of client CN %s\n", client_cn);
  }
  if (tls_debug) {
    fprintf(stderr, "TLS cert CN %s has %d Chaos address(es): ", client_cn, naddrs);
    for (i = 0; i < naddrs; i++)
      fprintf(stderr,"%#o ", claddrs[i]);
    fprintf(stderr,"\n");
  }
  int found = 0;
  if (do_tls_server) {
    // Check if configured myaddrs are among server CN addresses
    // (Check if server CN addresses are configured in myaddrs: not necessarily)
    for (i = 0; i < tls_n_myaddrs; i++) {
      found = 0;
      for (int j = 0; j < naddrs; j++) {
	if (claddrs[j] == tls_myaddrs[i]) {
	  found = 1;
	  break;
	}
      }
      if (!found) {
	// Couldn't find this myaddr among CN addresses, see whose it is?
	u_char hname[256];	/* random size limit */
	int nlen;
	if ((nlen = dns_name_of_addr(tls_myaddrs[i], hname, sizeof(hname))) < 0) {
	  if (nlen < -1)
	    fprintf(stderr,"%%%% TLS: DNS error while looking up myaddr:\n");
	  fprintf(stderr,"%%%% TLS: Addresses of cert %s CN %s do not match the configured myaddr %#o\n", 
		  fname, client_cn, tls_myaddrs[i]);
	} else
	  fprintf(stderr,"%%%% TLS: Configured myaddr %#o does not belong to cert %s CN %s but to %s\n", 
		tls_myaddrs[i], fname, client_cn, hname);
	// Make sure to do something about it, like terminate
	return -1;
      } else if (tls_debug) 
	fprintf(stderr,"TLS found myaddr %#o in addresses of %s\n", tls_myaddrs[i], client_cn);
    }
  }
  // Check that all TLS links have a myaddr among the CN addresses
  for (i = 0; i < tlsdest_len; i++) {
    if (tlsdest[i].tls_myaddr != 0) {
      found = 0;
      for (j = 0; j < naddrs; j++) {
	if (tlsdest[i].tls_myaddr == claddrs[j]) {
	  found = 1;
	  break;
	}
      }
      if (!found) {
	u_char hname[256];	/* random size limit */
	int nlen;
	if ((nlen = dns_name_of_addr(tlsdest[i].tls_myaddr, hname, sizeof(hname))) < 0) {
	  if (nlen < -1)
	    fprintf(stderr,"%%%% TLS: DNS error while looking up myaddr:\n");
	  fprintf(stderr,"%%%% TLS: myaddr %#o of tls destination %d (%s) not among addresses of cert %s CN %s\n",
		  tlsdest[i].tls_myaddr, i, tlsdest[i].tls_name, fname, client_cn);
	} else
	  fprintf(stderr,"%%%% TLS: myaddr %#o of tls destination %d (%s) does not belong to cert %s CN %s but to %s\n",
		  tlsdest[i].tls_myaddr, i, tlsdest[i].tls_name, fname, client_cn, hname);
	// Make sure to do something about it, like terminate
	return -1;
      } else if (tls_debug)
	fprintf(stderr,"TLS found tlsdest %d (%s) myaddr %#o in addresses of cert CN %s\n",
		i, tlsdest[i].tls_name, tlsdest[i].tls_myaddr, client_cn);
    }
  }
#endif // CHAOS_DNS
  // Check that it hasn't been revoked
  if (strlen(tls_crl_file) > 0) {
    if (validate_cert_vs_crl(cert, fname) != 0)
      return -1;
  } else if (server_cert_p(cert)) {
    fprintf(stderr,"%%%% Warning: your certificate can be used for a server, but you have not configured a crl.\n"
	    "%%%% Please do - see https://github.com/bictorv/chaosnet-bridge/blob/master/TLS.md for how\n");
  }
  if (do_tls_server && !server_cert_p(cert)) {
    fprintf(stderr,"%%%% Error: your certificate can not be used for a server, "
	    "but your configured cbridge to start a tls server.\n"
	    "%%%% If you want to run a server, get a new certificate!\n");
    return -1;
  }
  return 0;
}

// module initialization
void init_chaos_tls()
{
  init_openssl();
  if (validate_cert_file(tls_cert_file) < 0) {
    fprintf(stderr,"TLS: certificate problem - see message above\n");
    exit(1);
  }
}
