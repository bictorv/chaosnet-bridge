/* Copyright © 2018 Björn Victor (bjorn@victor.se) */
/* Program to tunnel UDP over TCP,
   intended for (or as a prototype for) the bridge program for various
   Chaosnet implementations.

   The main use case is when one end of the UDP communication doesn't
   have a public IP address, and thus can't receive UDP at a specific
   port, and only in response to an outgoing UDP packet.

   However, in this situation the server does't know the client
   address beforehand, and it becomes hard/unfeasible to configure a
   firewall for protection. Thus we need to use TLS (which is a good
   thing anyway). The drawback is the cert management...
*/
// TODO:
// - TLS (without + with cert verification)
// - statistics
// - keep-alive?
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

#ifndef UTTUN_TLS
// **** TLS stuff.
// See https://wiki.openssl.org/index.php/Simple_TLS_Server,
//     https://github.com/CloudFundoo/SSL-TLS-clientserver
# define UTTUN_TLS 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>

#if UTTUN_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

// connect from remote/client (non-permanent-IP) end to server (with permanent IP)
// read UDP pkts at one end, send to the other over TCP, resend to UDP dest there
// - so two threads at each end
// when either end gets an error (on TCP), try to re-open TCP,
// - can happen both on reading and writing
// - client connects, server listens
// - so third thread does the connect/listen
// re-parse server spec at re-open time (in case it moves)

// some authentication? 
// - minimize attack vector - maybe use TLS?
// - initial handshake to "validate" that the other end speaks BSWM?
// some robustness/input (content) validation? 
// - Check for CHUDP header, at least? Minimum length (CHUDP+Chaos headers)?

// consider using setsockopt(tsock, SO_LINGER, {1, 0}) to make close do RST, in error cases
// (cf https://stackoverflow.com/questions/6439790/sending-a-reset-in-tcp-ip-socket-connection)

// add statistics
// - how often do we need to reopen?
// - how often does the address change?
// - how many partial chunks are received?

// maybe add a keep-alive MARK signal, based on how long ago TCP was used?

#define UTTUN_BACKLOG 3
// minimum Chaos max (8*2+288+3*2) + CHUDP header (4) = 510 + UDP header (4*2) = 518
// typical Ether MTU is 1500 - 20 (ip header) - 8 (udp header) = 1472
#define UTTUN_UDP_MAXLEN 1472
#define UTTUN_TCP_MAXLEN UTTUN_UDP_MAXLEN

// default ports
#define UTTUN_UDP_PORT 42042
#define UTTUN_TCP_PORT 42042

int usock; // UDP socket, bidirectional
int tsock; // TCP socket, bidirectional
int tursock; // TCP ur-socket (for listen/accept)
#if UTTUN_TLS
SSL *uttun_ssl; // SSL conn
#endif

struct sockaddr_in udpdest;	/* where to send pkts read from TCP */
struct sockaddr_in tcpdest;	/* where to send pkts read from UDP */

// condition var to wait for open TCP conn
pthread_cond_t tcp_is_open = PTHREAD_COND_INITIALIZER;
// and related mutex
pthread_mutex_t tcp_is_open_mutex = PTHREAD_MUTEX_INITIALIZER;

// condition var to wait for to re-open TCP conn
pthread_cond_t tcp_reconnect = PTHREAD_COND_INITIALIZER;
pthread_mutex_t tcp_reconnect_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_t uthread, tthread, cthread;

// for keeping trace printouts unmixed
pthread_mutex_t trace_print_mutex = PTHREAD_MUTEX_INITIALIZER;

#define TRACE_SIGNALS 1
#define TRACE_UDP 2
#define TRACE_TCP 4
#define TRACE_PACKETS 8
int trace = 0;

void dumppkt(unsigned char *ucp, int cnt);

void tprintln(char *fmt, ...)
{
  struct tm ltime;
  char ts[5+3+3+3+3+3+1];
  time_t now = time(NULL);
  pthread_t self = pthread_self();
  char tid[14];
  sprintf(tid, "%#08x", (unsigned int)self);

  localtime_r(&now,&ltime);
  strftime(ts, sizeof(ts), "%Y-%d-%m %H:%M:%S", &ltime);

  pthread_mutex_lock(&trace_print_mutex);
  fprintf(stderr, "%s %-10s ", ts, (self == uthread ? "UDP" : (self == tthread ? "TCP" : self == cthread ? "conn" : tid)));
  {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  }
  fputs("\n", stderr);
  pthread_mutex_unlock(&trace_print_mutex);
}

// **** signalling between threads
void please_reopen_tcp()
{
  if (trace & TRACE_SIGNALS)
    tprintln("! please_reopen_tcp");
  // signal the connection thread - don't care if nobody's waiting (already working on it, probably)
  if (pthread_mutex_lock(&tcp_reconnect_mutex) < 0)
    perror("pthread_mutex_lock(reconnect)");
  if (pthread_cond_signal(&tcp_reconnect) < 0) {
    perror("please_reopen_tcp\n");
    exit(1);
  } 
  if (pthread_mutex_unlock(&tcp_reconnect_mutex) < 0)
    perror("pthread_mutex_unlock(reconnect)");
}
void wait_for_reconnect_signal()
{
  /* wait for someone to ask for reconnection, typically after an error in read/write */
  if (trace & TRACE_SIGNALS)
    tprintln("! wait_for_reconnect_signal...");

  pthread_mutex_lock(&tcp_reconnect_mutex);
  if (pthread_cond_wait(&tcp_reconnect, &tcp_reconnect_mutex) < 0) {
    perror("wait_for_reconnect_signal");
    exit(1);
  }
  if (pthread_mutex_unlock(&tcp_reconnect_mutex) < 0)  {
    perror("wait_for_reconnect_signal(unlock)");
    exit(1);
  }
  if (trace & TRACE_SIGNALS)
    tprintln("! wait_for_reconnect_signal done");
}

void inform_tcp_is_open()
{
  if (trace & TRACE_SIGNALS)
    tprintln("! inform_tcp_is_open");
  if (pthread_mutex_lock(&tcp_is_open_mutex) < 0)
    perror("pthread_mutex_lock(tcp_is_open)");
  /* wake everyone waiting on this */
  if (pthread_cond_broadcast(&tcp_is_open) < 0) {
    perror("inform_tcp_is_open");
    exit(1);
  }
  if (pthread_mutex_unlock(&tcp_is_open_mutex) < 0)
    perror("pthread_mutex_unlock(tcp_is_open)");
}
void wait_for_tcp_open()
{
  /* wait for tcp_is_open, and get a mutex lock */

  if (trace & TRACE_SIGNALS)
    tprintln("! wait_for_tcp_open...");

  pthread_mutex_lock(&tcp_is_open_mutex);
  if (trace & TRACE_SIGNALS)
    tprintln("! wait_for_tcp_open got lock, waiting...");
  if (pthread_cond_wait(&tcp_is_open, &tcp_is_open_mutex) < 0) {
    perror("wait_for_tcp_open(wait)");
    exit(1);
  }
  if (trace & TRACE_SIGNALS)
    tprintln("! wait_for_tcp_open got signal");

  if (pthread_mutex_unlock(&tcp_is_open_mutex) < 0)  {
    perror("wait_for_tcp_open(unlock)");
    exit(1);
  }
  if (trace & TRACE_SIGNALS)
    tprintln("! wait_for_tcp_open done");
}

// **** write a record length (two bytes MSB first) and that many bytes
#if UTTUN_TLS
int tcp_write_record(SSL *ssl, u_char *buf, int len)
#else
int tcp_write_record(int fd, u_char *buf, int len)
#endif
{
  u_char reclen[2];
  struct iovec iov[2];
  int wrote;

  if (len > 0xffff) {
    fprintf(stderr,"tcp_write_record: too long: %#x  > 0xffff\n", len);
    exit(1);
  }
  if (len > UTTUN_TCP_MAXLEN) {
    fprintf(stderr,"tcp_write_record: too long: %#x > %#x\n", len, UTTUN_TCP_MAXLEN);
    exit(1);
  }

#if UTTUN_TLS
  u_char obuf[UTTUN_TCP_MAXLEN+2];

  obuf[0] = (len >> 8) & 0xff;
  obuf[1] = len & 0xff;
  memcpy(obuf+2, buf, len);
  if ((wrote = SSL_write(ssl, obuf, 2+len)) <= 0) {
    int err = SSL_get_error(ssl, wrote);
    // punt;
    fprintf(stderr,"SSL_write error %d\n", err);
    ERR_print_errors_fp(stderr);
#if 1 // debug
    exit(1);
#else // probably what we want later
    please_reopen_tcp();
#endif
  }
#else
  reclen[0] = (len >> 8) & 0xff;
  reclen[1] = len & 0xff;

  iov[0].iov_base = reclen;
  iov[0].iov_len = 2;
  iov[1].iov_base = buf;
  iov[1].iov_len = len;

  if ((wrote = writev(fd, iov, 2)) < 0) {
    perror("writev");
/*     close(fd); */
    please_reopen_tcp();
  }
#endif
  else if (wrote != len+2)
    fprintf(stderr,"tcp_write_record: wrote %d bytes != %d\n", wrote, len+2);
  else if (trace & TRACE_TCP)
    tprintln("> TCP sent %d bytes (reclen %d)", wrote, len);


  return wrote;
}

// **** read a record length (two bytes MSB first) and that many bytes
#if UTTUN_TLS
int tcp_read_record(SSL *ssl, u_char *buf, int blen)
#else
int tcp_read_record(int fd, u_char *buf, int blen)
#endif
{
  int cnt, rlen, actual;
  u_char reclen[2];

#if UTTUN_TLS
  cnt = SSL_read(ssl, reclen, 2);
#else
  cnt = read(fd, reclen, 2);
#endif
  if ((cnt) < 0) {
    perror("read record length");
    please_reopen_tcp();
    return -1;
  }
  if (cnt == 0) {
    // EOF
    if (trace & TRACE_TCP)
      tprintln("< 0 bytes read");
    please_reopen_tcp();
    return -1;
  } else if (cnt != 2) {
    if (trace & TRACE_TCP)
      tprintln("< record len not 2: %d", cnt);
    return 0;
  }
  rlen = reclen[0] << 8 | reclen[1]; //ntohs(reclen[0] << 8 || reclen[1]);
  if (rlen == 0) {
    if (trace & TRACE_TCP)
      tprintln("< TCP MARK read");
    return 0;
  }
 if (trace & TRACE_TCP)
   tprintln("< TCP record len %d", rlen);
  if (rlen > blen) {
    tprintln("TCP record too long for buffer: %d > %d", rlen, blen);
    please_reopen_tcp();
    return -1;
  }
#if UTTUN_TLS
  actual = SSL_read(uttun_ssl, buf, rlen);
#else
  actual = read(fd, buf, rlen);
#endif
  if (actual < 0) {
    perror("read record");
    please_reopen_tcp();
    return -1;
  }
  if (actual < rlen) {
    if (trace & TRACE_TCP)
      tprintln("< TCP read less than record: %d < %d", actual, rlen);
    // read the remaining data
    int p = actual;
    while (rlen - p > 0) {
#if UTTUN_TLS
      actual = SSL_read(uttun_ssl, &buf[p], rlen-p);
#else
      actual = read(fd, &buf[p], rlen-p);
#endif
      if (actual < 0) {
	perror("re-read record");
	please_reopen_tcp();
	return -1;
      }
      if (trace & TRACE_TCP)
	tprintln("< TCP read %d more bytes", actual);
      if (actual == 0) {
	please_reopen_tcp();
	return -1;
      }
      p += actual;
    }
    actual = p;
  }
  if (trace & TRACE_TCP)
    tprintln("< TCP read %d bytes total", actual);

  if (trace & TRACE_PACKETS)
    dumppkt(buf,actual);
  return actual;
}

// **** low-level stuff
int tcp_server_accept(int sock)
{
  struct sockaddr_in caddr;
  int fd;
  u_int clen = sizeof(struct sockaddr_in);

  if ((fd = accept(sock, (struct sockaddr *)&caddr, &clen)) < 0) {
    perror("accept");
    // @@@@ better error handling, back off and try again? what could go wrong here?
    exit(1);
  }
  // @@@@ log stuff about the connection
  // @@@@ maybe validate/authenticate the other end
  if (trace & TRACE_TCP)
    tprintln("  TCP accept connection from %s port %d",
	     inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
 
  return fd;
}

void tcp_server_listen(int sock)
{
  if (listen(sock, UTTUN_BACKLOG) < 0) {
    perror("listen");
    exit(1);
  }
}

int tcp_client_connect(struct sockaddr_in *sin)
{
  int sock, unlucky = 1, foo;
  
  while (unlucky) {
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket(tcp)");
      exit(1);
    }

    if (connect(sock, (struct sockaddr *)sin, sizeof(struct sockaddr_in)) < 0) {
      perror("connect");
      // @@@@ better error handling, back off and try again - the other end might be down
      if (trace & TRACE_TCP)
	tprintln("  TCP trying again in %d s", unlucky);
      if ((foo = sleep(unlucky)) != 0)
	tprintln("  TCP sleep returned %d", foo);
      unlucky++;
      if (unlucky > 30) unlucky /= 3;
      if (close(sock) < 0)
	perror("close(tcp_client_connect)");
      continue;
    }
    else
      unlucky = 0;
  }
  // @@@@ log stuff about the connection
  if (trace & TRACE_TCP)
    tprintln("  TCP connected to %s port %d",
	     inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));

  return sock;  
}

int bind_socket(int type, u_short port) 
{
  int sock;
  struct sockaddr_in sin;

  if ((sock = socket(AF_INET, type, 0)) < 0) {
    perror("socket failed");
    exit(1);
  }
  // @@@@ SO_REUSEADDR or SO_REUSEPORT
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
    perror("setsockopt(SO_REUSEADDR)");

  if (trace)
    tprintln("  binding socket type %d (%s) to port %d", 
	     type, (type == SOCK_DGRAM ? "dgram" : (type == SOCK_STREAM ? "stream" : "?")),
	     port);
  memset(&sin,0,sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock,(struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("bind() failed");
    exit(1);
  }
  return sock;
}

void
udp_send_pkt(int sock, struct sockaddr_in *sout, unsigned char *buf, int len)
{
  ssize_t n;
  if ((n = sendto(sock, buf, len, 0, (struct sockaddr *)sout, sizeof(struct sockaddr_in))) < 0) {
    perror("sendto failed");
    exit(1);
  }
  if (trace & TRACE_UDP)
    tprintln("> UDP send %d bytes to %s port %d", n, inet_ntoa(sout->sin_addr), ntohs(sout->sin_port));
}

int
udp_receive(int sock, unsigned char *buf, int buflen)
{
  struct sockaddr_in sin;
  u_int sinlen;
  int cnt;

  memset(&sin,0,sizeof(sin));
  sinlen = sizeof(sin);
  cnt = recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&sin, &sinlen);
  if (cnt < 0) {
    perror("recvfrom");
    exit(1);
  }
  if (trace & TRACE_UDP)
    tprintln("< UDP read %d bytes from %s port %d", cnt,
	     inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

  if (trace & TRACE_PACKETS)
    dumppkt(buf,cnt);
  return cnt;
}

#if UTTUN_TLS
void init_openssl()
{ 
  SSL_library_init();
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_some_context(SSL_METHOD *method)
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

SSL_CTX *create_client_context()
{
  SSL_METHOD *method;

    method = SSLv23_client_method();
    return create_some_context(method);
}

SSL_CTX *create_server_context()
{
   SSL_METHOD *method;
    method = SSLv23_server_method();
    return create_some_context(method);
}

void configure_context(SSL_CTX *ctx)
{
  // Auto-select elliptic curve
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    // @@@@ parameter
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    // @@@@ parameter
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
      fprintf(stderr,"Private key and certificate is not matching\n");
      exit(EXIT_FAILURE);
    }
#if UTTUN_TLS_VERIFY
    // See function man pages for instructions on generating CERT files
    if (!SSL_CTX_load_verify_locations(ctx, SSL_SERVER_RSA_CA_CERT, NULL)) {
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
      }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
#endif
}
#endif // UTTUN_TLS

// **** read from UDP, send on TCP
void *udp_listener(void *arg)
{
  int rlen, wlen;
  u_char ubuf[UTTUN_UDP_MAXLEN];

  // wait for initial open
  wait_for_tcp_open();

  while (1) {
    rlen = udp_receive(usock, (u_char *)&ubuf, sizeof(ubuf));
    // @@@@ make sure it's from the right source? here or in udp_receive
    if (rlen > 0) {
#if UTTUN_TLS
      wlen = tcp_write_record(uttun_ssl, (u_char *)&ubuf, rlen);
#else
      wlen = tcp_write_record(tsock, (u_char *)&ubuf, rlen);
#endif

      if (wlen < 0) {
	// error. tcp_write_record already closed and asked for reopen.
	// wait for it to happen.
	wait_for_tcp_open();
      }
    }
  }
}

// **** read from TCP, send on UDP
void *tcp_reader(void *arg)
{
  int rlen;
  u_char tbuf[UTTUN_TCP_MAXLEN];

  // wait for initial open
  wait_for_tcp_open();

  while (1) {
#if UTTUN_TLS
    rlen = tcp_read_record(uttun_ssl, (u_char *)&tbuf, sizeof(tbuf));
#else
    rlen = tcp_read_record(tsock, (u_char *)&tbuf, sizeof(tbuf));
#endif

    if (rlen > 0) {
      udp_send_pkt(usock, &udpdest, (u_char *)&tbuf, rlen);
    } else if (rlen < 0) {
      // error. tcp_read_record already closed and asked for reopen.
      // wait for it to happen.
      wait_for_tcp_open();
    }
  }
}

// **** keep connected
void *tcp_listener(void *arg)
{
  tcp_server_listen(tursock);

  sleep(1); // make sure the other threads are waiting

#if UTTUN_TLS
  SSL *ssl;
  SSL_CTX *ctx = create_server_context();
  configure_context(ctx);
#endif

  while (1) {
    tsock = tcp_server_accept(tursock);
#if UTTUN_TLS
    if ((ssl = SSL_new(ctx)) == NULL) {
      fprintf(stderr,"SSL_new failed");
      ERR_print_errors_fp(stderr);
      close(tsock);
      continue;
    }
    SSL_set_fd(ssl, tsock);
    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      close(tsock);
      SSL_free(ssl);
      continue;
    }
#if UTTUN_TLS_VERIFY
    X509 *ssl_client_cert = NULL;

    ssl_client_cert = SSL_get_peer_certificate(ssl);

    if(ssl_client_cert) {
	long verifyresult;

	verifyresult = SSL_get_verify_result(ssl);
	if(verifyresult != X509_V_OK) {
	  fprintf(stderr,"Certificate Verify Failed\n"); 
	}
	X509_free(ssl_client_cert);				
      }
    else
      fprintf(stderr,"There is no client certificate\n");
#endif
    uttun_ssl = ssl;
#endif

    inform_tcp_is_open();

    wait_for_reconnect_signal();
#if UTTUN_TLS
    SSL_free(ssl);
    uttun_ssl = NULL;
#endif
#if 1
    // should already be closed, ignore return
    close(tsock);
#else
    if (close(tsock) < 0)
      perror("close(tcp)");
#endif
  }
}

void *tcp_connector(void *arg)
{
#if UTTUN_TLS
  SSL *ssl;
  SSL_CTX *ctx = create_client_context();
  configure_context(ctx);
#endif

  while (1) {
				// @@@@ re-parse tcpdest?
    // connect to server
    tsock = tcp_client_connect(&tcpdest);

#if UTTUN_TLS
    if ((ssl = SSL_new(ctx)) == NULL) {
      fprintf(stderr,"SSL_new failed");
      ERR_print_errors_fp(stderr);
      close(tsock);
      continue;
    }
    SSL_set_fd(ssl, tsock);
    if (SSL_connect(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(tsock);
      continue;
    }
#if UTTUN_TLS_VERIFY
    X509 *ssl_server_cert = NULL;

    ssl_server_cert = SSL_get_peer_certificate(ssl);

    if(ssl_server_cert) {
	long verifyresult;

	verifyresult = SSL_get_verify_result(ssl);
	if(verifyresult != X509_V_OK) {
	  fprintf(stderr,"Certificate Verify Failed\n"); 
	}
	X509_free(ssl_server_cert);				
      }
    else
      fprintf(stderr,"There is no server certificate\n");
#endif
    uttun_ssl = ssl;
#endif

    // tell others about it
    inform_tcp_is_open();

    // wait for someone to ask us to reconnect
    wait_for_reconnect_signal();
    // make sure it's closed, try to tell the other end
    if (close(tsock) < 0)
      ; // should already be closed, ignore.
	// perror("close(tcp)");
#if UTTUN_TLS
    uttun_ssl = NULL;
    SSL_free(ssl);
#endif
  }
}


// **** main stuff
int parse_dest(char *token, u_short *port, u_short *myport, struct sockaddr_in *sin)
{
  // @@@@ rewrite using gettaddrinfo
  struct hostent *he;
  struct in_addr ip;
  char s[256];
  int val, a, b;

  if (trace > 0)
    tprintln("parsing host spec %s", token);

  if (sscanf(token, "%d:%[^:]:%d", &a, (char *)&s, &b) == 3) {
    if ((he = gethostbyname(s)) == NULL) {
      fprintf(stderr,"bad host '%s'\n", s);
      return -1;
    }
    tprintln("parsed myport:host:port %d:%s:%d", a, s, b);
    *myport = a;
    *port = b;
  } else if (sscanf(token, "%d:%s", &a, (char *)&s) == 2) {
    if ((he = gethostbyname(s)) == NULL) {
      fprintf(stderr,"bad host '%s' (d:s)\n", s);
      return -1;
    }
    tprintln("parsed myport:host %d:%s", a, s);
    *myport = a;
  } else if (sscanf(token,"%[^:]:%d", (char *)&s, &b) == 2) {
    if ((he = gethostbyname(s)) == NULL) {
      fprintf(stderr,"bad host '%s' (s:d)\n", s);
      return -1;
    }
    tprintln("parsed host:port %s:%d", s, b);
    *port = b;
  } else if ((inet_aton(token, &ip) == 1) &&
	     (inet_netof(ip) != 0) &&
	     (inet_lnaof(ip) != 0)) {
    if ((he = gethostbyname(token)) == NULL) {
      fprintf(stderr,"bad host '%s' (ip)\n", token);
      return -1;
    }
    tprintln("parsed host %s", token);
  } else if (sscanf(token,"%d", &b) == 1) {
    fprintf(stderr,"must specify host - '%s'\n", token);
    return -1;
  } else if ((he = gethostbyname(token)) == NULL) {
    fprintf(stderr,"bad host '%s' (plain)\n", token);
    return -1;
  }

  memset(sin,0,sizeof(struct sockaddr_in));
  sin->sin_family = AF_INET;
  sin->sin_port = htons(*port);
  memcpy((u_char *)&sin->sin_addr.s_addr, (u_char *)he->h_addr, he->h_length);

  return 0;
}

int main(int argc, char *argv[])
{
  signed char c;
  char *x;
  int server_end = 1;
  u_short uport = UTTUN_UDP_PORT, 
    myuport = UTTUN_UDP_PORT,
    tport = UTTUN_TCP_PORT,
    mytport = UTTUN_TCP_PORT,
    val;


  memset(&udpdest, 0, sizeof(udpdest));
  memset(&tcpdest, 0, sizeof(tcpdest));

  // parse args
  // -u host:port -t host:port -p port -t[ut]
  while ((c = getopt(argc, argv, "u:t:d:")) != -1) {
    switch (c) {
    case 'd':
      if (strncmp(optarg,"t",1) == 0)
	trace |= TRACE_TCP;
      else if (strncmp(optarg,"u",1) == 0)
	trace |= TRACE_UDP;
      else if (strncmp(optarg,"s",1) == 0)
	trace |= TRACE_SIGNALS;
      else if (strncmp(optarg,"p",1) == 0)
	trace |= TRACE_PACKETS;
      else if (strncmp(optarg,"a",1) == 0)
	trace = 0xffff;
      else if ((val = atoi(optarg)) != 0)
	trace = val;
      else
	fprintf(stderr,"unknown trace spec '%s'\n", optarg);
      break;
    case 'u':
      // specifying the UDP destination for received TCP data,
      // at either end
      if (parse_dest(optarg, &uport, &myuport, &udpdest) < 0)
	exit(1);
      break;
    case 't':
      // specifying the TCP destination for received UDP data,
      // thus this is the TCP client end
      if (parse_dest(optarg, &tport, &mytport, &tcpdest) < 0)
	exit(1);
      server_end = 0;
      break;
    default:
      fprintf(stderr,"unknown option '%c'\n", c);
      fprintf(stderr,"usage: %s [-u [myport:]host[:port]] | [-t [myport:]host[:port]] [-d t|u|s|p|a]\n"
	      "  -u for UDP destination (where to send TCP data)\n"
	      "  -t for TCP destination (where to send UDP data)\n"
	      "     (omit this for the server end)\n"
	      "  -d s for tracing the synchronization thread (1)\n"
	      "  -d u for tracing the UDP thread (2)\n"
	      "  -d t for tracing the TCP thread (4)\n"
	      "  -d p for printing pkts received as Chaosnet pkts (8)\n"
	      "  -d a for tracing everything\n"
	      "  -d N for enabling trace bits N (e.g. 7 for all threads, but not Chaos pkts)\n",
	      argv[0]);
      exit(1);
    }
  }

  if (udpdest.sin_addr.s_addr == 0) {
    fprintf(stderr,"must specify UDP destination\n");
    exit(1);
  }

  if (trace > 0) {
    char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
    fprintf(stderr,"%s mode\nUDP: %s port %d (my %d)\nTCP: %s port %d (my %d)\n",
	    (server_end ? "server" : "client"), 
	    inet_ntop(udpdest.sin_family, &udpdest.sin_addr,ip1, sizeof(ip1)),
	    ntohs(udpdest.sin_port), myuport, 
	    inet_ntop(tcpdest.sin_family, &tcpdest.sin_addr,ip2, sizeof(ip2)),
	    ntohs(tcpdest.sin_port), mytport);
  }
  // ignore SIGPIPE, we just want the error return from writev, not a bleeping crash
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler=SIG_IGN;
  sigaddset(&sa.sa_mask, SIGPIPE);
  if (sigaction(SIGPIPE, &sa, NULL) < 0)
    perror("sigaction(SIGPIPE)");

#if UTTUN_TLS
  init_openssl();
#endif

  if (server_end) {
    // send from my local port (this is also where replies go)
    usock = bind_socket(SOCK_DGRAM, myuport);
    // listen to the specified server port
    tursock = bind_socket(SOCK_STREAM, mytport);
  } else {
    // receive on this UDP port (tursock not used, replies sent to the connection)
    usock = bind_socket(SOCK_DGRAM, myuport);
  }


  // one thread to read from UDP, send to TCP
  if (pthread_create(&uthread, NULL, &udp_listener, NULL) < 0) {
    perror("pthread_create(udp_listener)");
    exit(1);
  }
  // one thread to read from TCP, send to UDP
  if (pthread_create(&tthread, NULL, &tcp_reader, NULL) < 0) {
    perror("pthread_create(tcp_reader)");
    exit(1);
  }
  // and one to keep the connection up
  if (server_end) {
    if (pthread_create(&cthread, NULL, &tcp_listener, NULL) < 0) {
      perror("pthread_create(tcp_listener)");
      exit(1);
    }
  } else {
    if (pthread_create(&cthread, NULL, &tcp_connector, NULL) < 0) {
      perror("pthread_create(tcp_connector)");
      exit(1);
    }
  }
  while(1) // ho hum
    sleep(15);
  
}

// ****************************************************************
// **** Debug stuff
#include "cbridge-chaos.h"	/* chaos pkt format etc */
#include "chudp.h"		/* chudp pkt format etc */

static unsigned int
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

static char *
ch_opcode_name(int op)
  {
    if (op < 017 && op > 0)
      return ch_opc[op];
    else if (op == 0200)
      return "DAT";
    else if (op == 0300)
      return "DWD";
    else
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
char *
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

void
ch_11_puts(unsigned char *out, unsigned char *in) 
{
  int i, x = ((strlen((char *)in)+1)/2)*2;
  for (i = 0; i < x; i++) {
    if (i % 2 == 1)
      out[i-1] = in[i];
    else
      out[i+1] = in[i];
  }
}

unsigned char *
ch_11_gets(unsigned char *in, unsigned char *out, int maxlen)
{
  int i, l = ((strlen((char *)in)+1)/2)*2;
  if (l > maxlen)
    l = maxlen;
  for (i = 0; i < l /* && ((in[i] & 0200) == 0) */; i++) { /* Where did I get 0200 bit from? */
    if (i % 2 == 1)
      out[i] = in[i-1];
    else
      out[i] = in[i+1];
  }
  out[i] = '\0';
  return out;
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

void
ch_dumpkt(unsigned char *ucp, int cnt)
{
  int i, row, len;
  char b1[3],b2[3];
  struct chaos_header *ch = (struct chaos_header *)ucp;
  struct chaos_hw_trailer *tr;
  unsigned char *data = malloc(ch_nbytes(ch)+1);

  fprintf(stderr,"Opcode: %o (%s), unused: %o\r\nFC: %o, Nbytes %d.\r\n",
	  ch_opcode(ch), ch_opcode_name(ch_opcode(ch)),
	  ch->ch_opcode_u.ch_opcode_s.ch_unused,
	  ch_fc(ch), ch_nbytes(ch));
  fprintf(stderr,"Dest host: %o, index %o\r\nSource host: %o, index %o\r\n",
	  ch_destaddr(ch), ch_destindex(ch), ch_srcaddr(ch), ch_srcindex(ch));
  fprintf(stderr,"Packet #%o\r\nAck #%o\r\n",
	  ch_packetno(ch), ch_ackno(ch));

  fprintf(stderr,"Data:\r\n");

  len = ch_nbytes(ch);
  tr = (struct chaos_hw_trailer *)&ucp[cnt-6];

  /* Skip headers */
  ucp += CHAOS_HEADERSIZE;

  switch (ch_opcode(ch)) {
  case CHOP_RFC:
    ch_11_gets(ucp, data, ch_nbytes(ch));
    fprintf(stderr,"[Contact: \"%s\"]\n", data);
    break;

  case CHOP_OPN:
  case CHOP_STS:
    {
      unsigned short rcpt, winsz;
      rcpt = WORD16(ucp);
      winsz = WORD16(ucp+2);
      fprintf(stderr,"[Received up to and including %#o, window size %#o]\n",
	     rcpt, winsz);
      break;
    }
  case CHOP_CLS:
  case CHOP_LOS:
    ch_11_gets(ucp, data, ch_nbytes(ch));
    fprintf(stderr,"[Reason: \"%s\"]\n", data);
    break;

  case CHOP_FWD:
    ch_11_gets(ucp, data, ch_nbytes(ch));
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
  if (cnt < len)
    fprintf(stderr,"... (header length field > buf len)\n");

  /* Now show trailer */
  if (len % 2)
    len++;			/* Align */
  if (cnt < len+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE)
    fprintf(stderr,"[Incomplete trailer: pkt size %d < (header + len + trailer size) = %lu]\n",
	    cnt, len+CHAOS_HEADERSIZE+CHAOS_HW_TRAILERSIZE);
  else {
    u_int cks = ch_checksum((u_char *)ch, len);
    fprintf(stderr,"HW trailer:\r\n  Dest: %o\r\n  Source: %o\r\n  Checksum: %#x (%#x)\r\n",
	    ntohs(tr->ch_hw_destaddr), ntohs(tr->ch_hw_srcaddr), ntohs(tr->ch_hw_checksum),
	    cks);
  }
}

void
dumppkt(unsigned char *ucp, int cnt)
{
    fprintf(stderr,"CHUDP version %d, function %d\n", ucp[0], ucp[1]);
    ch_dumpkt(ucp+CHUDP_HEADERSIZE, cnt-CHUDP_HEADERSIZE);
}