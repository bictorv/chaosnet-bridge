/* Copyright © 2020 Björn Victor (bjorn@victor.se) */
/* Copyright © 2023 Lars Brinkoff <lars@nocrew.org> */

/* RTAPE remote tape server.

   This server was implemented primarily by reading and testing
   against the ITS DUMP tape backup program, which can optionally use
   RTAPE.  The Unix rtape server from MIT/Symbolics was used as a
   secondary reference.
 */

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
#include <sys/ioctl.h>
#include <time.h>

#include "cbridge-chaos.h"
#include "tape-image.h"

#define MAX_PACKET    492  /* Max size of a Chaosnet NCP packet. */
#define MAX_RECORD  65536  /* Max size of a tape record we handle. */

/* From user to server. */
#define CMD_LGI   1  /* Login */
#define CMD_MNT   2  /* Mount */
#define CMD_PRB   3  /* Probe status */
#define CMD_RD    4  /* Read records */
#define CMD_WRT   5  /* Write record */
#define CMD_RWD   6  /* Rewind */
#define CMD_SYN   7  /* Rewind-sync */
#define CMD_UNL   8  /* Rewind-unload */
#define CMD_SPF   9  /* Space files */
#define CMD_SPR  10  /* Space records */
#define CMD_WFM  12  /* Write file mark */
#define CMD_CLS  13  /* Close */
/* From server to user. */
#define CMD_LGR  33  /* Login response */
#define CMD_DTA  34  /* Read data */
#define CMD_RFM  35  /* Read file mark */
#define CMD_STS  36  /* Status */

#define FLG_SOL    000001  /* Solicited */
#define FLG_BOT    000002  /* Beginning of tape */
#define FLG_EOT    000004  /* End of tape */
#define FLG_EOF    000010  /* EOF in read */
#define FLG_NLI    000020  /* Not logged in */
#define FLG_MNT    000040  /* Mounted */
#define FLG_STRG   000100  /* Explanatory string follows status */
#define FLG_HER    000200  /* Hard error */
#define FLG_SER    000400  /* Soft error */
#define FLG_OFFL   001000  /* Offline */
#define FLG_NREC   002000  /* Non-record-oriented device */
/* Not part of status response. */
#define FLG_NOREW  00200000
#define FLG_WRITE  00400000

#define MIN(X, Y)  ((X) < (Y) ? (X) : (Y))

static unsigned char command_data[MAX_RECORD + 3];
static int command_opcode;
static int command_len;
static unsigned char *command_ptr;
static int flags;
static int allow_slash = 0;
static int daemonize = 0;
static int read_only = 0;
static char peer[MAX_PACKET];

#define VERSION 1
static const char *contact = "RTAPE";
static const char *version = "RECORD STREAM VERSION 1\215";

static void serve(void);
static void send_packet(int opcode, const void *data, size_t len);
static void send_status(int id, const char *message);
static void handle_packet(void);

typedef void handler_t(const unsigned char *data, int len);

static handler_t packet_rfc;
static handler_t packet_los;
static handler_t packet_cls;
static handler_t packet_dat;

static handler_t state_ignore;
static handler_t state_version;
static handler_t state_opcode;
static handler_t state_len1;
static handler_t state_len2;
static handler_t state_data;
static handler_t *state;

static handler_t cmd_login;
static handler_t cmd_mount;
static handler_t cmd_probe;
static handler_t cmd_read;
static handler_t cmd_write;
static handler_t cmd_space_file;
static handler_t cmd_space_record;
static handler_t cmd_rewind;
static handler_t cmd_write_mark;
static handler_t cmd_close;

struct handler {
  int opcode;
  handler_t *fn;
};

struct handler packet_handler[] = {
  { CHOP_RFC, packet_rfc },
  { CHOP_LOS, packet_los },
  { CHOP_CLS, packet_cls },
  { CHOP_DAT, packet_dat }
};

#define MAX_HANDLERS (sizeof packet_handler / sizeof packet_handler[0])

struct handler command_handler[] = {
  { CMD_LGI, cmd_login },
  { CMD_MNT, cmd_mount },
  { CMD_PRB, cmd_probe },
  { CMD_RD,  cmd_read },
  { CMD_WRT, cmd_write },
  { CMD_RWD, cmd_rewind },
  { CMD_SPF, cmd_space_file },
  { CMD_SPR, cmd_space_record },
  { CMD_WFM, cmd_write_mark },
  { CMD_CLS, cmd_close }
};

#define MAX_COMMANDS (sizeof command_handler / sizeof command_handler[0])

static char chaos_socket_directory[] = "/tmp";
static FILE *log, *debug;
static int sock = -1;
static int tape;

static void dispatch(int opcode, int n, struct handler *handler,
                     const unsigned char *data, int len)
{
  int i;
  for (i = 0; i < n; i++) {
    if (opcode == handler[i].opcode) {
      handler[i].fn(data, len);
      return;
    }
  }
  fprintf(stderr, "Peer %s: Unknown operation: %d\n", peer, opcode);
  exit(1);
}

static int
connect_to_named_socket(int socktype, char *path)
{
  int sock, slen;
  struct sockaddr_un server;
  
  if ((sock = socket(AF_UNIX, socktype, 0)) < 0) {
    perror("socket(AF_UNIX)");
    exit(1);
  }
  
  server.sun_family = AF_UNIX;
  sprintf(server.sun_path, "%s/%s", chaos_socket_directory, path);
  slen = strlen(server.sun_path)+ 1 + sizeof(server.sun_family);

  if (connect(sock, (struct sockaddr *)&server, slen) < 0) {
    perror("connect(server)");
    exit(1);
  }
  return sock;
}

static void fatal(const char *message)
{
  cmd_close((const unsigned char *)message, 0);
}

static void send_packet(int opcode, const void *data, size_t len)
{
  unsigned char buf[4];
  ssize_t n;

  buf[0] = opcode;
  buf[1] = 0;
  buf[2] = len & 0xFF;
  buf[3] = (len >> 8) & 0xFF;
  n = send(sock, buf, sizeof buf, 0);
  if (n <= 0)
    fatal("Network send error");
  if (len > 0) {
    n = send(sock, data, len, 0);
    if (n <= 0)
      fatal("Network send error");
  }
}

static void packet_rfc(const unsigned char *data, int len)
{
  if (fork())
    serve();
  else {
    strncpy(peer, (const char *)data, len);
    fprintf(log, "Open connection from %s\n", peer);
    state = state_version;
    flags = 0;
    tape = -1;
    send_packet(CHOP_OPN, NULL, 0);
  }
}

static void packet_los(const unsigned char *data, int len)
{
  fatal("Connection error");
}

static void packet_cls(const unsigned char *data, int len)
{
  fatal("Connection closed");
}

static void packet_dat(const unsigned char *data, int len)
{
  state(data, len);
}

static void state_ignore(const unsigned char *data, int len)
{
  (void)data;
  (void)len;
}

static void state_version(const unsigned char *data, int len)
{
  if (strncasecmp((const char *)data, version, strlen(version)) != 0) {
    fprintf(log, "Peer %s: Bad record version\n", peer);
    send_packet(CHOP_CLS, NULL, 0);
    return;
  }

  fprintf(debug, "Record stream version ok\n");
  send_packet(CHOP_DAT, version, strlen(version));
  state = state_opcode;
}

static void state_opcode(const unsigned char *data, int len)
{
  command_opcode = data[0];
  state = state_len1;
  if (len > 1)
    state(data + 1, len - 1);
}

static void state_len1(const unsigned char *data, int len)
{
  command_len = (int)data[0] << 8;
  state = state_len2;
  if (len > 1)
    state(data + 1, len - 1);
}

static void state_len2(const unsigned char *data, int len)
{
  command_len |= data[0];
  state = state_data;
  command_ptr = command_data;
  state(data + 1, len - 1);
}

static void state_data(const unsigned char *data, int len)
{
  int n = MIN(len, command_len - (command_ptr - command_data));
  memcpy(command_ptr, data, n);
  command_ptr += n;
  if (command_ptr - command_data == command_len) {
    dispatch(command_opcode, MAX_COMMANDS, command_handler,
             command_data, command_len);
    state = state_opcode;
    data += n;
    len -= n;
    if (len > 0)
      state(data, len);
  }
}

static void send_command(int command, const void *data, size_t len)
{
  char buf[MAX_PACKET];
  const char *p;
  size_t n;

  buf[0] = command;
  buf[1] = (len >> 8) & 0xFF;
  buf[2] = len & 0xFF;
  n = MIN(len, 450);
  if (n > 0)
    memcpy(buf + 3, data, n);
  len -= n;
  send_packet(CHOP_DAT, buf, n + 3);

  for (p = (const char *)data + n; len > 0; p += n, len -= n) {
    n = MIN(len, 450);
    send_packet(CHOP_DAT, p, n);
  }
}

static void cmd_login(const unsigned char *data, int len)
{
  char buf[1];
  fprintf(log, "Peer %s: Received login: %s\n", peer, data);
  memset(buf, 0, sizeof buf);
  send_command(CMD_LGR, buf, sizeof buf);
}

static char *
parse(char **p)
{
  char *v;
  v = *p;
  while (**p != 0 && **p != ' ')
    (*p)++;
  **p = 0;
  (*p)++;
  return v;
}

static void cmd_mount(const unsigned char *data, int len)
{
  char buf[MAX_PACKET];
  char *p, *type, *reel, *drive, *size, *density;

  strncpy(buf, (const char *)data, len);

  p = buf;
  type = parse(&p);
  reel = parse(&p);
  drive = parse(&p);
  size = parse(&p);
  density = parse(&p);

  while (*p) {
    char *option = parse(&p);
    if (strcasecmp(option, "NOREWIND") == 0)
      flags |= FLG_NOREW;
  }

  fprintf(log, "Peer %s: Mount: type=%s, reel=%s, drive=%s, size=%s, density=%s\n",
          peer, type, reel, drive, size, density);

  if (!allow_slash && strchr(drive, '/')) {
    flags |= FLG_HER;
    send_status(0, "Slash not allowed in drive name");
    fatal("Slash not allowed in drive name");
    return;
  }

  if (strcmp(type, "READ") == 0) {
    tape = read_tape(drive);
    flags = 0;
  } else if (strcmp(type, "WRITE") == 0) {
    if (read_only) {
      flags |= FLG_HER;
      send_status(0, "Only read-only mounts allowed");
      fatal("Only read-only mounts allowed");
      return;
    }
    tape = write_tape(drive);
    flags = FLG_WRITE;
  } else if (strcmp(type, "BOTH") == 0) {
    if (read_only) {
      flags |= FLG_HER;
      send_status(0, "Only read-only mounts allowed");
      fatal("Only read-only mounts allowed");
      return;
    }
    tape = rw_tape(drive);
    flags = FLG_WRITE;
  }
  if (tape == -1) {
    flags |= FLG_HER;
    send_status(0, "Error mounting drive");
    fatal("Error mounting device");
  } else
    flags |= FLG_MNT | FLG_BOT;
}

static void send_status(int id, const char *message)
{
  char buf[MAX_PACKET-3];
  int n = 0;

  memset(buf, 0, sizeof buf);
  buf[0] = VERSION;
  buf[1] = id & 0xFF;
  buf[2] = (id >> 8) & 0xFF;
  buf[33] = flags & 0xFF;
  buf[34] = (flags >> 8) & 0xFF;
  if (message) {
    fprintf(debug, "Peer %s: Send status: %s\n", peer, message);
    buf[33] |= FLG_STRG;
    n = MIN(strlen(message), sizeof buf - 36);
    memcpy(buf+36, message, n);
  }
  send_command(CMD_STS, buf, 36 + n);
}

static void cmd_probe(const unsigned char *data, int len)
{
  int id;
  fprintf(debug, "Peer %s: Probe status\n", peer);
  id = data[0];
  id |= (int)data[1] << 8;
  flags |= FLG_SOL;
  send_status(id, NULL);
  flags &= ~FLG_SOL;
}

static int number(const unsigned char *data, int len)
{
  char buf[100];
  char *p;
  
  strncpy(buf, (const char *)data, len);
  p = buf;
  return atoi(parse(&p));
}

static void millisleep(int ms)
{
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000;
  nanosleep(&ts, NULL);
}

static int pending(void)
{
  int n;
  if (ioctl(sock, FIONREAD, &n) < 0)
    perror("ioctl(FIONREAD)");
  return n > 0;
}

static void cmd_read(const unsigned char *data, int len)
{
  char buf[MAX_RECORD];
  size_t n;
  int records;
  
  if (len == 0) {
    fprintf(log, "Peer %s: Read continuous records\n", peer);
    records = -1;
  } else {
    records = number(data, len);
    fprintf(log, "Peer %s: Read %d records\n", peer, records);
  }
  flags &= ~(FLG_BOT | FLG_EOT | FLG_EOF | FLG_HER | FLG_SER);
  
  while (records == -1 || records-- > 0) {
    if (pending())
      return;

    n = read_record(tape, buf, sizeof buf);
    if (n == RECORD_MARK) {
      fprintf(log, "Peer %s: Read mark\n", peer);
      flags |= FLG_EOF;
      send_command(CMD_RFM, NULL, 0);
      return;
    } else if (n == RECORD_EOM) {
      fprintf(log, "Peer %s: Read end of tape medium\n", peer);
      flags |= FLG_EOT | FLG_HER;
      send_status(0, "End of tape medium");
      return;
    } else if (n & RECORD_ERR) {
      fprintf(log, "Peer %s: Read error\n", peer);
      flags |= FLG_HER;
      send_status(0, "Tape read error");
      return;
    } else {
      fprintf(debug, "Peer %s: Read record: %d octets\n", peer, (int)n);
      send_command(CMD_DTA, buf, n);
      millisleep(10);
    }
  }
}

static void cmd_write(const unsigned char *data, int len)
{
  if ((flags & FLG_WRITE) == 0) {
    flags |= FLG_SER;
    fprintf(log, "Peer %s: Mount read-only, write not allowed\n", peer);
    send_status(0, "Mount read-only, write not allowed");
    return;
  }
  fprintf(log, "Peer %s: Write record: %d octets\n", peer, len);
  flags &= ~(FLG_BOT | FLG_EOT | FLG_EOF | FLG_HER | FLG_SER);
  write_record(tape, data, len);
}

static void space_file(void)
{
  char buf[MAX_RECORD];
  size_t m;
  do
    m = read_record(tape, buf, sizeof buf);
  while (m != 0 && (m & RECORD_ERR) == 0);
  if (m == RECORD_MARK)
    flags |= FLG_EOF;
  else if (m == RECORD_EOM)
    flags |= FLG_EOT;
  else if (m & RECORD_ERR)
    flags |= FLG_HER;
}

static void cmd_space_file(const unsigned char *data, int len)
{
  int n = number(data, len);

  flags &= ~(FLG_BOT | FLG_EOT | FLG_EOF | FLG_HER | FLG_SER);
  fprintf(log, "Peer %s: Space file: %d\n", peer, n);
  if (n == 0)
    return;
  if (n < 0) {
    fprintf(stderr, "NOT IMPLEMENTED\n");
    fatal("Space file reverse not implemented");
  }
  do
    space_file();
  while (--n > 0 && (flags & (FLG_EOT | FLG_SER | FLG_HER)) == 0);
}

static void cmd_space_record(const unsigned char *data, int len)
{
  char buf[MAX_RECORD];
  int n = number(data, len);
  size_t m;

  flags &= ~(FLG_BOT | FLG_EOT | FLG_EOF | FLG_HER | FLG_SER);
  fprintf(log, "Peer %s: Space record: %d\n", peer, n);
  if (n == 0)
    return;
  if (n < 0) {
    fprintf(stderr, "NOT IMPLEMENTED\n");
    fatal("Space file reverse not implemented");
  }
  do
    m = read_record(tape, buf, sizeof buf);
  while (n-- > 0 && (m & RECORD_ERR) == 0);
  if (m == RECORD_MARK)
    flags |= FLG_EOF;
  else if (m == RECORD_EOM)
    flags |= FLG_EOT;
  else if (m & RECORD_ERR)
    flags |= FLG_HER;
}

static void cmd_rewind(const unsigned char *data, int len)
{
  off_t x;

  fprintf(log, "Peer %s: Rewind\n", peer);

  if (flags & FLG_WRITE)
    write_eot(tape);

  x = lseek(tape, 0, SEEK_SET);
  if (x == -1) {
    flags |= FLG_SER;
    return;
  }

  flags |= FLG_BOT;
  flags &= ~(FLG_EOT | FLG_EOF | FLG_HER | FLG_SER);
}

static void cmd_write_mark(const unsigned char *data, int len)
{
  off_t x;
  if ((flags & FLG_WRITE) == 0) {
    flags |= FLG_SER;
    fprintf(log, "Peer %s: Mount read-only, write not allowed\n", peer);
    send_status(0, "Mount read-only, write not allowed");
    return;
  }
  fprintf(log, "Peer %s: Write mark\n", peer);
  write_mark(tape);
  write_mark(tape);
  x = lseek(tape, -4, SEEK_CUR);
  if (x == -1)
    flags |= FLG_SER;
}

static void cmd_close(const unsigned char *data, int len)
{
  char buf[MAX_PACKET];
  if (len == 0)
    strcpy(buf, data);
  else
    strncpy(buf, (const char *)data, len);
  fprintf(log, "Peer %s: %s\n", peer, buf);
  if (flags & FLG_NOREW)
    ; /* Don't rewind; not applicable. */
  send_packet(CHOP_CLS, NULL, 0);
  if (*peer)
    exit(0);
  else
    serve();
}

static void
handle_packet(void) {
  unsigned char buf[MAX_PACKET];
  unsigned char *data;
  int len, opcode, m;
  ssize_t n;

  len = 4;
  data = buf;
  while (len > 0) {
    n = recv(sock, data, len, 0);
    if (n == -1) {
      perror("recv");
      fatal("Connection error");
      return;
    }
    if (n == 0) {
      fatal("Connection closed");
      return;
    }
    data += n;
    len -= n;
  }

  opcode = buf[0];
  len = buf[2] | ((int)buf[3] << 8);

  data = buf;
  m = len;
  while (m > 0) {
    n = recv(sock, data, m, 0);
    if (n == -1) {
      perror("recv");
      fatal("Connection error");
      return;
    }
    if (n == 0) {
      fatal("Connection closed");
      return;
    }
    data += n;
    m -= n;
  }
  
  dispatch(opcode, MAX_HANDLERS, packet_handler, buf, len);
}

static void serve(void)
{
  close(sock);
  *peer = 0;
  sock = connect_to_named_socket(SOCK_STREAM, "chaos_packet");
  state = state_ignore;
  send_packet(CHOP_LSN, contact, strlen(contact));
}  

static void usage(char *s)
{
  fprintf(stderr, "Usage: %s [-adqrv]\n", s);
  fprintf(stderr, "  -a  Allow slashes in mount drive name.\n");
  fprintf(stderr, "  -d  Run as daemon.\n");
  fprintf(stderr, "  -q  Quiet operation - no logging, just errors.\n");
  fprintf(stderr, "  -r  Only allow read-only mounts.\n");
  fprintf(stderr, "  -v  Verbose operation - detailed logging.\n");
  exit(1);
}

int
main(int argc, char *argv[])
{
  char *pname;
  int quiet = 0, verbose = 0;
  int c;

  pname = argv[0];
  log = stderr;
  debug = stderr;

  while ((c = getopt(argc, argv, "adqrv")) != -1) {
    switch (c) {
    case 'a':
      allow_slash = 1;
      break;
    case 'd':
      daemonize = 1;
      break;
    case 'q':
      quiet = 1;
      break;
    case 'r':
      read_only = 1;
      break;
    case 'v':
      verbose++;
      break;
    default:
      fprintf(stderr, "Unknown option: %c\n", c);
      usage(pname);
    }
  }
  argc -= optind;
  argv += optind;

  if (argc > 0)
    usage(pname);

  if (quiet)
    log = fopen("/dev/null", "w");

  if (!verbose)
    debug = fopen("/dev/null", "w");

  if (daemonize)
    daemon(1, 1);

  serve();
  for (;;)
    handle_packet();
}
