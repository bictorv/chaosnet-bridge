/* Copyright © 2020 Björn Victor (bjorn@victor.se) */
/* Simple demonstration program for 
   NCP (Network Control Program) implementing Chaosnet transport layer
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "cbridge-chaos.h"

void usage(char *s) 
{
  fprintf(stderr,"usage: %s [-wtja] [user]@host\n"
	  " -w  whois: lengthy info\n"
	  " -t  time: print last logout times\n"
	  " -j  jobno: include job nrs\n"
	  " -a  abbrev: do not print full names\n",
	  s);
  exit(1);
}

char chaos_socket_directory[] = "/tmp";

static int
connect_to_named_socket(int socktype, char *path)
{
  int sock, slen;
  struct sockaddr_un local, server;
  
  local.sun_family = AF_UNIX;
  sprintf(local.sun_path, "%s/%s_%d", chaos_socket_directory, path, getpid());
  if (unlink(local.sun_path) < 0) {
    //perror("unlink(chaos_sockfile)");
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
    perror("chmod(local, 0777)");
  
  server.sun_family = AF_UNIX;
  sprintf(server.sun_path, "%s/%s", chaos_socket_directory, path);
  slen = strlen(server.sun_path)+ 1 + sizeof(server.sun_family);

  if (connect(sock, (struct sockaddr *)&server, slen) < 0) {
    perror("connect(server)");
    exit(1);
  }
  return sock;
}

int
main(int argc, char *argv[])
{
  signed char c;
  char opts[] = "wjta";		// Whois Jobno Time Abbrev
  char *host, *contact = "NAME", *pname, *spec;
  char args[32];
  char buf[CH_PK_MAXLEN];
  char *nl, *at, *user = NULL;
  int i, cnt, sock;

  // program name
  pname = argv[0];

  args[0] = '\0';
  while ((c = getopt(argc, argv, opts)) != -1) {
    switch (c) {
    case 'w': strcat(args,"/W "); break;
    case 'j': strcat(args,"/J "); break;
    case 't': strcat(args,"/T "); break;
    case 'a': strcat(args,"/A "); break;
    default:
      fprintf(stderr,"unknown option '%c'\n", c);
      usage(pname);
    }
  }
  argc -= optind;
  argv += optind;

  if (argc < 1)
    usage(pname);

  // parse user@host (should handle switches too)
  spec = argv[0];
  at = index(spec, '@');
  if (at != NULL) {
    host = at+1;
    *at = '\0';
    if (at > spec)
      user = spec;
  } else
    usage(pname);

  sock = connect_to_named_socket(SOCK_STREAM, "chaos_stream");
  
  // printf("Trying %s %s %s %s...\n", host, contact, args, user);
  if (user != NULL) 
    dprintf(sock,"RFC %s %s %s%s\r\n", host, contact, args, user);
  else if (strlen(args) > 0)
    dprintf(sock,"RFC %s %s %s\r\n", host, contact, args);
  else
    dprintf(sock,"RFC %s %s\r\n", host, contact);

  if ((cnt = recv(sock, buf, sizeof(buf), 0)) < 0) {
    perror("recv"); exit(1);
  }
  nl = index((char *)buf, '\n');
  if (nl != NULL) {
    *nl = '\0';
    nl++;
  }

  if (strncmp(buf, "OPN ", 4) != 0) {
    if (nl != NULL) *nl = '\0';
    fprintf(stderr,"Unexpected reply from %s: %s\n", host, buf);
    exit(1);
  }

  while ((cnt = recv(sock, buf, sizeof(buf), 0)) > 0) {
    for (i = 0; i < cnt; i++)
      switch ((u_char)buf[i]) {
      case 0211: putchar('\t'); break;
      case 0212: break; // see CRLF
      case 0214: putchar('\f'); break;
      case 0215: putchar('\n'); break; // CRLF
      default: putchar(buf[i]);
      }
  }
}
