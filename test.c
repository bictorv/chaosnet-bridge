#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
  struct in_addr ip;
  struct in6_addr ip6;
  char buf[INET6_ADDRSTRLEN];

  if (argc < 2) {
    printf("No arg?\n");
    exit(1);
  }
  if (inet_aton(argv[1], &ip) == 1) {
    printf("aton: Parsed IP %s\n", inet_ntoa(ip));
    in_addr_t net = inet_netof(ip);
    printf("netof: %ld\n", net);
  }
  if (inet_pton(AF_INET, argv[1], &ip) == 1) {
    printf("pton: Parsed IP %s\n", inet_ntop(AF_INET, &ip, buf, sizeof(buf)));
  }
  if (inet_pton(AF_INET6, argv[1], &ip6) == 1) {
    printf("pton: Parsed IPv6 %s\n", inet_ntop(AF_INET6, &ip6, buf, sizeof(buf)));
  }
  printf("Done.\n");
}
