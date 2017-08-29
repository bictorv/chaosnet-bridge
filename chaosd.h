/*
 * $Id: chaosd.h,v 1.2 2005/10/04 19:48:14 brad Exp $
 */

#define CHAOSD_SERVER_VERSION 003

#ifndef CHAOSD_SOCK_TYPE
/* # define CHAOSD_SOCK_TYPE SOCK_DGRAM */
# define CHAOSD_SOCK_TYPE SOCK_STREAM
#endif

#define UNIX_SOCKET_PATH	"/var/tmp/"
#define UNIX_SOCKET_CLIENT_NAME	"chaosd_"
#define UNIX_SOCKET_SERVER_NAME	"chaosd_server"
#define UNIX_SOCKET_PERM	S_IRWXU

typedef struct node_s {
    int fd;
    int index;
} node_t;

int node_close(int fd, void *node, int context);
int node_stream_reader(int fd, void *void_client, int context);


/*
 * Local Variables:
 * indent-tabs-mode:nil
 * c-basic-offset:4
 * End:
*/
