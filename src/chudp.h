/* CHUDP protocol header is 4 bytes; data after those
*/
struct chudp_header {
  char chudp_version;
  char chudp_function;
  char chudp_arg1;
  char chudp_arg2;
};

/* CHUDP protocol port - should perhaps be registered? */
#define CHUDP_PORT 42042
/* Protocol version */
#define CHUDP_VERSION 1
/* Protocol function codes */
#define CHUDP_PKT 1		/* Chaosnet packet */

#define CHUDP_HEADERSIZE (sizeof(struct chudp_header))
