#include <arpa/inet.h>

/* 11-format word */
#define WORD32(c) ((c[1]) + ((c)[0]<<8) + ((c)[3]<<16) + ((c)[2]<<24))
#define WORD16(c) (*(c+1) + (*(c)<<8))
// Max forwarding count (4 bits)
#define CH_FORWARD_MAX 0xF

enum { CHOP_RFC=1, CHOP_OPN, CHOP_CLS, CHOP_FWD, CHOP_ANS, CHOP_SNS, CHOP_STS,
       CHOP_RUT, CHOP_LOS, CHOP_LSN, CHOP_MNT, CHOP_EOF, CHOP_UNC, CHOP_BRD };

#define CHOP_DAT 0200
#define CHOP_DWD 0300

static char
  *ch_opc[] = { "NIL",
		"RFC", "OPN", "CLS", "FWD", "ANS", "SNS", "STS",
		"RUT", "LOS", "LSN", "MNT", "EOF", "UNC", "BRD" };
char *ch_opcode_name(int opc);

struct chaos_header {
  union {
    unsigned short ch_opcode_x;
    struct {
      unsigned char ch_opcode;
      unsigned char ch_unused;
    } ch_opcode_s;
  } ch_opcode_u;
  struct {
    unsigned char ch_fc_nbytes1;
    unsigned char ch_fc_nbytes2;
  } ch_fc_nbytes;
  union {
    unsigned short ch_destaddr_x:16;
    struct {
      unsigned char ch_destaddr1;
      unsigned char ch_destaddr2;
    } ch_destaddr_s;
  } ch_destaddr_u;
  union {
    unsigned short ch_destindex_x:16;
    struct {
      unsigned char ch_destindex1;
      unsigned char ch_destindex2;
    } ch_destindex_s;
  } ch_destindex_u;
  union {
    unsigned short ch_srcaddr_x:16;
    struct {
      unsigned char ch_srcaddr1;
      unsigned char ch_srcaddr2;
    } ch_srcaddr_s;
  } ch_srcaddr_u;
  union {
    unsigned short ch_srcindex_x:16;
    struct {
      unsigned char ch_srcindex1;
      unsigned char ch_srcindex2;
    } ch_srcindex_s;
  } ch_srcindex_u;
  union {
    unsigned short ch_packetno_x:16;
    struct {
      unsigned char ch_packetno1;
      unsigned char ch_packetno2;
    } ch_packetno_s;
  } ch_packetno_u;
  union {
    unsigned short ch_ackno_x:16;
    struct {
      unsigned char ch_ackno1;
      unsigned char ch_ackno2;
    } ch_ackno_s;
  } ch_ackno_u;
};

#define ch_opcode(CH) ((CH)->ch_opcode_u.ch_opcode_s.ch_opcode)
#define ch_fc(CH) ((CH)->ch_fc_nbytes.ch_fc_nbytes1 >> 4)
#define ch_nbytes(CH) ((((CH)->ch_fc_nbytes.ch_fc_nbytes1 & 0xf) << 8) | (CH)->ch_fc_nbytes.ch_fc_nbytes2)
#define ch_destaddr(CH) (ntohs((CH)->ch_destaddr_u.ch_destaddr_x))
#define ch_destindex(CH) (ntohs((CH)->ch_destindex_u.ch_destindex_x))
#define ch_srcaddr(CH) (ntohs((CH)->ch_srcaddr_u.ch_srcaddr_x))
#define ch_srcindex(CH) (ntohs((CH)->ch_srcindex_u.ch_srcindex_x))
#define ch_packetno(CH) (ntohs((CH)->ch_packetno_u.ch_packetno_x))
#define ch_ackno(CH) (ntohs((CH)->ch_ackno_u.ch_ackno_x))

#define set_ch_opcode(CH,val) ((CH)->ch_opcode_u.ch_opcode_s.ch_opcode = (val))
#define set_ch_fc(CH,val) ((CH)->ch_fc_nbytes.ch_fc_nbytes1 = ((CH)->ch_fc_nbytes.ch_fc_nbytes1 & 0xf)|(val<<4))
#define set_ch_nbytes(CH,val) (((CH)->ch_fc_nbytes.ch_fc_nbytes1 = ((CH)->ch_fc_nbytes.ch_fc_nbytes1 &0xf0) | (((val) & 0xf00) >> 8)), (CH)->ch_fc_nbytes.ch_fc_nbytes2 = (val) & 0xff)
#define set_ch_destaddr(CH,val) ((CH)->ch_destaddr_u.ch_destaddr_x = htons(val))
#define set_ch_destindex(CH,val) ((CH)->ch_destindex_u.ch_destindex_x = htons(val))
#define set_ch_srcaddr(CH,val) ((CH)->ch_srcaddr_u.ch_srcaddr_x = htons(val))
#define set_ch_srcindex(CH,val) ((CH)->ch_srcindex_u.ch_srcindex_x = htons(val))
#define set_ch_packetno(CH,val) ((CH)->ch_packetno_u.ch_packetno_x = htons(val))
#define set_ch_ackno(CH,val) ((CH)->ch_ackno_u.ch_ackno_x = htons(val))

struct chaos_hw_trailer {
  unsigned short ch_hw_destaddr:16;
  unsigned short ch_hw_srcaddr:16;
  unsigned short ch_hw_checksum:16;
};

#define CHAOS_HEADERSIZE (sizeof(struct chaos_header))
#define CHAOS_HW_TRAILERSIZE (sizeof(struct chaos_hw_trailer))
// Max pkt size (12 bits) plus header
// The limit of 488 bytes is from MIT AIM 628, although more would fit any modern pkt (and 12 bits would give 4096 as max).
// This is due to original Chaos hardware pkts limited to 4032 bits, of which 16 bytes are header.
#define CH_PK_MAX_DATALEN 488
#define CH_PK_MAXLEN (CH_PK_MAX_DATALEN + CHAOS_HEADERSIZE + CHAOS_HW_TRAILERSIZE)
