#include <arpa/inet.h>

/* 11-format word */
#define WORD16(c) (ntohs(*(u_short *)(c)))

// Max forwarding count (4 bits)
#define CH_FORWARD_MAX 0xF

enum { CHOP_RFC=1, CHOP_OPN, CHOP_CLS, CHOP_FWD, CHOP_ANS, CHOP_SNS, CHOP_STS,
       CHOP_RUT, CHOP_LOS, CHOP_LSN, CHOP_MNT, CHOP_EOF, CHOP_UNC, CHOP_BRD };

#define CHOP_ACK 0177 // Note: extension for the NCP Packet socket
#define CHOP_DAT 0200
#define CHOP_DWD 0300

static char
  *ch_opc[] = { "NIL",
		"RFC", "OPN", "CLS", "FWD", "ANS", "SNS", "STS",
		"RUT", "LOS", "LSN", "MNT", "EOF", "UNC", "BRD" };
char *ch_opcode_name(int opc);

struct chaos_header {
  unsigned short ch_opcode_x:16;
  unsigned short ch_fc_nbytes_n:16;
  unsigned short ch_destaddr_n:16;
  unsigned short ch_destindex_n:16;
  unsigned short ch_srcaddr_n:16;
  unsigned short ch_srcindex_n:16;
  unsigned short ch_packetno_n:16;
  unsigned short ch_ackno_n:16;
};

// network order
#define ch_opcode(CH) (ntohs((CH)->ch_opcode_x) >> 8)
#define ch_unused(CH) (ntohs((CH)->ch_opcode_x) & 0xff)
#define ch_fc(CH) (ntohs((CH)->ch_fc_nbytes_n) >> 12)
#define ch_nbytes(CH) (ntohs((CH)->ch_fc_nbytes_n) & 0xfff)
#define ch_nbytes_n(CH) (((CH)->ch_fc_nbytes_n) & 0xfff)
#define ch_destaddr(CH) (ntohs((CH)->ch_destaddr_n))
#define ch_destindex(CH) (ntohs((CH)->ch_destindex_n))
#define ch_srcaddr(CH) (ntohs((CH)->ch_srcaddr_n))
#define ch_srcindex(CH) (ntohs((CH)->ch_srcindex_n))
#define ch_packetno(CH) (ntohs((CH)->ch_packetno_n))
#define ch_ackno(CH) (ntohs((CH)->ch_ackno_n))

#define set_ch_opcode(CH,val) ((CH)->ch_opcode_x = htons(ch_opcode(CH) | ((val) << 8)))
#define set_ch_fc(CH,val) ((CH)->ch_fc_nbytes_n = htons((ch_nbytes(CH) | ((val) << 12))))
#define set_ch_nbytes(CH,val) ((CH)->ch_fc_nbytes_n = htons((ch_fc(CH) << 12) | ((val) & 0xfff)))
#define set_ch_destaddr(CH,val) ((CH)->ch_destaddr_n = htons(val))
#define set_ch_destindex(CH,val) ((CH)->ch_destindex_n = htons(val))
#define set_ch_srcaddr(CH,val) ((CH)->ch_srcaddr_n = htons(val))
#define set_ch_srcindex(CH,val) ((CH)->ch_srcindex_n = htons(val))
#define set_ch_packetno(CH,val) ((CH)->ch_packetno_n = htons(val))
#define set_ch_ackno(CH,val) ((CH)->ch_ackno_n = htons(val))

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
