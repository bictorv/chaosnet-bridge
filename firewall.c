/* Copyright © 2024 Björn Victor (bjorn@victor.se) */
/*  Simple firewall for cbridge, the bridge program for various Chaosnet implementations. */
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
#include "firewall.h"
#include <ctype.h>

static int firewall_enabled = 0;
static int debug_firewall = 0;
static int log_firewall = 0;

typedef enum rule_addr_type {	// A rule address can have this type:
  rule_addr_any=1, 		// "any" matching any addr
  rule_addr_host,		// a specific host addr
  rule_addr_subnet,		// a specific subnet
  rule_addr_myself,		// "myself" meaning any of the addresses of this cbridge
  rule_addr_broadcast,		// as destination
  rule_addr_none,		// used in addr_match_broadcast_dest
} rule_addr_t;
struct rule_addr {		// A rule address has
  rule_addr_t type;		// a type (above)
  u_int n_addrs;
  u_short *addrs; // and an array of addresses (except for "any" and "myself")
};
typedef enum rule_action_type {	// What to do when the rule matched
  rule_action_allow=1,		// Just allow it
  rule_action_drop,		// Just drop it
  rule_action_reject,		// Send a CLS in response
  rule_action_forward,		// Send a FWD in response
} rule_action_t;
struct rule_action {
  rule_action_t action;		// What to do
  union {
    char *reject_reason;	// the CLS reason to use
    struct forward_args {	// the FWD args to use
      u_short forward_addr;
      char *forward_contact;	// (default "same as in RFC")
    } *fwd_args;
  } args;
};
struct contact_rule {
  struct rule_addr *rule_sources; // the sources t match
  struct rule_addr *rule_dests;	  // the dests to match
  struct rule_action *rule_action; // what happens
  u_int rule_match_count;	  // how many times it matched (for statistics)
};
typedef enum rule_contact_type {
  rule_contact_all=1,
  rule_contact_string,
} rule_contact_t;
struct firewall_rule {
  rule_contact_t contact_type;	// the type of contact (all or string)
  char *contact;		// the contact name (for rule_contact_string)
  u_int contact_length;		// the strlen 
  u_int n_rules;		// how long the array is
  struct contact_rule **rules;	// the array of rules
};

static u_int n_firewall_rules = 0;
static struct firewall_rule **fw_rules = NULL;
static int fw_has_rule_for_all = 0;

static int firewall_handle_rfc_or_brd(struct chaos_header *pkt, rule_addr_t broadcast_match_class);

static int 
num_occurrences(char c, char *s)
{
  int i = 0;
  while ((s = index(s,c)) != NULL) {
    i++; s++;
  }
  return i;
}

static struct rule_addr *
parse_numeric_addrs(char *tok, struct rule_addr *ruleaddr) 
{
  int n = num_occurrences(',', tok)+1;
  u_short *addrs = calloc(n, sizeof(u_short));
  for (int i = 0; i < n; i++) {
    char *comma = index(tok,',');
    if (comma != NULL) *comma = '\0';
    if ((sscanf(tok,"%ho",&addrs[i]) != 1) || 
	(ruleaddr->type == rule_addr_subnet && (addrs[i] > 0xff || addrs[i] == 0)) ||
	(ruleaddr->type == rule_addr_host && !valid_chaos_host_address(addrs[i]))) {
      fprintf(stderr,"Firewall: bad %s spec '%s'\n", ruleaddr->type == rule_addr_host ? "host" : "subnet", tok);
      return NULL;
    }
    if (comma != NULL) tok = comma+1;
  }
  ruleaddr->n_addrs = n;
  ruleaddr->addrs = addrs;
  return ruleaddr;
}
static struct rule_addr *
make_addr_spec(rule_addr_t type)
{
  struct rule_addr *r = malloc(sizeof(struct rule_addr));
  if (r == NULL) abort();
  r->type = type;
  return r;
}
static struct rule_addr *
parse_addr_spec()
{
  char *tok = strtok(NULL," \t\r\n");
  rule_addr_t type;
  struct rule_addr *rule;
  if (tok != NULL) {
    if (strcasecmp(tok,"subnet") == 0 || strcasecmp(tok,"net") == 0) 
      type = rule_addr_subnet;
    else if (strcasecmp(tok,"host") == 0) 
      type = rule_addr_host;
    else if (strcasecmp(tok,"any") == 0)
      type = rule_addr_any;
    else if (strcasecmp(tok,"myself") == 0)
      type = rule_addr_myself;
    else if (strcasecmp(tok,"broadcast") == 0)
      type = rule_addr_broadcast;
    else {
      fprintf(stderr,"Firewall: bad address keyword '%s', expected subnet/host/any/myself\n", tok);
      return NULL;
    }
    rule = malloc(sizeof(struct rule_addr));
    if (rule == NULL) abort();
    rule->type = type;
    rule->n_addrs = 0;
    rule->addrs = NULL;
    if (type == rule_addr_subnet || type == rule_addr_host) {
      tok = strtok(NULL," \t\r\n");
      if (tok != NULL) {
	rule = parse_numeric_addrs(tok, rule);
	if (rule == NULL || rule->n_addrs == 0) {
	  return NULL;
	}
      }
    }
    return rule;
  } else 
    return NULL;
}
static char *
parse_quoted_string(char *tok, int upcase) 
{
  if (tok[0] != '"' || strlen(tok) < 2)
    return NULL;		// Not a quoted string
  int slen = strlen(tok);
  char *sval = calloc(1,256);	// Get a string
  ++tok;				// Skip over "
  --slen;				// update len

  // Consume more tokens, separating them with space
  while (tok != NULL && tok[slen-1] != '"') {
    strcat(sval, tok);
    strcat(sval, " ");
    tok = strtok(NULL," \t\r\n");
    slen = strlen(tok);
  }
  if (tok != NULL && tok[slen-1] == '"') {
    tok[slen-1] = '\0';		// Zap final "
    strcat(sval, tok);
    if (upcase) {
      char *sp = sval;
      while (*sp != '\0') {
	if (islower(*sp)) *sp = toupper(*sp);
	sp++;
      }
    }
    return sval;
  } else {
    return NULL;
  }
}
struct forward_args *
parse_forward_args()
{
  u_short fwd;
  char *new_contact;
  char *tok = strtok(NULL," \t\r\n");
  if (tok != NULL) {
    if (sscanf(tok,"%ho",&fwd) != 1 || !valid_chaos_host_address(fwd)) {
      fprintf(stderr,"Firewall: bad forward address %s\n", tok);
      return NULL;
    }
    tok = strtok(NULL," \t\r\n");
    if (tok != NULL)
      new_contact = parse_quoted_string(tok, 1);
    struct forward_args *fa = malloc(sizeof(struct forward_args));
    if (fa == NULL) abort();
    fa->forward_addr = fwd;
    fa->forward_contact = new_contact;
    return fa;
  } else {
    fprintf(stderr,"Firewall: forward args missing\n");
    return NULL;
  }
}
// <"contact"|all> [from <source> (default any)] [to <dest> (default any)] allow/drop/forward <destaddr [contact]>/reject [reason]
// source,dest: net sn-list | host addr-list | any | myself (meaning "any of this cbridge's addresses")
// action: allow | drop | forward dest [new-contact] | reject Reason (default "No server for this contact name")
static int
parse_firewall_line(char *line)
{
  rule_contact_t contact_type;
  char *contact_name = NULL;

  // construct the rule action
  struct rule_action *rule_action = calloc(1,sizeof(struct rule_action));
  // construct the contact rule
  struct contact_rule *rule = calloc(1,sizeof(struct contact_rule));

  char *tok = NULL;
  // Look for comment start
  char *comment_start = index(line, '#');
  if (comment_start == NULL) comment_start = index(line, ';');
  if (comment_start != NULL)
    *comment_start = '\0';	// Zap string at that point
  tok = strtok(line," \t\r\n");
  if (tok == NULL)
    return 0;			// Empty line

  // First is contact name in doublequotes, or all
  if (strcasecmp(tok, "all") == 0) {
    contact_type = rule_contact_all;
    fw_has_rule_for_all = 1;
  } else {
    contact_type = rule_contact_string;
    contact_name = parse_quoted_string(tok, 1);
    if (contact_name == NULL) {
      fprintf(stderr,"firewall config parse error: not a quoted string: %s\n", tok);
      return -1;
    }
  }
  // next is a keyword: from/to/[action]
  while (tok != NULL) {
    tok = strtok(NULL, " \t\r\n");
    if (tok != NULL) {
      if (strcasecmp(tok,"from") == 0) {
	if (rule->rule_sources != NULL) {
	  fprintf(stderr,"Firewall: only specify one 'from'\n");
	  return -1;
	}
	// parse an addr spec
	rule->rule_sources = parse_addr_spec();
	if (rule->rule_sources == NULL)
	  return -1;
	else if (rule->rule_sources->type == rule_addr_broadcast) {
	  fprintf(stderr,"Firewall: using 'from broadcast' is nonsense.\n");
	  return -1;
	}
      } else if (strcasecmp(tok,"to") == 0) {
	if (rule->rule_dests != NULL) {
	  fprintf(stderr,"Firewall: only specify one 'to'\n");
	  return -1;
	}
	rule->rule_dests = parse_addr_spec();
	if (rule->rule_dests == NULL)
	  return -1;
      } else if (strcasecmp(tok, "allow") == 0) {
	if (rule_action->action != 0) {
	  fprintf(stderr,"Firewall: only one action per rule is allowed.\n");
	  return -1;
	}
	rule_action->action = rule_action_allow;
      } else if (strcasecmp(tok, "drop") == 0) {
	if (rule_action->action != 0) {
	  fprintf(stderr,"Firewall: only one action per rule is allowed.\n");
	  return -1;
	}
	rule_action->action = rule_action_drop;
      } else if (strcasecmp(tok,"forward") == 0) {
	if (rule_action->action != 0) {
	  fprintf(stderr,"Firewall: only one action per rule is allowed.\n");
	  return -1;
	}
	rule_action->action = rule_action_forward;
	// parse parameters
	rule_action->args.fwd_args = parse_forward_args();
	if (rule_action->args.fwd_args == NULL)
	  return -1;
      } else if (strcasecmp(tok,"reject") == 0) {
	if (rule_action->action != 0) {
	  fprintf(stderr,"Firewall: only one action per rule is allowed.\n");
	  return -1;
	}
	rule_action->action = rule_action_reject;
	// parse quoted string
	tok = strtok(NULL," \t\r\n");
	if (tok != NULL)
	  rule_action->args.reject_reason = parse_quoted_string(tok, 0);
	if (rule_action->args.reject_reason == NULL)
	  rule_action->args.reject_reason = "Connection rejected by firewall"; // "No server for this contact name";
      } else {
	fprintf(stderr,"Firewall: bad keyword '%s'\n", tok);
	return -1;
      }
    }
  }
  rule->rule_action = rule_action;
  if (rule->rule_action == NULL) {
    fprintf(stderr,"Firewall: no action specified for rule.\n");
    return -1;
  }
  // Default these
  if (rule->rule_sources == NULL) {
    rule->rule_sources = make_addr_spec(rule_addr_any); // Default "from" is any
  }
  if (rule->rule_dests == NULL) {
    rule->rule_dests = make_addr_spec(rule_addr_myself); // Default "to" is myself, not any
  }

  // Remind people.
  if (contact_type == rule_contact_string && strcasecmp(contact_name, "STATUS") == 0 &&
      rule_action->action != rule_action_allow) 
    fprintf(stderr,"%%%% Warning: disallowing STATUS is against the spec (Amber Section 5.1).\n");
  // @@@@ Should ideally check if there is a preceding "allow" rule.
  if (contact_type == rule_contact_all && rule_action->action != rule_action_allow)
    fprintf(stderr,"%%%% Warning: by disallowing \"all\" contacts, STATUS might be disallowed, which is against the spec (Amber Section 5.1).\n");

  // Find the contact name in fw_rules, add the rule to it
  if (fw_rules == NULL) {
    fw_rules = malloc(sizeof(struct firewall_rule));
  }
  struct firewall_rule *this = NULL;
  for (int i = 0; i < n_firewall_rules; i++) {
    if ((fw_rules[i]->contact_type == contact_type) && 
	(contact_type == rule_contact_all || (strcasecmp(fw_rules[i]->contact, contact_name) == 0))) {
      this = fw_rules[i];
      break;
    }
  }
  if (this == NULL) {		// Didn't find it, add space for it
    fw_rules = realloc(fw_rules, (n_firewall_rules+1)*sizeof(struct firewall_rule));
    fw_rules[n_firewall_rules] = calloc(1, sizeof(struct firewall_rule));
    this = fw_rules[n_firewall_rules++];
  }
  this->contact_type = contact_type;
  if (contact_type == rule_contact_string) { 
    this->contact = contact_name;
    this->contact_length = strlen(contact_name);
  }
  // add the rule to this->rules
  if (this->rules == NULL) {	// no rules yet, add the first
    this->rules = malloc(sizeof(struct contact_rule));
    this->n_rules = 0;
  }
  else
    this->rules = realloc(this->rules, (this->n_rules+1)*sizeof(struct contact_rule));
  this->rules[this->n_rules++] = rule;
  return 0;
}

// Returns success (0) or failure (-1, for syntax error or other fatal error)
// Creates the config in fw_rules.
// Warn if both source and addr are any when action is not allow?
static int 
parse_firewall_file(char *fname)
{
  FILE *fp = fopen(fname,"r");
  if (fp == NULL) {
    fprintf(stderr,"Can't open firewall config file \"%s\"\n", fname);
    return -1;
  }
  char *line = NULL;
  size_t linecap = 0;
  ssize_t linelen;
  while (!feof(fp)) {
    linelen = getline(&line, &linecap, fp);
    if (linelen < 0) {
      if (feof(fp)) {
	fclose(fp);
	return 0;
      }  
      fclose(fp);
      fprintf(stderr,"While reading from \"%s\": %s\n", fname, strerror(errno));
      return -1;
    }
    if (parse_firewall_line(line) < 0) {
      fclose(fp);
      return -1;
    }
  }
  fclose(fp);
  return 0;
}

static int parse_on_off(char *name)
{
  char *tok = strtok(NULL, " \t\r\n");
  if (tok == NULL) {
    fprintf(stderr,"firewall: no arg specified for '%s'\n", name);
    return -1;
  } else if ((strcasecmp(tok,"on") == 0) || (strcasecmp(tok,"yes") == 0)) {
    return 1;
  } else if ((strcasecmp(tok,"off") == 0) || (strcasecmp(tok,"no") == 0)) {
    return 0;
  } else {
    fprintf(stderr,"firewall: bad '%s' arg %s specified\n", name, tok);
    return -1;
  }
}

// Called from cbridge.c for the cbridge.conf line:
// firewall enabled yes/no debug yes/no log yes/no rules fname
int parse_firewall_config_line()
{
  char *tok = NULL;
  while ((tok = strtok(NULL, " \t\r\n")) != NULL) {
    if (strcasecmp(tok,"enabled") == 0) {
      firewall_enabled = parse_on_off("enabled");
      if (firewall_enabled < 0) 
	return -1;
    } else if (strcasecmp(tok,"debug") == 0) {
      debug_firewall = parse_on_off("debug");
      if (debug_firewall < 0)
	return -1;
    } else if (strcasecmp(tok,"log") == 0) {
      log_firewall = parse_on_off("log");
      if (log_firewall < 0)
	return -1;
    } else if (strcasecmp(tok,"rules") == 0) {
      tok = strtok(NULL," \t\r\n");
      if (tok == NULL) {
	fprintf(stderr,"firewall: no arg specified for 'rules'\n");
	return -1;
      }
      if (parse_firewall_file(tok) < 0)
	return -1;
    } else {
      fprintf(stderr,"bad firewall keyword %s\n", tok);
      return -1;
    }
  }
  if (debug_firewall) {
    printf("firewall %s: debug %s log %s, \"all\" rule used: %s\n", firewall_enabled ? "enabled" : "disabled",
	   debug_firewall ? "on" : "off", log_firewall ? "on" : "off", fw_has_rule_for_all ? "yes" : "no");
    print_firewall_rules();
  }
  // @@@@ validate config more?
  if (n_firewall_rules == 0 && firewall_enabled == 1) {
    printf("%%%% Warning: firewall was enabled, but no rules given. Disabling.\n");
    firewall_enabled = 0;
  } else if (n_firewall_rules > 0 && firewall_enabled == 0)
    printf("%%%% Warning: firewall disabled, but rules given. I hope you wanted this.\n");
  return 0;
}

static char *
action_name(rule_action_t a)
{
  switch (a) {
  case rule_action_allow: return "allow";
  case rule_action_drop: return "drop";
  case rule_action_reject: return "reject";
  case rule_action_forward: return "forward";
  }
}
static void
print_firewall_action(struct rule_action *a)
{
  printf("%s", action_name(a->action));
  switch (a->action) {
  case rule_action_reject: 
    printf(" \"%s\"", a->args.reject_reason); 
    break;
  case rule_action_forward: 
    printf(" %o \"%s\"", a->args.fwd_args->forward_addr, a->args.fwd_args->forward_contact);
  default:
    ;
  }
}
static char *
addr_type_name(rule_addr_t type)
{
  switch (type) {
  case rule_addr_any: return "any"; 
  case rule_addr_myself: return "myself";
  case rule_addr_broadcast: return "broadcast";
  case rule_addr_host: return "host";
  case rule_addr_subnet: return "subnet";
  case rule_addr_none: return "none";
  }
  return "?";
}
static void 
print_firewall_addrs(struct rule_addr *addr)
{
  printf("%s",addr_type_name(addr->type));
  if (addr->type == rule_addr_host || addr->type == rule_addr_subnet) {
    printf(" ");
    if (addr->n_addrs > 0) {
      for (int i = 0; i < addr->n_addrs-1; i++) 
	printf("%o,", addr->addrs[i]);
      printf("%o", addr->addrs[addr->n_addrs-1]);
    }
  }
}
void print_firewall_rules(void)
{
  printf("Firewall has rules for %d contact%s\n", n_firewall_rules, 
	 n_firewall_rules == 0 ? "s." : n_firewall_rules == 1 ? ":" : "s:");
  for (int c = 0; c < n_firewall_rules; c++) {
    if (fw_rules[c]->contact_type == rule_contact_string)
      printf("%2d: \"%s\"\n", c, fw_rules[c]->contact);
    else
      printf("%2d: *\n", c);
    for (int r = 0; r < fw_rules[c]->n_rules; r++) {
      printf("   from "); print_firewall_addrs(fw_rules[c]->rules[r]->rule_sources);
      printf(" to "); print_firewall_addrs(fw_rules[c]->rules[r]->rule_dests);
      printf(" "); print_firewall_action(fw_rules[c]->rules[r]->rule_action);
      printf(" [matched %d times]\n", fw_rules[c]->rules[r]->rule_match_count);
    }
  }
}

// Match a rule address with an actual address.
static int 
addr_match_broadcast_dest(struct rule_addr *addr, u_short pkaddr, rule_addr_t broadcast_match) 
{
  if (addr->type == rule_addr_any) return 1;
  // Only in some cases, match broadcast destinations against anything
  if ((pkaddr == 0) && (broadcast_match != rule_addr_none) && (addr->type == broadcast_match))
    return 1;
  if (addr->type == rule_addr_host) {
    for (int i = 0; i < addr->n_addrs; i++)
      if (addr->addrs[i] == pkaddr)
	return 1;
  } else if (addr->type == rule_addr_subnet) {
    for (int i = 0; i < addr->n_addrs; i++)
      if (addr->addrs[i] == (pkaddr >> 8))
	return 1;
  } else if (addr->type == rule_addr_myself)
    return is_mychaddr(pkaddr);
  else if (addr->type == rule_addr_broadcast)
    return (pkaddr == 0);
  return 0;
}
// Match a rule address with an actual address.
static int 
addr_match(struct rule_addr *addr, u_short pkaddr) 
{
  return addr_match_broadcast_dest(addr, pkaddr, rule_addr_none);
}

// (There are too many functions like this one, e.g. in ncp.c)
static void
send_basic_response(struct chaos_header *pkt, int opcode, char *data, int len, u_short fwd_addr)
{
  u_char resp[CH_PK_MAXLEN];
  struct chaos_header *ch = (struct chaos_header *)resp;

  // Initialize header
  memset(resp, 0, CHAOS_HEADERSIZE);
  set_ch_opcode(ch, opcode);
  // Use src/dest from pkt we're responding to (even if dest wasn't us!)
  set_ch_destaddr(ch, ch_srcaddr(pkt));
  set_ch_destindex(ch, ch_srcindex(pkt));
  set_ch_srcaddr(ch, ch_destaddr(pkt));
  set_ch_srcindex(ch, ch_destindex(pkt));
  set_ch_nbytes(ch, len);
  // Set up content
  u_short *datao = (u_short *)&resp[CHAOS_HEADERSIZE];
  if ((opcode == CHOP_CLS) || (opcode == CHOP_FWD)) {
    if (opcode == CHOP_FWD)
      set_ch_ackno(ch, fwd_addr);
    strncpy((char *)&resp[CHAOS_HEADERSIZE], data, len); // Copy data (CLS reason or FWD contact)
    htons_buf(datao, datao, len);
    // Send it off
    send_chaos_pkt(resp, len+CHAOS_HEADERSIZE);
  } else {
    fprintf(stderr,"%%%% Firewall %s: opcode %#o (%s) not handled\n", __func__, opcode, ch_opcode_name(opcode));
  }
}
// send CLS using the pkt dest as source
static void
send_cls_response(struct chaos_header *pkt, char *reason)
{
  send_basic_response(pkt, CHOP_CLS, reason, strlen(reason), 0);
}
// send FWD using the pkt dest as source
static void
send_fwd_response(struct chaos_header *pkt, u_short newdest, char *newcontact)
{
  send_basic_response(pkt, CHOP_FWD, newcontact, strlen(newcontact), newdest);
}

static int 
do_action(struct contact_rule *rule, struct chaos_header *pkt)
{
  u_char contact[CH_PK_MAXLEN];
  get_packet_string(pkt, contact, sizeof(contact));

  switch (rule->rule_action->action) {
  case rule_action_allow:
    if (log_firewall)
      fprintf(stderr,"Firewall: allow %s \"%s\" from <%#o,%#x> to <%#o,%#x>\n",
	      ch_opcode_name(ch_opcode(pkt)), contact, ch_srcaddr(pkt), ch_srcindex(pkt),
	      ch_destaddr(pkt), ch_destindex(pkt));
    return 0;
  case rule_action_drop:
    if (log_firewall)
      fprintf(stderr,"Firewall: drop %s \"%s\" from <%#o,%#x> to <%#o,%#x>\n",
	      ch_opcode_name(ch_opcode(pkt)), contact, ch_srcaddr(pkt), ch_srcindex(pkt),
	      ch_destaddr(pkt), ch_destindex(pkt));
    return -1;
  case rule_action_reject:
    if (log_firewall)
      fprintf(stderr,"Firewall: reject %s \"%s\" from <%#o,%#x> to <%#o,%#x>\n",
	      ch_opcode_name(ch_opcode(pkt)), contact, ch_srcaddr(pkt), ch_srcindex(pkt),
	      ch_destaddr(pkt), ch_destindex(pkt));
    // send CLS using the pkt dest as source (but not for BRD)
    if (ch_opcode(pkt) != CHOP_BRD)
      send_cls_response(pkt, rule->rule_action->args.reject_reason);
    return -1;
  case rule_action_forward: {
    char *c = rule->rule_action->args.fwd_args->forward_contact;
    if (c == NULL)
      c = (char *)contact;
    if (log_firewall)
      fprintf(stderr,"Firewall: forward %s \"%s\" from <%#o,%#x> to <%#o,%#x>: %#o \"%s\"\n",
	      ch_opcode_name(ch_opcode(pkt)), contact, ch_srcaddr(pkt), ch_srcindex(pkt),
	      ch_destaddr(pkt), ch_destindex(pkt), 
	      rule->rule_action->args.fwd_args->forward_addr, c);
    // send FWD using the pkt dest as source (but not for BRD)
    if (ch_opcode(pkt) != CHOP_BRD)
      send_fwd_response(pkt, rule->rule_action->args.fwd_args->forward_addr, c);
    return -1;
  }
  default:			// "Never happens", he said.
    fprintf(stderr,"Firewall: unrecognized rule action %d\n", rule->rule_action->action);
  }
  return 0;
}

// Handle a packet.
// Return 0 for "not handled or accept" (so proceed as usual), or
// -1 for "handled, don't proceeed" for drop/forward/reject (response has already been sent)
// Note the use of broadcast_match_class, to allow broadcast destaddr (0) to match
// anything in that class. Use e.g. rule_addr_myself in handle_pkt_for_me, and rule_addr_none
// in the general forwarding code (forward_chaos_pkt).
int 
firewall_handle_forward(struct chaos_header *pkt)
{
  return firewall_handle_rfc_or_brd(pkt, rule_addr_none);
}
int 
firewall_handle_pkt_for_me(struct chaos_header *pkt)
{
  return firewall_handle_rfc_or_brd(pkt, rule_addr_myself);
}
static int 
firewall_handle_rfc_or_brd(struct chaos_header *pkt, rule_addr_t broadcast_match_type)
{
  if (firewall_enabled == 0) return 0;

  u_char opc = ch_opcode(pkt);
  if ((opc != CHOP_RFC) && (opc != CHOP_BRD)) {
    fprintf(stderr,"%%%% Firewall: not an RFC/BRD pkt: %s\n", ch_opcode_name(opc));
    return 0;
  }
  char contact[CH_PK_MAXLEN];
  get_packet_string(pkt, (u_char *)contact, sizeof(contact));
  int contact_maxlen = ch_nbytes(pkt);
  if (ch_opcode(pkt) == CHOP_BRD) {
    // check reasonable values too, since this code runs early
    if (ch_ackno(pkt) > 0 && ch_ackno(pkt) <= 32 && (ch_ackno(pkt) % 4) == 0 && ch_nbytes(pkt) > ch_ackno(pkt))
      contact_maxlen -= ch_ackno(pkt);
    else {
      if (debug_firewall) printf("Firewall: dropping malformed BRD (ackno %#x, len %d)\n", ch_ackno(pkt), ch_nbytes(pkt));
      return -1;
    }
  }

  u_short srcaddr = ch_srcaddr(pkt);
  u_short destaddr = ch_destaddr(pkt);

  if (debug_firewall) {
    printf("Checking %s \"%s\" from <%#o,%#x> to <%#o,%#x> (brd match type %s)\n",
	   ch_opcode_name(ch_opcode(pkt)), contact, ch_srcaddr(pkt), ch_srcindex(pkt),
	   ch_destaddr(pkt), ch_destindex(pkt), addr_type_name(broadcast_match_type));
  }

  for (int i = 0; i < n_firewall_rules; i++) {
    if (debug_firewall) printf("Checking rule %d: type %s contact %s len %d pkt contact %s\n", i, 
			       fw_rules[i]->contact_type == rule_contact_all ? "all" : "string",
			       fw_rules[i]->contact, fw_rules[i]->contact_length, contact);
    if ((fw_rules[i]->contact_type == rule_contact_all) ||
	((fw_rules[i]->contact_type == rule_contact_string) &&
	 (fw_rules[i]->contact_length <= contact_maxlen) &&
	 (strncasecmp(contact, fw_rules[i]->contact, fw_rules[i]->contact_length) == 0) &&
	 // RFC contact is "contact" precisely or "contact args", not "contactless"
	 (fw_rules[i]->contact_length == contact_maxlen || contact[fw_rules[i]->contact_length] == ' '))) {
      struct contact_rule **rules = fw_rules[i]->rules;
      for (int r = 0; r < fw_rules[i]->n_rules; r++) { // foreach rule
	// Note the use of broadcast_match_type, to allow broadcast destaddr (0) to match
	// anything in that type. Use e.g. rule_addr_myself in handle_pkt_for_me.
	if (addr_match(rules[r]->rule_sources, srcaddr) && 
	    addr_match_broadcast_dest(rules[r]->rule_dests, destaddr, broadcast_match_type)) {
	  rules[r]->rule_match_count++;
	  // do the action
	  return do_action(rules[r], pkt);
	}
      }
      if (!fw_has_rule_for_all) {
	// This shortcut should only be taken if there is no "all" rule.
	// If there is no "all" rule, there is no possibility of another match, but if there is an "all" rule, it might match.
	if (debug_firewall) printf("Contact matched (%s) but no rule matched, proceed\n", fw_rules[i]->contact);
	return 0;			// Contact matched, but no rule matched, so proceed
      }
    }
#if 0
    else if (debug_firewall) 
      printf(" rule did not match (comp %d clen %d maxlen %d)\n", 
	     strncasecmp(contact, fw_rules[i]->contact, fw_rules[i]->contact_length),
	     fw_rules[i]->contact_length, contact_maxlen);
#endif
  }
  if (debug_firewall) printf("No contact matched, proceed\n");
  return 0;			// No contact matched, so proceed
}
