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

int parse_firewall_config_line(void);
void print_firewall_rules(void);

int firewall_handle_forward(struct chaos_header *pkt);
int firewall_handle_pkt_for_me(struct chaos_header *pkt);
