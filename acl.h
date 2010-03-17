/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */
   
#ifndef _ACL_H
#define _ACL_H 1

void do_accesslist(const char *);
void do_accesslist_mac(const char *cmdline);
void do_accesslist_policy(const char *);
void no_accesslist(const char *);
void interface_acl(const char *);
void interface_no_acl(const char *);

void set_ports(const char *ports, char *str);
void print_flags(FILE *out, char *flags);
void dump_acl(char *xacl, FILE *F, int conf_format);
void dump_policy(FILE *F);

#endif

