/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */
   
#ifndef _ACL_H
#define _ACL_H 1

void do_accesslist(const char *);
void do_accesslist_mac(const char *);
void do_accesslist_policy(const char *);
void no_accesslist(const char *);
void interface_acl(const char *);
void interface_no_acl(const char *);

#endif

