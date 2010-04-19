#ifndef _NAT_H
#define _NAT_H

void do_nat_rule(const char *);
void no_nat_rule(const char *);
void interface_nat(const char *);
void interface_no_nat(const char *);

void dump_nat(char *xacl, FILE *F, int conf_format);
int nat_rule_exists(char *acl);
int matched_nat_rule_exists(char *acl, char *iface_in, char *iface_out, char *chain);
int get_iface_nat_rules(char *iface, char *in_acl, char *out_acl);
int get_nat_rule_refcount(char *acl);
int clean_iface_nat_rules(char *iface);

#endif

