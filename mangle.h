#ifndef _MANGLE_H
#define _MANGLE_H

#include <stdio.h>

void do_mangle(const char *);
void no_mangle_rule(const char *);
void interface_mangle(const char *);
void interface_no_mangle(const char *);

void dump_mangle(char *xmangle, FILE *F, int conf_format);
int mangle_exists(char *mangle);
int matched_mangle_exists(char *mangle, char *iface_in, char *iface_out, char *chain);
int get_iface_mangle_rules(char *iface, char *in_mangle, char *out_mangle);
int get_mangle_refcount(char *mangle);
int clean_iface_mangle_rules(char *iface);

#endif

