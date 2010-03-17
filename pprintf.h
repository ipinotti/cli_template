#ifndef _PPRINTF_H
#define _PPRINTF_H 1

#include <stdio.h>

extern int terminal_lines;

void pager_init (void);
int pager_skipping (void);
void pprintf (const char *, ...);
void pfprintf (FILE *, const char *, ...);

#endif
