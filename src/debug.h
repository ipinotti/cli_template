#ifndef _DEBUG_H
#define _DEBUG_H 1

#include "commandtree.h"

extern cish_command CMD_DEBUG[];
extern int _cish_debug;

void debug_all(const char *);
void debug_one(const char *);
void show_debug(const char *cmd);

void debug_console(const char *cmd);

#endif

