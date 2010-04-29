#ifndef _CISH_CONFIG_H
#define _CISH_CONFIG_H 1

#define CISH_CFG_FILE "/var/run/cish_cfg"

extern cish_config *cish_cfg;

int mmap_cfg(void);
int munmap_cfg(void);

#endif

