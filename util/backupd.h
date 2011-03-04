/*
 * backupd.h
 *
 *  Created on: May 21, 2010
 *      Author: tgrande
 */

#ifndef BACKUPD_H_
#define BACKUPD_H_

#include <librouter/modem3G.h>

//#define DEBUG_BCKP_SYSLOG
#ifdef DEBUG_BCKP_SYSLOG
#define bkpd_dbgs(x,...) \
		syslog(LOG_INFO,  "%s : %d => "x, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define bkpd_dbgs(x,...)
#endif

//#define DEBUG_BCKP_PRINTF
#ifdef DEBUG_BCKP_PRINTF
#define bkpd_dbgp(x,...) \
		printf("%s : %d => "x, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define bkpd_dbgp(x,...)
#endif

#endif /* BACKUPD_H_ */
