#ifndef _BWMON_H_
#define _BWMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <termios.h>
#ifndef TIOSCGWINSZ
#include <sys/ioctl.h>
#endif
#include "../defines.h"

typedef enum
{ 
    FALSE = 0,
    TRUE
} bool_t;

typedef struct interface {
    char name[16];
    struct timeval time_old, time_new;
    long long tx_bytes_old, rx_bytes_old, tx_bytes_new;
    long long rx_bytes_new, tx_kbytes_dif, rx_kbytes_dif;
    long long tx_pkt_old, rx_pkt_old, tx_pkt_new;
    long long rx_pkt_new, tx_pkt_dif, rx_pkt_dif;
    long long time_diff_ms;
    long tx_rate_whole, rx_rate_whole, tot_rate_whole;
    long tx_rate_part, rx_rate_part, tot_rate_part;
    long rx_max_whole, rx_max_part, tx_max_whole, tx_max_part;
    long tx_pkt_rate, rx_pkt_rate;
} * interface_t;

#if 0
typedef struct total_interface {
    long long rx_bw_total_whole, tx_bw_total_whole, tot_bw_total_whole;
    unsigned rx_bw_total_part, tx_bw_total_part, tot_bw_total_part;
} total_interface_t;

void initialize_total(total_interface_t *);
bool_t do_total(total_interface_t *, interface_t *);
bool_t print_total(char *, total_interface_t *);
#endif

bool_t do_interface(char *, interface_t *);
bool_t count_average(interface_t *, float *);
long bwm_calc_remainder(long long, long long);

bool_t print_interface(interface_t *);
bool_t print_max(interface_t *);
void  print_help(char *);

void  exit_handler(int);

#ifdef __GNUC__
#define fatal(...)\
{\
    fprintf(stderr, "FATAL ERROR OCCURED: ");\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, ": %s\n", strerror(errno));\
    exit(-1);\
}

#else /* __GNUC__ */
void
fatal(const char * fmt, ...)
{
    va_list list;

    fprintf(stderr, "FATAL ERROR OCCURED: ");
    va_start(list, fmt);
    vfprintf(stderr, fmt, list);
    va_end(list);
    fprintf(stderr, ": %s\n", strerror(errno));
    exit(-1);
}

#endif /* __GNUC__ */

#endif  /* _BWMON_H_ */
