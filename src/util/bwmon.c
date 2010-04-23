#include <libconfig/args.h>
#include "bwmon.h"

static int print_bytes = 0;
static struct termios new_settings, initial_settings;

int main(int argc, char **argv)
{
	FILE *f;
	unsigned int k;
	char buffer[256];
	arg_list argl = NULL;
	float cpu, mem, scale;
	long mem_free, mem_total;
	struct sigaction eact, eoldact;
	interface_t interface[MAX_INTERFACES];
	int opt, i = 0, j = 0, max = 0, timeout = 1, first_pass = 1;
	long long idle, user, nice, system, iowait, irq, softirq; 
	long long idle_old = 0, nice_old = 0, user_old = 0, system_old = 0;
	long long iowait_old = 0, irq_old = 0, softirq_old = 0;
#if 1
	fd_set rfds;
	struct timeval tv;
#endif
#if 0
	total_interface_t sum_if;
#endif

	for (k=0; k < MAX_INTERFACES; k++)
		interface[k] = NULL;
	if (argc > 0) {
		while ((opt = getopt(argc, argv, "bu:m")) != -1) {
			switch (opt) {
				case 'b':
					print_bytes = 1;
					break;
				case 'm': 
					max = 1;
					break;
				case 'u':
					if ((timeout = atoi(optarg)) < 1)
						fatal("timeout must be larger than 0");
			}
		}
	}

	eact.sa_handler = exit_handler;
	sigemptyset(&eact.sa_mask);
	eact.sa_flags = 0;
	if (sigaction(SIGINT, &eact, &eoldact) < 0)
		fatal("sigaction failed in %s", __FUNCTION__);

	if (isatty(STDIN_FILENO) == 0)
		fatal("isatty failed in %s. not on terminal", __FUNCTION__);

	tcgetattr(0, &initial_settings);
	new_settings = initial_settings;
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_lflag &= ~ECHO;
	new_settings.c_lflag &= ~ISIG;
	new_settings.c_cc[VMIN] = 1;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new_settings);

	for (;;) {
#if 0
		initialize_total(&sum_if);
#endif
		sprintf(buffer, "/bin/cat %s", STATFILE);
		if (!(f = popen(buffer, "r")))
			fatal("popen() failed  in %s", __FUNCTION__);
		if (fgets(buffer, 255, f) && fgets(buffer, 255, f)) {
			buffer[255] = 0;
			if ((parse_args_din(buffer, &argl) > 7) && (strcmp(argl[0], "cpu0") == 0)) {
				user = atoll(argl[1]);
				nice = atoll(argl[2]);
				system = atoll(argl[3]);
				idle = atoll(argl[4]);
				iowait = atoll(argl[5]);
				irq = atoll(argl[6]);
				softirq = atoll(argl[7]);
				scale = 100.0 / (float) ( (user - user_old) + 
					(nice - nice_old) + (system - system_old) + 
					(idle - idle_old) 
#if 1
					+ (iowait - iowait_old) +
					(irq - irq_old)   + (softirq - softirq_old)
#endif
 					);
				cpu = (float) ( (user - user_old) + 
					(nice - nice_old) + (system - system_old) 
#if 1
					+ (iowait - iowait_old) + (irq - irq_old)   + 
					(softirq - softirq_old) 
#endif
					) * scale ;

				user_old = user;
				nice_old = nice;
				system_old = system;
				idle_old = idle;
				iowait_old = iowait;
				irq_old = irq;
				softirq_old = softirq; 
			}
			free_args_din(&argl);
		}
		pclose(f);

		if ((f = fopen(MEMFILE, "r")) == NULL)
			fatal("fopen() failed  in %s", __FUNCTION__);
		j = 0;
		if (fgets(buffer, 255, f)) {
			buffer[255] = 0;
			if (parse_args_din(buffer, &argl) > 1) {
				if (strcmp(argl[0], "MemTotal:") == 0) {
					mem_total = atoll(argl[1]);
					j++;
				}
			}
			free_args_din(&argl);
		}
		if (fgets(buffer, 255, f)) {
			buffer[255] = 0;
			if (parse_args_din(buffer, &argl) > 1) {
				if (strcmp(argl[0], "MemFree:") == 0) {
					mem_free = atoll(argl[1]);
					j++;
				}
			}
			free_args_din(&argl);
		}
		if (j == 2)
			mem = (float)(mem_total-mem_free)*100.0/mem_total;
		fclose(f);

		if ((f = fopen(DEVFILE, "r")) == NULL)
			fatal("fopen() failed  in %s", __FUNCTION__);
		if (fgets(buffer, 255, f) && fgets(buffer, 255, f)) {
			i = 0;
			while (fgets(buffer, 255, f) && (i < (MAX_INTERFACES - 1))) {
				if (!do_interface(buffer, &interface[i]))
					continue;
				i++;
			}
		}
		fclose(f);
#if 0
		for (j = 0; j < i; j++)
			if (!do_total(&sum_if, &interface[j]))
				fatal("do_total failed in %s", __FUNCTION__);
#endif

		if (!first_pass) {
			printf(" %#5.1f%%  ", cpu);
			printf(" %#5.1f%% ", mem);
			for (j=0; j < i; j++) {
				print_interface(&interface[j]);
				if (max == 1) {
					print_max(&interface[j]);
					printf("\n");
				}
			}
			printf("\n");
			/* Watch stdin (fd 0) to see when it has input. */
			FD_ZERO(&rfds);
			FD_SET(0, &rfds);
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			if (select(1, &rfds, NULL, NULL, &tv)) {
				if (FD_ISSET(0, &rfds)) {
					getc(stdin);
					break;
				}
			}
		} else {
/*
                             serial0                   ethernet0
CPU used MEM used  TX(Kbps)@pps  RX(Kbps)@pps  TX(Kbps)@pps  RX(Kbps)@pps
  46.2%    79.1%    246.656@111   314.242@111   370.758@111   275.436@111
*/
			printf("                 ");
			for (j = 0; j < i; j++)
				printf("          %11s         ", interface[j]->name);
			printf("\n");
			printf("CPU used MEM used");
			for (j = 0; j < i; j++)
				printf("  TX(K%cps)@pps    RX(K%cps)@pps  ", print_bytes == 1 ? 'B': 'b', print_bytes == 1 ? 'B': 'b');
			printf("\n");
			first_pass = 0;

			sleep(1);
		}
    }
    tcsetattr(0, TCSANOW, &initial_settings);
    exit(0);
}

bool_t do_interface(char * buffer, interface_t *interface)
{
	char *pbuffer = NULL;
	int field_number = 0;
	long long conv_field = 0;

	pbuffer = buffer;
	pbuffer = strtok(pbuffer, " :");

	if (strncmp(pbuffer, "ethernet", 8) && strncmp(pbuffer, "serial", 6) && strncmp(pbuffer, "aux", 3))
		return FALSE; /* Filter interfaces */

	if (*interface == NULL) {
		if ((*interface = (interface_t)malloc(sizeof(struct interface))) == NULL)
			return FALSE;
		strncpy((*interface)->name, pbuffer, 16);
	}
	(*interface)->time_old = (*interface)->time_new;
	gettimeofday(&((*interface)->time_new), NULL);

	(*interface)->time_diff_ms = ((*interface)->time_new.tv_sec * 1000 + (*interface)->time_new.tv_usec / 1000)
								- ((*interface)->time_old.tv_sec * 1000 + (*interface)->time_old.tv_usec / 1000);
	field_number = 0;

	while ((pbuffer = strtok(NULL, " :") ) != NULL) {
		conv_field = strtoull(pbuffer, NULL, 10);
		field_number++;

		switch (field_number) {
			case 1:
				(*interface)->rx_bytes_old = (*interface)->rx_bytes_new;
				if (print_bytes == 0)
					(*interface)->rx_bytes_new = conv_field * 8;
				else
					(*interface)->rx_bytes_new = conv_field;
				if ((*interface)->rx_bytes_new > (*interface)->rx_bytes_old)
					(*interface)->rx_kbytes_dif = ((*interface)->rx_bytes_new - (*interface)->rx_bytes_old) * 1000 / 1024;
				else
					(*interface)->rx_kbytes_dif = 0;
				(*interface)->rx_rate_whole = (*interface)->rx_kbytes_dif / (*interface)->time_diff_ms;
				(*interface)->rx_rate_part = bwm_calc_remainder((*interface)->rx_kbytes_dif, (*interface)->time_diff_ms);
				if ((*interface)->rx_rate_whole >= (*interface)->rx_max_whole) {
					if (((*interface)->rx_rate_part > (*interface)->rx_max_part) ||
						((*interface)->rx_rate_whole >= (*interface)->rx_max_whole)) {
						(*interface)->rx_max_part  = (*interface)->rx_rate_part;
						(*interface)->rx_max_whole = (*interface)->rx_rate_whole;
					}
				}
				break;

			case 2:
				(*interface)->rx_pkt_old = (*interface)->rx_pkt_new;
				(*interface)->rx_pkt_new = conv_field;
				if ((*interface)->rx_pkt_new > (*interface)->rx_pkt_old)
					(*interface)->rx_pkt_dif = ((*interface)->rx_pkt_new - (*interface)->rx_pkt_old);
				else
					(*interface)->rx_pkt_dif = 0;
				(*interface)->rx_pkt_rate = (*interface)->rx_pkt_dif;
				break;

			case 9:
				(*interface)->tx_bytes_old = (*interface)->tx_bytes_new;
				if (print_bytes == 0)
					(*interface)->tx_bytes_new = conv_field * 8;
				else
					(*interface)->tx_bytes_new = conv_field;
				if ((*interface)->tx_bytes_new > (*interface)->tx_bytes_old)
					(*interface)->tx_kbytes_dif = ((*interface)->tx_bytes_new - (*interface)->tx_bytes_old) * 1000 / 1024;
				else
					(*interface)->tx_kbytes_dif = 0;
				(*interface)->tx_rate_whole = (*interface)->tx_kbytes_dif / (*interface)->time_diff_ms;
				(*interface)->tx_rate_part = bwm_calc_remainder((*interface)->tx_kbytes_dif, (*interface)->time_diff_ms);
				if ((*interface)->tx_rate_whole >= (*interface)->tx_max_whole) {
					if (((*interface)->tx_rate_part > (*interface)->tx_max_part) ||
						((*interface)->tx_rate_whole >= (*interface)->tx_max_whole) ) {
						(*interface)->tx_max_part  = (*interface)->tx_rate_part;
						(*interface)->tx_max_whole = (*interface)->tx_rate_whole;
					}
				}

				(*interface)->tot_rate_whole = (*interface)->rx_rate_whole +
					(*interface)->tx_rate_whole;
				(*interface)->tot_rate_part = (*interface)->rx_rate_part +
					(*interface)->tx_rate_part;
			
				if ((*interface)->tot_rate_part >= 1000) {
					(*interface)->tot_rate_whole++;
					(*interface)->tot_rate_part -= 1000;
				}
				break;

			case 10:
				(*interface)->tx_pkt_old = (*interface)->tx_pkt_new;
				(*interface)->tx_pkt_new = conv_field;
				if ((*interface)->tx_pkt_new > (*interface)->tx_pkt_old)
					(*interface)->tx_pkt_dif = ((*interface)->tx_pkt_new - (*interface)->tx_pkt_old);
				else
					(*interface)->tx_pkt_dif = 0;
				(*interface)->tx_pkt_rate = (*interface)->tx_pkt_dif;
				break;
		}
	}
	return TRUE;
}

bool_t print_interface(interface_t * interface) 
{
	printf(" %5lu.%03lu@%-5lu %5lu.%03lu@%-5lu",
		   (*interface)->tx_rate_whole,  (*interface)->tx_rate_part, (*interface)->tx_pkt_rate,
		   (*interface)->rx_rate_whole,  (*interface)->rx_rate_part, (*interface)->rx_pkt_rate);

	return(TRUE);
}

bool_t print_max(interface_t * interface)
{
	long max_part = (*interface)->rx_max_part + (*interface)->tx_max_part;
	long max_whole = (*interface)->rx_max_whole + (*interface)->tx_max_whole;

	if (max_part >= 1000) {
		max_whole++;
		max_part -= 1000;
	}
	printf("        max:      %7lu.%03lu     %7lu.%03lu     %7lu.%03lu\n", (*interface)->rx_max_whole,
																			(*interface)->rx_max_part,
																			(*interface)->tx_max_whole,
																			(*interface)->tx_max_part,
																			max_whole,
																			max_part);
	return TRUE;
}

long bwm_calc_remainder(long long num, long long den)
{
	long long d = den, n = num;

	return (((n - (n / d) * d) * 1000) / d);
}

#if 0
void initialize_total(total_interface_t *total_if)
{
	total_if->rx_bw_total_whole = total_if->tx_bw_total_whole = 0;
	total_if->tot_bw_total_whole = total_if->rx_bw_total_part = 0;
	total_if->tx_bw_total_part = total_if->tot_bw_total_part  = 0;
}

bool_t do_total(total_interface_t * total_if, interface_t * interface)
{
	total_if->rx_bw_total_whole += (*interface)->rx_rate_whole;
	total_if->rx_bw_total_part += (*interface)->rx_rate_part;

	if (total_if->rx_bw_total_part >= 1000) {
		total_if->rx_bw_total_whole++;
		total_if->rx_bw_total_part -= 1000;
	}
	total_if->tx_bw_total_whole += (*interface)->tx_rate_whole;
	total_if->tx_bw_total_part += (*interface)->tx_rate_part;

	if (total_if->tx_bw_total_part >= 1000) {
		total_if->tx_bw_total_whole++;
		total_if->tx_bw_total_part -= 1000;
	}
	total_if->tot_bw_total_whole = total_if->rx_bw_total_whole + total_if->tx_bw_total_whole;
	total_if->tot_bw_total_part = total_if->rx_bw_total_part + total_if->tx_bw_total_part;

	if (total_if->tot_bw_total_part >= 1000) {
		total_if->tot_bw_total_whole++;
		total_if->tot_bw_total_part -= 1000;
	}
	return TRUE;
}

bool_t print_total(char * method, total_interface_t * total_if)
{
	printf("%12s     %8lu.%03u    %8lu.%03u    %8lu.%03u\n\n", method,
															total_if->rx_bw_total_whole,
															total_if->rx_bw_total_part,
															total_if->tx_bw_total_whole,
															total_if->tx_bw_total_part,
															total_if->tot_bw_total_whole,
															total_if->tot_bw_total_part);
	return TRUE;
}
#endif

void exit_handler(int signo)
{
	tcsetattr(0, TCSANOW, &initial_settings);
 	exit(signo);
}

