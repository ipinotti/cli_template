/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * Policy Map Command Support  
 *	
 * Thomás Del Grande - PD3 Tecnologia
 * 
 * ============================================================================== */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/mman.h> /* mmap */

#include "options.h"

#include "defines.h"
#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"
#include "commands_mangle.h"
#include "policymap.h"


//#define PRINTF() printf("%s : %d\n", __FUNCTION__, __LINE__);


extern cish_command CMD[];
extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_POLICYMAP[];
extern cish_command CMD_POLICYMAP_MARKRULE[];
extern int _cish_booting;

static char pname[32];
static int mark;

/* Main functions - parsing and configuring via libconfig */
void do_policy_description(const char *cmdline) /* [no] description [<text>]*/
{
	
	arglist *args;

	args = make_args(cmdline);
	
	if (args->argc < 2) {
		destroy_args(args);
		return;
	}

	if (!strcmp(args->argv[0],"no")) {
		destroy_policymap_desc(pname);
		destroy_args(args);
	} else {
		pmap_cfg_t *pmap;
		char *description;
		description = (char *) cmdline;
		while (*description == ' ') ++description;
		description = strchr (description, ' ');
		if (!description) {
			destroy_args(args);
			return;
		}
		while (*description == ' ') ++description;
		if (get_policymap(pname,&pmap) <= 0) {
			destroy_args(args);
			return;
		} 
		strncpy(pmap->description, description,255);
		save_policymap_desc(pname, pmap);
	
	free_policymap(pmap);
	destroy_args(args);
	}
}



void do_policy_mark(const char *cmdline) /* [no] mark [1-200000000]*/
{
	arglist *args;
	pmap_cfg_t *pmap;
	
	args = make_args(cmdline);
	if (args->argc < 2) { 
		destroy_args(args); 
		return; 
	}

	if (get_policymap(pname,&pmap) < 0) {
		destroy_args(args); 
		return; 
	}

	if (!strcmp(args->argv[0],"no")) {
		mark = atoi(args->argv[2]);
		delete_policy_mark(pname, mark);
		mark=0;
	} else {
		mark = atoi(args->argv[1]);
		add_policy_mark(pname, mark); /* Add if it does not exit */
		command_root = CMD_POLICYMAP_MARKRULE;
	}
	free_policymap(pmap);
	destroy_args(args);
}

void config_policy_bw(const char *cmdline) /* [no] bandwidth */
{
	arglist *args;
	pmap_cfg_t *pmap;
	pmark_cfg_t *pmark;
	int i;

	args = make_args(cmdline);
	if (args->argc < 2) {
		printf("%% Not enough arguments");
		destroy_args(args);
		return;
	}
	if (get_policymap(pname,&pmap) <= 0) {
		destroy_args(args); 
		return; 
	}
	
	i = get_mark_index(mark, pmap);
	if (i < 0 || i == pmap->n_mark) {
		printf("Could not find mark %d for this policy map\n", mark);
		return;
	}
	pmark = &(pmap->pmark[i]);
	pmark->bw=0;
	pmark->bw_perc=0;
	pmark->bw_remain_perc=0;

	if (args->argc == 2 && strcmp(args->argv[0],"no")) {
		int tmp = atoi(args->argv[1]);
		
		if (strcasestr(args->argv[1],"kbps")) pmark->bw=tmp*1024;
		else if (strcasestr(args->argv[1],"mbps")) pmark->bw=tmp*1048576;
		else if (strcasestr(args->argv[1],"bps")) pmark->bw=tmp;
		else printf("Bandwidth value ERROR\n");

	} else if (args->argc == 3) {
		pmark->bw_perc = atoi(args->argv[2]);
	
	} else if (args->argc == 4) {
		pmark->bw_remain_perc = atoi(args->argv[3]);
	}
	free_policymap(pmap);
	destroy_args(args);
}

void config_policy_ceil(const char *cmdline) /* [no] ceil */
{
	arglist *args;
	pmap_cfg_t *pmap;
	pmark_cfg_t *pmark;
	int i;

	args = make_args(cmdline);
	if (args->argc < 2) {
		printf("%% Not enough arguments");
		destroy_args(args);
		return;
	}
	if (get_policymap(pname,&pmap) <= 0) {
		destroy_args(args); 
		return; 
	}
	i = get_mark_index(mark, pmap);
	if (i < 0 || i == pmap->n_mark) {
		printf("Could not find mark %d for this policy map\n", mark);
		return;
	}
	pmark = &(pmap->pmark[i]);
	pmark->ceil=0;
	pmark->ceil_perc=0;
	pmark->ceil_remain_perc=0;

	if (args->argc == 2 && strcmp(args->argv[0],"no")) {
		int tmp = atoi(args->argv[1]);
		if (strcasestr(args->argv[1],"kbps")) pmark->ceil=tmp*1024;
		else if (strcasestr(args->argv[1],"mbps")) pmark->ceil=tmp*1048576;
		else if (strcasestr(args->argv[1],"bps")) pmark->ceil=tmp;
		else printf("Ceil value ERROR\n");
	
	} else if (args->argc == 3) {
		pmark->ceil_perc = atoi(args->argv[2]);
	
	} else if (args->argc == 4) {
		pmark->ceil_remain_perc = atoi(args->argv[3]);
	}
	free_policymap(pmap);
	destroy_args(args);
}

void config_policy_queue(const char *cmdline) /* [no] queue [fifo|red|sfq|wfq] */
{
	arglist *args;
	pmap_cfg_t *pmap;
	int i=0;
	pmark_cfg_t *pmark = NULL;

	args = make_args(cmdline);
	if (args->argc < 2) {
		printf("%% Not enough arguments");
		return;
	}

	/* Import policy map*/
	if (get_policymap(pname,&pmap) <= 0) {
		destroy_args(args);
		return;
	}
	i = get_mark_index(mark, pmap);
	if (i < 0 || i == pmap->n_mark) {
		printf("Could not find mark %d for this policy map\n", mark);
		return;
	}

	pmark = &(pmap->pmark[i]);

	if (!strcmp(args->argv[0],"no")) {
		pmark->queue = FIFO; /* default is FIFO */
		pmark->fifo_limit=0;
	
	} else if (strcmp(args->argv[1], "fifo") == 0) {
		pmark->queue = FIFO;
		if (args->argc == 3) pmark->fifo_limit = atoi(args->argv[2]);
		else pmark->fifo_limit = 0;
	
	} else if (strcmp(args->argv[1], "sfq") == 0) {
		pmark->queue = SFQ;
		if (args->argc == 3) pmark->sfq_perturb = atoi(args->argv[2]);
		else pmark->sfq_perturb = 0;
	
	} else if (strcmp(args->argv[1], "wfq") == 0) {
		pmark->queue = WFQ;
		if (args->argc == 3) pmark->wfq_hold_queue = atoi(args->argv[2]);
		else pmark->wfq_hold_queue = 1024;
	
	} else if (strcmp(args->argv[1], "red") == 0) {
		pmark->queue = RED;
		pmark->red_latency=atoi(args->argv[2]);
		pmark->red_probability=atoi(args->argv[3]);
		if (args->argc == 6) {
			if (strcmp(args->argv[4], "ecn") == 0) pmark->red_ecn = 1;
			else pmark->red_ecn = 0;
		}
		else pmark->red_ecn=0;
	}
	free_policymap(pmap);
	destroy_args(args);
}

void config_policy_realtime(const char *cmdline) /* [no] realtime <64-1500> <50-5000> <bandwidth> */
{
	arglist *args;
	pmap_cfg_t *pmap;
	pmark_cfg_t *pmark;
	int i;

	args = make_args(cmdline);
	if (args->argc < 2) {
		printf("%% Not enough arguments");
		destroy_args(args);
		return;
	}
	if (get_policymap(pname,&pmap) <= 0) {
		destroy_args(args); 
		return; 
	}
	i = get_mark_index(mark, pmap);
	if (i < 0 || i == pmap->n_mark) {
		printf("Could not find mark %d for this policy map\n", mark);
		return;
	}
	pmark = &(pmap->pmark[i]);
	pmark->realtime=BOOL_FALSE;
	pmark->rt_max_delay=0;		
	pmark->rt_max_unit=0;	

	if (args->argc == 3) {
		pmark->realtime = BOOL_TRUE;
		pmark->rt_max_delay = atoi(args->argv[1]);
		pmark->rt_max_unit = atoi(args->argv[2]);
	}

	free_policymap(pmap);
	destroy_args(args);
}

void do_policymap(const char *cmdline) /* [no] policy-map <text> */
{
	arglist *args;
	pmap_cfg_t *pmap;
	char *dev;
	int idx;

	args = make_args(cmdline);
	if (args->argc < 2) {
		printf("%% Not enough arguments\n");
		destroy_args(args);
		return;
	}

	idx = (args->argc == 3) ? 2 : 1;
	if ((dev = check_active_qos(args->argv[idx]))) {
		printf("Policy-map %s is active on interface %s. Please disable it before configuring.\n",
		args->argv[idx], dev);
		destroy_args(args);
		free(dev);
		return;
	}

	if (args->argc == 3 && !strcmp(args->argv[0],"no")) {
		destroy_policymap(args->argv[2]);
		destroy_args(args);
		return;
	}

	if (args->argc == 2) {
		if (get_policymap(args->argv[1],&pmap) == 0) {
			if (create_policymap(args->argv[1]))
				return;
			if (get_policymap(args->argv[1],&pmap) < 0)
				return;
		}
		if (pmap == NULL) 
			printf("%% ERROR: Could not enter %s configuration\n", args->argv[1]);
		else {/* success */
			command_root = CMD_POLICYMAP;
			strncpy(pname, args->argv[1], 31);
		}
	}
	free_policymap(pmap);
	destroy_args(args);
}

void quit_mark_config(const char *cmdline) 
{
	mark=0;	/* Clear global variable mark */
	command_root = CMD_POLICYMAP;
}

void policymap_done(const char *cmdline)
{
	memset(pname,0,32); /* Clear global value pname */
	command_root = CMD_CONFIGURE;
}
