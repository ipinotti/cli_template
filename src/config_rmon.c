#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

#include <libconfig/defines.h>
#include <libconfig/args.h>
#include <libconfig/exec.h>
#include <libconfig/snmp.h>
#include <libconfig/mib.h>

void rmon_agent(const char *cmd)
{
	if( libconfig_exec_check_daemon(RMON_DAEMON) == 0 )
		libconfig_exec_daemon(RMON_DAEMON);
}

void rmon_event(const char *cmd)
{
	int i, log;
	arglist *args;
	char *descr, *owner, *community;

	args = libconfig_make_args(cmd);
	if( args->argc > 3 ) {
		for(i=3, log=0, community=NULL, descr=NULL, owner=NULL; i < args->argc; i++) {
			if( strcmp(args->argv[i], "log") == 0 )
				log = 1;
			else if( strcmp(args->argv[i], "trap") == 0 ) {
				if( (++i) < args->argc )
					community = args->argv[i];
			}
			else if( strcmp(args->argv[i], "description") == 0 ) {
				if( (++i) < args->argc )
					descr = args->argv[i];
			}
			else if( strcmp(args->argv[i], "owner") == 0 ) {
				if( (++i) < args->argc )
					owner = args->argv[i];
			}
		}
		if( libconfig_snmp_rmon_add_event(atoi(args->argv[2]), log, community, 1, descr, owner) < 0 )
			printf("%% Not possible to add event\n");
		libconfig_snmp_rmon_send_signal(SIGUSR1);
	}
	libconfig_destroy_args(args);
}

void rmon_alarm(const char *cmd)
{
	arglist *args;
	char *owner = NULL;
	oid name[MAX_OID_LEN];
	size_t namelen = MAX_OID_LEN;
	int i, var_type = 0, rising_th = 0, rising_event = 0, falling_th = 0, falling_event = 0;

	args = libconfig_make_args(cmd);
	if( args->argc < 10 ) {
		printf("%% Invalid command\n");
		return;
	}

	if( libconfig_snmp_translate_oid(args->argv[3], name, &namelen) == 0 ) {
		printf("%% Invalid object identifier\n");
		return;
	}
	/* Verificacao da instancia */
	{
		int n, isstr;
		char *p, *local;
		arg_list argl=NULL;

		if( (local = strdup(args->argv[3])) != NULL ) {
			while( (p = strchr(local, '.')) != NULL )
				*p = ' ';
			if( (n = libconfig_parse_args_din(local, &argl)) > 0 ) {
				for( i=(n-1), isstr=-1; (i >= 0) && (isstr == -1); i-- ) {
					for( p=argl[i]; *p != 0; p++ ) {
						if( isdigit(*p) == 0 ) {
							isstr = i;
							break;
						}
					}
				}
				if( isstr == (n-1) )
					printf("ALERT: Apparently no instance specified. Is this really what you want?\n\n");
			}
			libconfig_destroy_args_din(&argl);
			free(local);
		}
	}

	for( i=5; i < args->argc; i++ ) {
		if( strcmp(args->argv[i], "absolute") == 0 )
			var_type = SAMPLE_ABSOLUTE;
		else if( strcmp(args->argv[i], "delta") == 0 )
			var_type = SAMPLE_DELTA;
		else if( strcmp(args->argv[i], "rising-threshold") == 0 ) {
			if( (++i) < args->argc ) {
				rising_th = atoi(args->argv[i]);
				if( (i + 1) < args->argc ) {
					if( (strcmp(args->argv[i+1], "falling-threshold") != 0) && (strcmp(args->argv[i+1], "owner") != 0) )
						rising_event = atoi(args->argv[++i]);
				}
			}
		}
		else if( strcmp(args->argv[i], "falling-threshold") == 0 ) {
			if( (++i) < args->argc ) {
				falling_th = atoi(args->argv[i]);
				if( (i + 1) < args->argc ) {
					if( (strcmp(args->argv[i+1], "rising-threshold") != 0) && (strcmp(args->argv[i+1], "owner") != 0) )
						falling_event = atoi(args->argv[++i]);
				}
			}
		}
		else if( strcmp(args->argv[i], "owner") == 0 ) {
			if( (++i) < args->argc )
				owner = args->argv[i];
		}
	}

	if( libconfig_snmp_rmon_add_alarm( atoi(args->argv[2]), 
				args->argv[3], 
				name, 
				namelen, 
				atoi(args->argv[4]), 
				var_type, 
				rising_th, 
				rising_event, 
				falling_th, 
				falling_event, 
				atoi(args->argv[4]) ? 1 : 0, owner) < 0 )
		printf("%% Not possible to add alarm\n");

	libconfig_snmp_rmon_send_signal(SIGUSR1);

	libconfig_destroy_args(args);
}

void no_rmon_agent(const char *cmd)
{
	if( libconfig_exec_check_daemon(RMON_DAEMON) )
		libconfig_kill_daemon(RMON_DAEMON);
}

void no_rmon_event(const char *cmd)
{
	arglist *args = libconfig_make_args(cmd);

	switch( args->argc ) {
		case 3:
			if( libconfig_snmp_rmon_remove_event(NULL) < 0 )
				printf("%% Not possible to remove all events\n");
			break;

		case 4:
			if( libconfig_snmp_rmon_remove_event(args->argv[3]) < 0 )
				printf("%% Not possible to remove all events\n");
			break;
	}
	libconfig_destroy_args(args);
	libconfig_snmp_rmon_send_signal(SIGUSR1);
}

void no_rmon_alarm(const char *cmd)
{
	arglist *args = libconfig_make_args(cmd);

	switch( args->argc ) {
		case 3:
			if( libconfig_snmp_rmon_remove_alarm(NULL) < 0 )
				printf("%% Not possible to remove all alarms\n");
			break;

		case 4:
			if( libconfig_snmp_rmon_remove_alarm(args->argv[3]) < 0 )
				printf("%% Not possible to remove all alarms\n");
			break;
	}
	libconfig_destroy_args(args);
	libconfig_snmp_rmon_send_signal(SIGUSR1);
}

void show_rmon_events(const char *cmd)
{
	arglist *args = libconfig_make_args(cmd);

	switch( args->argc ) {
		case 3:
			libconfig_snmp_rmon_show_event(NULL);
			break;

		case 4:
			libconfig_snmp_rmon_show_event(args->argv[3]);
			break;
	}
	libconfig_destroy_args(args);
}

void show_rmon_alarms(const char *cmd)
{
	arglist *args = libconfig_make_args(cmd);

	switch( args->argc ) {
		case 3:
			libconfig_snmp_rmon_show_alarm(NULL);
			break;

		case 4:
			libconfig_snmp_rmon_show_alarm(args->argv[3]);
			break;
	}
	libconfig_destroy_args(args);
}

void show_rmon_agent(const char *cmd)
{
	int i, show;
	struct rmon_config *shm_rmon_p;

	if( libconfig_exec_check_daemon(RMON_DAEMON) ) {
		if( libconfig_snmp_rmon_send_signal(SIGUSR2) ) {
			for(i=0, show=0; i < 10; i++) {
				if( libconfig_snmp_rmon_get_access_cfg(&shm_rmon_p) ) {
					if( shm_rmon_p->valid_state ) {
						printf("  %s\n", shm_rmon_p->state);
						shm_rmon_p->valid_state = 0;
						libconfig_snmp_rmon_free_access_cfg(&shm_rmon_p);
						show++;
						break;
					}
					else {
						libconfig_snmp_rmon_free_access_cfg(&shm_rmon_p);
						usleep(110000);
					}
				}
				else
					usleep(110000);
			}
			if( show == 0 )
				printf("  Not possible to show RMON agent state\n");
		}
	}
	else
		printf("  RMON agent isn't running\n");
}

void show_rmon_mibs(const char *cmd)
{
	FILE *f;
	char *p, buf[256];
	int printed_full = 0, printed_part = 0;

	/* MIBs completamente carregadas */
	if( (f = fopen(MIB_FILES_LOAD_STATS, "r")) != NULL ) {
		while( (feof(f) == 0) ) {
			if( fgets(buf, 255, f) != buf )
				break;
			buf[255] = 0;
			if( (p = strchr(buf, '.')) )
				*p = 0;
			if( printed_full == 0 ) {
				printf("MIBs loaded:\n");
				printed_full = 1;
			}
			printf("   %s\n", buf);
		}
		fclose(f);
	}
	/* MIBs parcialmente carregadas */
	if( (f = fopen(MIB_FILES_PARTLOAD_STATS, "r")) != NULL ) {
		while( (feof(f) == 0) ) {
			if( fgets(buf, 255, f) != buf )
				break;
			buf[255] = 0;
			if( (p = strchr(buf, '.')) )
				*p = 0;
			if( printed_part == 0 ) {
				printf("%sMIBs partially loaded:\n", (printed_full == 1) ? "\n" : "");
				printed_part = 1;
			}
			printf("   %s\n", buf);
		}
		fclose(f);
	}
	printf("%s\n", ((printed_full == 1) || (printed_part == 1)) ? "" : "No MIBs loaded\n");
}

void show_rmon_mibtree(const char *cmd)
{
	if( libconfig_snmp_dump_mibtree() < 0 )
		printf("Not possible to show MIB tree!\n");
}

void clear_rmon_events(const char *cmd)
{
	libconfig_snmp_rmon_clear_events();
}

