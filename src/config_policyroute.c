/*
 * config_policyroute.c
 *
 *  Created on: Feb 2, 2011
 *      Author: Igor Kramer Pinotti (ipinotti@pd3.com.br)
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>

#include <librouter/options.h>
#include <librouter/pbr.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"

static int route_fill_pbr_struct_from_args(librouter_pbr_struct * pbr, arglist * args)
{
	memset(pbr,0,sizeof(librouter_pbr_struct));

	if (!strcmp(args->argv[1],"default")){
		switch (args->argc){
			case 6:/*default opt com via */
				sprintf(pbr->table,"%s%s",args->argv[4],args->argv[5]);
				sprintf(pbr->via_ipaddr,"%s",args->argv[3]);
				sprintf(pbr->network_opt,"%s",args->argv[1]);
				break;

			case 7:/*default opt*/
				sprintf(pbr->table,"%s%s",args->argv[5],args->argv[6]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[3],atoi(args->argv[4]),-1));
				sprintf(pbr->network_opt,"%s",args->argv[1]);
				break;

			case 9:/*default opt com via + dev*/
				sprintf(pbr->table,"%s%s",args->argv[7],args->argv[8]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[5],atoi(args->argv[6]),-1));
				sprintf(pbr->via_ipaddr,"%s",args->argv[3]);
				sprintf(pbr->network_opt,"%s",args->argv[1]);
				break;

			default:
				return -1;
				break;
		}
	}
	else {
		switch (args->argc){
			case 7:/*ipaddr opt com via*/
				sprintf(pbr->table,"%s%s",args->argv[5],args->argv[6]);
				sprintf(pbr->via_ipaddr,"%s",args->argv[4]);
				sprintf(pbr->network_opt_ipmask,"%s",args->argv[2]);
				sprintf(pbr->network_opt,"%s",args->argv[1]);
				break;

			case 8:/*ipaddr opt*/
				sprintf(pbr->table,"%s%s",args->argv[6],args->argv[7]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[4],atoi(args->argv[5]),-1));
				sprintf(pbr->network_opt_ipmask,"%s",args->argv[2]);
				sprintf(pbr->network_opt,"%s",args->argv[1]);
				break;

			case 10:/*ipaddr opt com via + dev*/
				sprintf(pbr->table,"%s%s",args->argv[8],args->argv[9]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[6],atoi(args->argv[7]),-1));
				sprintf(pbr->via_ipaddr,"%s",args->argv[4]);
				sprintf(pbr->network_opt_ipmask,"%s",args->argv[2]);
				sprintf(pbr->network_opt,"%s",args->argv[1]);
				break;

			default:
				return -1;
				break;
		}
	}
	return 0;
}

static int route_fill_pbr_struct_no_from_args(librouter_pbr_struct * pbr, arglist * args)
{
	memset(pbr,0,sizeof(librouter_pbr_struct));

	if (!strcmp(args->argv[2],"default")){
		switch (args->argc){
			case 7:/*default opt com via*/
				sprintf(pbr->table,"%s%s",args->argv[5],args->argv[6]);
				sprintf(pbr->via_ipaddr,"%s",args->argv[4]);
				sprintf(pbr->network_opt,"%s",args->argv[2]);
				break;

			case 8:/*default opt*/
				sprintf(pbr->table,"%s%s",args->argv[6],args->argv[7]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[4],atoi(args->argv[5]),-1));
				sprintf(pbr->network_opt,"%s",args->argv[2]);
				break;

			case 10:/*default opt com via + dev*/
				sprintf(pbr->table,"%s%s",args->argv[8],args->argv[9]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[6],atoi(args->argv[7]),-1));
				sprintf(pbr->via_ipaddr,"%s",args->argv[4]);
				sprintf(pbr->network_opt,"%s",args->argv[2]);
				break;

			default:
				return -1;
				break;
		}
	}
	else {
		switch (args->argc){
			case 8:/*ipaddr opt com via*/
				sprintf(pbr->table,"%s%s",args->argv[6],args->argv[7]);
				sprintf(pbr->via_ipaddr,"%s",args->argv[5]);
				sprintf(pbr->network_opt_ipmask,"%s",args->argv[3]);
				sprintf(pbr->network_opt,"%s",args->argv[2]);
				break;

			case 9:/*ipaddr opt*/
				sprintf(pbr->table,"%s%s",args->argv[7],args->argv[8]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[5],atoi(args->argv[6]),-1));
				sprintf(pbr->network_opt_ipmask,"%s",args->argv[3]);
				sprintf(pbr->network_opt,"%s",args->argv[2]);
				break;

			case 11:/*ipaddr opt com via + dev*/
				sprintf(pbr->table,"%s%s",args->argv[9],args->argv[10]);
				sprintf(pbr->dev,"%s",librouter_device_cli_to_linux(args->argv[7],atoi(args->argv[8]),-1));
				sprintf(pbr->via_ipaddr,"%s",args->argv[5]);
				sprintf(pbr->network_opt_ipmask,"%s",args->argv[3]);
				sprintf(pbr->network_opt,"%s",args->argv[2]);
				break;

			default:
				return -1;
				break;
		}
	}
	return 0;
}

static int route_set_info_no(arglist * args)
{
	librouter_pbr_struct pbr;
	int check = 0;
	char cmd_cish_pbr[128];
	memset (&cmd_cish_pbr, 0 , 128);

	check = route_fill_pbr_struct_no_from_args(&pbr,args);
	if (check < 0)
		goto end;

	check = librouter_pbr_route_del(&pbr);
	if (check < 0){
		goto end;
	}

	strcpy(args->argv[0],"");
	check = librouter_args_parse_args_to_string(args,cmd_cish_pbr);
	if (check < 0){
		goto end;
	}

	check = librouter_pbr_log_entry_route_del(cmd_cish_pbr);

end:
	return check;
}

static int route_set_info(arglist * args)
{
	librouter_pbr_struct pbr;
	int check = 0;
	char cmd_cish_pbr[128];
	memset (&cmd_cish_pbr, 0 , 128);

	check = route_fill_pbr_struct_from_args(&pbr,args);
	if (check < 0)
		goto end;

	check = librouter_pbr_route_add(&pbr);
	if (check < 0)
		goto end;

	check = librouter_args_parse_args_to_string(args,cmd_cish_pbr);
	if (check < 0){
		goto end;
	}

	check = librouter_pbr_log_entry_route_add(cmd_cish_pbr);

end:
	return check;
}

void policyroute_route_set_info(const char *cmdline)
{
	arglist * args;
	int check = -1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0],"no"))
		check = route_set_info_no(args);
	else
		check = route_set_info(args);

	if (check < 0){
		printf("\n%% Error on set route for policy route - PBR");
		printf("\n%% Settings could not be applied\n\n");
	}

	librouter_destroy_args(args);
}

void policyroute_rule_set_info(const char *cmdline)
{
	arglist * args;
	int check = -1;
	char table_name[8];
	char cmd_cish_pbr[128];
	memset (&cmd_cish_pbr, 0 , 128);

	args = librouter_make_args(cmdline);

	switch (args->argc){
		case 4:
			if ((check = librouter_pbr_verify_rule_exist_in_log_entry(atoi(args->argv[1]),atoi(args->argv[3])))){
				printf("\n%% Error on set rule for policy route - PBR");
				printf("\n%% Same settings already applied\n\n");
				goto end;
			}
			sprintf(table_name,"%s%s",args->argv[2],args->argv[3]);
			if ((check = librouter_pbr_rule_add(atoi(args->argv[1]),table_name)) < 0)
				break;

			check = librouter_pbr_log_entry_rule_add((char *)cmdline);
			break;
		case 5:
			sprintf(table_name,"%s%s",args->argv[3],args->argv[4]);
			if ((check = librouter_pbr_rule_del(atoi(args->argv[2]),table_name)) < 0)
				break;

			strcpy(args->argv[0],"");
			if ((check = librouter_args_parse_args_to_string(args,cmd_cish_pbr)) < 0)
				break;

			check = librouter_pbr_log_entry_rule_del(cmd_cish_pbr);
			break;
		default:
			check = -1;
			break;
	}

end:
	if (check < 0){
		printf("\n%% Error on set rule for policy route - PBR");
		printf("\n%% Settings could not be applied\n\n");
	}

	librouter_destroy_args(args);
}

void policyroute_route_flush_table(const char *cmdline)
{
	arglist * args;
	char table_name[8];
	char table_name_log[8];
	int ret=0;
	args = librouter_make_args(cmdline);

	sprintf(table_name,"%s%s",args->argv[1],args->argv[2]);
	sprintf(table_name_log,"%s %s",args->argv[1],args->argv[2]);

	if ((ret = librouter_pbr_flush_route_table(table_name)) < 0)
		goto end;

	ret = librouter_pbr_log_entry_flush_table(table_name_log);

end:
	if (ret < 0){
		printf("\n%% Error on flush route table for policy route - PBR");
		printf("\n%% Settings could not be applied\n\n");
	}
	librouter_destroy_args(args);
}

void policyroute_done(const char *cmdline)
{
	command_root = CMD_CONFIGURE;
}

void cd_policyroute_dir(const char *cmdline)
{
	command_root = CMD_POLICY_ROUTE;
}
