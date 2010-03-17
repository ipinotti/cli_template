
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <linux/config.h>

#define __USE_XOPEN
#include <unistd.h> 

#include <libconfig/args.h>
#include <libconfig/cish_defines.h>
#include <libconfig/str.h>
#include <libconfig/ip.h>
#include <libconfig/nv.h>
#include <libconfig/ipsec.h>

#include "cish_config.h"
#include "commandtree.h"
#include "commands.h"
#include "cish_main.h"
#include "terminal_echo.h"
#include "cish_main.h"
#include "hash.h"

enum /* Key ID */
{
#if 0 /* Sempre abilitados! */
	FEATURE_OSPF_ID=0, /* old 0 */
	FEATURE_RIP_ID, /* old 1 */
#endif
	FEATURE_VPN_ID=2,
	FEATURE_MPC180_VPN_ID, /* 3 */
	FEATURE_X25_ID, /* 4 */
};

#define NUM_FEATURES 2

struct
{
	unsigned char id;
	unsigned char pos;
	char name[16];
	char descr[32];
	int mask;
} features[NUM_FEATURES] = {
	{ FEATURE_VPN_ID, 1, "vpn", "VPN support", MSK_VPN },
#ifndef OPTION_X25
	{ FEATURE_X25_ID, 0, "x25", "X.25 encapsulation", MSK_X25 | MSK_X25XOT | MSK_X25MAP },
#else
	{ FEATURE_X25_ID, 0, "x25map", "X.25 map legacy", MSK_X25XOT | MSK_X25MAP },
#endif
};

#ifdef OPTION_FEATURE

struct _saved_feature saved_features[NUM_FEATURES];

extern cish_command CMD_FEATURE[];
extern cish_command CMD_NO_FEATURE[];

void set_model_feature(int enable, int feature)
{
	int v = enable ? 1 : 1000;

	if (enable) {
		_cish_mask |= MSK_FEATURE;
	} else {
		_cish_mask &= ~MSK_FEATURE;
	}
	CMD_FEATURE[feature].privilege = v;
#ifdef FEATURE_NO
	CMD_NO_FEATURE[feature].privilege = v;
#endif
}

int is_feature_on(int index)
{
	return ((_cish_mask & features[index].mask) == features[index].mask);
}

#ifdef FEATURES_ON_FLASH
static void save_ftures(void)
{
	int i;
	char buf[6];

	memset(buf, 0, 6);
	get_mac("ethernet0", buf);
	for (i=0; i < NUM_FEATURES; i++) {
		saved_features[i].id = features[i].id;
		if (is_feature_on(i)) memcpy(saved_features[i].key, 
			hash_str((unsigned char *)buf, features[i].id), 16); /* !!! hash_str in loop! */
			else memset(saved_features[i].key, 0, 16);
	}
	save_features(&saved_features[0], sizeof(saved_features));
}
#else
static void save_ftures(int index)
{
#ifdef I2C_HC08_ID_ADDR
	char *buf;

	if ((buf=get_system_ID(0)) == NULL) return;
#else
	char buf[6];

	memset(buf, 0, 6);
	get_mac("ethernet0", buf);
#endif
	saved_features[index].pos = features[index].pos;
	if (is_feature_on(index)) {
		memcpy(saved_features[index].key, 
			hash_str((unsigned char *)buf, features[index].id), 16);
		save_feature(&saved_features[index]);
	}
}
#endif

static int feature_index(char *feature)
{
	int i;
	
	for (i=0; i < NUM_FEATURES; i++) {
		if (strcmp(features[i].name, feature) == 0)
			return  i;
	}
	printf("%% feature %s not found\n", feature);
	return (-1);
}

static void feature_on_off(int index, int on_off)
{
	if (on_off) {
		_cish_mask |= features[index].mask;
	} else {
		_cish_mask &= ~features[index].mask;
	}
}

static int ask_key(unsigned char id)
{
	char key[32];
#ifdef I2C_HC08_ID_ADDR
	char *buf;
#else
	char buf[6];
#endif

#ifdef I2C_HC08_ID_ADDR
	if ((buf=get_system_ID(0)) == NULL) return 0;
#else
	memset(buf, 0, 6);
	get_mac("ethernet0", buf);
#endif

	printf("Key: ");
	fflush(stdout);
	key[0] = 0;

	echo_off();
	cish_timeout = cish_cfg->terminal_timeout;
	fgets(key, 17, stdin);
	cish_timeout = 0;
	echo_on();
	printf("\n");

	key[16] = 0;
	striplf(key);

	return (strcmp(key, hash_str((unsigned char *)buf, id)) == 0);
}

void feature(const char *cmd) /* feature <vpn|x25> */
{
	int index;
	char feature[16];
	arglist *args;

	args = make_args(cmd);
	strncpy(feature, args->argv[1], 16);
	feature[15]=0;
	destroy_args(args);

	index = feature_index(feature);
	if (index < 0) return;

	if (is_feature_on(index)) {
		printf("%% %s is already enabled\n", features[index].descr);
	} else {
		if (ask_key(features[index].id)) {
			feature_on_off(index, 1);
			printf("%s enabled\n", features[index].descr);
#ifdef FEATURES_ON_FLASH
			save_ftures();
#else
			save_ftures(index);
#endif
		} else {
			printf("%% invalid key\n");
		}
	}
}

#ifdef NO_FEATURE
void no_feature(const char *cmd) /* no feature <vpn|x25> */
{
	int index;
	char feature[16];
	arglist *args;

	args = make_args(cmd);
	strncpy(feature, args->argv[2], 16);
	feature[15]=0;
	destroy_args(args);

	index = feature_index(feature);
	if (index < 0) return;

	if (!is_feature_on(index)) {
		printf("%% %s is already disabled\n", features[index].descr);
	} else {
		feature_on_off(index, 0);
#ifdef FEATURES_ON_FLASH
		save_ftures();
#else
		save_ftures(index);
#endif
	}
}
#endif

void show_features(const char *cmd)
{
	int i;

	for (i=0; i < NUM_FEATURES; i++)
#if 1 /* show only enabled ones */
		if (is_feature_on(i)) printf("%s is enabled\n", features[i].descr);
#else
		printf("%s is %sabled\n", features[i].descr, is_feature_on(i) ? "en" : "dis");
#endif
}

void load_ftures(void)
{
	int i;
#ifdef I2C_HC08_ID_ADDR
	char *buf;
#else
	char buf[6];
#endif
	char scratch[33];

#ifdef I2C_HC08_ID_ADDR
	if ((buf=get_system_ID(0)) == NULL) return;
#else
	memset(buf, 0, 6);
	get_mac("ethernet0", buf);
#endif

#ifdef OPTION_IPSEC
	if (get_mpc180()) features[FEATURE_VPN].id=FEATURE_MPC180_VPN_ID; /* Ajusta id para a presenca do MPC180 */
#endif

#ifdef FEATURES_ON_FLASH
	load_features(&saved_features[0], sizeof(saved_features));
#endif

	for (i=0; i < NUM_FEATURES; i++) {
#ifndef FEATURES_ON_FLASH
		saved_features[i].pos = features[i].pos;
		load_feature(&saved_features[i]);
#endif
		memcpy(scratch, buf, sizeof(scratch)); /* hash_str modify scratch! */
		if (memcmp(saved_features[i].key, 
			hash_str((unsigned char *)scratch, features[i].id), 16) == 0)
			feature_on_off(i, 1);
		else
			feature_on_off(i, 0);
	}
}

#endif /* OPTION_FEATURE */

void crypto_on_off(int on_off)
{
	if (on_off) {
		_cish_mask |= features[FEATURE_VPN].mask;
	} else {
		_cish_mask &= ~features[FEATURE_VPN].mask;
	}
}
