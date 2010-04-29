#define TACACS_TEMP "/var/run/tacacs.temp"

/*priv-lvl*/
#define TAC_PLUS_PRIV_LVL_MIN 0x0
#define TAC_PLUS_PRIV_LVL_USR 0x1
#define TAC_PLUS_PRIV_LVL_MAX 0xf

int tacacs_log(unsigned char *, int);
