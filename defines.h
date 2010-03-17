
/*
 * 2.2 kernel supports only 16 network cards, and since there are not
 * that many 2.4 linuxes running more than 16 interfaces..
 */
#define MAX_INTERFACES 16
#define INTERFACE_NAME 16

#define PROC_NET_DEV	"/proc/net/dev"
#define STATFILE	"/proc/stat"
#define MEMFILE		"/proc/meminfo"
#define DEVFILE		"/proc/net/dev"

#define TRAPCONF	"/etc/trap.cfg"

#define	DATACOM_FACTORY_TEST_PASSWD			"ioEmqFWj"
#define	DATACOM_FACTORY_TEST_PASSWD_ENCRYPT	"jT2sUjN6pMdAM"

/*
 * Codigos de produto dos modens nos quais
 * a placa roteadora satelite pode operar.
 */
#define	SUPP_MOTHERBOARD_CODE_DM991CR	3033 /* DM991CR, equipamento original sobre o qual foi desenvolvida a placa satelite */
#define	SUPP_MOTHERBOARD_CODE_DM991CS	3040

#define	SUPP_MOTHERBOARD_CODE_DM706CR	3034
#define	SUPP_MOTHERBOARD_CODE_DM706CS	3041

#define	SUPP_MOTHERBOARD_CODE_DM706E	3051
#define	SUPP_MOTHERBOARD_CODE_DM706M1	3052
#define	SUPP_MOTHERBOARD_CODE_DM706M2	3053
#define	SUPP_MOTHERBOARD_CODE_DM706M4	3054

#define	SUPP_MOTHERBOARD_CODE_DM706XM	3055
#define	SUPP_MOTHERBOARD_CODE_DM706XM1	3045
#define	SUPP_MOTHERBOARD_CODE_DM706XM2	3049

#define	SUPP_MOTHERBOARD_CODE_DM706XD	3056
#define	SUPP_MOTHERBOARD_CODE_DM706XD1	3046
#define	SUPP_MOTHERBOARD_CODE_DM706XD2	3050

