/*
 * don't put the environment in it's own section if we are building
 * the host based program "tools/envcrc" (ENV_CRC is only defined when
 * building ppcboot itself)
 */
	.section	".crc"

	.globl	_crc
_crc:
#ifdef  ENV_CRC  		/* If we are building with computed CRC...	*/
	.long	ENV_CRC  	/* ...use it!					*/
#else
	.long	~0
#endif
