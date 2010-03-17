#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <fcntl.h>
#include <linux/config.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include <libconfig/nv.h>

#if !defined(CONFIG_DEVELOPMENT)
#define HARDKEY_RESET
#endif

/*
 * Constants for Hash routine
 */
#define S11 2
#define S12 3
#define S13 4
#define S14 6
#define S21 1
#define S22 2
#define S23 4
#define S24 5
#define S31 1
#define S32 3
#define S33 4
#define S34 6
#define S41 2
#define S42 3
#define S43 4
#define S44 5

/*
 * F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (8-(n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4. Rotation is
 * separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F ((b), (c), (d)) + (x) + (ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
	(a) += G ((b), (c), (d)) + (x) + (ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
	(a) += H ((b), (c), (d)) + (x) + (ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
	(a) += I ((b), (c), (d)) + (x) + (ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
}

#define HC08_QT4

#ifdef HC08_QT4
static void CalcHash(unsigned char *rx_buffer, unsigned char *hash, int qt4)
#else
static void CalcHash(unsigned char *rx_buffer, unsigned char *hash)
#endif
{
	unsigned char temp[4];

	temp[0] = hash[0];
	temp[1] = hash[1];
	temp[2] = hash[2];
	temp[3] = hash[3];

	/* Round 1 */
	FF(temp[0], temp[1], temp[2], temp[3], rx_buffer[0], S11, 0xd7);	/* 1 */
	FF(temp[3], temp[0], temp[1], temp[2], rx_buffer[1], S12, 0xe8);	/* 2 */
	FF(temp[2], temp[3], temp[0], temp[1], rx_buffer[2], S13, 0x24);	/* 3 */
	FF(temp[1], temp[2], temp[3], temp[0], rx_buffer[3], S14, 0xc1);	/* 4 */
	FF(temp[0], temp[1], temp[2], temp[3], rx_buffer[4], S11, 0xf5);	/* 5 */
	FF(temp[3], temp[0], temp[1], temp[2], rx_buffer[5], S12, 0x47);	/* 6 */
	FF(temp[2], temp[3], temp[0], temp[1], rx_buffer[6], S13, 0xa8);	/* 7 */
	FF(temp[1], temp[2], temp[3], temp[0], rx_buffer[7], S14, 0xfd);	/* 8 */
	FF(temp[0], temp[1], temp[2], temp[3], rx_buffer[8], S11, 0x69);	/* 9 */
	FF(temp[3], temp[0], temp[1], temp[2], rx_buffer[9], S12, 0x8b);	/* 10 */
	FF(temp[2], temp[3], temp[0], temp[1], rx_buffer[10], S13, 0xff);	/* 11 */
	FF(temp[1], temp[2], temp[3], temp[0], rx_buffer[11], S14, 0x89);	/* 12 */
	FF(temp[0], temp[1], temp[2], temp[3], rx_buffer[12], S11, 0x6b);	/* 13 */
	FF(temp[3], temp[0], temp[1], temp[2], rx_buffer[13], S12, 0xfd);	/* 14 */
	FF(temp[2], temp[3], temp[0], temp[1], rx_buffer[14], S13, 0xa6);	/* 15 */
	FF(temp[1], temp[2], temp[3], temp[0], rx_buffer[15], S14, 0x49);	/* 16 */

	/* Round 2 */
	GG(temp[0], temp[1], temp[2], temp[3], rx_buffer[1], S21, 0xf6);	/* 17 */
	GG(temp[3], temp[0], temp[1], temp[2], rx_buffer[6], S22, 0xc0);	/* 18 */
	GG(temp[2], temp[3], temp[0], temp[1], rx_buffer[11], S23, 0x26);	/* 19 */
	GG(temp[1], temp[2], temp[3], temp[0], rx_buffer[0], S24, 0xe9);	/* 20 */
	GG(temp[0], temp[1], temp[2], temp[3], rx_buffer[5], S21, 0xd6);	/* 21 */
	GG(temp[3], temp[0], temp[1], temp[2], rx_buffer[10], S22, 0x24);	/* 22 */
	GG(temp[2], temp[3], temp[0], temp[1], rx_buffer[15], S23, 0xd8);	/* 23 */
	GG(temp[1], temp[2], temp[3], temp[0], rx_buffer[4], S24, 0xe7);	/* 24 */
	#ifdef HC08_QT4
	if (qt4) {
		GG(temp[0], temp[1], temp[2], temp[3], rx_buffer[9], S21, 0x21);	/* 25 */
		GG(temp[3], temp[0], temp[1], temp[2], rx_buffer[14], S22, 0xc3);	/* 26 */
		GG(temp[2], temp[3], temp[0], temp[1], rx_buffer[3], S23, 0xf4);	/* 27 */
		GG(temp[1], temp[2], temp[3], temp[0], rx_buffer[8], S24, 0x45);	/* 28 */
		GG(temp[0], temp[1], temp[2], temp[3], rx_buffer[13], S21, 0xa9);	/* 29 */
		GG(temp[3], temp[0], temp[1], temp[2], rx_buffer[2], S22, 0xfc);	/* 30 */
		GG(temp[2], temp[3], temp[0], temp[1], rx_buffer[7], S23, 0x67);	/* 31 */
		GG(temp[1], temp[2], temp[3], temp[0], rx_buffer[12], S24, 0x8d);	/* 32 */
	}
	#endif

	/* Round 3 */
	HH(temp[0], temp[1], temp[2], temp[3], rx_buffer[5], S31, 0xff);	/* 33 */
	HH(temp[3], temp[0], temp[1], temp[2], rx_buffer[8], S32, 0x87);	/* 34 */
	HH(temp[2], temp[3], temp[0], temp[1], rx_buffer[11], S33, 0x6d);	/* 35 */
	HH(temp[1], temp[2], temp[3], temp[0], rx_buffer[14], S34, 0xfd);	/* 36 */
	HH(temp[0], temp[1], temp[2], temp[3], rx_buffer[1], S31, 0xa4);	/* 37 */
	HH(temp[3], temp[0], temp[1], temp[2], rx_buffer[4], S32, 0x4b);	/* 38 */
	HH(temp[2], temp[3], temp[0], temp[1], rx_buffer[7], S33, 0xf6);	/* 39 */
	HH(temp[1], temp[2], temp[3], temp[0], rx_buffer[10], S34, 0xbe);	/* 40 */
	HH(temp[0], temp[1], temp[2], temp[3], rx_buffer[13], S31, 0x28);	/* 41 */
	HH(temp[3], temp[0], temp[1], temp[2], rx_buffer[0], S32, 0xea);	/* 42 */
	HH(temp[2], temp[3], temp[0], temp[1], rx_buffer[3], S33, 0xd4);	/* 43 */
	#ifdef HC08_QT4
	if (qt4) {
		HH(temp[1], temp[2], temp[3], temp[0], rx_buffer[6], S34, 0x48);	/* 44 */
		HH(temp[0], temp[1], temp[2], temp[3], rx_buffer[9], S31, 0xd9);	/* 45 */
		HH(temp[3], temp[0], temp[1], temp[2], rx_buffer[12], S32, 0xe6);	/* 46 */
		HH(temp[2], temp[3], temp[0], temp[1], rx_buffer[15], S33, 0x1f);	/* 47 */
		HH(temp[1], temp[2], temp[3], temp[0], rx_buffer[2], S34, 0xc4);	/* 48 */
	}
	#endif

	/* Round 4 */
	II(temp[0], temp[1], temp[2], temp[3], rx_buffer[0], S41, 0xf4);	/* 49 */
	II(temp[3], temp[0], temp[1], temp[2], rx_buffer[7], S42, 0x43);	/* 50 */
	II(temp[2], temp[3], temp[0], temp[1], rx_buffer[14], S43, 0xab);	/* 51 */
	II(temp[1], temp[2], temp[3], temp[0], rx_buffer[5], S44, 0xfc);	/* 52 */
	II(temp[0], temp[1], temp[2], temp[3], rx_buffer[12], S41, 0x65);	/* 53 */
	II(temp[3], temp[0], temp[1], temp[2], rx_buffer[3], S42, 0x8f);	/* 54 */
	II(temp[2], temp[3], temp[0], temp[1], rx_buffer[10], S43, 0xff);	/* 55 */
	II(temp[1], temp[2], temp[3], temp[0], rx_buffer[1], S44, 0x85);	/* 56 */
	II(temp[0], temp[1], temp[2], temp[3], rx_buffer[8], S41, 0x6f);	/* 57 */
	II(temp[3], temp[0], temp[1], temp[2], rx_buffer[15], S42, 0xfe);	/* 58 */
	II(temp[2], temp[3], temp[0], temp[1], rx_buffer[6], S43, 0xa3);	/* 59 */
	#ifdef HC08_QT4
	if (qt4) {
		II(temp[1], temp[2], temp[3], temp[0], rx_buffer[13], S44, 0x4e);	/* 60 */
		II(temp[0], temp[1], temp[2], temp[3], rx_buffer[4], S41, 0xf7);	/* 61 */
		II(temp[3], temp[0], temp[1], temp[2], rx_buffer[11], S42, 0xbd);	/* 62 */
		II(temp[2], temp[3], temp[0], temp[1], rx_buffer[2], S43, 0x2a);	/* 63 */
		II(temp[1], temp[2], temp[3], temp[0], rx_buffer[9], S44, 0xeb);	/* 64 */
	}
	#endif

	hash[0] += temp[0];
	hash[1] += temp[1];
	hash[2] += temp[2];
	hash[3] += temp[3];
}

#undef HARDKEY_ECHO

int hardkey(void)
{
	int fd, ret=0;
#if defined(CONFIG_DEVFS_FS)
	char device[] = "/dev/i2c/0";
#else
	char device[] = "/dev/i2c-0";
#endif
	int i;
#ifdef HARDKEY_ECHO
	char *s;
#endif
	unsigned char buffer[64];
	unsigned char hash[16];
#ifdef HC08_QT4
	unsigned char dateversion[16]; /* "2005/12/05     1" */
	char version;
#endif

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0) return -1;
	i=read(fd, buffer, 8);
	close(fd);
	if (i != 8) return -1;

	if ((fd = open(device, O_RDWR)) < 0) return -1;
#ifdef HARDKEY_ECHO
	printf("CalcHash(%02X%02X%02X%02X%02X%02X%02X%02X):", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);
#endif
	buffer[8]=0xa0;
	buffer[9]=0xb4;
	buffer[10]=0xfe;
	buffer[11]=0x32;
	buffer[12]=0xe2;
	buffer[13]=0xf6;
	buffer[14]=0xb1;
	buffer[15]=0x54;
	hash[0]=0x67;
	hash[1]=0xef;
	hash[2]=0x98;
	hash[3]=0x10;
#ifdef HC08_QT4
	if (i2c_read_block_data(fd, I2C_HC08_ADDR, I2C_HC08_DATEVERSION, 16, dateversion) < 0) goto error;
	version=dateversion[15];
#ifdef CONFIG_BERLIN_MU0
	CalcHash(buffer, hash, version == 0xff || version == 0x00 ? 1 : version); /* Dont accept old ones! */
#else
	CalcHash(buffer, hash, version == 0xff || version == 0x00 ? 0 : version);
#endif
#else
	CalcHash(buffer, hash);
#endif
#ifdef HARDKEY_ECHO
	s = hash;
	for (i=0; i<4; i++) {
		printf(" %02x", *s++);
	}
	printf("\t");
#endif

#ifdef HARDKEY_ECHO
	printf("Hash:");
#endif
	if (i2c_hardkey_challange(fd, I2C_HC08_ADDR, buffer) < 0)
	{
		goto error;
	} else {
#ifdef HARDKEY_ECHO
		s = buffer;
		for (i=0; i<4; i++) {
			printf(" %02x", *s++);
		}
#endif
		if (buffer[0]==hash[0] && buffer[1]==hash[1] && buffer[2]==hash[2] && buffer[3]==hash[3])
		{	
#ifdef HARDKEY_ECHO
			printf("OK!\n");
#endif
		}
			else { printf("ERROR!\n"); goto error; }
	}
exit_now:
	close(fd);
#ifdef HARDKEY_RESET
#if defined(CONFIG_BERLIN_REV1)||defined(CONFIG_BERLIN_REV2)||defined(CONFIG_BERLIN_BU0)||defined(CONFIG_BERLIN_MU0)
	if (ret < 0)
	{
		printf("\nCritical: firmware not licensed!\nRebooting!\n\n\n");
		sleep(5);
		reboot(0x01234567);
	}
#endif
#endif
	return ret;
error:
	ret=-1;
	goto exit_now;
}

