/* ==============================================================================
 * rfc1356 - IPoX25 daemon
 *
 * (C) 2004 PD3 Tecnologia
 * ============================================================================== */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
//#include <linux/x25.h>
#include <stdlib.h>
#include <linux/if.h>
//#include <linux/ppp_defs.h>
//#include <linux/if_ppp.h>
#include <linux/sk_tunnel.h>

/*
 * X.25 CUD (call user data) values to distinguish between ppp and ip
 * upper layer protocol and other services.
 */
/* PPP over X.25 as specified in RFC 1598: */
#define CUD_PPP 0xCF
/* IP over X.25 as specified in RFC 1356: */
#define CUD_IP	0xCC /* 0x80 (5-byte SNAP encoding) 0xCC backwards-compatible with RFC877 */
/* IPX over X.25 as specified in RFC 1356: */
#define CUD_IPX	0x80 /* 0x80 (5-byte SNAP encoding) - 0xD3 (CISCO) */
/* Muiltiple protocols over single X.25 connection, multiplexed by means
   of ISO/OSI Network Layer Protocol Id, also specified in RFC 1356: */
#define CUD_NLPID 0x00

static int s=0, id;

void clean(int signal)
{
	if (ioctl(s, SIOCSKTNUNREGISTER, &id) != 0) {
		syslog(LOG_NOTICE, "SIOCSKTNUNREGISTER failed!");
	}
	close(s);
	exit(0);
}

int main (int argc, char **argv)
{
	int ls, c, cnt, m_one=-1, newfd, accept_ip=0, do_flood=0;
	enum {client,server,config} role=server;
	enum {dev,mk_dev,rm_dev,cat,flood} mode=cat;
	unsigned char buf[5501];

	struct sockaddr_x25 x25bind, x25connect;
	struct x25_calluserdata cud;
	#if 0
	struct x25_facilities facilities;
	#endif
	int sz = sizeof(x25connect);
	char *sbind="", *sconn=NULL; 

	signal(SIGTERM, clean);
	signal(SIGKILL, clean);

	while ((c=getopt(argc, argv, "b:c:d:")) != EOF) { /* :m:r:f */
		switch (c) {
		case 'b':
			sbind = optarg;
			break;
		case 'c':
			role = client; 
			sconn = optarg;
			break;
		case 'd':
			mode = dev;
			accept_ip = 1;
			id = atoi(optarg);
			break;
#if 0
		case 'f':
			mode = flood;
			do_flood=1;
			break;
		case 'm':
			mode = mk_dev;
			role = config;
			id = atoi(optarg);
			break;
		case 'r':
			mode = rm_dev;
			role = config;
			id = atoi(optarg);
			break;
#endif
		default:
			return -1;
		}
	}
	openlog("rfc1356", LOG_CONS|LOG_PID, LOG_DAEMON);
	/*
	 * create socket
	 */
	if ((s=socket(AF_X25, SOCK_SEQPACKET, 0)) < 0)
	{
		syslog(LOG_DEBUG, "X.25 socket creation failed");
		exit(1);
	}
	/* 
	 * bind local X.25 address to socket
	 */
	x25bind.sx25_family = AF_X25;
	strncpy(x25bind.sx25_addr.x25_addr, sbind, 15);
	if (bind(s, (struct sockaddr *)&x25bind, sizeof (x25bind)) < 0) {
		syslog(LOG_NOTICE, "unable to bind X.121 local address to socket");
		close(s);
		exit(1);
	}
	switch (role)
	{
	case client:
		/*
		 * Request of special service can be indicated by a special
		 * direct call user data string in x25 call request packet
		 *
		 * IP over X.25 and ppp over X.25 are recognized by special
		 * cud values which are defined in the relevant RFCs
		 */
		switch (mode) {
		case dev:
			cud.cuddata[0]=CUD_IP;
			cud.cudlength=1;
			break;

		default:
			break;
		}
		if ((cud.cudlength > 0) && 
		    (ioctl(s, SIOCX25SCALLUSERDATA, &cud) != 0) ) {
				syslog(LOG_NOTICE, "SIOCX25SCALLUSERDATA failed!");
				close(s);
				exit(1);
		}
		/* 
		 * connect socket to remote destination x25 address 
		 */
		x25connect.sx25_family = AF_X25;
		strncpy(x25connect.sx25_addr.x25_addr, sconn, 15);
		syslog(LOG_NOTICE, "connecting to remote X.121 address %s", x25connect.sx25_addr.x25_addr);
		if (connect(s, (struct sockaddr *)&x25connect, sizeof (x25connect)) < 0) {
			syslog(LOG_NOTICE, "connection timeout!");
			close(s);
			exit(1);
		}
		syslog(LOG_NOTICE, "X.25 connection established!");
		break;

	case server:
		ls = s;
		s = -1;
		
		if (listen(ls, 1) < 0) {
			syslog(LOG_NOTICE, "server mode failed!");
			close(ls);
			exit(1);
		}
		syslog(LOG_NOTICE, "waiting for incoming connection on X.25 local address %s", x25bind.sx25_addr.x25_addr);
		s=accept(ls, (struct sockaddr *)&x25connect, &sz);
		if (s < 0) {
			syslog(LOG_NOTICE, "accept failed!");
			close(ls);
			exit(1);
		}
		syslog(LOG_NOTICE, "X.25 connection accepted from %s.", x25connect.sx25_addr.x25_addr);
		if (ioctl(s, SIOCX25GCALLUSERDATA, &cud) != 0) {
			syslog(LOG_NOTICE, "SIOCX25GCALLUSERDATA failed!");
			close(s);
			exit(1);
		}
		mode=cat;
		if (cud.cudlength > 0) {
			switch (cud.cuddata[0]) {
			case CUD_IP:
				if (accept_ip) mode=dev;
				break;
			default:
				syslog(LOG_NOTICE, "CUD=0x%2.2x", (int)cud.cuddata[0]);
				break;
			}
		} else {
			syslog(LOG_NOTICE, "no CUD present!");
		}
		break;
#if 0
	case config:
		switch (mode) {
		case mk_dev:
			fprintf(stderr,"trying to create serial0.%d ...",id);
			if( ioctl(s, SIOCSKTNNEWIF, &id) != 0 ){
				perror(" SIOCSKTNNEWIF failed");
				exit(1);
			} else {
				fprintf(stderr," (succeeded).\n");
				exit(0);
			};
			break;

		case rm_dev:
			fprintf(stderr,"trying to remove serial0.%d ...",id);
			if( ioctl(s, SIOCSKTNDELIF, &id) != 0 ){
				perror(" SIOCSKTNDELIF failed");
				exit(1);
			} else {
				fprintf(stderr," (succeeded).\n");
				exit(0);
			};
			break;

		default:
			fprintf(stderr,	"rfc1356: invalid option combination\n");
			exit(1);
		}
		break;
#endif
	default:
		fprintf(stderr,	"rfc1356: internal option parsing error\n");
		exit(1);
	}

	/*
	 * Only arrive here when (either incoming or outgoing)
	 * connection  shall be immediately attached to upper tunnel layer.
	 */
	switch (mode) {
	case dev:
		if (ioctl(s, SIOCSKTNREGISTER, &id) != 0 ) {
			syslog(LOG_NOTICE, "SIOCSKTNREGISTER failed!");
			close(s);
			exit(1);
		}
		//syslog(LOG_NOTICE, "Register channel at tunnel device layer ... (serial0.%d)", id);
		break;
#if 0
	case flood:
		fprintf(stderr,"flooding peer with data and\n");
#endif
	case cat:
		//fprintf(stderr,"writing received data to stdout\n");
		break;

	default:
		fprintf(stderr,	"rfc1356: internal option parsing error\n");
		close(s);
		exit(1);
	}
#if 0
	if (do_flood) {
		if (fcntl(s, F_SETFL, O_NONBLOCK)) perror("fcntl()");
		sleep(1);
		while (1){
			if(((cnt=read(s,buf,5500))<0) && 
			   (errno != EWOULDBLOCK))        break;
			if(cnt>0){
				int i;
				for(i=0;i<cnt;i++) printf("%2.2X ", buf[i]);
				printf("\n");
			}
			if(((cnt=write(s,buf,1000))<0) && 
			   (errno != EWOULDBLOCK))        break;
		}
		perror("rfc1356: last read/write() returned because of:"); 
		exit(0);
	}
#endif
	//fprintf(stderr,"writing received data to stdout\n");
	while ((cnt=read(s,buf,5500)) >= 0) {
		int i;
		for (i=0;i<cnt;i++) printf("%2.2X ", buf[i]);
		printf("\n");
		write(1,buf,cnt);
	}
	perror("rfc1356: last read/write() returned because of:");
	if (mode == cat) exit(0);

	switch(mode){
	case cat:
		break;
	}
	if (ioctl(s, SIOCSKTNUNREGISTER, &id) != 0) {
		syslog(LOG_NOTICE, "SIOCSKTNUNREGISTER failed!");
	}
	close(s);
}

/*
 * code fragments, maybe usable for possible future extensions
 */	
#if 0
	/* 
	 * for larger packet size of (e.g. 1024 bytes). However, not really
	 * necessary because X.25 can fragment an re-assemble the frame
	 */
	if (ioctl(s, SIOCX25GFACILITIES, &facilities) != 0 ){
		perror("rfc1356: SIOCX25GFACILITIES failed!");
		return 1;
	}
	printf("current facilies wi %d wo %d pi %d po %d\n",
	       facilities.winsize_in,
	       facilities.winsize_out,
	       facilities.pacsize_in,
	       facilities.pacsize_out);
	
	facilities.winsize_in  = 7;
	/* avm server hangs with outgoing winsize=7 */
	facilities.winsize_out = 6;
	facilities.pacsize_in  = X25_PS1024;
	facilities.pacsize_out = X25_PS1024;
	
	printf("requested facilies wi %d wo %d pi %d po %d\n",
	       facilities.winsize_in,
	       facilities.winsize_out,
	       facilities.pacsize_in,
	       facilities.pacsize_out);
	
	/* Unfortunatly, this doesn't work with kernels  up to at least 2.1.90
	   unless the socket is in the listen state (x.25 kernel bug)
	   unless af_x25.c is patched.  */
	printf("Trying to set X.25 facilities on socket ...\n");
	if (ioctl(s, SIOCX25SFACILITIES, &facilities) != 0 ){
		perror("rfc1356: SIOCX25SFACILITIES failed!");
		return 1;
	}
#endif

