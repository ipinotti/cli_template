#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig/str.h>

typedef struct logfile_conf_str
{
	char	fname[64];
	size_t	msize;
	char	pidfname[64];
} logfile_conf;

logfile_conf	LOGROTATE[8];
int		LOGROTATE_COUNT;

void init_logrotate (void)
{
	FILE *F;
	char *l, *r;
	static char buf[256];	
	
	LOGROTATE_COUNT = 0;
	
	F = fopen ("/etc/logrotate.conf","r");
	if (F)
	{
		while ((!feof (F))&&(LOGROTATE_COUNT < 8))
		{
			buf[0] = 0;
			fgets (buf, 255, F);
			striplf (buf);
			if ((*buf)&&(*buf != '#'))
			{
				l = buf;
				r = strchr (l, '\t');
				if (r)
				{
					*r = 0;
					++r;
					strncpy (LOGROTATE[LOGROTATE_COUNT].fname, l, 63);
					l = r;
					while (*l == '\t') ++l;
					r = strchr (l, '\t');
					if (r)
					{
						*r = 0;
						++r;
						LOGROTATE[LOGROTATE_COUNT].msize = (size_t) atoi (l);
						l = r;
						while (*l == '\t') ++l;
						strncpy (LOGROTATE[LOGROTATE_COUNT++].pidfname, l, 63);
					}
				}
			}
		}
		fclose (F);
	}
}

void do_hup (const char *pidf)
{
	FILE *PF;
	char  buf[32];
	pid_t pid;

	PF=fopen(pidf, "r");
	if (!PF) return;

	fgets(buf, 31, PF);
	fclose (PF);

	pid=(pid_t)atoi(buf);
	if (pid > 1)
	{
		kill(pid, SIGHUP);
	}
}

void check_logrotate (void)
{
	struct stat st;
	int			cr;
	
	for (cr=0; cr<LOGROTATE_COUNT; ++cr)
	{
		if (! stat (LOGROTATE[cr].fname, &st))
		{
			if (st.st_size >= LOGROTATE[cr].msize)
			{
				remove (LOGROTATE[cr].fname);
				do_hup (LOGROTATE[cr].pidfname);
			}
		}
	}
}

