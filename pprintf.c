/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */
   
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <curses.h>

#include <libconfig/cish_defines.h>

#include "terminal_echo.h"
#include "cish_config.h"
#include "cish_main.h"

int terminal_lines;

struct pagerstat
{
	int numlines;
	int tsize;
	int skip;
} PAGER;

void pager_init (void)
{
	PAGER.numlines = 0;
	PAGER.skip = 0;
	PAGER.tsize = terminal_lines;
}

int pager_skipping (void)
{
	return (PAGER.skip);
}

void pprintf (const char *fmt, ...)
{
	char key;
	va_list ap;
	char buf[1024];

	buf[0]=0;
	if (PAGER.skip) return;

	va_start(ap, fmt);
	vsnprintf(buf, 1023, fmt, ap);
	va_end(ap);	
	buf[1023]=0;

	printf ("%s", buf);

	if ((PAGER.tsize)&&(strchr (buf, '\n')))
	{
		++PAGER.numlines;
		if (PAGER.numlines >= PAGER.tsize)
		{
			printf ("<more>"); fflush (stdout);
			canon_off();
			echo_off();
			cish_timeout = cish_cfg->terminal_timeout;
			key = fgetc (stdin);
			cish_timeout = 0;
			echo_on();
			canon_on();
			printf ("\r      \r"); fflush (stdout);
			if (key == 'q') PAGER.skip = 1;
			if (key == '\n') PAGER.numlines=PAGER.tsize-1; 
			  else PAGER.numlines = 1;
		}
	}
}
