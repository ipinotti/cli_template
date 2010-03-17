/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include "commands.h"

extern int _cish_loggedin;
extern int _cish_enable;

void exit_cish (const char *cmdline)
{
	if(_cish_enable)
	{
		disable("disable");
		return;
	}
	_cish_enable = 0;
	_cish_loggedin = 0;
}
