/* ==============================================================================
 * cish - the cisco shell emulator for LPR
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#ifndef _TERMINAL_ECHO_H
#define _TERMINAL_ECHO_H 1

void echo_off (void);
void echo_on (void);
void canon_off (void);
void canon_on (void);
void save_termios(void);
void reload_termios(void);

#endif
