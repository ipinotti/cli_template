/* ==============================================================================
 * cish - the cisco shell emulator for LPR
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#ifndef _OUTPUT_H
#define _OUTPUT_H 1

extern int lines_done;
void init_termcap (void);
void xprintf (char *, ...);

#endif
