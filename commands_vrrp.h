/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

void interface_no_vrrp(const char *cmd);
void interface_vrrp(const char *cmd);

extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP[];

