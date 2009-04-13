/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupgui_mac_utils.c
 *
 * \author chris@open1x.org
 **/

#include <string.h>
#include <stdio.h>

#ifdef WINDOWS
#include "src/stdintwin.h"
#else
#include "stdint.h"
#endif

#include <libxml/parser.h>

#include "libxsupconfig/xsupconfig_common.h"

/**
 * \brief Verify that the string is a valid MAC address.
 *
 *  Verify that we have a valid MAC address by making sure it is of the form :
 *  xx:xx:xx:xx:xx:xx
 *   or
 *  xx-xx-xx-xx-xx-xx
 *
 * @param[in] inhexstr   The string that should contain a MAC address.
 *
 * \retval 0 if the string isn't a MAC address.
 * \retval 1 if the string is a MAC address.
 **/
int xsupgui_mac_utils_is_valid_mac(char *inhexstr)
{
	int i;

	// A valid MAC should be 17 characters.
	if (strlen(inhexstr) != 17)
		return 0;

	for (i = 0; i < 17; i++) {
		if ((i == 2) || (i == 5) || (i == 8) || (i == 11) || (i == 14)) {
			if (is_delim(inhexstr[i]) == 0)
				return 0;
		} else {
			if (is_hex(inhexstr[i]) == 0)
				return 0;
		}
	}

	return 1;
}

/**
 *  \brief Convert a string that has passed the validation test above to
 *			a hex MAC address.
 *
 * @param[in] instr   The string that we need to convert to a binary version 
 *                    of the MAC address.
 *
 * @param[in] mac   The MAC binary version of the MAC address.
 **/
void xsupgui_mac_utils_convert_mac(char *instr, char *mac)
{
	if (strlen(instr) != 17) {
		printf("Invalid string passed to %s()!\n", __FUNCTION__);
		return;
	}

	mac[0] = ((ctonib(instr[0]) << 4) | ctonib(instr[1]));
	mac[1] = ((ctonib(instr[3]) << 4) | ctonib(instr[4]));
	mac[2] = ((ctonib(instr[6]) << 4) | ctonib(instr[7]));
	mac[3] = ((ctonib(instr[9]) << 4) | ctonib(instr[10]));
	mac[4] = ((ctonib(instr[12]) << 4) | ctonib(instr[13]));
	mac[5] = ((ctonib(instr[15]) << 4) | ctonib(instr[16]));
}
