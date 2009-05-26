/**
 * Handler for profile related things.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file profile.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "snmp.h"
#include "xsup_common.h"
#include "xsup_err.h"
#include "platform/cardif.h"
#include "xsup_debug.h"
#include "eapol.h"
#include "xsupconfig.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 * Initalize the default values for the structure.  In general, state machine
 * and user configuration variables won't need to be set here.  We should
 * set up variables that are in the root of the structure.
 */
int init_interface_struct(struct interface_data *work, char *intname)
{
	char dot1x_default_dest[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

	if (!xsup_assert((work != NULL), "work != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((intname != NULL), "intname != NULL", FALSE))
		return XEMALLOC;

	work->intName = (char *)Malloc(strlen(intname) + 1);
	if (work->intName == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory in %s at line %d!\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}
	strncpy(work->intName, intname, strlen(intname));

	memset(work->source_mac, 0x00, 6);
	memset(work->dest_mac, 0x00, 6);

	work->keyingMaterial = NULL;

	work->tick = FALSE;

	work->rsn_ie = NULL;
	work->wpa_ie = NULL;

	work->flags = WAS_DOWN;

	// The default MAC specified by the IEEE 802.1x spec.
	memcpy(&work->dest_mac[0], &dot1x_default_dest, 6);

	work->cur_essid = NULL;

	eapol_init(work);

	work->tempPassword = NULL;

	work->send_size = 0;
	work->recv_size = 0;

	return XENONE;
}

/**
 * Clean out a structure. 
 */
void destroy_interface_struct(struct interface_data *intdata)
{
	if (intdata == NULL)
		return;

	FREE(intdata->intName);

	FREE(intdata->cur_essid);

	// We don't need to free keyingMaterial, because it should be the same as
	// the pointer to PMK.

	FREE(intdata->sockData);

	FREE(intdata->statemachine);
	FREE(intdata->tempPassword);

	FREE(intdata->wpa_ie);
	FREE(intdata->rsn_ie);
}

/**
 *  Write the flags of an interface_data structure into a logfile
 */
void profile_dump_flags(struct interface_data *intdata)
{
	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
		return;

	debug_printf(DEBUG_INT, "Flags in interface_data :\n");

	if (TEST_FLAG(intdata->flags, IS_WIRELESS))
		debug_printf(DEBUG_INT, "IS_WIRELESS\n");

	if (TEST_FLAG(intdata->flags, WAS_DOWN))
		debug_printf(DEBUG_INT, "WAS_DOWN\n");

	if (TEST_FLAG(intdata->flags, SCANNING))
		debug_printf(DEBUG_INT, "SCANNING\n");

	if (TEST_FLAG(intdata->flags, ALLMULTI))
		debug_printf(DEBUG_INT, "ALLMULTI\n");

	if (TEST_FLAG(intdata->flags, ROAMED))
		debug_printf(DEBUG_INT, "ROAMED\n");

	if (TEST_FLAG(intdata->flags, ONEDOWN))
		debug_printf(DEBUG_INT, "ONEDOWN\n");

	if (TEST_FLAG(intdata->flags, TERM_ON_FAIL))
		debug_printf(DEBUG_INT, "DONT_USE_TEMP\n");

	if (TEST_FLAG(intdata->flags, DONT_KEY))
		debug_printf(DEBUG_INT, "DONT_KEY\n");

	if (TEST_FLAG(intdata->flags, CLEAR_IPC))
		debug_printf(DEBUG_INT, "CLEAR_IPC\n");

	if (TEST_FLAG(intdata->flags, PASV_SCANNING))
		debug_printf(DEBUG_INT, "PASV_SCANNING\n");
}

/**
 * Get configuration information out of memory, and 
 */
char config_build(struct interface_data *ctx, char *network_name)
{
	struct config_network *result;
	struct config_data *config_info;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	config_info = config_get_config_info();

	if (config_info != NULL) {
		debug_printf(DEBUG_CONFIG, "Working from config file %s.\n",
			     config_info->config_fname);

		// We were passed in a "network name".  First, look through the config
		// to see if it matches any friendly names.
		result =
		    config_find_network(config_info->networks, network_name);

		if (result != NULL) {
			config_set_network_config(result);
			return TRUE;
		}
		// If we are wireless, we don't want to switch to a default network,
		// we want to either sit tight, or scan for a network.
		if (TEST_FLAG(ctx->flags, IS_WIRELESS)) {
			config_set_network_config(NULL);
			return FALSE;
		}
		// This is not good.  We don't have any configuration information
		// for the requested network.  So, we need to return the default
		// information, and a warning.
		debug_printf(DEBUG_NORMAL,
			     "No configuration information for network \"%s\" found.  Using default.\n",
			     network_name);

		result = config_find_network(config_info->networks,
					     config_info->globals->default_net);

		if (result != NULL) {
			config_set_network_config(result);
			return TRUE;
		}

	} else {
		debug_printf(DEBUG_CONFIG,
			     "config_info == NULL!  No config to update!\n");
	}
	return FALSE;
}

/**
 * Set statemachine/config related variables for this interface.
 */
int config_set_globals(struct interface_data *myint)
{
	struct config_data *config_info;

	if (!xsup_assert((myint != NULL), "myint != NULL", FALSE))
		return XEMALLOC;

	config_info = config_get_config_info();

	if (!xsup_assert((config_info != NULL), "config_info != NULL", FALSE))
		return XEMALLOC;

	// Start by seeing if we need to set any global values.
	if ((CONFIG_GLOBALS_AUTH_PER & config_info->globals->flags) ==
	    CONFIG_GLOBALS_AUTH_PER) {
		myint->statemachine->authPeriod =
		    config_info->globals->auth_period;
	}

	if ((CONFIG_GLOBALS_HELD_PER & config_info->globals->flags) ==
	    CONFIG_GLOBALS_HELD_PER) {
		myint->statemachine->heldPeriod =
		    config_info->globals->held_period;
	}

	if ((CONFIG_GLOBALS_MAX_STARTS & config_info->globals->flags) ==
	    CONFIG_GLOBALS_MAX_STARTS) {
		myint->statemachine->maxStart =
		    config_info->globals->max_starts;
	}

	return 0;
}
