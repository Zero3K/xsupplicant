/**
 * Handler for context related things.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file context.c
 *
 * \authors chris@open1x.org
 */

#include <stdlib.h>
#include <stdio.h>

#ifndef WINDOWS
#include <strings.h>

#define stricmp strcasecmp
#else
#include <windows.h>
#endif

#include <string.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "snmp.h"
#include "context.h"
#include "statemachine.h"
#include "ipc_events_index.h"
#include "ipc_events.h"

#ifndef WINDOWS
#include <event_core.h>
#else
#include "event_core_win.h"
#endif

#include "xsup_common.h"
#include "xsup_err.h"
#include "platform/cardif.h"
#include "xsup_debug.h"
#include "eapol.h"
#include "interfaces.h"
#include "libxsupconfig/xsupconfig_devices.h"
#include "config_ssid.h"
#include "wireless_sm.h"
#include "timer.h"
#include "eap_sm.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

void global_deinit();		// In xsup_driver.c, there is no header we can include so this prototype keeps the compiler from complaining.

/**
 * \brief Initalize the default values for the structure.  
 *
 * In general, state machine and user configuration variables won't need to be 
 * set here.  We should  set up variables that are in the root of the structure.
 *
 * @param[in] work  A pointer to the context that we want to initialize.
 * @param[in] intname   The OS specific interface name that will be mapped on 
 *                      to the newly initialized context.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XEGENERROR on general failure
 * \retval XENONE on success
 **/
int context_init(context * work, char *intname)
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

	if (Strncpy(work->intName, (strlen(intname) + 1), intname,
	     strlen(intname) + 1) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't make a copy of the interface name in %s() at "
			     "%d!\n", __FUNCTION__, __LINE__);
		return XEGENERROR;
	}

	memset(work->source_mac, 0x00, 6);
	memset(work->dest_mac, 0x00, 6);

	work->tick = FALSE;

	work->flags = WAS_DOWN;

	// The default MAC specified by the IEEE 802.1x spec.
	memcpy(&work->dest_mac[0], &dot1x_default_dest, 6);

	timer_init(work);

	eapol_init(work);

	work->send_size = 0;
	work->recv_size = 0;

#ifdef HAVE_TNC
	if (work->tnc_data != NULL) {
		work->tnc_data->connectionID = -1;	// Set it to something that we won't be using for a LOOONG time!
	}
#endif

	return XENONE;
}

/**
 * \brief Clean out a context structure.  
 *
 * @param[in] ctx   A pointer to the context that we want to destroy.
 **/
void context_destroy(context * ctx)
{
	if (ctx == NULL)
		return;

	debug_printf(DEBUG_INT, "Sending Logoff!\n");
	txLogoff(ctx);

	debug_printf(DEBUG_DEINIT, "Cleaing up EAPoL state.\n");
	eapol_cleanup(ctx);

	debug_printf(DEBUG_DEINIT, "Clean up timers\n");
	timer_cleanup(ctx);

	debug_printf(DEBUG_DEINIT, "Deinit wireless SM\n");
	wireless_sm_deinit(ctx->intTypeData);

	if (ctx->intType == ETH_802_11_INT) {
		context_destroy_wireless_ctx((wireless_ctx **) &
					     ctx->intTypeData);
	}
	// Only call deinit if the interface isn't gone.
	cardif_deinit(ctx);

	FREE(ctx->intName);

	// We don't need to free keyingMaterial, because it should be the same as
	// the pointer to PMK.

	FREE(ctx->sockData);

	FREE(ctx->statemachine);

	FREE(ctx->conn_name);
	FREE(ctx->desc);

	FREE(ctx->sendframe);
	FREE(ctx->recvframe);
}

/**
 *  \brief Dump the flags value so that we know what it is.  (This is used for 
 *         debug purposes only.
 *
 * @param[in] ctx   The context that contains the flags variable we want
 *                  to dump.
 **/
void context_dump_flags(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	debug_printf(DEBUG_CONTEXT, "Flags in interface_data :\n");

	if (TEST_FLAG(ctx->flags, WAS_DOWN))
		debug_printf(DEBUG_CONTEXT, "WAS_DOWN\n");

	if (TEST_FLAG(ctx->flags, ALLMULTI))
		debug_printf(DEBUG_CONTEXT, "ALLMULTI\n");

	if (TEST_FLAG(ctx->flags, TERM_ON_FAIL))
		debug_printf(DEBUG_CONTEXT, "DONT_USE_TEMP\n");
}

/**
 * \brief Determine if the context has everything it needs to be sure that an 
 *        automatic authentication can complete.
 *
 * @param[in] cur   The connection configuration structure for the connection that
 *                  we want to auto connect to.
 *
 * \retval TRUE if we can use the connection safely.
 * \retval FALSE if we cannot use the connection safely.
 **/
int context_has_all_data(struct config_connection *cur)
{
	struct config_profiles *prof = NULL;
	char *password = NULL;
	char *username = NULL;
	struct config_eap_peap *peapconf = NULL;

	if (cur == NULL)
		return FALSE;	// We can't use a NULL connection! ;)

	prof = config_find_profile(CONFIG_LOAD_GLOBAL, cur->profile);
	if (prof == NULL) {
		prof = config_find_profile(CONFIG_LOAD_USER, cur->profile);
		if (prof == NULL)
			return FALSE;
	}

	if (prof->method->method_num == EAP_TYPE_PEAP) {
		peapconf = (struct config_eap_peap *)prof->method->method_data;

		if (TEST_FLAG(peapconf->flags, FLAGS_PEAP_MACHINE_AUTH))
			return TRUE;
	}

	if (prof->identity == NULL)
		return FALSE;

	password = config_get_pwd_from_profile(prof->method);

	if (password == NULL)
		return FALSE;

	if (stricmp(prof->identity, "Anonymous") == 0) {
		// Need to check the inner username.
		username = config_get_inner_user_from_profile(prof->method);
		if (username == NULL)
			return FALSE;
	}

	return TRUE;
}

/**
 * \brief Get configuration information out of the configuration file, and in to
 *        memory.
 *
 * @param[in] ctx   The context whose configuration pointers we want to update
 *                  to point at the configuration for 'network_name'.
 * @param[in] network_name   The name of the network that we want to change
 *                           the configuration to.
 *
 * \retval FALSE on error
 * \retval TRUE on success
 **/
char config_build(context * ctx, char *network_name)
{
	struct config_connection *result = NULL;
	struct xsup_interfaces *myint = NULL;
#ifdef WINDOWS
	struct config_globals *pGlobals = NULL;
#endif				// WINDOWS

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return FALSE;

	// If we are searching for nothing, return nothing. ;)
	if (network_name == NULL) {
		debug_printf(DEBUG_CONFIG_PARSE,
			     "Network name passed in is NULL!\n");

		if (ctx->desc != NULL)	// Which it shouldn't ever be NULL!
		{
			myint = config_find_int(ctx->desc);
			if (myint == NULL) {
				// Clear our binding connections, so we don't do anything weird.
				ctx->conn = NULL;
				ctx->prof = NULL;

				return FALSE;
			}
			// Otherwise, bind to the default.
			debug_printf(DEBUG_CONFIG_PARSE,
				     "Searching configuration information in "
				     "memory!\n");

			// If there is no user on the console, then start with the machine authentication
			// configuration (if we have one.)
#ifdef WINDOWS
			// Only set this if nobody is logged in.
			if (win_impersonate_is_user_on_console() == FALSE) {
				pGlobals = config_get_globals();

				if (ctx->intType == ETH_802_11_INT) {
					if (pGlobals->wirelessMachineAuthConnection != NULL)
						result = config_find_connection(CONFIG_LOAD_GLOBAL,
						     pGlobals->wirelessMachineAuthConnection);
				} else {
					if (pGlobals->wiredMachineAuthConnection
					    != NULL)
						result = config_find_connection(CONFIG_LOAD_GLOBAL,
						     pGlobals->wiredMachineAuthConnection);
				}

				// If the machine auth connection wasn't found, then try to find the interface default.
				if ((ctx->intType != ETH_802_11_INT)
				    && (result == NULL))
					result = config_find_wired_default();
			} else {
				if (ctx->intType != ETH_802_11_INT)
					result = config_find_wired_default();
			}
#else
			// Default networks can only be administratively defined, so don't search the user config.
			if (ctx->intType != ETH_802_11_INT)
				result = config_find_wired_default();
#endif
			// Only use a default connection if we are managing the interface.
			if ((result != NULL)
			    && (!TEST_FLAG(myint->flags, CONFIG_INTERFACE_DONT_MANAGE))) {
				debug_printf(DEBUG_CONFIG_PARSE,
					     "Setting default network to : %s\n",
					     result->name);

				if (context_has_all_data(result) == TRUE) {
					ctx->conn = result;
					FREE(ctx->conn_name);
					ctx->conn_name = _strdup(result->name);

					ctx->prof = config_find_profile(CONFIG_LOAD_USER,
					     ctx->conn->profile);

					if (ctx->prof == NULL)
						ctx->prof = config_find_profile(CONFIG_LOAD_GLOBAL,
						     ctx->conn->profile);
					return TRUE;
				} else {
					debug_printf(DEBUG_NORMAL,
						     "Default connection does not have enough configuration "
						     "information to complete an automatic connection.\n");
					ipc_events_ui(ctx,
						      IPC_EVENT_UI_NEED_UPW,
						      result->name);
				}
			}
		}
		// Clear our binding connections, so we don't do anything weird.
		ctx->conn = NULL;
		ctx->prof = NULL;

		return FALSE;
	}

	debug_printf(DEBUG_CONFIG_PARSE, "Working from config file %s.\n",
		     config_fname);

	// We were passed in a "network name".  First, look through the config
	// to see if it matches any friendly names.
	debug_printf(DEBUG_CONFIG_PARSE,
		     "Searching configuration information in " "memory!\n");
	result = config_find_connection(CONFIG_LOAD_GLOBAL, network_name);
	if (result == NULL) {
		// Search the user config.
		result = config_find_connection(CONFIG_LOAD_USER, network_name);
	}

	if (result != NULL) {
		if (ctx->desc != NULL) {
			ctx->conn = result;
			FREE(ctx->conn_name);
			ctx->conn_name = _strdup(network_name);	// XXX This shouldn't be network name.  (Need to leave it broken for now.  Clean up later.)

			ctx->prof = config_find_profile(CONFIG_LOAD_GLOBAL,
						ctx->conn->profile);
			if (ctx->prof == NULL) {
				ctx->prof = config_find_profile(CONFIG_LOAD_USER,
							ctx->conn->profile);
			}
		} else {
			result = config_find_connection_from_ssid(CONFIG_LOAD_GLOBAL,
							     network_name);
			if (result == NULL) {
				result = config_find_connection_from_ssid(CONFIG_LOAD_USER, network_name);
			}

			if (result != NULL) {
				ctx->conn = result;
				FREE(ctx->conn_name);
				ctx->conn_name = _strdup(network_name);	// XXX This shouldn't be network_name.  (Need to leave it broken for now.  Clean up later.)

				ctx->prof = config_find_profile(CONFIG_LOAD_GLOBAL,
							ctx->conn->profile);
				if (ctx->prof == NULL) {
					ctx->prof = config_find_profile(CONFIG_LOAD_USER,
					     ctx->conn->profile);
				}
			}
		}

		return TRUE;
	}

	debug_printf(DEBUG_NORMAL,
		     "No configuration information is in memory!  "
		     "Are you sure you have a valid network configuration!?\n");
	ctx->conn = NULL;
	ctx->conn_name = NULL;
	ctx->prof = NULL;

	return FALSE;
}

/**
 * \brief Set statemachine/config related variables for this interface.
 *
 * @param[in] ctx   The context that we want to set global statemachine values
 *                  on.
 *
 * \retval XEMALLOC on memory allocation errors
 * \retval XENONE on success
 **/
int context_config_set_globals(context * ctx)
{
	struct config_globals *globals;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return XEMALLOC;

	// Start by seeing if we need to set any global values.
	if (globals->auth_period != 0) {
		ctx->statemachine->authPeriod = globals->auth_period;
	}

	if (globals->held_period != 0) {
		ctx->statemachine->heldPeriod = globals->held_period;
	}

	if (globals->max_starts != 0) {
		ctx->statemachine->maxStart = globals->max_starts;
	}

	return XENONE;
}

/**
 *  \brief Allocate memory for a context structure.
 *
 * @param[in] ctx   A pointer that we can use to allocate memory that is needed
 *                  to store a new context.
 *
 * \retval NULL on error (memory allocation failure is the only error)
 * \retval ptr to new context on success.
 **/
context *context_allocate(context ** ctx)
{
	(*ctx) = Malloc(sizeof(context));
	if ((*ctx) == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store context information!\n");
		return NULL;
	}

	return (*ctx);
}

/**
 * \brief Call what's needed to set up the interface to be used.
 *
 * @param[in] ctx   The context that we want to set the interface up for.
 * @param[in] desc   The description for the device we want to use.
 * @param[in] device   The OS specific device name for the device we want to use.
 * @param[in] driveridx   A numeric value that specifies the type of driver that
 *                        is in use on the interface.
 * @param[in] flags   Flags that specify how the interface should be treated.
 *
 * \todo Clean up XXX areas.
 *
 * \retval XEMALLOC on memory allocation errors
 * \retval XENOTINT if the interface isn't a physical interface
 * \retval XENONE on success
 **/
int context_init_interface_hdwr(context ** ctx, char *desc, char *device,
				char driveridx, FDEPTH flags)
{
	context *cur = NULL;
	wireless_ctx *wctx = NULL;

	xsup_assert((device != NULL), "device != NULL", TRUE);

	cur = context_allocate(ctx);
	if (cur == NULL)
		return XEMALLOC;

	// Start by setting up the structure, and assigning the interface.
	if (context_init(cur, device) != XENONE) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't init interface struct for device "
			     "%s!  Cannot continue!\n", device);
		global_deinit();
	}
	// Set our flags.
	cur->flags |= flags;

	// Set our interface description.   If the description is NULL, then we will
	// use the interface name itself.
	if (desc == NULL) {
		cur->desc = _strdup(device);
	} else {
		cur->desc = _strdup(desc);
	}

	// Establish a handler to the interface. Only need to manually turn on WPA if
	// force is set, otherwise should only turn it on if AP indicates support.
	if (cardif_init(cur, driveridx) < 0)
		return XENOTINT;

#ifdef WINDOWS
	if (TEST_FLAG(cur->flags, INT_IGNORE)) {
		cardif_cancel_io((*ctx));	// Make sure we don't queue up frames that we won't process.
	}
#endif

	if (cur->intType == ETH_802_11_INT) {
		// XXX Fix - On Linux we need to set the first parameter based on other information.
		wireless_sm_init(FALSE, (*ctx));

		cardif_get_abilities(cur);

		wctx = (wireless_ctx *) cur->intTypeData;

		if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
			return -1;

		if (wctx->enc_capa == 0) {
			debug_printf(DEBUG_CONTEXT,
				     "Interface has no encryption capabilities, or "
				     "unknown abilitites.\n");
		} else {
			debug_printf(DEBUG_INT,
				     "Card reported capabilitites :");
			if (wctx->enc_capa & DOES_WEP40)
				debug_printf_nl(DEBUG_INT, " WEP40");
			if (wctx->enc_capa & DOES_WEP104)
				debug_printf_nl(DEBUG_INT, " WEP104");
			if (wctx->enc_capa & DOES_WPA)
				debug_printf_nl(DEBUG_INT, " WPA");
			if (wctx->enc_capa & DOES_WPA2)
				debug_printf_nl(DEBUG_INT, " WPA2");
			if (wctx->enc_capa & DOES_TKIP)
				debug_printf_nl(DEBUG_INT, " TKIP");
			if (wctx->enc_capa & DOES_CCMP)
				debug_printf_nl(DEBUG_INT, " CCMP");
			debug_printf_nl(DEBUG_INT, "\n");
		}
	}

	debug_printf(DEBUG_CONTEXT, "Interface initialized!\n");

	return XENONE;
}

/**
 * \brief Take a string for a driver name, and return a numeric value that 
 *        indicates which driver we should use.
 *
 * @param[in] drname   The string that identifies the name of the driver that
 *                     will be used.  (OS Specific)
 *
 * \retval int that is the OS specific identifier for a specific driver.
 **/
int context_get_driver(char *drname)
{
#ifdef LINUX
	if (drname == NULL)
		return DRIVER_WEXT;

	lowercase(drname);

	if (strcmp(drname, "none") == 0)
		return DRIVER_NONE;
	if (strcmp(drname, "wext") == 0)
		return DRIVER_WEXT;
	if (strcmp(drname, "nl80211") == 0)
		return DRIVER_NL80211;
	printf("Unknown driver '%s' requested.\n", drname);
	return DRIVER_WEXT;
#else
	return DRIVER_NONE;
#endif
}

/**
 * \brief Initialize a single interface.  
 *
 * This function should get called in one of two ways:
 *  
 *  1) To initialize a single interface based on information passed in from the command line.
 *  2) To initialize a single interface based on information in the configuration file.
 *
 * @param[in] ctx   The context that contains the interface we want to init.
 * @param[in] desc   The description for the interface that we want to init.
 * @param[in] device   The OS specific device name for the interface that we
 *                     want to init.
 * @param[in] drivernam   The name of the driver that this interface uses.
 * @param[in] flags   Interface specific flags that tell the supplicant how to
 *                    treat this interface.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation errors
 **/
int context_init_interface(context ** ctx, char *desc, char *device,
			   char *drivernam, FDEPTH flags)
{
	context *intcur;
	char driveridx = 0, retval = XENONE;
	struct config_globals *globals;
	wireless_ctx *wctx;

	if (!xsup_assert((device != NULL), "device != NULL", FALSE)) {
		// Nothing to do.
		return XENONE;
	}

	intcur = NULL;

	driveridx = context_get_driver(drivernam);

	// This line *MUST* always come after the call to xsup_driver_init_config.
	// If config_get_globals() is called before it, then you will always get
	// a NULL value, and probably return an error.
	globals = config_get_globals();

	if (!globals) {
		// Do *NOT* debug_printf this section, or you will have problems!
		// debug_printf may not work until logfile_setup() is called!
		printf("No valid configuration globals in %s!\n", __FUNCTION__);
		return XEMALLOC;
	}

	retval = context_init_interface_hdwr(ctx, desc, device, driveridx, flags);
	if (retval != XENONE) {
		debug_printf(DEBUG_NORMAL, "Couldn't init interface!\n");
		return retval;
	}

	if ((*ctx)->intType == ETH_802_11_INT) {
		wctx = (wireless_ctx *) (*ctx)->intTypeData;

		if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
			return -1;

		if (config_build((*ctx), wctx->cur_essid) != TRUE) {
			// If we fail to build a config for this SSID, display a message so
			// that the user has a chance of knowing that there is a problem, but
			// continue to run so that we can authenticate if the user changes
			// SSIDs to something we know about.
			if (wctx->cur_essid != NULL) {
				debug_printf(DEBUG_NORMAL,
					     "Couldn't build config for network %s!\n",
					     wctx->cur_essid);
			}
		}
	} else {
		if (config_build((*ctx), NULL) != TRUE) {
			debug_printf(DEBUG_INT,
				     "No default connection defined for interface '%s'.\n",
				     desc);
		}
	}

	context_config_set_globals((*ctx));

	return XENONE;
}

/**
 * \brief Initialize interfaces based on information in the devices section of 
 *        the configuration, and the information stored in the interface cache.
 *
 * @param[in,out] ctx   A pointer that will contain a context that is for the 
 *                     interface that was read from the configuration file.
 **/
void context_init_ints_from_conf(context ** ctx)
{
	struct xsup_interfaces *ints = NULL;
	char *intname = NULL;
	config_globals *globals = NULL;
	uint8_t flags;

	// Get the list of interfaces we want to monitor.  It is possible that we 
	// have interfaces configured, that don't currently exist on the system, so
	// we need to check that prior to initializing the interface.
	ints = xsupconfig_devices_get_interfaces();

	globals = config_get_globals();

	while (ints != NULL) {
		debug_printf(DEBUG_INT,
			     "Checking if interface '%s' is available.\n",
			     ints->description);
		flags = 0;

		intname = interfaces_get_name_from_mac((char *)ints->mac);
		if (intname != NULL) {
			if (TEST_FLAG(ints->flags, CONFIG_INTERFACE_DONT_MANAGE)) {
				debug_printf(DEBUG_NORMAL,
					     "Not managing interface '%s'.\n",
					     ints->description);
				flags = INT_IGNORE;
			}

			if (context_init_interface(ctx, ints->description, intname, NULL, 0) != 0) {
				debug_printf(DEBUG_NORMAL,
					     "Couldn't initialize interface '%s'!\n",
					     ints->description);
			}
#ifdef WINDOWS
			if ((globals != NULL)
			    &&
			    (TEST_FLAG(globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY))) {
				if ((*ctx)->intType != ETH_802_11_INT) {
					cardif_cancel_io((*ctx));
				}
			}
#endif				// WINDOWS
		} else {
			// This probably indicates that the interface isn't currently in the machine.
			debug_printf(DEBUG_INT,
				     "Couldn't init interface '%s'!\n",
				     ints->description);
		}

		ints = ints->next;
	}
}

/**
 * \brief Initialize a wireless context.  This includes populating all 
 *        information found in the wireless_ctx structure.
 *
 * @param[in,out] new_wctx   A pointer that will contain the wireless context
 *                           for this interface.
 * @param[in] drivernum   The number that indicates the type of driver this 
 *                        interface uses.
 *
 * \retval XEMALLOC on memory related errors
 * \retval XENONE on success
 **/
int context_create_wireless_ctx(wireless_ctx ** new_wctx, uint8_t drivernum)
{
	wireless_ctx *wctx = NULL;

	(*new_wctx) = Malloc(sizeof(wireless_ctx));

	if ((*new_wctx) == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store wireless "
			     "context data!\n");
		return XEMALLOC;
	}
	// Init wireless_sm 
	wctx = (*new_wctx);

	wctx->driver_in_use = drivernum;
	wctx->state = 0;

	return XENONE;
}

/**
 * \brief Deinit a wireless context.  Free all memory, and call deinits for
 *        any pieces that may be needed.
 *
 * @param[in] dest_wctx   The wireless context that we want to destroy
 *
 * \retval XENONE on success
 **/
int context_destroy_wireless_ctx(wireless_ctx ** dest_wctx)
{
	wireless_ctx *wctx;

	wctx = (*dest_wctx);

	if (wctx == NULL)
		return XENONE;	// Nothing to do.

	debug_printf(DEBUG_DEINIT, "Cleaning up SSID structs.\n");
	config_ssid_clear(wctx);

	FREE(wctx->cur_essid);
	FREE(wctx->rsn_ie);
	FREE(wctx->wpa_ie);

	return XENONE;
}

void context_disconnect(context * ctx)
{
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (ctx->intType == ETH_802_11_INT) {
		wctx = (wireless_ctx *) ctx->intTypeData;
		cardif_disassociate(ctx, 1);
		FREE(wctx->cur_essid);
	} else {
		txLogoff(ctx);
	}

	if (ctx->conn != NULL)
		ipc_events_ui(NULL, IPC_EVENT_CONNECTION_UNBOUND,
			      ctx->conn->name);

	ctx->conn = NULL;
	FREE(ctx->conn_name);
	ctx->prof = NULL;
}
