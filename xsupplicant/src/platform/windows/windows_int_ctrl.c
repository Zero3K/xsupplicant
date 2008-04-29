/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file windows_int_ctrl.c
 *
 * \author chris@open1x.org
 *
 **/

#include <windows.h>

#include "xsupconfig.h"
#include "../../xsup_debug.h"
#include "../../context.h"
#include "../../event_core_win.h"

#include "wzc_ctrl.h"
#include "windows_eapol_ctrl.h"
#include "windows_int_ctrl.h"
#include "wlanapi_interface.h"

/**
 * \brief Take control of all interfaces from Windows.
 **/
void windows_int_ctrl_take_ctrl(context *ctx)
{
	int retval = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	if (ctx->intType == ETH_802_11_INT)
	{
		// Disable WZC (if it is running.)
		if ((retval = wlanapi_interface_disable_wzc(ctx->desc)) == WLANAPI_NOT_AVAILABLE)
		{
			if (wzc_ctrl_disable_wzc(ctx->intName) != 0)
			{
				debug_printf(DEBUG_NORMAL, "Unable to disable WZC for interface %s.\n", ctx->desc);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Disabled WZC on interface %s.\n", ctx->desc);
			}
		}
		else if (retval != WLANAPI_OK)
		{
			debug_printf(DEBUG_NORMAL, "Unable to disable WZC for interface %s\n", ctx->desc);
		}
	}
	else
	{
		// Disable the Windows 802.1X stack on a wired interface.
		if (windows_eapol_ctrl_disable(ctx->desc, ctx->intName) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Unable to configure the interface '%s'.\n", ctx->desc);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Disabled 802.1X on interface %s.\n", ctx->desc);
		}
	}
}

/**
 * \brief Give Windows control of all interfaces.
 **/
void windows_int_ctrl_give_to_windows(context *ctx)
{
	int retval = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	if (ctx->intType == ETH_802_11_INT)
	{
		// Enable WZC (if it is running.)
		if ((retval = wlanapi_interface_enable_wzc(ctx->desc)) == WLANAPI_NOT_AVAILABLE)
		{
			if (wzc_ctrl_enable_wzc(ctx->intName) != 0)
			{
				debug_printf(DEBUG_NORMAL, "Unable to enable WZC for interface %s.\n", ctx->desc);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Enabled WZC on interface %s.\n", ctx->desc);
			}
		} 
		else if (retval != WLANAPI_OK)
		{
			debug_printf(DEBUG_NORMAL, "Unable to enable WZC for interface %s.\n", ctx->desc);
		}
	}
	else
	{
		// Enable the Windows 802.1X stack on a wired interface.
		if (windows_eapol_ctrl_enable(ctx->desc, ctx->intName) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Unable to configure the interface '%s'.\n", ctx->desc);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Enabled 802.1X on interface %s.\n", ctx->desc);
		}
	}
}

/**
 * \brief Compare the current flag setting to the new one, and take or release control of the
 *        interface as needed.
 *
 * @param[in] newsettings   A pointer to the new version of the global configuration structure.
 **/
void windows_int_ctrl_change(config_globals *newsettings)
{
	config_globals *globals = NULL;
	int endis = 0;

	if (!xsup_assert((newsettings != NULL), "newsettings != NULL", FALSE)) return;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE)) return;

	if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_INT_CTRL) != TEST_FLAG(newsettings->flags, CONFIG_GLOBALS_NO_INT_CTRL))
	{
		if (TEST_FLAG(newsettings->flags, CONFIG_GLOBALS_NO_INT_CTRL))
		{
			_beginthread(event_core_change_os_ctrl_state, 0, NULL);
		}
		else
		{
			_beginthread(event_core_change_os_ctrl_state, 0, 1);
		}
	}
}