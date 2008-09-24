/**
 * Routines for checking the "completeness" of a piece of the configuration.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfcheck_conn.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/error_prequeue.h"
#include "src/interfaces.h"
#include "src/context.h"
#include "src/platform/cardif.h"

#ifdef WINDOWS
#include <windows.h>
#include "src/event_core_win.h"
#else
#include "src/event_core.h"
#endif

#include "xsupconfcheck.h"
#include "xsupconfcheck_conn.h"
#include "xsupconfcheck_common.h"


/**
 * \brief Check the connection to be sure that it is valid.
 *
 * @param[in] conn   The connection structure that we want to check.
 *
 * \retval -1 on error
 * \retval 0 on success
 * \retval CONNECTION_NEED_* if something more is needed.
 **/
int xsupconfcheck_conn_check(context *ctx, struct config_connection *conn, int log)
{
	char *errmsg = NULL;
	int retval = 0;
	wireless_ctx *wctx = NULL;
	struct interfaces *liveint = NULL;

	// By nature of the fact that we got this far, we know we have a connection
	// name.  So don't bother checking that. ;)

	if (xsupconfcheck_check_interface(conn->device, log) != 0)
	{
		// No need to throw an error message here.  If the above call failed, it will have already filled the queue.
		retval = -1;
	}

	liveint = xsupconfcheck_common_is_live_int(conn->device);
	if (liveint == NULL)
	{
		if (log == TRUE) error_prequeue_add("Connection is attempting to use an interface that isn't currently available.");
		return -1;
	}

	// If the interface is wireless, then we need to check association and SSID settings.
	if (liveint->is_wireless == TRUE)
	{
		// Make sure we have an SSID
		if (conn->ssid == NULL)
		{
			if (log == TRUE) error_prequeue_add("The interface being used is wireless, but the connection configuration doesn't have an SSID defined.");
			retval = -1;
		}

		// Make sure that if authentication is set to NONE or PSK that we don't have a profile defined
		if ((conn->association.auth_type == AUTH_NONE) || (conn->association.auth_type == AUTH_PSK))
		{
			if (conn->profile != NULL)
			{
				if (log == TRUE) error_prequeue_add("The connection configuration has a profile defined when a profile can't be used in this configuration.");
				retval = -1;
			}
		}

		// Make sure that if authentication is set to PSK that we have either 'psk' or 'psk_hex' defined.
		if (conn->association.auth_type == AUTH_PSK)
		{
			if ((conn->association.psk == NULL) && (conn->association.psk_hex == NULL) && (conn->association.temp_psk == NULL))
			{
				if (log == TRUE) error_prequeue_add("The connection configuration is set to PSK, but there is no pre-shared key configured.");
				retval = CONNECTION_NEED_PSK;
			}
		}

		// Make sure that if authentication is set to EAP that we DO have a profile set, and that it is valid.
		if (conn->association.auth_type == AUTH_EAP)
		{
			if (conn->profile == NULL)
			{
				if (log == TRUE) error_prequeue_add("The connection configuration is set to use EAP, but there is no profile configured.");
				retval = -1;
			}
			else
			{
				// Check to see that the profile is valid.
				switch (xsupconfcheck_check_profile(conn->profile, log))
				{
				case PROFILE_NEED_UPW:
					retval = CONNECTION_NEED_UPW;
					break;

				case 0:
					break;

				default:
					// No need to queue an error message here, since the profile should have already set all of the needed error strings.
					retval = -1;
					break;
				}
			}
		}

		if (conn->association.auth_type == AUTH_UNKNOWN)
		{
			if (conn->profile != NULL)
			{
				switch (xsupconfcheck_check_profile(conn->profile, log))
				{
				case PROFILE_NEED_UPW:
					retval = PROFILE_NEED_UPW;
					break;

				case 0:
					break;

				default:
					retval = -1;
					break;
				}
			}
		}

		// If txkey is set to something other than 0, make sure there is key data in that slot.
		if (conn->association.txkey != 0)
		{
			if ((conn->association.keys[conn->association.txkey] == NULL) ||
				(strlen(conn->association.keys[conn->association.txkey]) <= 0) ||
				((strlen(conn->association.keys[conn->association.txkey]) != 10) &&
				(strlen(conn->association.keys[conn->association.txkey]) != 26)))
			{
				retval = CONNECTION_NEED_UPW;
			}
		}

		// Make sure that pairwise and group keys a valid for the association method being used.
		switch (conn->association.association_type)
		{
		case ASSOC_AUTO:
			// For auto association, we can't be sure of the key types.  So, anything goes.
			break;

		case ASSOC_OPEN:
		case ASSOC_SHARED:
		case ASSOC_LEAP:
			// For Open/Shared/LEAP, only WEP will do.
			if ((conn->association.pairwise_keys != 0) &&
				(conn->association.pairwise_keys != CRYPT_WEP40) &&
				(conn->association.pairwise_keys != CRYPT_WEP104))
			{
				if (log == TRUE) error_prequeue_add("Connection attempted to use a pairwise (unicast) key type other than NONE, or WEP with Open, Shared, or LEAP association.");
				retval = -1;
			}

			if ((conn->association.group_keys != 0) &&
				(!(conn->association.group_keys & CRYPT_FLAGS_WEP40)) &&
				(!(conn->association.group_keys & CRYPT_FLAGS_WEP104)))
			{
				if (log == TRUE) error_prequeue_add("Connection attempted to use a group (multicast/broadcast) key type other than NONE, or WEP with Open, Shared, or LEAP association.");
				retval = -1;
			}
			break;

		case ASSOC_WPA:
		case ASSOC_WPA2:
			// For WPA/WPA2, anything goes (for now).  In the future this may change.
			break;

		default:
			if (log == TRUE) error_prequeue_add("Connection attempted to use an unknown association method.");
			retval = -1;
			break;
		}

		// Make sure that the pairwise and group key types are valid based on what the card will allow
		wctx = ctx->intTypeData;

		if (conn->association.pairwise_keys > (CRYPT_FLAGS_WEP40 |CRYPT_FLAGS_TKIP | CRYPT_FLAGS_WRAP | CRYPT_FLAGS_CCMP
			| CRYPT_FLAGS_WEP104))
		{
			if (log == TRUE) error_prequeue_add("An unknown type of encryption was configured for this connection.  Please update xsupconfcheck_conn_check() with the new type!");
			retval = -1;
		}
		else
		{
			if (conn->association.pairwise_keys == 0)
			{
				// Do nothing.
			}
			else if (conn->association.pairwise_keys & CRYPT_FLAGS_WEP40)
			{
				if ((wctx->enc_capa & DOES_WEP40) == 0)
				{
					if (log == TRUE) error_prequeue_add("Connection is configured to use WEP 40 as the pairwise/unicast cipher, but the card doesn't seem to support it.");
					retval = -1;
				}
			}
			else if (conn->association.pairwise_keys & CRYPT_FLAGS_WEP104)
			{
				if ((wctx->enc_capa & DOES_WEP104) == 0)
				{
					if (log == TRUE) error_prequeue_add("Connection is configured to use WEP 104 as the pairwise/unicast cipher, but the card doesn't seem to support it.");
					retval = -1;
				}
			}
			else if (conn->association.pairwise_keys & CRYPT_FLAGS_TKIP)
			{
				if ((wctx->enc_capa & DOES_TKIP) == 0)
				{
					if (log == TRUE) error_prequeue_add("Connection is configured to use TKIP as the pairwise/unicast cipher, but the card doesn't seem to support it.");
					retval = -1;
				}
			}
			else if (conn->association.pairwise_keys & CRYPT_FLAGS_WRAP)
			{
				if (log == TRUE) error_prequeue_add("Connection is configured to use WRAP, but it isn't supported!");
				retval = -1;
			}
			else if (conn->association.pairwise_keys & CRYPT_FLAGS_CCMP)
			{
				if ((wctx->enc_capa & DOES_CCMP) == 0)
				{
					if (log == TRUE) error_prequeue_add("Connection is configured to use CCMP as the pairwise/unicast cipher, but the card doesn't seem to support it.");
					retval = -1;
				}
			}
			else
			{
				if (log == TRUE) error_prequeue_add("An unknown type of encryption was configured for this connection.  Please update xsupconfcheck_conn_check() with the new type!");
				retval = -1;
			}
		}
		
		switch (conn->association.group_keys)
		{
		case 0:
			// The default "AUTO" setting.
			break;

		case CRYPT_WEP40:
			if ((wctx->enc_capa & DOES_WEP40) == 0)
			{
				if (log == TRUE) error_prequeue_add("Connection is configured to use WEP 40 as the group/broadcast/multicast cipher, but the card doesn't seem to support it.");
				retval = -1;
			}
			break;		

		case CRYPT_WEP104:
			if ((wctx->enc_capa & DOES_WEP104) == 0)
			{
				if (log == TRUE) error_prequeue_add("Connection is configured to use WEP 104 as the group/broadcast/multicast cipher, but the card doesn't seem to support it.");
				retval = -1;
			}
			break;	

		case CRYPT_TKIP:
			if ((wctx->enc_capa & DOES_TKIP) == 0)
			{
				if (log == TRUE) error_prequeue_add("Connection is configured to use TKIP as the group/broadcast/multicast cipher, but the card doesn't seem to support it.");
				retval = -1;
			}
			break;	

		case CRYPT_WRAP:
			if (log == TRUE) error_prequeue_add("Connection is configured to use WRAP, but it isn't supported!");
			break;

		case CRYPT_CCMP:
			if ((wctx->enc_capa & DOES_CCMP) == 0)
			{
				if (log == TRUE) error_prequeue_add("Connection is configured to use CCMP as the group/broadcast/multicast cipher, but the card doesn't seem to support it.");
				retval = -1;
			}
			break;

		default:
			if (log == TRUE) error_prequeue_add("An unknown type of encryption was configured for this connection.  Please update xsupconfcheck_conn_check() with the new type!");
			retval = -1;
			break;
		}
	}
	else
	{
		if (conn->profile != NULL)
		{
			// If the interface is wired, and we have a profile, make sure it is valid.
			switch (xsupconfcheck_check_profile(conn->profile, log))
			{
			case PROFILE_NEED_UPW:
				retval = CONNECTION_NEED_UPW;
				break;

			case 0:
				break;

			default:
				// Don't need to write an error string here.
				retval = -1;
			}
		}
	}

	// If the user has configured to use static IPs, make sure they are really there.
	if (conn->ip.type == CONFIG_IP_USE_STATIC)
	{
		// Verify that an IP address and netmask is defined at a minimum.
		if ((conn->ip.ipaddr == NULL) || (strlen(conn->ip.ipaddr) == 0))
		{
			if (log == TRUE) error_prequeue_add("Connection is configured to use a static IP address, but one isn't configured.");
			retval = -1;
		}

		if ((conn->ip.netmask == NULL) || (strlen(conn->ip.netmask) == 0))
		{
			if (log == TRUE) error_prequeue_add("Connection is configured to use a static IP address, but no netmask is specified.");
			retval = -1;
		}

		// We don't really care if the DNS, or Gateway are correct, since there
		// may be situations where setting them isn't needed.
	}

	return retval;
}

