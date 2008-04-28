/**
 * Interface to Windows WMI for events, and getting various data.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_wmi.c
 *
 * \author chris@open1x.org
 *
 * \todo Implement calls to get the list of DNS servers.
 *
 **/

#define _WIN32_DCOM

// We need to define COBJMACROS so that we can make the C calls
// to the IWbem* interfaces.
#ifndef COBJMACROS
#define COBJMACROS
#endif 

#include <wbemidl.h>

#include <windows.h>
#include <iphlpapi.h>
#include <process.h>

#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "cardif_windows.h"
#include "../../event_core_win.h"
#include "../../ipc_events_index.h"
#include "../../eap_sm.h"
#include "../../error_prequeue.h"
#include "cardif_windows_wmi_async.h"
#include "cardif_windows_wmi.h"

///< The WQL select string that is needed to get adapter information for a specific interface.
#define GET_ADAPTER_BY_IDX           L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = %d"

typedef struct {
	wchar_t *intName;
	uint8_t numChecks;
	uint8_t interval;
} check_type;

#define BIND_INTERVAL            5  // The amount of time to wait between bind checks.
#define NUM_BIND_CHECKS          3  // The number of times to attempt to bind before we give up.
#define BIND_CHECKS_SIZE         5  // We can only have 5 outstanding binding requests.  This is probably plenty since they shouldn't last long.
check_type checks[5];            

// Some globals to make life easy.
IWbemLocator *wmiLoc = NULL;
IWbemServices *wmiSvc = NULL;
IWbemServices *wmiEvents = NULL;
IEnumWbemClassObject *pConnectEvent = NULL;
IEnumWbemClassObject *pDisconnectEvent = NULL;
IEnumWbemClassObject *pMediaSpecificEvent = NULL;
IEnumWbemClassObject *pInsertEvent = NULL;
IEnumWbemClassObject *pRemoveEvent = NULL;
int WMIConnected = FALSE;

// XXX ICK..  Do this better.
extern void (*imc_disconnect_callback)(uint32_t connectionID);

/**
 * \brief Create an event handler to watch for media connect events.
 *
 * \retval 0 on success.
 **/
int cardif_windows_wmi_event_setup_connect()
{
	HRESULT hr;

	hr = IWbemServices_ExecNotificationQuery(wmiEvents,
        L"WQL",
        L"SELECT * FROM MSNdis_StatusMediaConnect" ,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 
        NULL, &pConnectEvent);

	if (FAILED(hr)) return -1;

	return 0;
}

/**
 * \brief Check an event handler to see if any media connect events have happened.
 *
 *  When an event is triggered here, this function will also take care of processing
 *  the event, and changing the needed state options for interfaces.
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_event_check_connect()
{
	HRESULT hr;
    IWbemClassObject *pclsObj = NULL;
	ULONG uReturn;
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	char *intdesc = NULL;
	VARIANT vtProp;
	uint8_t bssid[6];
	char ssid[34];
	int ssidsize = 34;

	if (pConnectEvent == NULL) return -1;

	hr = IEnumWbemClassObject_Next(pConnectEvent, 0, 1, &pclsObj, &uReturn);
	if (FAILED(hr)) return -1;

	if (uReturn > 0)
	{
		// We have an event.
		debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Connect Event !!!!!!!!!!!!!!!!!!!!!\n");
		hr = IWbemClassObject_Get(pclsObj, L"InstanceName", 0, &vtProp, 0, 0);
		if (FAILED(hr))
		{
			debug_printf(DEBUG_NORMAL, "Got a connect event, but it didn't seem to have any "
					"information in it.\n");
		}
		
		// Locate the context we want to work on.
		debug_printf(DEBUG_INT, "Looking for interface with caption : %ws\n", vtProp.bstrVal);
		ctx = event_core_locate_by_caption(vtProp.bstrVal, FALSE);

		if (ctx == NULL)
		{
			intdesc = uni_to_ascii(vtProp.bstrVal);
			debug_printf(DEBUG_INT, "Couldn't find by caption, looking by description.\n");
			ctx = event_core_locate_by_desc_strstr(intdesc);
			if (ctx == NULL)
			{
				debug_printf(DEBUG_INT, "Couldn't locate a context for connect event. (Perhaps "
					"we aren't managing this interface?)\n");
				VariantClear(&vtProp);
				return -1;
			}
		}
		VariantClear(&vtProp);

		debug_printf(DEBUG_INT, "Interface is : %s\n", ctx->intName);

		// Send event.
		ipc_events_ui(NULL, IPC_EVENT_UI_LINK_UP, ctx->desc);

		if (ctx->intType == ETH_802_11_INT)
		{
			wctx = (wireless_ctx *)ctx->intTypeData;
			if (wctx == NULL)
			{
				debug_printf(DEBUG_NORMAL, "Interface %s claims to be wireless, but doesn't "
					"have a wireless context!?\n", ctx->intName);
				return -1;
			}

			if (cardif_windows_wireless_get_bssid(ctx, &bssid) != 0)
			{
				debug_printf(DEBUG_NORMAL, "Unable to get BSSID for interface '%s'.\n", ctx->desc);
				ctx->auths = 0;     // Reset the number of authentications this interface has done.
			}
			else
			{
				if (cardif_windows_wireless_get_ssid(ctx, &ssid, ssidsize) != 0)
				{
					debug_printf(DEBUG_NORMAL, "Interface '%s' assocated to the AP with BSSID %02X:%02X:%02X:%02X:%02X:%02X\n",
						ctx->desc, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
				}
				else
				{
					debug_printf(DEBUG_NORMAL, "Interface '%s' assocated to the SSID '%s' with BSSID %02X:%02X:%02X:%02X:%02X:%02X\n",
						ctx->desc, ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
				}

				if ((wctx->cur_essid != NULL) && (strcmp(ssid, wctx->cur_essid) != 0))
				{
					// We hopped to a new SSID.  Reset our counters.
					ctx->auths = 0;
				}
			}

			if (memcmp(wctx->cur_bssid, &bssid, 6) != 0)
			{
				SET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);  // We are now associated.
				UNSET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);

				// Reset the EAP state machine.
				eap_sm_force_init(ctx->eap_state);
				memcpy(wctx->cur_bssid, bssid, 6);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Interface '%s' sent us an associate event about a BSSID we are already associated to.  This usually indicates a firmware, driver, or environmental issue.  This event has been ignored.\n", ctx->desc);
				debug_printf(DEBUG_PHYSICAL_STATE, "Clearing replay counter.\n");
				memset(&wctx->replay_counter, 0x00, 8);

				//Reset our EAP IDs so we don't discard frames when an AP is dumb,
				// and resets it's EAP counter. ;)
				ctx->eap_state->reqId = 0xff;
				ctx->eap_state->lastId = 0xff;
			}

			if (TEST_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK))
			{
				ipc_events_ui(ctx, IPC_EVENT_BAD_PSK, ctx->intName);

				// We sent the error so unset the flag.
				UNSET_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK);
			}
		}
		else
		{
			debug_printf(DEBUG_INT, "Enabling wired port.\n");
			debug_printf(DEBUG_NORMAL, "Interface '%s' now has link.\n", ctx->desc);
			ctx->auths = 0;

			// Reset the EAP state machine.
			eap_sm_force_init(ctx->eap_state);
		}
	}

	return 0;
}

/**
 * \brief Create an event handler to watch for card insertion events.
 *
 * \retval 0 on success.
 **/
int cardif_windows_wmi_event_setup_insert()
{
	HRESULT hr;

	hr = IWbemServices_ExecNotificationQuery(wmiEvents,
        L"WQL",
        L"SELECT * FROM MSNdis_NotifyAdapterArrival" ,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 
        NULL, &pInsertEvent);

	if (FAILED(hr)) return -1;

	return 0;
}

/**
 * \brief On some machines and interfaces Windows will send the WMI "card inserted"
 *		message before the interface is bound to our protocol driver.  So, we need
 *      to give it some time to get bound.
 *
 * @param[in] action   An int that defines the action to take.  (One of WMI_BIND_ADD,
 *                     WMI_BIND_CHECK)
 * @param[in] name     The name of the device we want to look for.  (Only needed 
 *	                   when action == WMI_BIND_ADD)
 **/
void cardif_windows_wmi_late_bind_insert_check(int action, wchar_t *name)
{
	int i = 0;
	int retval = 0;

	switch (action)
	{
	case WMI_BIND_ADD:
		while ((checks[i].intName != NULL) && (i < BIND_CHECKS_SIZE)) i++;

		if (i >= BIND_CHECKS_SIZE)
		{
			debug_printf(DEBUG_NORMAL, "All bind check slots are currently in use.  The newly inserted interface won't be discovered!\n");
			return;
		}

		checks[i].intName = wcsdup(name);
		checks[i].interval = BIND_INTERVAL;
		checks[i].numChecks = NUM_BIND_CHECKS;
		return;
		break;

	case WMI_BIND_CHECK:
		while (i < BIND_CHECKS_SIZE)
		{
			if (checks[i].intName != NULL)
			{
				checks[i].interval--;

				if (checks[i].interval <= 0)
				{
					// Try to bind again.
					retval = cardif_windows_wmi_post_insert_bind(checks[i].intName);
					if (retval != -1)
					{
						// We are done looking for this interface!
						if (retval == -2)
						{
							debug_printf(DEBUG_NORMAL, "An unrecoverable error was encountered binding the newly inserted interface '%ws'. "
								"It will not be available for use.\n", checks[i].intName);
						}

						FREE(checks[i].intName);
						return;
					}

					checks[i].numChecks--;
					if (checks[i].numChecks <= 0)
					{
						debug_printf(DEBUG_NORMAL, "Failed to bind newly discovered interface '%ws'.  It will not be usable.\n", checks[i].intName);
						FREE(checks[i].intName);
						return;
					}

					// Otherwise, reset 'interval'.
					checks[i].interval = BIND_INTERVAL;
				}
			}

			i++;
		}
		return;
		break;

	default:
		debug_printf(DEBUG_NORMAL, "You attempted to make use of the function %s() in an naughty way!  Stop that! ;)\n", __FUNCTION__);
		break;
	}
}

/**
 * \brief Check an event handler to see if any insertion events have happened.
 *
 *  When an event is triggered here, this function will also take care of processing
 *  the event, and sending an IPC event..
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_event_check_insert()
{
	HRESULT hr;
    IWbemClassObject *pclsObj = NULL;
	ULONG uReturn;
	VARIANT vtProp;

	if (pInsertEvent == NULL) return -1;

	hr = IEnumWbemClassObject_Next(pInsertEvent, 0, 1, &pclsObj, &uReturn);
	if (FAILED(hr)) return -1;

	if (uReturn > 0)
	{
		// We have an event.
		debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Card Insertion Event !!!!!!!!!!!!!!!!!!!!!\n");
		hr = IWbemClassObject_Get(pclsObj, L"InstanceName", 0, &vtProp, 0, 0);
		if (FAILED(hr))
		{
			debug_printf(DEBUG_NORMAL, "Got a card insertion event, but it didn't seem to have any "
					"information in it.\n");
		}
		
		// Locate the context we want to work on.
		debug_printf(DEBUG_INT, "Looking for interface with caption : %ws\n", vtProp.bstrVal);

		if (cardif_windows_wmi_post_insert_bind(vtProp.bstrVal) == -1)
		{
			// We get a LOT of insert events.  The ones we care about have "Packet Scheduler Miniport" in the name.
			if (wcsstr(vtProp.bstrVal, L"Packet Scheduler Miniport") != NULL)
			{
				// Need to queue it up to try to bind later.
				debug_printf(DEBUG_NORMAL, "Windows indicated that an interface was inserted, but it doesn't appear to have bound to the "
					"Open1X driver yet.   We will wait and try again...\n");
				cardif_windows_wmi_late_bind_insert_check(WMI_BIND_ADD, vtProp.bstrVal);
			}
		}

		VariantClear(&vtProp);
	}

	return 0;
}

/**
 * \brief Attempt to bind the interface that Windows told us was inserted.
 *
 * @param[in] name   The name of the interface that we need to bind to.
 *
 * \retval 0 on success
 * \retval -1 on failed (should try again.. to some point)
 * \retval -2 on failed (unrecoverable failure)
 **/
int cardif_windows_wmi_post_insert_bind(wchar_t *name)
{
	char *intname = NULL;
	char *intdesc = NULL;
	struct xsup_interfaces *confints = NULL;
	char mac[6];
	char is_wireless = 0;
	context *ctx = NULL;
	uint8_t flags;

	intname = cardif_windows_find_os_name_from_desc(name);
	intdesc = uni_to_ascii(name);
		
	if (intname == NULL)
	{
		debug_printf(DEBUG_INT, "Couldn't locate information about this instance, ignoring.\n");
		FREE(intdesc);
		return -1;
	}

	if (intdesc == NULL)
	{
		debug_printf(DEBUG_INT, "Couldn't convert description string from this interface, ignoring.\n");
		FREE(intname);
		return 0;
	}

	// Send event.
	ipc_events_ui(NULL, IPC_EVENT_INTERFACE_INSERTED, intname);

	if (get_mac_by_name(intname, (char *)&mac) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to get the MAC address for interface with description '%s'.  (OS Device Name : %s)\n", intdesc, intname);
		return -2;
	}

	is_wireless = cardif_is_wireless_by_name(intname);

	if (interfaces_add(intname, intdesc, mac, is_wireless) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to add interface '%s' to our live interfaces cache!\n", intdesc);
		// Don't die here, because we may be able to manage it, which would at least be something.
	}

	confints = config_get_config_ints();

	while ((confints != NULL) && (memcmp(mac, confints->mac, 6) != 0))
		confints = confints->next;

	if (confints != NULL)
	{
		flags = 0;
		if (TEST_FLAG(confints->flags, CONFIG_INTERFACE_DONT_MANAGE))
		{
			flags |= INT_IGNORE;
		}

		// Build the interface, and start watching it.
		if (context_init_interface(&ctx, intdesc, intname, NULL, flags) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't allocate context to manage newly inserted interface!\n");
		}
		else
		{
			// Add it to the event loop.
			debug_printf(DEBUG_NORMAL, "Interface '%s' was inserted or enabled.\n", intdesc);
		}
	}
	else
	{
		debug_printf(DEBUG_NORMAL, "Interface '%s' isn't in our configuration file.  We will not manage it.\n", intdesc);
	}

	FREE(intname);
	FREE(intdesc);
	
	return 0;
}

/**
 * \brief Create an event handler to watch for card removal events.
 *
 * \retval 0 on success.
 **/
int cardif_windows_wmi_event_setup_remove()
{
	HRESULT hr;

	hr = IWbemServices_ExecNotificationQuery(wmiEvents,
        L"WQL",
        L"SELECT * FROM MSNdis_NotifyAdapterRemoval" ,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 
        NULL, &pRemoveEvent);

	if (FAILED(hr)) return -1;

	return 0;
}

/**
 * \brief Check an event handler to see if any removal events have happened.
 *
 *  When an event is triggered here, this function will also take care of processing
 *  the event, and sending an IPC event..
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_event_check_remove()
{
	HRESULT hr;
    IWbemClassObject *pclsObj = NULL;
	ULONG uReturn;
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	VARIANT vtProp;
	char *intdesc = NULL;

	if (pRemoveEvent == NULL) return -1;

	hr = IEnumWbemClassObject_Next(pRemoveEvent, 0, 1, &pclsObj, &uReturn);
	if (FAILED(hr)) return -1;

	if (uReturn > 0)
	{
		// We have an event.
		debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Card Removal Event !!!!!!!!!!!!!!!!!!!!!\n");
		hr = IWbemClassObject_Get(pclsObj, L"InstanceName", 0, &vtProp, 0, 0);
		if (FAILED(hr))
		{
			debug_printf(DEBUG_NORMAL, "Got a card removal event, but it didn't seem to have any "
					"information in it.\n");
		}
		
		// Locate the context we want to work on.
		debug_printf(DEBUG_INT, "Looking for interface with caption : %ws\n", vtProp.bstrVal);

		intdesc = uni_to_ascii(vtProp.bstrVal);

		if (intdesc != NULL)
		{
			// Try to delete the interface from the interface cache.
			if (interfaces_delete(intdesc) == TRUE)
			{
				debug_printf(DEBUG_NORMAL, "Removed device '%s' from our live interfaces list.\n", intdesc);
			}
		}

		ctx = event_core_locate_by_desc(intdesc);
		VariantClear(&vtProp);

		if (ctx == NULL)
		{
			debug_printf(DEBUG_INT, "Couldn't locate a context for removal event. (Perhaps "
				"we aren't managing this interface?)\n");

			FREE(intdesc);
			return -1;
		}

		debug_printf(DEBUG_INT, "Interface is : %s\n", ctx->intName);
		ipc_events_ui(ctx, IPC_EVENT_INTERFACE_REMOVED, ctx->desc);

		debug_printf(DEBUG_NORMAL, "Interface '%s' was removed or disabled.\n", ctx->desc);

#ifdef HAVE_TNC
		// If we are using a TNC enabled build, signal the IMC to clean up.
		if(imc_disconnect_callback != NULL)
			imc_disconnect_callback(ctx->tnc_connID);
#endif

		ctx->flags |= INT_GONE;
		if ((ctx != NULL) && (ctx->statemachine != NULL)) ctx->statemachine->portEnabled = FALSE;
		if ((ctx != NULL) && (ctx->eap_state != NULL)) ctx->eap_state->portEnabled = FALSE;

		// Always deregister the secondary first!!
		event_core_deregister(((struct win_sock_data *)ctx->sockData)->devHandle, EVENT_SECONDARY);
		event_core_deregister(((struct win_sock_data *)ctx->sockData)->devHandle, EVENT_PRIMARY);

		FREE(intdesc);
	}

	return 0;
}

/**
 * \brief Create an event handler to watch for media disconnect events.
 *
 * \retval 0 on success.
 **/
int cardif_windows_wmi_event_setup_disconnect()
{
	HRESULT hr;

	hr = IWbemServices_ExecNotificationQuery(wmiEvents,
        L"WQL",
        L"SELECT * FROM MSNdis_StatusMediaDisconnect" ,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 
        NULL, &pDisconnectEvent);

	if (FAILED(hr)) return -1;

	return 0;
}

/**
 * \brief Check an event handler to see if any media disconnect events have happened.
 *
 *  When an event is triggered here, this function will also take care of processing
 *  the event, and changing the needed state options for interfaces.
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_event_check_disconnect()
{
	HRESULT hr;
    IWbemClassObject *pclsObj = NULL;
	ULONG uReturn;
	VARIANT vtProp;
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	char *intdesc = NULL;
	char bssid_dest[6];

	if (pDisconnectEvent == NULL) return -1;

	hr = IEnumWbemClassObject_Next(pDisconnectEvent, 0, 1, &pclsObj, &uReturn);
	if (FAILED(hr)) return -1;

	if (uReturn > 0)
	{
		// We have an event.
		debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Disconnect Event !!!!!!!!!!!!!!!!!!!!!\n");
		hr = IWbemClassObject_Get(pclsObj, L"InstanceName", 0, &vtProp, 0, 0);
		if (FAILED(hr))
		{
			debug_printf(DEBUG_NORMAL, "Got a disconnect event, but it didn't seem to have any "
					"information in it.\n");
		}
		
		// Locate the context we want to work on.
		debug_printf(DEBUG_INT, "Looking for interface with caption : %ws\n", vtProp.bstrVal);
		ctx = event_core_locate_by_caption(vtProp.bstrVal, FALSE);

		if (ctx == NULL)
		{
			intdesc = uni_to_ascii(vtProp.bstrVal);
			debug_printf(DEBUG_INT, "Couldn't find by caption, looking by description.\n");
			ctx = event_core_locate_by_desc_strstr(intdesc);
			if (ctx == NULL)
			{
				debug_printf(DEBUG_INT, "Couldn't locate a context for disconnect event. (Perhaps "	
					"we aren't managing the interface?)\n");
				VariantClear(&vtProp);
				return -1;
			}
		}
		VariantClear(&vtProp);

		debug_printf(DEBUG_INT, "Interface is : %s\n", ctx->intName);

		// Send event.
		ipc_events_ui(NULL, IPC_EVENT_UI_LINK_DOWN, ctx->desc);

		ctx->auths = 0;     // Reset the number of authentications this interface has done.

		if (ctx->intType == ETH_802_11_INT)
		{
			wctx = (wireless_ctx *)ctx->intTypeData;
			if (wctx == NULL)
			{
				debug_printf(DEBUG_NORMAL, "Interface %s claims to be wireless, but doesn't "
					"have a wireless context!?\n", ctx->intName);
				return -1;
			}

			// Double check to make sure that we really are disconnected.  Sometimes weird things
			// can happen because the events aren't being received in real time.
			if (cardif_windows_wireless_get_bssid(ctx, bssid_dest) != XENONE)
			{
				UNSET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);  // We are now disassociated.
				UNSET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);

				// Clear out our destination MAC, since we are disconnected now.
				memset(&ctx->dest_mac, 0x00, sizeof(ctx->dest_mac));
			}

			if (TEST_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK))
			{
				ipc_events_ui(ctx, IPC_EVENT_BAD_PSK, ctx->intName);

				// We sent the error so unset the flag.
				UNSET_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK);
			}
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Interface '%s' no longer has link.\n", ctx->desc);
			ctx->eap_state->portEnabled = FALSE;
			ctx->statemachine->initialize = TRUE;
		}
	}

	return 0;
}

/**
 * \brief Create an event handler to watch for media specific events.
 *
 * \retval 0 on success.
 **/
int cardif_windows_wmi_event_setup_media_specific()
{
	HRESULT hr;

	hr = IWbemServices_ExecNotificationQuery(wmiEvents,
        L"WQL",
        L"SELECT * FROM MSNdis_StatusMediaSpecificIndication" ,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, 
        NULL, &pMediaSpecificEvent);

	if (FAILED(hr)) return -1;

	return 0;
}

/**
 * \brief Check an event handler to see if any media specific events have happened.
 *
 *  When an event is triggered here, this function will also take care of processing
 *  the event, and changing any needed state options for interfaces.
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_event_check_media_specific()
{
	HRESULT hr;
    IWbemClassObject *pclsObj = NULL;
	ULONG uReturn;
	VARIANT vtProp;
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	LONG k;

	BSTR *bstr = NULL;
	char *data = NULL;
	LONG lower, upper;
	UCHAR ch;

	if (pMediaSpecificEvent == NULL) return -1;

	return 0;  // Don't do the stuff below right now.


	hr = IEnumWbemClassObject_Next(pMediaSpecificEvent, 0, 1, &pclsObj, &uReturn);
	if (FAILED(hr)) return 0;
//	printf("hr = %d\n", hr);

//	while (uReturn > 0)
	{
		/*
		debug_printf(DEBUG_NORMAL, "!!!!!!!!!!!!!!!!!!!!!!!!!!!! Media Specific Event !!!!!!!!!!!!!!!!!!!!!!!!!\n");

		if (uReturn > 0)
		{
			hr = IWbemClassObject_Get(pclsObj, L"InstanceName", 0, &vtProp, 0, 0);
			if (FAILED(hr))
			{
				debug_printf(DEBUG_NORMAL, "Got a media specific event, but it didn't seem to have any "
						"information in it.\n");
			}

			/*
			IWbemClassObject_BeginEnumeration(pclsObj, WBEM_FLAG_REFS_ONLY);

			debug_printf(DEBUG_NORMAL, "------------- Properties ------------\n");

//			bstr = Malloc(1024);

			while (IWbemClassObject_Next(pclsObj, 0, bstr, NULL, NULL, NULL) != WBEM_S_NO_MORE_DATA)
			{
				data = uni_to_ascii(bstr);
				debug_printf(DEBUG_NORMAL, "Property Name : %s\n", data);
				wprintf("Property Name : %ws\n", bstr);
//				printf("Property Name : %s\n", data);
				if (bstr != NULL) SysFreeString(bstr);
				free(data);
			}

			IWbemClassObject_EndEnumeration(pclsObj);
			
		}

		hr = IEnumWbemClassObject_Next(pMediaSpecificEvent, 0, 1, &pclsObj, &uReturn);
*/

		if (uReturn > 0)
		{
			// We have an event.
			debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Media Specific Event !!!!!!!!!!!!!!!!!!!!!\n");
			hr = IWbemClassObject_Get(pclsObj, L"InstanceName", 0, &vtProp, 0, 0);
			if (FAILED(hr))
			{
				debug_printf(DEBUG_NORMAL, "Got a media specific event, but it didn't seem to have any "
						"information in it.\n");
			}
		
			// Locate the context we want to work on.
			debug_printf(DEBUG_INT, "Looking for interface with caption : %ws\n", vtProp.bstrVal);
			printf("Interface : %ws\n", vtProp.bstrVal);
			ctx = event_core_locate_by_caption(vtProp.bstrVal, FALSE);
			VariantClear(&vtProp);

			hr = IWbemClassObject_Get(pclsObj, L"NdisStatusMediaSpecificIndication", 0, &vtProp, 0, 0);
			SafeArrayGetLBound(V_ARRAY(&vtProp), 1, &lower);
			SafeArrayGetUBound(V_ARRAY(&vtProp), 1, &upper);
			
			for (k = lower; k < upper; k++)
			{
				SafeArrayGetElement(V_ARRAY(&vtProp), &k, &ch);
				printf(" %02X ", ch);
			}

			if (ctx == NULL)
			{
				debug_printf(DEBUG_INT, "Couldn't locate a context for media specific event. (Perhaps "
					"we aren't managing the interface?)\n");
				return -1;
			}

			debug_printf(DEBUG_INT, "Interface is : %s\n", ctx->intName);

			if (ctx->intType == ETH_802_11_INT)
			{
				wctx = (wireless_ctx *)ctx->intTypeData;
				if (wctx == NULL)
				{
					debug_printf(DEBUG_NORMAL, "Interface %s claims to be wireless, but doesn't "
						"have a wireless context!?\n", ctx->intName);
					return -1;
				}
			}
			else
			{
				debug_printf(DEBUG_INT, "Interface isn't wireless.  Not doing anything with it for now.\n");
				return -1;
			}
		}
	}

	return 0;
}

/**
 * \brief Check to see if any events have triggered.
 **/
void cardif_windows_wmi_check_events()
{
//	cardif_windows_wmi_event_check_media_specific();
//	cardif_windows_wmi_event_check_connect();
//	cardif_windows_wmi_event_check_disconnect();
//	cardif_windows_wmi_event_check_insert();
//	cardif_windows_wmi_event_check_remove();

	// Check to see if any WMI method calls have completed.
	cardif_windows_wmi_async_check();
	
	cardif_windows_wmi_late_bind_insert_check(WMI_BIND_CHECK, NULL);
}

/**
 * \brief Initialize WMI so that we can use it.
 *
 * \retval 0 on success.
 **/
int cardif_windows_wmi_init()
{
	HRESULT hr;

	memset(checks, 0x00, sizeof(checks));

	// Set up notifications to let us know when an address has updated.
	cardif_windows_ip_update();

	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED); 
	if ((hr != S_OK) && (hr != S_FALSE))
	{
		if (FAILED(hr)) 
		{ 
			debug_printf(DEBUG_NORMAL, "Failed to initialize COM library. Error code = 0x%02x\n", hr);
			error_prequeue_add("Failed to initialize COM library.");
			return -1;
		}
	}

	hr =  CoInitializeSecurity(
	    NULL,                      // Security descriptor    
	    -1,                        // COM negotiates authentication service
	    NULL,                      // Authentication services
		NULL,                      // Reserved
	    RPC_C_AUTHN_LEVEL_DEFAULT, // Default authentication level for proxies
	    RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation level for proxies
	    NULL,                        // Authentication info
	    EOAC_NONE,                   // Additional capabilities of the client or server
	    NULL);                       // Reserved

	if (hr != S_OK && hr != RPC_E_TOO_LATE)
	{
		debug_printf(DEBUG_NORMAL, "Failed to initialize COM security. Error code = 0x%02x\n", hr);
		CoUninitialize();
		return -1;
	}

	hr = CoCreateInstance(&CLSID_WbemLocator, 0, 
        CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &wmiLoc);
 
    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Failed to create IWbemLocator object. Err code = 0x%02x\n", hr);
        CoUninitialize();
        return -1;
    }

	if (cardif_windows_wmi_connect() != 0) return -1;
	if (cardif_windows_wmi_event_connect() != 0) return -1;

	return 0;
}

/**
 * \brief Clean up the WMI connection(s) that we were using.
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_deinit()
{
	cardif_windows_wmi_event_disconnect();
	cardif_windows_wmi_disconnect();
	cardif_windows_wmi_async_cleanup();

	if(wmiLoc != NULL)
		IWbemLocator_Release(wmiLoc);   

    CoUninitialize();

	return 0;
}

/**
 * \brief Establish a connection to WMI to get interface events.
 *
 * This should only be called when the program starts up.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int cardif_windows_wmi_event_connect()
{
	HRESULT hr;

  // Connect to the root\default namespace with the current user.
    hr = IWbemLocator_ConnectServer(wmiLoc,
            L"ROOT\\WMI", 
            NULL, NULL, 0, 0, 0, 0, &wmiEvents);

    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not connect. Error code = 0x%04x\n", hr);
        return -1;    
    }

    debug_printf(DEBUG_INT, "Connected to WMI\n");

    hr = CoSetProxyBlanket(
       (IUnknown *)wmiEvents,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name 
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not set proxy blanket. Error code = 0x%04x\n", hr);
        return -1;
    }

	if (cardif_windows_wmi_event_setup_disconnect() != 0)
	{
		debug_printf(DEBUG_NORMAL, "Can't establish listener for media disconnect events.\n");
	}

	if (cardif_windows_wmi_event_setup_connect() != 0)
	{
		debug_printf(DEBUG_NORMAL, "Can't establish listener for media connect events.\n");
	}

	if (cardif_windows_wmi_event_setup_media_specific() != 0)
	{
		debug_printf(DEBUG_NORMAL, "Can't establish listener for media specific events.\n");
	}

	if (cardif_windows_wmi_event_setup_insert() != 0)
	{
		debug_printf(DEBUG_NORMAL, "Can't establish listener for card insertion events.\n");
	}

	if (cardif_windows_wmi_event_setup_remove() != 0)
	{
		debug_printf(DEBUG_NORMAL, "Can't establish listener for card removal events!\n");
	}

	return 0;
}

/**
 * \brief Establish a connection to WMI for future requests.
 *
 *  In general, this will only be called when the program starts up.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int cardif_windows_wmi_connect()
{
	HRESULT hr;

  // Connect to the root\default namespace with the current user.
    hr = IWbemLocator_ConnectServer(wmiLoc,
            L"ROOT\\CIMV2", 
            NULL, NULL, 0, 0, 0, 0, &wmiSvc);

    if (FAILED(hr))
    {
		error_prequeue_add("Unable to connect to WMI.  The supplicant will be unable to establish a connection.");
        debug_printf(DEBUG_NORMAL, "Could not connect. Error code = 0x%02x\n", hr);
        return -1;
    }

    debug_printf(DEBUG_INT, "Connected to CIMV2\n");

    hr = CoSetProxyBlanket(
       (IUnknown *)wmiSvc,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name 
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not set proxy blanket. Error code = 0x%02x\n", hr);
        return -1;
    }

	WMIConnected = TRUE;

	return XENONE;
}

/**
 * \brief Disconnect from the WMI event service when we are done with it.
 *
 * This should be called when the program shuts down.
 *
 * \retval 0 on success
 **/
int cardif_windows_wmi_event_disconnect()
{
	if (pConnectEvent != NULL) IWbemClassObject_Release(pConnectEvent);
	if (pDisconnectEvent != NULL) IWbemClassObject_Release(pDisconnectEvent);
	if (pMediaSpecificEvent != NULL) IWbemClassObject_Release(pMediaSpecificEvent);
	if (pInsertEvent != NULL) IWbemClassObject_Release(pInsertEvent);
	if (pRemoveEvent != NULL) IWbemClassObject_Release(pRemoveEvent);

	if (wmiEvents != NULL) IWbemServices_Release(wmiEvents);

	WMIConnected = FALSE;

	return XENONE;
}

/**
 * \brief Disconnect from the WMI service when we are done with it.  
 *
 *  In general, this will only be called when the program has been asked to shut down.
 *
 * \retval XENONE on success
 **/
int cardif_windows_wmi_disconnect()
{

	if (wmiSvc != NULL)
		IWbemServices_Release(wmiSvc);


	return XENONE;
}

///< \todo Move to_unicode to xsup_common.
// This function is found in mschapv2.c, but we need it here, so
// prototype it, and let the linker figure it out. ;)
char *to_unicode(char *);

/**
 * \brief Determine a device index given the context for a device.
 *
 * @param[in] ctx   A pointer to the context for the interface we need to find the 
 *                  index of.
 *
 * \todo  Find the proper way to convert unicode strings.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int cardif_windows_wmi_get_idx(context *ctx, char **description)
{
	char *matchstr = NULL;
	char *unimstr = NULL;
	HRESULT hr;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	int index = -1;
	ULONG uReturn = 0;
	VARIANT vtProp;
	struct win_sock_data *sockData = NULL;

	if (ctx == NULL) return -1;

	// First, we need to find the goop that follows the \DEVICE\ in the
	// interface name.
	matchstr = strstr(ctx->intName, "{");
	if (matchstr == NULL) return -1;      // It isn't there!?  This is BAD!

	if (wmiSvc == NULL)
	{
		debug_printf(DEBUG_NORMAL, "WMI Service is not available!\n");
		return -1;
	}

	// Request information about ALL of the interfaces known to Windows.
    hr = IWbemServices_ExecQuery(wmiSvc,
        L"WQL", 
        L"SELECT * FROM Win32_NetworkAdapterConfiguration",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if (FAILED(hr))
    {
        printf("Query for known interfaces failed. Error code = 0x%02x\n", hr);
        return -1;
    }

	// Then, search through them, looking for 'matchstr'.
	unimstr = to_unicode(matchstr);
	debug_printf(DEBUG_INT, "Searching for interface matching '%ws'.\n", unimstr);
    while (pEnumerator)
    {
        hr = IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, 
            &pclsObj, &uReturn);

        if(0 == uReturn)
        {
            break;
        }

		hr = IWbemClassObject_Get(pclsObj, L"SettingID", 0, &vtProp, 0, 0);
		if (FAILED(hr))
		{
			debug_printf(DEBUG_NORMAL, "Unable to obtain the 'SettingID' from the return "
					"results!\n");
			FREE(unimstr);
		    IWbemClassObject_Release(pEnumerator);
		    IWbemClassObject_Release(pclsObj);
			return -1;
		}

		if (wcscmp((wchar_t *)unimstr, vtProp.bstrVal) == 0)
		{
			debug_printf(DEBUG_INT, "Found interface.\n");

			// Clean up, so we can get the index.
			VariantClear(&vtProp);

			hr = IWbemClassObject_Get(pclsObj, L"Index", 0, &vtProp, 0, 0);
			if (FAILED(hr))
			{
				debug_printf(DEBUG_NORMAL, "Unable to obtain the Index for the desired "
						"interface!\n");
				FREE(unimstr);
				IWbemClassObject_Release(pEnumerator);
				IWbemClassObject_Release(pclsObj);
				return -1;
			}

			// Otherwise, we now know the index.
			debug_printf(DEBUG_INT, "Interface is at WMI index %d.\n", vtProp.intVal);
			sockData = (struct win_sock_data *)ctx->sockData;

			if (sockData == NULL)
			{
				debug_printf(DEBUG_NORMAL, "sockData for context '%s' is invalid!?\n",
							ctx->intName);
				FREE(unimstr);
				IWbemClassObject_Release(pEnumerator);
				IWbemClassObject_Release(pclsObj);
				VariantClear(&vtProp);
				return -1;
			}
	
			sockData->wmiIntIdx = vtProp.intVal;
			VariantClear(&vtProp);

			hr = IWbemClassObject_Get(pclsObj, L"Caption", 0, &vtProp, 0, 0);
			if (FAILED(hr))
			{
				debug_printf(DEBUG_NORMAL, "Unable to obtain the Index for the desired "
						"interface!\n");
				FREE(unimstr);
				IWbemClassObject_Release(pEnumerator);
				IWbemClassObject_Release(pclsObj);
				return -1;
			}
			
			// Store a copy of the caption for later use, if needed.
			sockData->caption = _wcsdup(vtProp.bstrVal);

			VariantClear(&vtProp);

			debug_printf(DEBUG_INT, "Interface Caption : %ws\n", sockData->caption);

			if (description != NULL)
			{
				hr = IWbemClassObject_Get(pclsObj, L"Description", 0, &vtProp, 0, 0);
				if (FAILED(hr))
				{
					debug_printf(DEBUG_NORMAL, "Unable to obtain the Index for the desired "
							"interface!\n");
					FREE(unimstr);
					IWbemClassObject_Release(pEnumerator);
					IWbemClassObject_Release(pclsObj);
					return -1;
				}
			
				(*description) = uni_to_ascii(vtProp.bstrVal);
				VariantClear(&vtProp);
			}

			IWbemClassObject_Release(pclsObj);
			break;
		}
		else
		{
			VariantClear(&vtProp);
			IWbemClassObject_Release(pclsObj);
		}
	}

	IWbemClassObject_Release(pEnumerator);

    FREE(unimstr);

	return XENONE;
}

/**
 *  \brief  Do a WQL request against WMI, and get the value at index 0 of the
 *          resulting array.
 *
 *  @param[in] ctx   The context for the interface we want to get data about.
 *  @param[in] prop   A wchar_t pointer that contains the property to be queried.
 *
 *  \retval NULL on error
 *  \retval ptr to result
 **/
wchar_t *cardif_windows_wmi_get_array_idx0(context *ctx, wchar_t *prop)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	wchar_t *adapt_select = NULL;
	VARIANT vtProp;
	IWbemClassObject *pclsObj = NULL;
	IEnumWbemClassObject *pEnumerator = NULL;
	ULONG uReturn;
	BSTR HUGEP *pbstr = NULL;
	wchar_t *retval = NULL;

	if (ctx == NULL) return NULL;

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		return NULL;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			return NULL;
		}
	}

	// We should know everything we need to locate the IP address for this interface.
	// Request information about ALL of the interfaces known to Windows.
	adapt_select = Malloc(512);
	if (adapt_select == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store adapter select string!\n");
		return NULL;
	}

	swprintf(adapt_select, L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = %d", sockData->wmiIntIdx);

    hr = IWbemServices_ExecQuery(wmiSvc,
        L"WQL", adapt_select,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);

	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to locate the WMI configuration block for interface "
				"'%s'!\n", ctx->intName);
                FREE(adapt_select);
		return NULL;
	}
        FREE(adapt_select);

    hr = IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, 
         &pclsObj, &uReturn);

    if(0 == uReturn)
    {
		debug_printf(DEBUG_NORMAL, "Couldn't build enumerator needed to get array data!\n");
        // Clean up and return nothing.
		IWbemClassObject_Release(pEnumerator);
		return NULL;
    }

	// We should have a pointer to what we need to know now.  So, get the data.
	hr = IWbemClassObject_Get(pclsObj, prop, 0, &vtProp, 0, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Couldn't determine array data via WMI query!\n");
		IWbemClassObject_Release(pEnumerator);
		VariantClear(&vtProp);
		IWbemClassObject_Release(pclsObj);
		return NULL;
	}

	if (vtProp.parray == NULL) return NULL;

	// Whew!  After all that, we should have an IP address now.
	hr = SafeArrayAccessData(vtProp.parray, (void HUGEP**)&pbstr);
	if (FAILED(hr)) 
	{
		debug_printf(DEBUG_NORMAL, "Get variant array data failed!\n");
		IWbemClassObject_Release(pEnumerator);
		VariantClear(&vtProp);
		IWbemClassObject_Release(pclsObj);
		return NULL;
	}

	debug_printf(DEBUG_INT, "Data : %ws\n", pbstr[0]);
	retval = _wcsdup(pbstr[0]);
	SafeArrayUnaccessData(vtProp.parray);
	
	// Clean up.
	IWbemClassObject_Release(pEnumerator);
	VariantClear(&vtProp);
	IWbemClassObject_Release(pclsObj);

	return retval;
}

/**
 * \brief Convert a unicode string to a UTF-8 string.
 *
 * @param[in] instr  A pointer to a wchar_t string that needs to be converted.
 *
 * \retval NULL on error
 * \retval ptr  instr converted to UTF-8.
 **/
char *convert_unicode_to_chars(wchar_t *instr)
{
	char *utf8result = NULL;

	utf8result = Malloc(wcslen(instr)+2);
	if (utf8result == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store UTF-8 result at %s()!\n",
				__FUNCTION__);
		return NULL;
	}

	sprintf(utf8result, "%ws", instr);

	return utf8result;
}

/**
 * \brief Get the IP address for a given device.
 *
 * If this is the first time we have requested information about this interface,
 * we will need to call cardif_windows_wmi_get_idx() to populate it's index number.
 * Once we have cached the index number, we shouldn't need to query for the index
 * again.
 *
 * @param[in] ctx  A pointer to the context for this interface.
 *
 * \retval NULL on error
 * \retval ptr  A pointer to a unicode string that identifies the IP address.  You should
 *               use the cardif_windows_wmi_get_ip_utf8() call to get a utf8 string.
 **/
wchar_t *cardif_windows_wmi_get_ip(context *ctx)
{
	return cardif_windows_wmi_get_array_idx0(ctx, L"IPAddress");
}

/**
 * \brief Get the IP address for a given device in UTF-8 format.
 *
 *  This function will call cardif_windows_wmi_get_ip(), and convert the
 *  resulting wide characater string in to UTF-8.
 *
 * \warning This function assumes that the resulting interface name will
 *          not contain characters with values > 0xff.  If they do, the
 *          resulting string will be invalid.
 *
 * \retval NULL on failure
 * \retval ptr  A pointer to a string that identifies the IP address.
 **/
char *cardif_windows_wmi_get_ip_utf8(context *ctx)
{
	wchar_t *wresult = NULL;
	char *utf8result = NULL;

	wresult = cardif_windows_wmi_get_ip(ctx);
	if (wresult == NULL) return NULL;

	utf8result = convert_unicode_to_chars(wresult);
	FREE(wresult);
	return utf8result;
}

/**
 * \brief Get the IP network mask for a given device.
 *
 * If this is the first time we have requested information about this interface,
 * we will need to call cardif_windows_wmi_get_idx() to populate it's index number.
 * Once we have cached the index number, we shouldn't need to query for the index
 * again.
 *
 * @param[in] ctx  A pointer to the context for this interface.
 *
 * \retval NULL on failure
 * \retval ptr  A pointer to a unicode string that identifies the IP network mask.  You should
 *               use the cardif_windows_wmi_get_netmask_utf8() call to get a utf8 string.
 **/
wchar_t *cardif_windows_wmi_get_netmask(context *ctx)
{
	return cardif_windows_wmi_get_array_idx0(ctx, L"IPSubnet");
}

/**
 * \brief Get the IP network mask for a given device in UTF-8 format.
 *
 *  This function will call cardif_windows_wmi_get_netmask(), and convert the
 *  resulting wide characater string in to UTF-8.
 *
 * \warning This function assumes that the resulting interface name will
 *          not contain characters with values > 0xff.  If they do, the
 *          resulting string will be invalid.
 *
 * \retval NULL on failure
 * \retval ptr  A pointer to a string that identifies the IP network mask.
 **/
char *cardif_windows_wmi_get_netmask_utf8(context *ctx)
{
	wchar_t *wresult = NULL;
	char *utf8result = NULL;

	wresult = cardif_windows_wmi_get_netmask(ctx);
	if (wresult == NULL) return NULL;

	utf8result = convert_unicode_to_chars(wresult);
	FREE(wresult);
	return utf8result;
}

/**
 * \brief Get the IP default gateway for a given device.
 *
 * If this is the first time we have requested information about this interface,
 * we will need to call cardif_windows_wmi_get_idx() to populate it's index number.
 * Once we have cached the index number, we shouldn't need to query for the index
 * again.
 *
 * @param[in] ctx  A pointer to the context for this interface.
 *
 * \todo Fix!
 *
 * \retval NULL on failure
 * \retval ptr  A pointer to a unicode string that identifies the IP default gateway.  You should
 *               use the cardif_windows_wmi_get_gw_utf8() call to get a utf8 string.
 **/
wchar_t *cardif_windows_wmi_get_gw(context *ctx)
{
	return NULL;
	return cardif_windows_wmi_get_array_idx0(ctx, L"DefaultIPGateway");
}

/**
 * \brief Get the IP default gateway address for a given device in UTF-8 format.
 *
 *  This function will call cardif_windows_wmi_get_gw(), and convert the
 *  resulting wide characater string in to UTF-8.
 *
 * \warning This function assumes that the resulting interface name will
 *          not contain characters with values > 0xff.  If they do, the
 *          resulting string will be invalid.
 *
 * \retval NULL on failure
 * \retval ptr  A pointer to a string that identifies the IP default gateway.
 **/
char *cardif_windows_wmi_get_gw_utf8(context *ctx)
{
	wchar_t *wresult = NULL;
	char *utf8result = NULL;

	wresult = cardif_windows_wmi_get_gw(ctx);
	if (wresult == NULL) return NULL;

	utf8result = convert_unicode_to_chars(wresult);
	FREE(wresult);
	return utf8result;
}

/**
 * \brief Free all memory used in an allocated 'SAFEARRAY'.
 *
 * @param[in] myarray  The SAFEARRAY we want to destroy.
 *
 **/
void cardif_windows_wmi_destroy_safearray(SAFEARRAY **myarray)
{
	SafeArrayDestroyData((*myarray));
	SafeArrayDestroyDescriptor((*myarray));
	(*myarray) = NULL;
}

/**
 * \brief Set the value of element 0 in the 'SAFEARRAY' to be the string
 *        passed in.
 *
 * \todo Do we need to free mybstr?
 *
 * @param[in] psa   A pointer to an allocated 'SAFEARRAY' that we want
 *                  to populate.
 * @param[in] mystr   The string to put in element 0 of the 'SAFEARRAY'.
 *
 * \retval HRESULT   An HRESULT value for the calls.
 **/
HRESULT cardif_windows_wmi_set_safearray_str(SAFEARRAY *psa, char *mystr)
{
	wchar_t *pbstr = NULL;
	LONG index[] = {0};
	BSTR mybstr = NULL;

	pbstr = malloc(strlen(mystr)*4);   // Should be big enough, and then some.
	if (pbstr == NULL)
	{
		// This is a garbage error, but it will cause the right thing to
		// happen.
		return MAKE_HRESULT(1, FACILITY_CONFIGURATION, 0);
	}

	memset(pbstr, 0x00, (strlen(mystr) * 4));
	mbstowcs(pbstr, mystr, (strlen(mystr)*4));

	mybstr = SysAllocString(pbstr);
	if (mybstr == NULL)
	{
		// This is a garbage error, but it will cause the right thing to
		// happen.
		return MAKE_HRESULT(1, FACILITY_CONFIGURATION, 0);
	}

	free(pbstr);

	return SafeArrayPutElement(psa, index, mybstr);
}

/**
 * \brief Make a WMI call that doesn't require any parameters.  (Semisync version)
 *
 * @param[in] ctx   The context to execute the command against.
 * @param[in] cmdname   The WMI command name to execute.
 * @param[in] callname   The name of the call for debugging and logging purposes.
 * @param[in] callback   The callback that will be called when this call finishes.
 *
 * \retval <0 an error occurred
 * \retval >=0 value returned from WMI call.
 **/
static int cardif_windows_wmi_call_async(context *ctx, char *cmdname, char *callname, void *callback)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	char lcmdname[200];
    BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR MethodName = NULL;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pOutParams = NULL;
	IWbemCallResult *pResult = NULL;
	LPVOID lpMsgBuf = NULL;
	VARIANT varReturnValue;
	BSTR IntPath = NULL;
	char apath[100];
	char lpath[200];
	int retval = 0;

	if (ctx == NULL)
	{
		retval = -1;
		goto done;
	}

	if (!xsup_assert((cmdname != NULL), "cmdname != NULL", FALSE))
	{
		retval = -1;
		goto done;
	}

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		return -1;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			retval = -1;
			goto done;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		retval = -1;
		goto done;
	}

	mbstowcs((wchar_t *)&lcmdname, cmdname, strlen(cmdname)+1);
	MethodName = SysAllocString((OLECHAR *)&lcmdname);
	if (MethodName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create long command name!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pClass, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get object for 'Win32_NetworkAdapterConfiguration'"
				" class!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, WBEM_FLAG_RETURN_IMMEDIATELY, // | WBEM_FLAG_FORWARD_ONLY, 
		NULL, pClass, NULL, &pResult);
    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not execute method. Error code = 0x%x\n", hr);

		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error : %s\n", lpMsgBuf);

		LocalFree(lpMsgBuf);
		retval = -1;
		goto done;
	}

done:
	// Clean up.
	if (pOutParams) IWbemClassObject_Release(pOutParams);
	if (pClass) IWbemClassObject_Release(pClass);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	if (retval != 0) return retval;

	return cardif_windows_wmi_async(callname, ctx, pResult, callback);
}

/**
 * \brief Make a WMI call that doesn't require any parameters.
 *
 * @param[in] ctx   The context to execute the command against.
 * @param[in] cmdname   The WMI command name to execute.
 *
 * \retval <0 an error occurred
 * \retval >=0 value returned from WMI call.
 **/
static int cardif_windows_wmi_call(context *ctx, char *cmdname)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	char lcmdname[200];
    BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR MethodName = NULL;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pOutParams = NULL;
	LPVOID lpMsgBuf = NULL;
	VARIANT varReturnValue;
	BSTR IntPath = NULL;
	char apath[100];
	char lpath[200];
	int retval = 0;

	if (ctx == NULL)
	{
		retval = -1;
		goto done;
	}

	if (!xsup_assert((cmdname != NULL), "cmdname != NULL", FALSE))
	{
		retval = -1;
		goto done;
	}

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		retval = -1;
		goto done;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			retval = -1;
			goto done;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		retval = -1;
		goto done;
	}

	mbstowcs((wchar_t *)&lcmdname, cmdname, strlen(cmdname)+1);
	MethodName = SysAllocString((OLECHAR *)&lcmdname);
	if (MethodName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create long command name!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pClass, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get object for 'Win32_NetworkAdapterConfiguration'"
				" class!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, 0,
		NULL, pClass, &pOutParams, NULL);
    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not execute method. Error code = 0x%x\n", hr);

		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error : %s\n", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_Get(pOutParams, L"ReturnValue", 0, 
        &varReturnValue, NULL, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'ReturnValue'.\n");

		retval = -1;
		goto done;
	}

	debug_printf(DEBUG_INT, "Return value : %d\n", varReturnValue.intVal);
	retval = varReturnValue.intVal;

	VariantClear(&varReturnValue);

done:
	// Clean up.
	if (pOutParams) IWbemClassObject_Release(pOutParams);
	if (pClass) IWbemClassObject_Release(pClass);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	return retval;
}

/**
 * \brief Request that an interface change itself to using DHCP.
 *
 * @param[in] ctx   The context that we want to enable DHCP on.
 *
 * \retval <0 on non-WMI error
 * \retval >=0 on success, or WMI error
 **/
int cardif_windows_wmi_enable_dhcp(context *ctx)
{
	return cardif_windows_wmi_call(ctx, "EnableDHCP");
}

/**
 * \brief Request that an interface release a DHCP address.
 *
 * @param[in] ctx   The context that we want to enable DHCP on.
 *
 * \retval <0 on non-WMI error
 * \retval >=0 on success, or WMI error
 **/
int cardif_windows_wmi_release_dhcp(context *ctx)
{
	return cardif_windows_wmi_call(ctx, "ReleaseDHCPLease");
}

/**
 * \brief Request that an interface renew a DHCP address.
 *
 * @param[in] ctx   The context that we want to enable DHCP on.
 *
 * \retval <0 on non-WMI error
 * \retval >=0 on success, or WMI error
 **/
int cardif_windows_wmi_renew_dhcp(context *ctx)
{
	debug_printf(DEBUG_NORMAL, "Interface '%s' requested a DHCP renew.\n", ctx->desc);
	return cardif_windows_wmi_call_async(ctx, "RenewDHCPLease", "DHCP renew", cardif_windows_wmi_async_dhcp_renew_callback);
}

/**
 * \brief Request that an interface release/renew a DHCP address.
 *
 * @param[in] ctx   The context that we want to release/renew DHCP on.
 *
 * \retval <0 on non-WMI error
 * \retval >=0 on success, or WMI error
 **/
int cardif_windows_wmi_release_renew(context *ctx)
{
	debug_printf(DEBUG_NORMAL, "Interface '%s' requested a DHCP release.\n", ctx->desc);
	return cardif_windows_wmi_call_async(ctx, "ReleaseDHCPLease", "DHCP release", cardif_windows_wmi_async_dhcp_release_renew_callback);
}

/**
 * \brief Switch the interface to use static IP addresses, and set the
 *        IP address and netmask.
 *
 * @param[in] ipaddr   The new IP address to use.
 * @param[in] netmask    The new netmask to use.
 * 
 * \retval <0 on error
 * \retval 0 on success
 * \retval >0 error returned by WMI method call
 **/
int cardif_windows_wmi_set_static_ip(context *ctx, char *ipaddr, char *netmask)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	VARIANT varIpaddr, varNetmask, varReturnValue;
	IWbemClassObject *pclsObj = NULL, *pClassInstance = NULL;
	IWbemClassObject *inobj = NULL, *outdata = NULL;
	IWbemCallResult *pResult = NULL;
	int retval = XENONE;
	BSTR MethodName = SysAllocString(L"EnableStatic");
	BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR IntPath = NULL;
	SAFEARRAY *iparray = NULL;
	SAFEARRAY *maskarray = NULL;
	LPVOID lpMsgBuf = NULL;
	char apath[100];
	char lpath[200];

	if (ctx == NULL)
	{
		retval = -1;
		goto done;
	}

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		retval = -1;
		goto done;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			retval = -1;
			goto done;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pclsObj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class handle!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}


	hr = IWbemClassObject_GetMethod(pclsObj, MethodName, 0, &inobj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'EnableStatic' method!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_SpawnInstance(inobj, 0, &pClassInstance);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class instance to execute 'EnableStatic'!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

	iparray = SafeArrayCreateVector(VT_BSTR, 0, 1);
	if (iparray == NULL)
	{
		retval = XEMALLOC;
		goto done;
	}

	maskarray = SafeArrayCreateVector(VT_BSTR, 0, 1);
	if (maskarray == NULL)
	{
		retval = XEMALLOC;
		goto done;
	}

	hr = cardif_windows_wmi_set_safearray_str(iparray, ipaddr);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to set the IP address parameter!\n");
		retval = XEMALLOC;
		goto done;
	}

	hr = cardif_windows_wmi_set_safearray_str(maskarray, netmask);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to set the netmask parameter!\n");
		retval = XEMALLOC;
		goto done;
	}

	varIpaddr.vt = VT_ARRAY | VT_BSTR;
	varIpaddr.parray = iparray;

	hr = IWbemClassObject_Put(pclsObj, L"IPAddress", 0, &varIpaddr, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed IP address in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	varNetmask.vt = VT_ARRAY | VT_BSTR;
	varNetmask.parray = maskarray;

	hr = IWbemClassObject_Put(pclsObj, L"SubnetMask", 0, &varNetmask, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed netmask in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, 0, //WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL, pclsObj, &outdata, &pResult);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to execute 'EnableStatic' method!\n");
		retval = -1;
		goto done;
	}

done:
	// Clean up.
	if (pclsObj) IWbemClassObject_Release(pclsObj);
	if (pClassInstance) IWbemClassObject_Release(pClassInstance);
	if (inobj) IWbemClassObject_Release(inobj);
	if (outdata) IWbemClassObject_Release(outdata);

	if (iparray) cardif_windows_wmi_destroy_safearray(&iparray);
	if (maskarray) cardif_windows_wmi_destroy_safearray(&maskarray);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	if (retval != 0) return retval;

	return cardif_windows_wmi_async("Set Static IP", ctx, pResult, 
									cardif_windows_wmi_async_static_ip_callback);
}

int cardif_windows_wmi_enable_static(context *ctx, char *ipaddr, char *netmask)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	VARIANT varIpaddr, varNetmask, varReturnValue;
	IWbemClassObject *pclsObj = NULL, *pClassInstance = NULL;
	IWbemClassObject *inobj = NULL, *outdata = NULL;
	IWbemCallResult *pResult = NULL;
	int retval = XENONE;
	BSTR MethodName = SysAllocString(L"EnableStatic");
	BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR IntPath = NULL;
	SAFEARRAY *iparray = NULL;
	SAFEARRAY *maskarray = NULL;
	LPVOID lpMsgBuf = NULL;
	char apath[100];
	char lpath[200];

	if (ctx == NULL)
	{
		retval = -1;
		goto done;
	}

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		retval = -1;
		goto done;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			retval = -1;
			goto done;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pclsObj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class handle!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}


	hr = IWbemClassObject_GetMethod(pclsObj, MethodName, 0, &inobj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'EnableStatic' method!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_SpawnInstance(inobj, 0, &pClassInstance);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class instance to execute 'EnableStatic'!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

	iparray = SafeArrayCreateVector(VT_BSTR, 0, 1);
	if (iparray == NULL)
	{
		retval = XEMALLOC;
		goto done;
	}

	maskarray = SafeArrayCreateVector(VT_BSTR, 0, 1);
	if (maskarray == NULL)
	{
		retval = XEMALLOC;
		goto done;
	}

	hr = cardif_windows_wmi_set_safearray_str(iparray, ipaddr);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to set the IP address parameter!\n");
		retval = XEMALLOC;
		goto done;
	}

	hr = cardif_windows_wmi_set_safearray_str(maskarray, netmask);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to set the netmask parameter!\n");
		retval = XEMALLOC;
		goto done;
	}

	varIpaddr.vt = VT_ARRAY | VT_BSTR;
	varIpaddr.parray = iparray;

	hr = IWbemClassObject_Put(pclsObj, L"IPAddress", 0, &varIpaddr, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed IP address in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	varNetmask.vt = VT_ARRAY | VT_BSTR;
	varNetmask.parray = maskarray;

	hr = IWbemClassObject_Put(pclsObj, L"SubnetMask", 0, &varNetmask, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed netmask in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL, pclsObj, &outdata, &pResult);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to execute 'EnableStatic' method!\n");
		retval = -1;
		goto done;
	}

done:
	// Clean up.
	if (pclsObj) IWbemClassObject_Release(pclsObj);
	if (pClassInstance) IWbemClassObject_Release(pClassInstance);
	if (inobj) IWbemClassObject_Release(inobj);
	if (outdata) IWbemClassObject_Release(outdata);

	if (iparray) cardif_windows_wmi_destroy_safearray(&iparray);
	if (maskarray) cardif_windows_wmi_destroy_safearray(&maskarray);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	if (retval != 0) return retval;

	return cardif_windows_wmi_async("Set Static IP", ctx, pResult, 
									cardif_windows_wmi_async_static_ip_callback);
}

/**
 * \brief Set the DNS domain for the connection.
 *
 * @param[in] ctx   The context to change the DNS domain on.
 * @param[in] newdomain   The new DNS domain to use.
 *
 * \retval -1 on error
 * \retval 0 on success
 * \retval >0 on WMI error
 **/
int cardif_windows_wmi_set_dns_domain(context *ctx, char *newdomain)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	VARIANT varDNS, varReturnValue;
	IWbemClassObject *pclsObj = NULL, *pClassInstance = NULL;
	IWbemClassObject *inobj = NULL, *outdata = NULL;
	int retval = XENONE;
	BSTR MethodName = SysAllocString(L"SetDNSDomain");
	BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR IntPath = NULL;
	BSTR DomainName = NULL;
	LPVOID lpMsgBuf = NULL;
	char apath[100];
	char lpath[258];

	if (ctx == NULL) return -1;

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		return -1;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			return -1;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		return -1;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pclsObj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class handle!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);
	}


	hr = IWbemClassObject_GetMethod(pclsObj, MethodName, 0, &inobj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'SetDNSDomain' method!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);
	}

    hr = IWbemClassObject_SpawnInstance(inobj, 0, &pClassInstance);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class instance to execute 'SetDNSDomain'!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);
	}

	if (newdomain != NULL)
	{
		mbstowcs((wchar_t *)&lpath[0], newdomain, strlen(newdomain)+1);
		DomainName = SysAllocString((OLECHAR *)&lpath);
	}
	else
	{
		DomainName = NULL;
	}

	varDNS.vt = VT_BSTR;
	varDNS.bstrVal = DomainName;

	hr = IWbemClassObject_Put(pclsObj, L"DNSDomain", 0, &varDNS, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed DNS domain in object!\n");
		SysFreeString(DomainName);
		return XEMALLOC;
	}

	hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, 0, NULL, pclsObj, 
		&outdata, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to execute 'DNSDomain' method!\n");
		SysFreeString(DomainName);
		return -1;
	}

    hr = IWbemClassObject_Get(outdata, L"ReturnValue", 0, 
        &varReturnValue, NULL, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'ReturnValue'.\n");
		SysFreeString(DomainName);
		return -1;
	}

	debug_printf(DEBUG_INT, "Return value : %d\n", varReturnValue.intVal);
	retval = varReturnValue.intVal;

done:
	// Clean up.
	if (pclsObj) IWbemClassObject_Release(pclsObj);
	if (pClassInstance) IWbemClassObject_Release(pClassInstance);
	if (inobj) IWbemClassObject_Release(inobj);
	if (outdata) IWbemClassObject_Release(outdata);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	if (DomainName) SysFreeString(DomainName);

	return retval;
}

/**
 * \brief Set the DNS server(s) and search order
 *
 * @param[in] ctx   The context to change the DNS domain on.
 * @param[in] dns1   The first DNS to search
 * @param[in] dns2   The second DNS to search
 * @param[in] dns3   The third DNS to search
 *
 * \retval -1 on error
 * \retval 0 on success
 * \retval >0 on WMI error
 **/
int cardif_windows_wmi_set_dns_servers(context *ctx, char *dns1, char *dns2, char *dns3)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	VARIANT varDNS, varReturnValue;
	IWbemClassObject *pclsObj = NULL, *pClassInstance = NULL;
	IWbemClassObject *inobj = NULL, *outdata = NULL;
	int retval = XENONE;
	BSTR MethodName = SysAllocString(L"SetDNSServerSearchOrder");
	BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR IntPath = NULL;
	BSTR DNS1 = NULL, DNS2 = NULL, DNS3 = NULL;
	SAFEARRAY *dnsarray = NULL;
	LPVOID lpMsgBuf = NULL;
	char apath[100];
	char lpath[258];
	LONG index[] = {0};
	unsigned int numsvrs = 0;

	if (ctx == NULL)
	{
		retval = -1;
		goto done;
	}

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		retval = -1;
		goto done;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			retval = -1;
			goto done;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pclsObj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class handle!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}


	hr = IWbemClassObject_GetMethod(pclsObj, MethodName, 0, &inobj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'SetDNSServerSearchOrder' method!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_SpawnInstance(inobj, 0, &pClassInstance);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class instance to execute 'SetDNSServerSearchOrder'!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

	if (dns1 != NULL) numsvrs++;
	if (dns2 != NULL) numsvrs++;
	if (dns3 != NULL) numsvrs++;

	dnsarray = SafeArrayCreateVector(VT_BSTR, 0, numsvrs);
	if (dnsarray == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Failed to allocate memory to store DNS array!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

	if (dns1 != NULL)
	{
		mbstowcs((wchar_t *)&lpath[0], dns1, strlen(dns1)+1);
		DNS1 = SysAllocString((OLECHAR *)&lpath);
		
		if (FAILED(SafeArrayPutElement(dnsarray, index, DNS1)))
		{
			debug_printf(DEBUG_NORMAL, "Failed to put DNS server #1 in the list!\n");
			debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
			lpMsgBuf = GetLastErrorStr(GetLastError());

			debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

			LocalFree(lpMsgBuf);

			retval = -1;
			goto done;
		}

		index[0]++;
	}

	if (dns2 != NULL)
	{
		mbstowcs((wchar_t *)&lpath[0], dns2, strlen(dns2)+1);
		DNS2 = SysAllocString((OLECHAR *)&lpath);

		if (FAILED(SafeArrayPutElement(dnsarray, index, DNS2)))
		{
			debug_printf(DEBUG_NORMAL, "Failed to put DNS server #2 in the list!\n");
			debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
			lpMsgBuf = GetLastErrorStr(GetLastError());

			debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

			LocalFree(lpMsgBuf);

			retval = -1;
			goto done;
		}

		index[0]++;
	}

	if (dns3 != NULL)
	{
		mbstowcs((wchar_t *)&lpath[0], dns3, strlen(dns3)+1);
		DNS3 = SysAllocString((OLECHAR *)&lpath);

		if (FAILED(SafeArrayPutElement(dnsarray, index, DNS3)))
		{
			debug_printf(DEBUG_NORMAL, "Failed to put DNS server #3 in the list!\n");
			debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
			lpMsgBuf = GetLastErrorStr(GetLastError());

			debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

			LocalFree(lpMsgBuf);

			retval = -1;
			goto done;
		}
	}

	varDNS.vt = VT_ARRAY | VT_BSTR;
	varDNS.parray = dnsarray;

	hr = IWbemClassObject_Put(pclsObj, L"DNSServerSearchOrder", 0, &varDNS, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed DNS server list in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, 0, NULL, pclsObj, 
		&outdata, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to execute 'SetDNSServerSearchOrder' method!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_Get(outdata, L"ReturnValue", 0, 
        &varReturnValue, NULL, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'ReturnValue'.\n");
		retval = -1;
		goto done;
	}

	debug_printf(DEBUG_INT, "Return value : %d\n", varReturnValue.intVal);
	retval = varReturnValue.intVal;

done:
	// Clean up.
	if (pclsObj) IWbemClassObject_Release(pclsObj);
	if (pClassInstance) IWbemClassObject_Release(pClassInstance);
	if (inobj) IWbemClassObject_Release(inobj);
	if (outdata) IWbemClassObject_Release(outdata);

	if (dnsarray) cardif_windows_wmi_destroy_safearray(&dnsarray);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	if (DNS1) SysFreeString(DNS1);
	if (DNS2) SysFreeString(DNS2);
	if (DNS3) SysFreeString(DNS3);

	return retval;
}

/**
 * \brief Switch the interface to use static gateway IP address.
 *
 * @param[in] gwip   The new gateway IP address to use.
 * 
 * \retval <0 on error
 * \retval 0 on success
 * \retval >0 error returned by WMI method call
 **/
int cardif_windows_wmi_set_static_gw(context *ctx, char *gwip)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	VARIANT varGWaddr, varMetric, varReturnValue;
	IWbemClassObject *pclsObj = NULL, *pClassInstance = NULL;
	IWbemClassObject *inobj = NULL, *outdata = NULL;
	int retval = XENONE;
	BSTR MethodName = SysAllocString(L"SetGateways");
	BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");
	BSTR IntPath = NULL;
	SAFEARRAY *gwarray = NULL;
	SAFEARRAY *metric_list = NULL;
	LPVOID lpMsgBuf = NULL;
	unsigned short metric = DEFAULT_GW_METRIC;
	long index[] = {0};
	char apath[100];
	char lpath[200];

	if (ctx == NULL) 
	{
		retval = -1;
		goto done;
	}

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		retval = -1;
		goto done;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			retval = -1;
			goto done;
		}
	}

	sprintf(&apath, "Win32_NetworkAdapterConfiguration.Index='%d'", sockData->wmiIntIdx);
	mbstowcs((wchar_t *)&lpath, apath, strlen(apath)+1);

	IntPath = SysAllocString((OLECHAR *)&lpath);
	if (IntPath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create interface path!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemServices_GetObject(wmiSvc, ClassName, 0, NULL, &pclsObj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class handle!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}


	hr = IWbemClassObject_GetMethod(pclsObj, MethodName, 0, &inobj, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'SetGateways' method!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_SpawnInstance(inobj, 0, &pClassInstance);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get class instance to execute 'SetGateways'!\n");
		debug_printf(DEBUG_NORMAL, "Error #%x\n", hr);
		lpMsgBuf = GetLastErrorStr(GetLastError());

		debug_printf(DEBUG_NORMAL, "Error was : %s", lpMsgBuf);

		LocalFree(lpMsgBuf);

		retval = -1;
		goto done;
	}

	gwarray = SafeArrayCreateVector(VT_BSTR, 0, 1);
	if (gwarray == NULL)
	{
		retval = XEMALLOC;
		goto done;
	}

	hr = cardif_windows_wmi_set_safearray_str(gwarray, gwip);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to set the gateway IP address parameter!\n");
		retval = XEMALLOC;
		goto done;
	}

	varGWaddr.vt = VT_ARRAY | VT_BSTR;
	varGWaddr.parray = gwarray;

	hr = IWbemClassObject_Put(pclsObj, L"DefaultIPGateway", 0, &varGWaddr, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed gateway IP address in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	metric_list = SafeArrayCreateVector(VT_UI1, 0, 1);
	SafeArrayPutElement(metric_list, index, &metric);

	varMetric.vt = VT_ARRAY | VT_UI1;
	varMetric.parray = metric_list;

	hr = IWbemClassObject_Put(pclsObj, L"GatewayCostMetric", 0, &varMetric, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to embed gateway cost metric in object!\n");
		retval = XEMALLOC;
		goto done;
	}

	hr = IWbemServices_ExecMethod(wmiSvc, IntPath, MethodName, 0, NULL, pclsObj, 
		&outdata, NULL);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to execute 'SetGateways' method!\n");
		retval = -1;
		goto done;
	}

    hr = IWbemClassObject_Get(outdata, L"ReturnValue", 0, 
        &varReturnValue, NULL, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get 'ReturnValue'.\n");
		retval = -1;
		goto done;
	}

	debug_printf(DEBUG_INT, "Return value : %d\n", varReturnValue.intVal);
	retval = varReturnValue.intVal;

done:
	// Clean up.
	if (pclsObj) IWbemClassObject_Release(pclsObj);
	if (pClassInstance) IWbemClassObject_Release(pClassInstance);
	if (inobj) IWbemClassObject_Release(inobj);
	if (outdata) IWbemClassObject_Release(outdata);

	if (gwarray) cardif_windows_wmi_destroy_safearray(&gwarray);
	if (metric_list) cardif_windows_wmi_destroy_safearray(&metric_list);

	if (MethodName) SysFreeString(MethodName);
	if (IntPath) SysFreeString(IntPath);
	if (ClassName) SysFreeString(ClassName);

	return retval;
}

#ifdef WINDOWS_USE_WMI
/**
 * \brief Determine the system uptime in seconds.
 *
 * @param[out] uptime   A 64 bit number that indicates the uptime of the system in seconds.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int cardif_windows_wmi_get_uptime(uint64_t *uptime)
{
	HRESULT hr;
	VARIANT vtProp;
	IWbemClassObject *pclsObj = NULL;
	IEnumWbemClassObject *pEnumerator = NULL;
	ULONG uReturn;
	char *rettime = NULL;

	if (WMIConnected == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine the system's uptime.  The time this connection has been connected will be unavailable.\n");
		return -1;
	}

	if (wmiSvc == NULL)
	{
		debug_printf(DEBUG_NORMAL, "WMI claimed to be connected, but the WMI service handle was NULL.  The time this connection has been connected will be unavailable.\n");
		return -1;
	}

    hr = IWbemServices_ExecQuery(wmiSvc,
        L"WQL", L"SELECT SystemUpTime FROM Win32_PerfFormattedData_PerfOS_System",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);

	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to get the system uptime from WMI!\n");
		return -1;
	}

    while (IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, 
         &pclsObj, &uReturn) != WBEM_S_FALSE)
	{
	    if(0 == uReturn)
	   {
			debug_printf(DEBUG_NORMAL, "Couldn't build enumerator needed to get array data!\n");
	     // Clean up and return nothing.
			IWbemClassObject_Release(pEnumerator);
			return -1;
		}

		// We should have a pointer to what we need to know now.  So, get the data.
		hr = IWbemClassObject_Get(pclsObj, L"SystemUpTime", 0, &vtProp, 0, 0);
		if (!FAILED(hr))
		{
			rettime = uni_to_ascii(vtProp.bstrVal);
			(*uptime) = _atoi64(rettime);
			FREE(rettime);
			break;
		}
		
	}

	
	// Clean up.
	IWbemClassObject_Release(pEnumerator);
	VariantClear(&vtProp);
	IWbemClassObject_Release(pclsObj);

	return 0;
}
#endif

/**
 * \brief Determine if DHCP is enabled.
 *
 * @param[in] ctx   The context for the interface that we are checking DHCP state
 *					on.
 * @param[in] enstate   A TRUE/FALSE value that indicates if DHCP is in use.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int cardif_windows_wmi_get_dhcp_enabled(context *ctx, int *enstate)
{
	struct win_sock_data *sockData = NULL;
	HRESULT hr;
	wchar_t *adapt_select = NULL;
	VARIANT vtProp;
	IWbemClassObject *pclsObj = NULL;
	IEnumWbemClassObject *pEnumerator = NULL;
	ULONG uReturn;
	BSTR HUGEP *pbstr = NULL;
	wchar_t *retval = NULL;

	(*enstate) = FALSE;   // Worst case, we want DHCP enabled and we go through the process of enabling it.

	sockData = (struct win_sock_data *)ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get socket data for context '%s'!?\n", 
			ctx->intName);
		return -1;
	}

	if (sockData->wmiIntIdx == INVALID_WMI_IDX)
	{
		// We don't know the index, so locate it.
		if (cardif_windows_wmi_get_idx(ctx, NULL) != XENONE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine WMI interface index in %s()!\n",
					__FUNCTION__);
			return -1;
		}
	}

	// We should know everything we need to locate the IP address for this interface.
	// Request information about ALL of the interfaces known to Windows.
	adapt_select = Malloc(512);
	if (adapt_select == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store adapter select string!\n");
		return -1;
	}

	swprintf(adapt_select, L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = %d", sockData->wmiIntIdx);

    hr = IWbemServices_ExecQuery(wmiSvc,
        L"WQL", adapt_select,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);

	FREE(adapt_select);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Failed to locate the WMI configuration block for interface "
				"'%s'!\n", ctx->intName);

        if(pEnumerator != NULL)
        {
		    IWbemClassObject_Release(pEnumerator);
        }

		return -1;
	}

    hr = IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, 
         &pclsObj, &uReturn);

    if(0 == uReturn)
    {
		debug_printf(DEBUG_NORMAL, "Couldn't build enumerator needed to get array data!\n");

        // Clean up and return nothing.
        if(pEnumerator != NULL)
        {
		    IWbemClassObject_Release(pEnumerator);
        }

		return -1;
    }

	// We should have a pointer to what we need to know now.  So, get the data.
	hr = IWbemClassObject_Get(pclsObj, L"DHCPEnabled", 0, &vtProp, 0, 0);
	if (FAILED(hr))
	{
		debug_printf(DEBUG_NORMAL, "Couldn't determine array data via WMI query!\n");

        if(pEnumerator != NULL)
        {
		    IWbemClassObject_Release(pEnumerator);
        }

		VariantClear(&vtProp);

        if(pclsObj)
        {
		    IWbemClassObject_Release(pclsObj);
        }
		return -1;
	}

	if (vtProp.bVal == 0xff)   // MS's version of a bool for C is a byte that is 0xff.
	{
		(*enstate) = TRUE;
	}
	else
	{
		(*enstate) = FALSE;
	}

	if(pEnumerator != NULL)
	  {
	    IWbemClassObject_Release(pEnumerator);
	  }

	if(pclsObj != NULL)
	  {
            IWbemClassObject_Release(pclsObj);
	  }

	return 0;
}
