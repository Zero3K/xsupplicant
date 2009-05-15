/**
*
* Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
*
* \file cardif_windows_events.c
*
* \author chris@open1x.org
*
**/  

#include <windows.h>
#include <iphlpapi.h>
#include <process.h>
#include <dbt.h>
#include <devguid.h>
#include <setupapi.h>

#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../cardif.h"
#include "cardif_windows.h"
#include "cardif_windows_wmi.h"
#include "../../event_core_win.h"
#include "../../ipc_events_index.h"
#include "../../eap_sm.h"
#include "../../error_prequeue.h"
#include "win_ip_manip.h"
#include "../../timer.h"
#include "../../wireless_sm.h"

#include <NtDDNdis.h>

// The nuiouser.h file is included with the Windows DDK.  Please 
// download the DDK and copy the file to the proper location.
#include "../../../vs2005/ndis_proto_driver/nuiouser.h"

///< A define for the DHCP release/renew calls.
#define TCPIP_DEVICE_PATH        "\\DEVICE\\TCPIP_"

///< Status values that we want to know about.  (Taken from ndis.h)
#define NDIS_STATUS_MEDIA_CONNECT						((NDIS_STATUS)0x4001000BL)
#define NDIS_STATUS_MEDIA_DISCONNECT					((NDIS_STATUS)0x4001000CL)
#define NDIS_STATUS_DOT11_SCAN_CONFIRM					((NDIS_STATUS)0x40030000L)
#define NDIS_STATUS_DOT11_DISASSOCIATION				((NDIS_STATUS)0x40030008L)
#define NDIS_STATUS_LINK_STATE							((NDIS_STATUS)0x40010017L)
#define NDIS_STATUS_DOT11_LINK_QUALITY                  ((NDIS_STATUS)0x4003000CL)

// The amount of time to wait between bind attempts.
#define REBIND_ATTEMPT_INTERVAL                          5
#define REBIND_ATTEMPTS									 3

// XXX ICK..  Do this better.
extern void (*imc_disconnect_callback) (uint32_t connectionID);


HANDLE ipupdate_handle = INVALID_HANDLE_VALUE;


int ipupdatecallback(context * ctx, HANDLE myhandle) 
{
	LPOVERLAPPED ovr = NULL;

	ipc_events_ui(ctx, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);

	ovr = event_core_get_ovr(myhandle, 0);

	// myhandle should NEVER change, so this is safe.
	NotifyAddrChange(&myhandle, ovr);

	return 0;
}


/**
* \brief Set up an event to trigger when an IP address changes.
**/ 
void cardif_windows_ip_update() 
{
	DWORD ret;
	LPOVERLAPPED ovr;
	HANDLE hand = INVALID_HANDLE_VALUE;

	ovr = Malloc(sizeof(OVERLAPPED));
	if (ovr == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Couldn't allocate memory for overlapped structure!\n");
		return;
	}

	ovr->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	ret = NotifyAddrChange(&ipupdate_handle, ovr);

	if ((ret != NO_ERROR) && (ret != ERROR_IO_PENDING))
	{
		debug_printf(DEBUG_NORMAL,
			"Can't establish IP address change notify handler.  Error was : %d\n",
			WSAGetLastError());
		return;
	}

	if (event_core_register(ipupdate_handle, NULL, &ipupdatecallback, 0, HIGH_PRIORITY,
		"IP address change event") != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to register IP address change handler.\n");
		return;
	}

	if (event_core_set_ovr(ipupdate_handle, 0, ovr) != TRUE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't set ovr!\n");
		return;
	}
}


/**
* \brief Properly deregister the IP update handle.
**/ 
void cardif_windows_ip_update_cleanup() 
{
	event_core_deregister(ipupdate_handle, 0);
} 

/**
* \brief Thread to delay connection of a wired interface for 1 second.
*
*  There are situations you can get in to with some switches when guest VLAN is enabled
*  where forwarding frames gets delayed.  Holding the authentication for 1 second seems
*  to work around this issue.
*
* @param[in] ctxptr   A pointer to the memory that contains the context we want to
*						activate.
**/ 
void cardif_windows_events_delay_link_up_thread(void *ctxptr) 
{
	context * ctx = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *) ctxptr;

	Sleep(1000);

	if (event_core_lock() != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain the event core lock.  Interface '%s' will miss it's link up event!\n",
			ctx->desc);
		_endthread();
		return;
	}

	debug_printf(DEBUG_INT, "Enabling wired port.\n");
	debug_printf(DEBUG_NORMAL, "Interface '%s' now has link.\n",
		ctx->desc);

	ctx->auths = 0;
	ctx->statemachine->to_authenticated = 0;
	SET_FLAG(ctx->flags, DHCP_RELEASE_RENEW);

	// Reset the EAP state machine.
	eap_sm_force_init(ctx->eap_state);

	ctx->eap_state->portEnabled = TRUE;
	ctx->statemachine->portEnabled = TRUE;

	if (event_core_unlock() != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to release the event core lock!  Bad stuff will happen!\n");
	}

	_endthread();
}


/**
* \brief Verify that the SSID change we just got is one that was expected.  If it wasn't drop the connection and
*			send the UI a message.
*
* @param[in] ctx   The context for the interface we want to check the status on.
* @param[in] ssid   The SSID that we just hopped to.  (Can be NULL)
**/ 
void cardif_windows_check_unexpected_change(context * ctx, char *ssid) 
{
	wireless_ctx * wctx = NULL;

	if (!TEST_FLAG(ctx->flags, INT_IGNORE))
	{
		if ((ctx->conn == NULL)	|| ((ssid != NULL) && (strcmp(ctx->conn->ssid, ssid) != 0)))
		{
			debug_printf(DEBUG_NORMAL,
				"XSupplicant has detected a change in SSIDs that was unexpected.  Another supplicant or manager might be running!\n");

			// We need to change our state so that we don't attempt to take the authentication farther, BUT
			// we can't use our normal disconnect routine since we don't want to disconnect the association,
			// we just want to go silent.

			// If we have a connection bound, let the UI know we are dumpping it.
			if (ctx->conn != NULL)
			{
				ipc_events_ui(NULL,
					IPC_EVENT_CONNECTION_UNBOUND,
					ctx->conn->name);

				ctx->conn = NULL;
				FREE(ctx->conn_name);
				ctx->prof = NULL;

				if (ctx->intType == ETH_802_11_INT)
				{
					if (ctx->intTypeData != NULL)
					{
						wctx = (wireless_ctx *) ctx->intTypeData;

						FREE(wctx->cur_essid);
					}
				}
			}

			ipc_events_ui(NULL,
				IPC_EVENT_OTHER_SUPPLICANT_POSSIBLE,
				ctx->desc);
		}
	}
}


/**
*  \brief Process the connect event that is passed up from the protocol driver.
*
*  There is no need to pass in any information from the protocol driver because the
*  indication that comes up has no parameters.  If this changes in the future, then
*  the parameters to this call may change.
*
*  @param[in] ctx   The context for the interface that had this event generated.
**/ 
void cardif_windows_int_event_connect(context * ctx) 
{
	wireless_ctx * wctx = NULL;
	uint8_t bssid[6];
	char ssid[34];
	int ssidsize = 34;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	debug_printf(DEBUG_INT,	"!!!!!!!!!!!!!!!!!!!! Connect Event !!!!!!!!!!!!!!!!!!!!!\n");
	debug_printf(DEBUG_INT, "    Device : %s\n", ctx->desc);

	// Send event.
	ipc_events_ui(NULL, IPC_EVENT_UI_LINK_UP, ctx->desc);

	if (ctx->intType == ETH_802_11_INT)
	{
		wctx = (wireless_ctx *) ctx->intTypeData;
		if (wctx == NULL)
		{
			debug_printf(DEBUG_NORMAL,
				"Interface %s claims to be wireless, but doesn't "
				"have a wireless context!?\n",
				ctx->intName);
			return;
		}

		// Clear this flag if it is still hanging around for some reason.
		UNSET_FLAG(wctx->flags, WIRELESS_SM_DISCONNECT_REQ);
		timer_cancel(ctx, CONN_DEATH_TIMER);

		if (cardif_windows_wireless_get_bssid(ctx, &bssid) != 0)
		{
			debug_printf(DEBUG_NORMAL,
				"Unable to get BSSID for interface '%s'.\n",
				ctx->desc);

			ctx->auths = 0;	// Reset the number of authentications this interface has done.
		}
		else
		{
			if (cardif_windows_wireless_get_ssid(ctx, &ssid, ssidsize) != 0)
			{
				debug_printf(DEBUG_NORMAL,
					"Interface '%s' assocated to the AP with BSSID %02X:%02X:%02X:%02X:%02X:%02X\n",
					ctx->desc, bssid[0], bssid[1],
					bssid[2], bssid[3], bssid[4],
					bssid[5]);
			}
			else
			{
				debug_printf(DEBUG_NORMAL,
					"Interface '%s' assocated to the SSID '%s' with BSSID %02X:%02X:%02X:%02X:%02X:%02X\n",
					ctx->desc, ssid, bssid[0],
					bssid[1], bssid[2], bssid[3],
					bssid[4], bssid[5]);

				cardif_windows_check_unexpected_change(ctx,	ssid);
			}

			if ((wctx->cur_essid != NULL) && (strcmp(ssid, wctx->cur_essid) != 0))
			{
				// We hopped to a new SSID.  Reset our counters.
				ctx->auths = 0;

				if (ctx->statemachine != NULL)
					ctx->statemachine->to_authenticated = 0;

				SET_FLAG(ctx->flags, DHCP_RELEASE_RENEW);
			}

			// Set our new destination.
			memcpy(ctx->dest_mac, bssid, 6);
		}

		memset(&wctx->replay_counter, 0x00, 8);
		wireless_sm_change_state(ASSOCIATED, ctx);
		ctx->eap_state->reqId = 0xff;
		ctx->eap_state->lastId = 0xff;

		if ((ctx->conn != NULL)	&& (ctx->conn->association.auth_type == AUTH_PSK))
		{
			SET_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK);
		}

		ctx->eap_state->portEnabled = TRUE;
		ctx->statemachine->portEnabled = TRUE;
	}
	else
	{
		_beginthread(cardif_windows_events_delay_link_up_thread, 0,	ctx);
	}
}


/**
* \brief Fire an event to the UI to let it know to ask the user if they want to search for a different network.
**/ 
void cardif_windows_int_disconnect_prompt(context * ctx) 
{
	ipc_events_ui(ctx, IPC_EVENT_UI_POST_CONNECT_TIMEOUT, ctx->intName);

	timer_cancel(ctx, CONN_DEATH_TIMER);

	// By this point, if we have not aged out the scan data from the cache, it
	// will go soon.  So call disassociate so that when/if the SSID comes back,
	// we don't associate until we know enough to actually do it.
	cardif_disassociate(ctx, 1);
} 


/**
* \brief  Handle a disconnect event that has been generated by a protocol driver indication.
*
* @param[in] ctx   The context for the interface that generated this event.
**/ 
void cardif_windows_int_event_disconnect(context * ctx) 
{
	wireless_ctx * wctx = NULL;
	char bssid_dest[6];
	char dot1x_default_dest[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
	config_globals * globals = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	debug_printf(DEBUG_INT,	"!!!!!!!!!!!!!!!!!!!! Disconnect Event !!!!!!!!!!!!!!!!!!!!!\n");
	debug_printf(DEBUG_INT, "    Device : %s\n", ctx->desc);

	if ((ctx->intType == ETH_802_11_INT) && (cardif_GetBSSID(ctx, (char *)&bssid_dest) == XENONE))
	{
		if (memcmp(ctx->dest_mac, &bssid_dest, 6) == 0)
		{
			debug_printf(DEBUG_INT,
				"Interface '%s' sent us a disconnect event, but an IOCTL check claims we are still connected!  Discarding!\n");
			return;
		}
	}

	// Send event.
	ipc_events_ui(NULL, IPC_EVENT_UI_LINK_DOWN, ctx->desc);

	ctx->auths = 0;	// Reset the number of authentications this interface has done.

	if (ctx->intType == ETH_802_11_INT)
	{
		wctx = (wireless_ctx *) ctx->intTypeData;
		if (wctx == NULL)
		{
			debug_printf(DEBUG_NORMAL,
				"Interface %s claims to be wireless, but doesn't "
				"have a wireless context!?\n",
				ctx->intName);
			return;
		}

		memset(ctx->dest_mac, 0x00, sizeof(ctx->dest_mac));
		wireless_sm_change_state(UNASSOCIATED, ctx);

		if (TEST_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK))
		{
			ipc_events_ui(ctx, IPC_EVENT_BAD_PSK, ctx->intName);

			// We sent the error so unset the flag.
			UNSET_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK);
			timer_cancel(ctx, PSK_DEATH_TIMER);
		}
		else
		{
			globals = config_get_globals();

			// See if we need to set up a time out timer.
			if (!TEST_FLAG(wctx->flags, WIRELESS_SM_DISCONNECT_REQ))
			{
				timer_add_timer(ctx, CONN_DEATH_TIMER,
					globals->dead_connection_timeout, NULL,
					cardif_windows_int_disconnect_prompt);
			}
		}
	}
	else
	{
		debug_printf(DEBUG_NORMAL,
			"Interface '%s' no longer has link.\n",
			ctx->desc);
		memcpy(&ctx->dest_mac[0], &dot1x_default_dest[0], 6);
		ctx->statemachine->to_authenticated = 0;

#ifdef HAVE_TNC
		// Flush TNC state.
		if (ctx->tnc_data != NULL) {
			if (imc_disconnect_callback != NULL)
				imc_disconnect_callback(ctx->tnc_data->connectionID);

			libtnc_tncc_DeleteConnection(ctx->tnc_data);

			ctx->tnc_data = NULL;
		}
#endif	
	}

	cardif_windows_wireless_set_operstate(ctx, XIF_OPER_LOWERLAYERDOWN);

	// We dropped our connection, so we want to reset our state machines.
	ctx->statemachine->initialize = TRUE;
	ctx->eap_state->eapRestart = TRUE;

	ctx->eap_state->portEnabled = FALSE;
	ctx->statemachine->portEnabled = FALSE;
}


/**
* \brief Return a string that identifies the reason code from Clause 7.3.1.7 of the IEEE 802.11-1999 
*        standard.
*
* @param[in] reason   The reason code that we want to translate in to a string.
*
* \retval NULL on failure, a reason string on success.
**/ 
char *cardif_windows_int_get_802_11_reason(ULONG reason) 
{
	switch (reason)
	{
	case 0:
	case 1:
		return _strdup("Unspecified Reason");
		break;

	case 2:
		return _strdup("Previous authentication no longer valid");
		break;

	case 3:
		return _strdup("Deauthenticated because sending STA is leaving (or has left) the network");
		break;

	case 4:
		return _strdup("Disassociated due to inactivity");
		break;

	case 5:
		return _strdup("Disassociated because AP is unable to handle all currently associated STAs");
		break;

	case 6:
		return _strdup("Class 2 frame received from nonauthenticated STA");
		break;

	case 7:
		return _strdup("Class 3 frame received from nonassociated STA");
		break;

	case 8:
		return _strdup("Disassociated because sending STA is leaving (or has left) the network");
		break;

	case 9:
		return _strdup("STA requresting (re)association is not authenticated with responding STA");
		break;

	case 10:
		return _strdup("Disassociated because the information in the Power Capability element is unacceptable");
		break;

	case 11:
		return _strdup("Disassociated because information in the Supported Channels element is unacceptible");
		break;

		// 12 is reserved
	case 13:
		return _strdup("Invalid information element");
		break;

	case 14:
		return _strdup("Message integrity code (MIC) failure");
		break;

	case 15:
		return _strdup("4-Way handshake timeout");
		break;

	case 16:
		return _strdup("Group key handshake timeout");
		break;

	case 17:
		return _strdup("Information element in 4-way handshake is different from (re)association request/probe response/beacon frame");
		break;

	case 18:
		return _strdup("Invalid group cipher");
		break;

	case 19:
		return _strdup("Invalid pairwise cipher");
		break;

	case 20:
		return _strdup("Invalid authenticated key management protocol (AKMP)");
		break;

	case 21:
		return _strdup("Unsupported RSN information element version");
		break;

	case 22:
		return _strdup("Invalid RSN information element capabilities");
		break;

	case 23:
		return _strdup("IEEE 802.1X authentication failed");
		break;

	case 24:
		return _strdup("Cipher suite rejected because of security policy");
		break;

		//25-31 reserved
	case 32:
		return _strdup("Disassociated for unspecified, QoS-related reason");
		break;

	case 33:
		return _strdup("Disassocaited because QoS AP lacks sufficient bandwidth for this QoS STA");
		break;

	case 34:
		return _strdup("Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions");
		break;

	case 35:
		return _strdup("Disassociated because STA is transmitting outside the limits of its TXOPs");
		break;

	case 36:
		return _strdup("Requested from peer STA as the STA is leaving the network (or resetting)");
		break;

	case 37:
		return _strdup("Requested from peer STA as it does not want to use the mechanism");
		break;

	case 38:
		return _strdup("Requested from peer STA as the STA received frames using the mechanism from which a setup is required");
		break;

	case 39:
		return _strdup("Requested from peer STA due to timeout");
		break;

	case 45:
		return _strdup("Peer STA does not support the requested cipher suite");
		break;
	}

	return _strdup("Unknown, or new reason code");
}


/**
* \brief Parse the data provided in a disassociate message, and add it to the log.
*
* @param[in] ctx   The context for the interface that the event was generated for.
* @param[in] eventdata   The entire set of data that came along with the indication from
*                        the protocol driver.
* @param[in] evtSize   The size of the data that \ref eventdata points to.
**/ 
void cardif_windows_int_event_disassociate(context * ctx, uint8_t * eventdata,
										   DWORD evtSize) 
{
	PNDISPROT_INDICATE_STATUS pStat = NULL;
	PDOT11_DISASSOCIATION_PARAMETERS pDis = NULL;
	ULONG reason = 0;
	char *reason_str = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((eventdata != NULL), "eventdata != NULL", FALSE))
		return;

	pStat = (PNDISPROT_INDICATE_STATUS) eventdata;
	pDis = (PDOT11_DISASSOCIATION_PARAMETERS) &eventdata[pStat->StatusBufferOffset];

	switch (pDis->uReason)
	{
	case DOT11_ASSOC_STATUS_SUCCESS:
		// Do nothing.
		break;

	case DOT11_ASSOC_STATUS_FAILURE:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated due to an interal driver error.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_ROAMING_ASSOCIATION_LOST:
	case DOT11_ASSOC_STATUS_UNREACHABLE:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated because the AP is no longer reachable.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_RADIO_OFF:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated because the local radio was turned off.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_PHY_DISABLED:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated because the hardware was disabled.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_DISASSOCIATED_BY_RESET:
	case DOT11_ASSOC_STATUS_CANCELLED:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated because the hardware was reset.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_CANDIDATE_LIST_EXHAUSTED:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated because there was no APs available to roam to.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_DISASSOCIATED_BY_OS:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated by request of the OS or driver.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_DISASSOCIATED_BY_ROAMING:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated in order to roam to a new AP.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_ROAMING_BETTER_AP_FOUND:
		debug_printf(DEBUG_NORMAL,
			"%s disassociated because a better AP was found.\n",
			ctx->desc);
		break;

	case DOT11_ASSOC_STATUS_ROAMING_ADHOC:
		debug_printf(DEBUG_NORMAL,
			"%s is roaming to a new ad-hoc network.\n",
			ctx->desc);
		break;

	default:
		// These reasons have reason codes appended to them.
		if (pDis->uReason & DOT11_ASSOC_STATUS_PEER_DEAUTHENTICATED)
		{
			reason &= (~DOT11_ASSOC_STATUS_PEER_DEAUTHENTICATED);
			reason_str = cardif_windows_int_get_802_11_reason(reason);

			debug_printf(DEBUG_NORMAL,
				"%s was deauthenticated from the AP.  (Reason : %s)\n",
				ctx->desc, reason_str);
			FREE(reason_str);
			break;
		}

		if (pDis->uReason & DOT11_ASSOC_STATUS_PEER_DISASSOCIATED)
		{
			reason &= (~DOT11_ASSOC_STATUS_PEER_DISASSOCIATED);
			reason_str = cardif_windows_int_get_802_11_reason(reason);

			debug_printf(DEBUG_NORMAL,
				"%s was disassociated from the AP.  (Reason : %s)\n",
				ctx->desc, reason_str);
			FREE(reason_str);
			break;
		}

		if (pDis->uReason & DOT11_ASSOC_STATUS_ASSOCIATION_RESPONSE)
		{
			reason &= (~DOT11_ASSOC_STATUS_ASSOCIATION_RESPONSE);
			reason_str = cardif_windows_int_get_802_11_reason(reason);

			debug_printf(DEBUG_NORMAL,
				"%s got an association response.  (Reason : %s)\n",
				ctx->desc, reason_str);
			FREE(reason_str);
			break;
		}

		debug_printf(DEBUG_NORMAL,
			"%s was disassociated for an unknown reason.\n",
			ctx->desc);
		break;
	}
}


/**
* \brief Parse a driver link quality event, and pass the event up to any connected
*        UIs.
*
* @param[in] ctx   The context for the interface that the link quality event came in on.
* @param[in] eventdata   The raw event data that came up from the OS.
* @param[in] evtSize   The size of the data pointed to by 'eventdata'.
**/ 
void cardif_windows_int_event_link_quality(context * ctx, uint8_t * eventdata,
										   DWORD evtSize) 
{
	PNDISPROT_INDICATE_STATUS pStat = NULL;
	PDOT11_LINK_QUALITY_PARAMETERS pParams = NULL;
	PDOT11_LINK_QUALITY_ENTRY pEntry = NULL;
	uint16_t i = 0;
	char temp[10];
	wireless_ctx * wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((eventdata != NULL), "eventdata != NULL", FALSE))
		return;

	if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
		return;

	if (!xsup_assert((ctx->intType == ETH_802_11_INT),
		"ctx->intType == ETH_802_11_INT", FALSE))
		return;

	pStat = (PNDISPROT_INDICATE_STATUS) eventdata;

	pParams = (PDOT11_LINK_QUALITY_PARAMETERS) &eventdata[pStat->StatusBufferOffset];

	pEntry = (PDOT11_LINK_QUALITY_ENTRY)&eventdata[pParams->uLinkQualityListOffset +
		pStat->StatusBufferOffset];

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (timer_check_existing(ctx, SIG_STRENGTH) == TRUE)
	{
		debug_printf(DEBUG_INT,
			"Canceling signal strength polling timer, since we are getting events.\n");

		timer_cancel(ctx, SIG_STRENGTH);
	}

	if (pParams->uLinkQualityListSize == 1)
	{
		// We don't care what the Peer MAC is, because the signal strength should be valid.
		//  NOTE : In some cases, the Peer MAC will be all 0s when only one entry is defined.
		//          (This is true on the Intel 3945ABG card at a minimum.)
		sprintf((char *)&temp, "%d", pEntry[0].ucLinkQuality);

		ipc_events_ui(ctx, IPC_EVENT_SIGNAL_STRENGTH, temp);

		wctx->strength = pEntry[0].ucLinkQuality;
		return;
	}
	else
	{
		for (i = 0; i < (pParams->uLinkQualityListSize / sizeof(DOT11_LINK_QUALITY_ENTRY)); i++)
		{
			if (memcmp(pEntry[i].PeerMacAddr, ctx->dest_mac, 6) == 0)
			{
				sprintf((char *)&temp, "%d",
					pEntry[i].ucLinkQuality);

				ipc_events_ui(ctx, IPC_EVENT_SIGNAL_STRENGTH,
					temp);

				wctx->strength = pEntry[i].ucLinkQuality;
				return;
			}
		}
	}

	debug_printf(DEBUG_INT, "Unable to determine the link quality!\n");
}


/**
* \brief Process a "scan confirm" event.  This event is sent by the driver to indicate
*        that a scan has completed.  We need to signal the wireless state machine that the
*        scan is complete, and let it move on.
*
* @param[in] ctx   The context for the interface that the scan completed on.
**/ 
void cardif_windows_int_event_scan_confirm(context * ctx) 
{
	wireless_ctx * wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((ctx->intType == ETH_802_11_INT),
		"ctx->intType == ETH_802_11_INT", FALSE))
		return;

	if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
		return;

	wctx = (wireless_ctx *) ctx->intTypeData;

	debug_printf(DEBUG_INT, "Got a scan complete event on %s!\n",
		ctx->desc);

	// Depending on what state we are in, we may want to handle things slightly differently.
	// If we are associated, then this scan event may be used to generate OKC data.  If we
	// aren't associated, then we need to just call the regular scan timeout.
	if (wctx->state == ASSOCIATED)
	{
		if (timer_check_existing(ctx, PASSIVE_SCAN_TIMER) == TRUE)
		{
			debug_printf(DEBUG_INT,
				"Canceling passive scan poll timer since we are getting events.\n");
			timer_cancel(ctx, PASSIVE_SCAN_TIMER);
		}

		cardif_windows_wireless_xp_passive(ctx);
	}
	else
	{
		cardif_windows_wireless_scan_timeout(ctx);
	}
}


/**
* \brief Look at the event that the protocol driver generated, and determine what to do
*		  with it.
*
* @param[in] ctx   The context for the interface that the event was generated for.
* @param[in] eventdata   The entire set of data that came along with the indication from
*                        the protocol driver.
* @param[in] evtSize   The size of the data that \ref eventdata points to.
**/ 
void cardif_windows_int_event_process(context * ctx, uint8_t * eventdata,
									  DWORD evtSize) 
{
	PNDISPROT_INDICATE_STATUS pStat = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((eventdata != NULL), "eventdata != NULL", FALSE))
		return;

	pStat = (PNDISPROT_INDICATE_STATUS) eventdata;

	switch (pStat->IndicatedStatus)
	{
	case NDIS_STATUS_MEDIA_CONNECT:
		cardif_windows_int_event_connect(ctx);
		break;

	case NDIS_STATUS_DOT11_DISASSOCIATION:
		// Process the disassocate message for logging purposes.
		//cardif_windows_int_event_disassociate(ctx, eventdata, evtSize);
		// Do any necessary state machine disconnection stuff.
		//cardif_windows_int_event_disconnect(ctx);
		break;

	case NDIS_STATUS_MEDIA_DISCONNECT:
		cardif_windows_int_event_disconnect(ctx);
		break;

	case NDIS_STATUS_DOT11_SCAN_CONFIRM:
		cardif_windows_int_event_scan_confirm(ctx);
		break;

	case NDIS_STATUS_DOT11_LINK_QUALITY:
		// We need to work with this event more.  It will keep us from polling like we currently do!
		debug_printf(DEBUG_INT,
			"Link quality indication on '%s'.\n",
			ctx->desc);
		cardif_windows_int_event_link_quality(ctx, eventdata, evtSize);
		break;

	default:
		debug_printf(DEBUG_INT, "Unknown NDIS indication : 0x%x\n",
			pStat->IndicatedStatus);
		break;
	}
}


/**
* \brief This callback is called whenever an event is triggered on the
*        protocol indication IOCTL.
*
*  This function should dispatch the event that came in, and then issue a new
*  IOCTL so that we get the next event in the queue.  One thing that is worth
*  noting is that the underlying protocol driver doesn't actually queue events.  So,
*  if an event happens while we are busy processing the current one, we WILL miss
*  it!  Because of this, event processing should be as quick as possible, and the
*  protocol driver should filter out events we don't care to get so we aren't processing
*  garbage events.
*
* @param[in] ctx   The context for the interface that generated the event.
* @param[in] evtHandle   The handle that was signaled to indicate that a new event was ready.
**/ 
int cardif_windows_int_event_callback(context * ctx, HANDLE evtHandle) 
{
	LPOVERLAPPED ovr = NULL;
	struct win_sock_data *sockData = NULL;
	DWORD ret = 0;
	uint8_t mydata[1500];
	DWORD dataSize = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (event_core_is_terminating() == TRUE)
	{
		// Discard the event.  The buffer may already be freed.
		return -1;
	}

	sockData = (struct win_sock_data *)ctx->sockData;

	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No valid socket data in %s()!\n",
			__FUNCTION__);
		return -1;
	}

	debug_printf(DEBUG_INT, "Got an interface event on interface '%s'!\n",
		ctx->desc);
	debug_hex_dump(DEBUG_INT, sockData->eventdata, sockData->evtSize);

	dataSize = sockData->evtSize;
	memcpy(&mydata[0], sockData->eventdata, dataSize);

	ovr = event_core_get_ovr(evtHandle, EVENT_SECONDARY);

	SetLastError(0);

	// This IOCTL waits until something happens.  So the completion status returned is only
	// an indication of if the IOCTL was recevied by the driver or not.
	if (!DeviceIoControl(sockData->devHandle, IOCTL_NDISPROT_INDICATE_STATUS, NULL, 0,
		sockData->eventdata, 1500, NULL, ovr))
	{
		ret = GetLastError();
		if (ret != ERROR_IO_PENDING)
		{
			if (ret != ERROR_BUSY)
			{
				debug_printf(DEBUG_NORMAL,
					"Error requesting status indications from interface '%s'.  (Error %d)\n",
					ctx->desc, ret);
			}

			return -1;
		}
	}

	//  Process the event we got.  This should work fine for the current situation where we should only
	//  ever have two events outstanding at any one time.  By processing the event last, the window for
	//  missing events is pretty small.  If we ever believe that we will have three or more events outstanding
	//  then we should try threading the event processing function.  Otherwise, we will have to queue
	//  in the driver, and that isn't fun.
	cardif_windows_int_event_process(ctx, mydata, dataSize);

	return 0;
}


/**
* \brief Issue an IOCTL so that when an event happens on an interface it is triggered,
*        and dealt with.
**/ 
void cardif_windows_setup_int_events(context * ctx) 
{
	DWORD ret = 0;
	LPOVERLAPPED ovr = NULL;
	HANDLE hand = INVALID_HANDLE_VALUE;
	struct win_sock_data *sockData = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (event_core_is_terminating() == TRUE)
		return;		// This should never happen, but better to be safe.

	debug_printf(DEBUG_INT, "Binding event IOCTL to interface '%s'.\n",
		ctx->desc);

	ovr = Malloc(sizeof(OVERLAPPED));
	if (ovr == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Couldn't allocate memory for overlapped structure!\n");
		return;
	}

	ovr->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	debug_printf(DEBUG_INT, "Created event handle %d.\n", ovr->hEvent);

	sockData = (struct win_sock_data *)ctx->sockData;

	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No valid socket data in %s()!\n",
			__FUNCTION__);
		return;
	}

	sockData->eventdata = Malloc(1500);	// Should be enough?
	if (sockData->eventdata == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory to store event data for interface %s!\n",
			ctx->desc);
		return;
	}

	if (event_core_register(sockData->devHandle, ctx, &cardif_windows_int_event_callback,
		EVENT_SECONDARY, HIGH_PRIORITY,
		"Interface status event callback") != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to register interface event handler for interface '%s'.\n",
			ctx->desc);
		return;
	}

	if (event_core_set_ovr(sockData->devHandle, EVENT_SECONDARY, ovr) != TRUE)
	{
		debug_printf(DEBUG_NORMAL,
			"Couldn't bind handle to overlapped structure for interface '%s'!\n",
			ctx->desc);
		return;
	}

	SetLastError(0);

	// This IOCTL waits until something happens.  So the completion status returned is only
	// an indication of if the IOCTL was recevied by the driver or not.
	if (!DeviceIoControl(sockData->devHandle, IOCTL_NDISPROT_INDICATE_STATUS, NULL, 0,
		sockData->eventdata, 1500, NULL, ovr))
	{
		ret = GetLastError();
		if (ret != ERROR_IO_PENDING)
		{
			debug_printf(DEBUG_NORMAL,
				"Error requesting status indications from interface '%s'.  (Error %d)\n",
				ctx->desc, ret);
			return;
		}
	}
}



/**
* \brief Restart the IOCTL to get interface events.
**/ 
int cardif_windows_restart_int_events(context * ctx) 
{
	LPOVERLAPPED ovr = NULL;
	struct win_sock_data *sockData = NULL;
	DWORD ret = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No valid socket data in %s()!\n",
			__FUNCTION__);
		return -1;
	}

	ovr = event_core_get_ovr(sockData->devHandle, EVENT_SECONDARY);

	SetLastError(0);

	// This IOCTL waits until something happens.  So the completion status returned is only
	// an indication of if the IOCTL was recevied by the driver or not.
	if (!DeviceIoControl(sockData->devHandle, IOCTL_NDISPROT_INDICATE_STATUS, NULL, 0,
		sockData->eventdata, 1500, NULL, ovr))
	{
		ret = GetLastError();
		if (ret != ERROR_IO_PENDING)
		{
			debug_printf(DEBUG_NORMAL,
				"Error requesting status indications from interface '%s'.  (Error %d)\n",
				ctx->desc, ret);
			return -1;
		}
	}

	return 0;
}


void cardif_windows_events_set_bytes_rx(context * ctx, DWORD bytesrx) 
{
	struct win_sock_data *sockData = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to locate handle information for interface '%s'!\n",
			ctx->desc);
		return;
	}

	sockData->evtSize = bytesrx;
}


/**
* \brief Get the GUID piece of the interface name.
*
* @param[in] ctx   The context we want to get the GUID from.
*
* \retval NULL   An error occurred getting the GUID piece.
* \retval char*   A pointer to the GUID.  (Caller MUST free the memory!)
**/ 
char *cardif_windows_event_get_guid(context * ctx) 
{
	char *matchstr = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return NULL;

	if (!xsup_assert((ctx->intName != NULL), "ctx->intName != NULL", FALSE))
		return NULL;

	matchstr = strstr(ctx->intName, "{");
	if (matchstr == NULL)
		return NULL;	// It isn't there!?  This is BAD!
	return _strdup(matchstr);	// Return the GUID portion.
}


/**
* \brief Return the path to the IP device for the GUID. 
*
* @param[in] ctx   The context for the interface we want to convert.
*
* \retval NULL   on error
* \retval wchar_t*   that points to a string that can be used in IP release and renew calls.
**/ 
wchar_t * cardif_windows_events_get_ip_guid_str(context * ctx) 
{
	char *guid = NULL;
	char *fullpath = NULL;
	wchar_t * longpath = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return NULL;

	guid = cardif_windows_event_get_guid(ctx);

	fullpath = Malloc(strlen(guid) + strlen(TCPIP_DEVICE_PATH) + 2);

	if (fullpath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		free(guid);
		return NULL;
	}

	strcpy(fullpath, TCPIP_DEVICE_PATH);
	strcat(fullpath, guid);

	FREE(guid);		// We are done with it.

	longpath = Malloc((strlen(fullpath) + 2) * 2);
	if (longpath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate wchar_t * in %s()!\n",
			__FUNCTION__);

		return NULL;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fullpath, strlen(fullpath), longpath,
		((strlen(fullpath) + 2) * 2)) == 0)
	{
		FREE(fullpath);
		FREE(longpath);
		return NULL;
	}

	FREE(fullpath);	// We are done with it.
	return longpath;
}

/**
* \brief Determine if DHCP is enabled on an interface.
*
* @param[in] ctx   The context for the interface we want to check if DHCP is enabled on.
*
* \retval TRUE if it is enabled, FALSE if it isn't.
**/ 
int cardif_windows_events_is_dhcp_enabled(context * ctx) 
{
	ULONG size = 0;
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	PIP_ADAPTER_INFO pCur = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return TRUE;	// err on the side of caution.

	// First, determine how large of a buffer we need.
	size = 0;

	if (GetAdaptersInfo(NULL, &size) != ERROR_BUFFER_OVERFLOW)
	{
		// Ack!  Something really bad happened.  Assuming that DHCP is enabled (since it will be in the general case).
		return TRUE;
	}

	pAdapterInfo = (PIP_ADAPTER_INFO) Malloc(size);	// Allocate the memory we think we need.
	if (pAdapterInfo == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory to store adapter information!\n");

		return TRUE;
	}

	if (GetAdaptersInfo(pAdapterInfo, &size) != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain adapter info.  Assuming DHCP is enabled.\n");
		FREE(pAdapterInfo);
		return FALSE;
	}

	// Walk the list, looking for our data.
	pCur = pAdapterInfo;

	while ((pCur != NULL)
		&& (memcmp(pCur->Address, ctx->source_mac, 6) != 0))
	{
		pCur = pCur->Next;
	}

	if ((pCur != NULL)
		&& (memcmp(pCur->Address, ctx->source_mac, 6) == 0))
	{
		if (pCur->DhcpEnabled == 0)
		{
			FREE(pAdapterInfo);
			return FALSE;
		}

		FREE(pAdapterInfo);
		return TRUE;
	}

	FREE(pAdapterInfo);

	debug_printf(DEBUG_NORMAL,
		"Unable to locate DHCP status information for interface '%s'.\n",
		ctx->desc);

	return TRUE;		// This is the most likely value.
}

/**
* \brief Take the information we got from the Windows event, and convert it in
*        to a windows description.
*
* @param[in] dev   The string from the windows event that indicates which interface to work with.
* @param[in] live_only   Should we only be looking at interfaces that are currently on the machine?
*
* \retval NULL on failure
* \retval wchar_t* that points to the interface description.
**/ 
char *cardif_windows_events_get_interface_desc(wchar_t * dev, char live_only) 
{
	HDEVINFO mySDIClass;
	SP_DEVINFO_DATA myData;
	unsigned int i = 0;
	TCHAR myString[1024];
	PCTSTR path = "ROOT\\MS_PSCHEDMP";
	char *numberonly = NULL;
	DWORD whatToGet = 0;
	wchar_t deviceNumber[6];
	char shortNum[6];
	int done = FALSE;
	char *result = NULL;

	if (!xsup_assert((dev != NULL), "dev != NULL", FALSE))
		return NULL;

	if (live_only == TRUE)
	{
		whatToGet = DIGCF_ALLCLASSES | DIGCF_PRESENT;
	}
	else
	{
		whatToGet = DIGCF_ALLCLASSES;
	}

	debug_printf(DEBUG_INT, "Building SetupDi information!\n");

	mySDIClass = SetupDiGetClassDevs(NULL, path, NULL, whatToGet);

	if (INVALID_HANDLE_VALUE == mySDIClass)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine interface name using SetupDi calls!  (%d)\n",
			GetLastError());

		return NULL;
	}

	// Make sure to zero out the buffer first.  wcsncpy doesn't append a NULL!
	memset(&deviceNumber, 0x00, sizeof(deviceNumber));

	wcsncpy((wchar_t *) & deviceNumber,
		&dev[strlen("\\\\?\\Root#MS_PSCHEDMP#")], 4);

	debug_printf(DEBUG_INT, "Whole interface name : %ws\n", dev);
	debug_printf(DEBUG_INT, "Looking for interface instance : %ws\n",
		deviceNumber);

	memset(&shortNum, 0x00, sizeof(shortNum));

	sprintf(shortNum, "%ws", deviceNumber);

	myData.cbSize = sizeof(SP_DEVINFO_DATA);

	while (SetupDiEnumDeviceInfo(mySDIClass, i, &myData))
	{
		if (SetupDiGetDeviceInstanceId(mySDIClass, &myData, (PSTR) & myString, 1024, NULL))
		{
			numberonly = (char *)&myString[strlen(path) + 1];

			if (strcmp(numberonly, shortNum) == 0)
			{
				done = TRUE;	// We found what we wanted.
				if (SetupDiGetDeviceRegistryProperty(mySDIClass, &myData, SPDRP_FRIENDLYNAME,
					NULL, (PBYTE) & myString, 1024, NULL))
				{
					debug_printf(DEBUG_INT,
						"Found interface : %s\n",
						myString);
				}
				break;	// Jump out of the loop.
			}
		}

		i++;
	}

	SetupDiDestroyDeviceInfoList(mySDIClass);

	if (TRUE == done)
	{
		result = _strdup(myString);
		return result;
	}

	return NULL;
}


/**
* \brief An interface was removed, so figure out which one, and deactivate it.
*
* \note This function should *ONLY* be called when it is invoked as a thread!
*
* @param[in] devPtr   A void pointer that points to a wchar_t string that has our interface name.
**/ 
void cardif_windows_events_interface_removed(void *devPtr) 
{
	char *interfaceName = NULL;
	context * ctx = NULL;

	if (!xsup_assert((devPtr != NULL), "devPtr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	if (event_core_get_sleep_state() == TRUE)
	{
		debug_printf(DEBUG_INT,
			"Removal event for an interface when we are attempting to go to sleep.  Ignoring.\n");
		_endthread();
		return;
	}

	interfaceName =	cardif_windows_events_get_interface_desc((wchar_t *) devPtr, FALSE);

	if (interfaceName == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to locate information about the interface that was just removed!\n");
		_endthread();
		return;
	}

	if (event_core_lock() != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"!!!!! Unable to acquire event core lock!  Bad things will happen!\n");
	}

	// Try to delete the interface from the interface cache.
	// It is safe not to mutex this for now since the event core lock will protect pretty much everything.  But,
	// we may need to mutex it in the future!
	if (interfaces_delete(interfaceName) == TRUE)
	{
		debug_printf(DEBUG_NORMAL,
			"Removed device '%s' from our live interfaces list.\n",
			interfaceName);
	}

	ctx = event_core_locate_by_desc(interfaceName);

	if (ctx == NULL)
	{
		debug_printf(DEBUG_INT,
			"Couldn't locate a context for removal event. (Perhaps "
			"we aren't managing this interface?)\n");

		FREE(interfaceName);

		if (event_core_unlock() != 0)
		{
			debug_printf(DEBUG_INT, "Unlock failure at %s():%d\n",
				__FUNCTION__, __LINE__);
		}

		_endthread();
		return;
	}

	debug_printf(DEBUG_INT, "Interface is : %s\n", ctx->intName);

	ipc_events_ui(ctx, IPC_EVENT_INTERFACE_REMOVED, ctx->desc);

	debug_printf(DEBUG_NORMAL,
		"Interface '%s' was removed or disabled.\n", ctx->desc);

#ifdef HAVE_TNC
	// If we are using a TNC enabled build, signal the IMC to clean up.
	if (ctx->tnc_data != NULL) {
		if (imc_disconnect_callback != NULL)
			imc_disconnect_callback(ctx->tnc_data->connectionID);

		libtnc_tncc_DeleteConnection(ctx->tnc_data);

		ctx->tnc_data = NULL;
	}
#endif	

	ctx->flags |= INT_GONE;

	if ((ctx != NULL) && (ctx->statemachine != NULL))
		ctx->statemachine->portEnabled = FALSE;

	if ((ctx != NULL) && (ctx->eap_state != NULL))
		ctx->eap_state->portEnabled = FALSE;

	// Always deregister the secondary first!!
	event_core_deregister(((struct win_sock_data *)ctx->sockData)->devHandle, EVENT_SECONDARY);

	event_core_deregister(((struct win_sock_data *)ctx->sockData)->devHandle, EVENT_PRIMARY);

	FREE(interfaceName);

	if (event_core_unlock() != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"!!!!!! Unable to release the lock on the event core!  We will probably deadlock!\n");
	}

	_endthread();
}


/**
* \brief An interface was inserted, so figure out which one, and activate it.
*
* \note This function should *ONLY* be called when it is invoked as a thread!
*
* @param[in] devPtr   A void pointer that points to a wchar_t string that has our interface name.
**/ 
void cardif_windows_events_interface_inserted(void *devPtr) 
{
	char *interfaceName = NULL;
	wchar_t * longName = NULL;
	int i = 0;
	int done = FALSE;

	if (!xsup_assert((devPtr != NULL), "devPtr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	if (event_core_get_sleep_state())
	{
		debug_printf(DEBUG_NORMAL,
			"Got an interface insertion event when we were going to sleep.  Discarding.\n");
		_endthread();
		return;
	}

	interfaceName =	cardif_windows_events_get_interface_desc((wchar_t *) devPtr, TRUE);

	if (interfaceName == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to locate information about the interface that was just inserted!\n");
		_endthread();
		return;
	}

	longName = Malloc((strlen(interfaceName) + 2) * 2);	// Allocate enough for a wchar_t string.
	if (longName == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		_endthread();
		return;
	}

	if (MultiByteToWideChar(CP_ACP, 0, interfaceName, strlen(interfaceName), longName,
		strlen(interfaceName)) == 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to convert multi-byte character set to wide character set in %s()!\n",
			__FUNCTION__);

		FREE(longName);
		FREE(interfaceName);
		_endthread();
		return;
	}

	if (event_core_lock() != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"!!!!! Unable to acquire lock on the event core!  Interface will be ignored!\n");
		_endthread();
		return;
	}

	// When we come out of sleep, sometimes we will get an insert event on interfaces that we never
	// saw a remove event from.  In those cases, we want to complain a little, and bail out so that we
	// don't complain a bunch about binding errors.
	//
	// NOTE : The event core lock should be obtained prior to this call so that we don't
	// end up in a situation where we have checked while another thread is enabling.  This
	// situation can happen on some drivers that like to send two insert events when coming 
	// out of sleep.
	if (event_core_locate_by_desc(interfaceName) != NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Got an interface inserted event for an interface that is already inserted!  (Interface : %s)\n",
			interfaceName);

		if (event_core_unlock() != 0)
		{
			debug_printf(DEBUG_NORMAL,
				"Failed to release event core lock at %s():%d\n",
				__FUNCTION__, __LINE__);
		}
		_endthread();
		return;
	}

	if (cardif_windows_wmi_post_insert_bind(longName) == -1)
	{
		// With service events, this first bind attempt pretty much always fails.  So don't complain about it
		// because the driver will figure it out fairly quickly.
		if (event_core_unlock() != 0)
		{
			debug_printf(DEBUG_NORMAL,
				"Failed to release event core lock at %s():%d\n",
				__FUNCTION__, __LINE__);
		}

		Sleep(REBIND_ATTEMPT_INTERVAL * 1000);

		while (done == FALSE)
		{
			if (event_core_lock() != 0)
			{
				debug_printf(DEBUG_NORMAL,
					"!!!!! Unable to acquire event core lock!  Bad things will happen!\n");
			}

			if (cardif_windows_wmi_post_insert_bind(longName) == 0)
			{
				done = TRUE;
			}

			if (event_core_unlock() != 0)
			{
				debug_printf(DEBUG_NORMAL,
					"!!!!! Unable to release event core lock in %s()!  We will probably deadlock!\n",
					__FUNCTION__);
			}

			if (i >= REBIND_ATTEMPTS)
			{
				done = TRUE;
			}

			i++;

			if (done == FALSE)
				Sleep(1000);	// Wait a second and try again.
		}
	}
	else
	{
		if (event_core_unlock() != 0)
		{
			debug_printf(DEBUG_NORMAL,
				"Error releasing event core lock at %s():%d\n",
				__FUNCTION__, __LINE__);
		}
	}

	FREE(longName);
	FREE(interfaceName);
	_endthread();
}


/**
* \brief Handle an interface insertion/removal that is dispatched from our service
*        event handler.
*
* \warning This function should spawn threads to do it's work.  It is bad mojo to
*          block up the service control thread.
*
* @param[in] device   The device name that is sent in with the event.
* @param[in] is_add   A TRUE or FALSE value that indicates if the interface was inserted.
**/ 
void cardif_windows_events_add_remove_interface(wchar_t * device, char is_add) 
{
	switch (is_add)
	{
	case TRUE:
		_beginthread(cardif_windows_events_interface_inserted, 0,
			device);
		break;

	case FALSE:
		_beginthread(cardif_windows_events_interface_removed, 0,
			device);
		break;

	default:
		debug_printf(DEBUG_NORMAL,
			"Invalid call to %s()!  is_add is invalid!\n");
		break;
	}
}


