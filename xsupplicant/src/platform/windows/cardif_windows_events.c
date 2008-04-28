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
#include "cardif_windows.h"
#include "cardif_windows_wmi.h"
#include "../../event_core_win.h"
#include "../../ipc_events_index.h"
#include "../../eap_sm.h"
#include "../../error_prequeue.h"
#include "win_ip_manip.h"

#include <NtDDNdis.h>

// The nuiouser.h file is included with the Windows DDK.  Please 
// download the DDK and copy the file to the proper location.
#include "../../../vs2005/ndis_proto_driver/nuiouser.h"

///< A define for the DHCP release/renew calls.
#define TCPIP_DEVICE_PATH        "\\DEVICE\\TCPIP_"

///< Status values that we want to know about.  (Taken from ndis.h)
#define NDIS_STATUS_MEDIA_CONNECT						((NDIS_STATUS)0x4001000BL)
#define NDIS_STATUS_MEDIA_DISCONNECT					((NDIS_STATUS)0x4001000CL)
#define NDIS_STATUS_SCAN_CONFIRM						((NDIS_STATUS)0x40030000L)
#define NDIS_STATUS_DOT11_DISASSOCIATION				((NDIS_STATUS)0x40030008L)
#define NDIS_STATUS_LINK_STATE							((NDIS_STATUS)0x40010017L)
#define NDIS_STATUS_DOT11_LINK_QUALITY                  ((NDIS_STATUS)0x4003000CL)

// The amount of time to wait between bind attempts.
#define REBIND_ATTEMPT_INTERVAL                          5
#define REBIND_ATTEMPTS									 3

// XXX ICK..  Do this better.
extern void (*imc_disconnect_callback)(uint32_t connectionID);

int ipupdatecallback(context *ctx, HANDLE myhandle)
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
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for overlapped structure!\n");
	  return;
  }

  ovr->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

  ret = NotifyAddrChange(&hand, ovr);

  if ((ret != NO_ERROR) && (ret != ERROR_IO_PENDING))
  {
		debug_printf(DEBUG_NORMAL, "Can't establish IP address change notify handler.  Error was : %d\n", WSAGetLastError());			
      return;
  }

  if (event_core_register(hand, NULL, &ipupdatecallback, 0, HIGH_PRIORITY, "IP address change event") != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to register IP address change handler.\n");
	  return;
  }

  if (event_core_set_ovr(hand, 0, ovr) != TRUE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't set ovr!\n");
	  return;
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
void cardif_windows_int_event_connect(context *ctx)
{
	wireless_ctx *wctx = NULL;
	uint8_t bssid[6];
	char ssid[34];
	int ssidsize = 34;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Connect Event !!!!!!!!!!!!!!!!!!!!!\n");
	debug_printf(DEBUG_INT, "    Device : %s\n", ctx->desc);

	// Send event.
	ipc_events_ui(NULL, IPC_EVENT_UI_LINK_UP, ctx->desc);

		if (ctx->intType == ETH_802_11_INT)
		{
			wctx = (wireless_ctx *)ctx->intTypeData;
			if (wctx == NULL)
			{
				debug_printf(DEBUG_NORMAL, "Interface %s claims to be wireless, but doesn't "
					"have a wireless context!?\n", ctx->intName);
				return;
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

/**
 * \brief  Handle a disconnect event that has been generated by a protocol driver indication.
 *
 * @param[in] ctx   The context for the interface that generated this event.
 **/
void cardif_windows_int_event_disconnect(context *ctx)
{
	wireless_ctx *wctx = NULL;
	char bssid_dest[6];

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	debug_printf(DEBUG_INT, "!!!!!!!!!!!!!!!!!!!! Disconnect Event !!!!!!!!!!!!!!!!!!!!!\n");
	debug_printf(DEBUG_INT, "    Device : %s\n", ctx->desc);

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
			return;
		}

		// Double check to make sure that we really are disconnected.  Sometimes weird things
		// can happen because the events aren't being received in real time.
		if (cardif_windows_wireless_get_bssid(ctx, bssid_dest) != XENONE)
		{
			UNSET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);  // We are now disassociated.
			UNSET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);
			memset(ctx->dest_mac, 0x00, sizeof(ctx->dest_mac));
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

/**
 * \brief Look at the event that the protocol driver generated, and determine what to do
 *		  with it.
 *
 * @param[in] ctx   The context for the interface that the event was generated for.
 * @param[in] eventdata   The entire set of data that came along with the indication from
 *                        the protocol driver.
 * @param[in] evtSize   The size of the data that \ref eventdata points to.
 **/
void cardif_windows_int_event_process(context *ctx, uint8_t *eventdata, DWORD evtSize)
{
  PNDISPROT_INDICATE_STATUS pStat = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  if (!xsup_assert((eventdata != NULL), "eventdata != NULL", FALSE)) return;

  pStat = (PNDISPROT_INDICATE_STATUS)eventdata;

  switch (pStat->IndicatedStatus)
  {
  case NDIS_STATUS_MEDIA_CONNECT:
	  cardif_windows_int_event_connect(ctx);
	  break;

  case NDIS_STATUS_DOT11_DISASSOCIATION:
	  // There is interesting information that comes through with this event, however, for
	  // now we want to just use it as an indication of a disconnect.
	  cardif_windows_int_event_disconnect(ctx);
	  break;

  case NDIS_STATUS_MEDIA_DISCONNECT:
	  cardif_windows_int_event_disconnect(ctx);
	  break;

  case NDIS_STATUS_SCAN_CONFIRM:
	  debug_printf(DEBUG_INT, "Scan confirm indication on '%s'.\n", ctx->desc);
	  break;

  case NDIS_STATUS_DOT11_LINK_QUALITY:
	  // We need to work with this event more.  It will keep us from polling like we currently do!
	  debug_printf(DEBUG_INT, "Link quality indication on '%s'.\n", ctx->desc);
	  break;

  default:
	  debug_printf(DEBUG_INT, "Unknown NDIS indication : 0x%x\n", pStat->IndicatedStatus);
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
int cardif_windows_int_event_callback(context *ctx, HANDLE evtHandle)
{
	LPOVERLAPPED ovr = NULL;
  struct win_sock_data *sockData = NULL;
  DWORD ret;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = (struct win_sock_data *)ctx->sockData;

  if (sockData == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "No valid socket data in %s()!\n", __FUNCTION__);
	  return -1;
  }

	debug_printf(DEBUG_INT, "Got an interface event on interface '%s'!\n", ctx->desc);
	debug_hex_dump(DEBUG_INT, sockData->eventdata, sockData->evtSize);

	//  Process the event we got.
	cardif_windows_int_event_process(ctx, sockData->eventdata, sockData->evtSize);

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
			debug_printf(DEBUG_NORMAL, "Error requesting status indications from interface '%s'.  (Error %d)\n", ctx->desc, ret);
			return -1;
		}
  }

	return 0;
}

/**
 * \brief Issue an IOCTL so that when an event happens on an interface it is triggered,
 *        and dealt with.
 **/
void cardif_windows_setup_int_events(context *ctx)
{
  DWORD ret = 0;
  LPOVERLAPPED ovr;
  HANDLE hand = INVALID_HANDLE_VALUE;
  struct win_sock_data *sockData = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  debug_printf(DEBUG_INT, "Binding event IOCTL to interface '%s'.\n", ctx->desc);

  ovr = Malloc(sizeof(OVERLAPPED));
  if (ovr == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for overlapped structure!\n");
	  return;
  }

  ovr->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

  sockData = (struct win_sock_data *)ctx->sockData;

  if (sockData == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "No valid socket data in %s()!\n", __FUNCTION__);
	  return;
  }

  sockData->eventdata = Malloc(1500);  // Should be enough?
  if (sockData->eventdata == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store event data for interface %s!\n", ctx->desc);
	  return;
  }

  if (event_core_register(sockData->devHandle, ctx, &cardif_windows_int_event_callback, EVENT_SECONDARY, HIGH_PRIORITY, "Interface status event callback") != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to register interface event handler for interface '%s'.\n", ctx->desc);
	  return;
  }

  if (event_core_set_ovr(sockData->devHandle, EVENT_SECONDARY, ovr) != TRUE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't bind handle to overlapped structure for interface '%s'!\n", ctx->desc);
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
			debug_printf(DEBUG_NORMAL, "Error requesting status indications from interface '%s'.  (Error %d)\n", ctx->desc, ret);
			return;
		}
  }
}

void cardif_windows_events_set_bytes_rx(context *ctx, DWORD bytesrx)
{
  struct win_sock_data *sockData = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  sockData = (struct win_sock_data *)ctx->sockData;

  if (sockData == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to locate handle information for interface '%s'!\n", ctx->desc);
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
char *cardif_windows_event_get_guid(context *ctx)
{
	char *matchstr = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return NULL;

	if (!xsup_assert((ctx->intName != NULL), "ctx->intName != NULL", FALSE)) return NULL;

	matchstr = strstr(ctx->intName, "{");
	if (matchstr == NULL) return NULL;      // It isn't there!?  This is BAD!

	return _strdup(matchstr);       // Return the GUID portion.
}

/**
 * \brief Return the path to the IP device for the GUID. 
 *
 * @param[in] ctx   The context for the interface we want to convert.
 *
 * \retval NULL   on error
 * \retval wchar_t*   that points to a string that can be used in IP release and renew calls.
 **/
wchar_t *cardif_windows_events_get_ip_guid_str(context *ctx)
{
	char *guid = NULL;
	char *fullpath = NULL;
	wchar_t *longpath = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return NULL;

	guid = cardif_windows_event_get_guid(ctx);

	fullpath = Malloc(strlen(guid)+strlen(TCPIP_DEVICE_PATH)+2);
	if (fullpath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return NULL;
	}

	strcpy(fullpath, TCPIP_DEVICE_PATH);
	strcat(fullpath, guid);

	FREE(guid);  // We are done with it.

	longpath = Malloc((strlen(fullpath)+2) * 2);
	if (longpath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate wchar_t * in %s()!\n", __FUNCTION__);
		return NULL;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fullpath, strlen(fullpath), longpath, ((strlen(fullpath)+2) * 2)) == 0)
	{
		FREE(fullpath);
		FREE(longpath);
		return NULL;
	}

	FREE(fullpath);  // We are done with it.

	return longpath;
}

int cardif_windows_events_enable_dhcp(context *ctx)
{
	char *guid = NULL;

	guid = cardif_windows_event_get_guid(ctx);
	if (SetAdapterIpAddress(guid, 1, 0, 0, 0) != NO_ERROR) return -1;

	return 0;
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
char *cardif_windows_events_get_interface_desc(wchar_t *dev, char live_only)
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

	if (!xsup_assert((dev != NULL), "dev != NULL", FALSE)) return NULL;

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
		debug_printf(DEBUG_NORMAL, "Unable to determine interface name using SetupDi calls!  (%d)\n", GetLastError());
		return NULL;
	}

	// Make sure to zero out the buffer first.  wcsncpy doesn't append a NULL!
	memset(&deviceNumber, 0x00, sizeof(deviceNumber));

	wcsncpy((wchar_t *)&deviceNumber, &dev[strlen("\\\\?\\Root#MS_PSCHEDMP#")], 4);

	debug_printf(DEBUG_INT, "Whole interface name : %ws\n", dev);
	debug_printf(DEBUG_INT, "Looking for interface instance : %ws\n", deviceNumber);

	memset(&shortNum, 0x00, sizeof(shortNum));

	sprintf(shortNum, "%ws", deviceNumber);

	myData.cbSize = sizeof(SP_DEVINFO_DATA);
	while (SetupDiEnumDeviceInfo(mySDIClass, i, &myData))
	{
		if (SetupDiGetDeviceInstanceId(mySDIClass, &myData, (PSTR)&myString, 1024, NULL))
		{
			numberonly = (char *)&myString[strlen(path)+1];

			if (strcmp(numberonly, shortNum) == 0)
			{
				done = TRUE;  // We found what we wanted.
				if (SetupDiGetDeviceRegistryProperty(mySDIClass, &myData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)&myString, 1024, NULL))
				{
					debug_printf(DEBUG_INT, "Found interface : %s\n", myString);
				}
				break;  // Jump out of the loop.
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
	context *ctx = NULL;

	if (!xsup_assert((devPtr != NULL), "devPtr != NULL", FALSE)) 
	{
		_endthread();
		return;
	}

	interfaceName = cardif_windows_events_get_interface_desc((wchar_t *)devPtr, FALSE);
	if (interfaceName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to locate information about the interface that was just removed!\n");
		_endthread();
		return;
	}

	if (event_core_lock() != 0)
	{
		debug_printf(DEBUG_NORMAL, "!!!!! Unable to acquire event core lock!  Bad things will happen!\n");
	}

	// Try to delete the interface from the interface cache.
	// It is safe not to mutex this for now since the event core lock will protect pretty much everything.  But,
	// we may need to mutex it in the future!
	if (interfaces_delete(interfaceName) == TRUE)
	{
		debug_printf(DEBUG_NORMAL, "Removed device '%s' from our live interfaces list.\n", interfaceName);
	}

	ctx = event_core_locate_by_desc(interfaceName);

	if (ctx == NULL)
	{
		debug_printf(DEBUG_INT, "Couldn't locate a context for removal event. (Perhaps "
			"we aren't managing this interface?)\n");

		FREE(interfaceName);
		event_core_unlock();
		_endthread();
		return;
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

	FREE(interfaceName);
	if (event_core_unlock() != 0)
	{
		debug_printf(DEBUG_NORMAL, "!!!!!! Unable to release the lock on the event core!  We will probably deadlock!\n");
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
	wchar_t *longName = NULL;
	int i = 0;
	int done = FALSE;

	if (!xsup_assert((devPtr != NULL), "devPtr != NULL", FALSE)) 
	{
		_endthread();
		return;
	}

	if (event_core_lock() != 0)
	{
		debug_printf(DEBUG_NORMAL, "!!!!! Unable to acquire lock on the event core!  Interface will be ignored!\n");
		_endthread();
		return;
	}

	interfaceName = cardif_windows_events_get_interface_desc((wchar_t *)devPtr, TRUE);
	if (interfaceName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to locate information about the interface that was just inserted!\n");
		event_core_unlock();
		_endthread();
		return;
	}

	longName = Malloc((strlen(interfaceName)+2)*2);  // Allocate enough for a wchar_t string.
	if (longName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		event_core_unlock();
		_endthread();
		return;
	}

	if (MultiByteToWideChar(CP_ACP, 0, interfaceName, strlen(interfaceName), longName, strlen(interfaceName)) == 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to convert multi-byte character set to wide character set in %s()!\n", __FUNCTION__);
		FREE(longName);
		FREE(interfaceName);
		event_core_unlock();
		_endthread();
		return;
	}

	if (cardif_windows_wmi_post_insert_bind(longName) == -1)
	{
		// With service events, this first bind attempt pretty much always fails.  So don't complain about it
		// because the driver will figure it out fairly quickly.
		event_core_unlock();

		Sleep(REBIND_ATTEMPT_INTERVAL*1000);

		while (done == FALSE)
		{
			if (event_core_lock() != 0)
			{
				debug_printf(DEBUG_NORMAL, "!!!!! Unable to acquire event core lock!  Bad things will happen!\n");
			}

			if (cardif_windows_wmi_post_insert_bind(longName) == 0)
			{
				done = TRUE;
			}
			
			if (event_core_unlock() != 0)
			{
				debug_printf(DEBUG_NORMAL, "!!!!! Unable to release event core lock in %s()!  We will probably deadlock!\n", __FUNCTION__);
			}

			if (i >= REBIND_ATTEMPTS)
			{
				done = TRUE;
			}

			i++;
		}
	}

	FREE(longName);
	FREE(interfaceName);
	event_core_unlock();
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
void cardif_windows_events_add_remove_interface(wchar_t *device, char is_add)
{
	switch (is_add)
	{
	case TRUE:
		_beginthread(cardif_windows_events_interface_inserted, 0, device);
		break;

	case FALSE:
		_beginthread(cardif_windows_events_interface_removed, 0, device);
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Invalid call to %s()!  is_add is invalid!\n");
		break;
	}
}