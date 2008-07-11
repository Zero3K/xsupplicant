/**
 * Windows wireless interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_wireless.c
 *
 * \authors chris@open1x.org
 *
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <winsock2.h>

#include <NtDDNdis.h>
#include <windot11.h>

// The nuiouser.h file is included with the Windows DDK.  Please 
// download the DDK and copy the file to the proper location.
#include "../../../vs2005/ndis_proto_driver/nuiouser.h"

#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../config_ssid.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../wpa.h"
#include "../../wpa2.h"
#include "../../wpa_common.h"
#include "../../platform/cardif.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "../../ipc_callout.h"
#include "cardif_windows.h"
#include "cardif_windows_wireless.h"
#include "../../wireless_sm.h"
#include "../../timer.h"
#include "../../wpa.h"
#include "../../wpa2.h"
#include "../../pmksa.h"
#include "../../statemachine.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

// In DDK 3790.1830 these values aren't defined.  So, define them.
#ifndef OID_802_11_CAPABILITY
#define OID_802_11_CAPABILITY    0x0D010122

// If the capability #define doesn't exist, then these values probably
// don't either.  If you have build errors complaining that these are
// already defined, then comment them out.
#define Ndis802_11AuthModeWPA2      6
#define Ndis802_11AuthModeWPA2PSK   7

typedef struct _NDIS_802_11_AUTHENTICATION_ENCRYPTION
{
  NDIS_802_11_AUTHENTICATION_MODE  AuthModeSupported;
  NDIS_802_11_ENCRYPTION_STATUS  EncryptStatusSupported;
} NDIS_802_11_AUTHENTICATION_ENCRYPTION, *PNDIS_802_11_AUTHENTICATION_ENCRYPTION;

typedef struct _NDIS_802_11_CAPABILITY
{
  ULONG  Length;
  ULONG  Version;
  ULONG  NoOfPMKIDs;
  ULONG  NoOfAuthEncryptPairsSupported;
  NDIS_802_11_AUTHENTICATION_ENCRYPTION AuthenticationEncryptionSupported[1];
} NDIS_802_11_CAPABILITY, *PNDIS_802_11_CAPABILITY;
#endif

typedef struct _NEEDED_OIDS
{
	DWORD oid;
	char oidname[50];
} NEEDED_OIDS;

NEEDED_OIDS oldoidsneeded[] = {
	{OID_802_11_BSSID_LIST, "OID_802_11_BSSID_LIST"},
	{OID_802_11_BSSID_LIST_SCAN, "OID_802_11_BSSID_LIST_SCAN"},
	{OID_802_11_ASSOCIATION_INFORMATION, "OID_802_11_ASSOCIATION_INFORMATION"},
	{OID_802_11_AUTHENTICATION_MODE, "OID_802_11_AUTHENTICATION_MODE"},
	{OID_802_11_ENCRYPTION_STATUS, "OID_802_11_ENCRYPTION_STATUS"},
	{OID_802_11_INFRASTRUCTURE_MODE, "OID_802_11_INFRASTRUCTURE_MODE"},
	{OID_802_11_SSID, "OID_802_11_SSID"},
	{OID_802_11_BSSID, "OID_802_11_BSSID"},
	{OID_802_11_DISASSOCIATE, "OID_802_11_DISASSOCIATE"},
	{OID_802_11_ADD_WEP, "OID_802_11_ADD_WEP"},
	{OID_802_11_ADD_KEY, "OID_802_11_ADD_KEY"},
	{OID_802_11_CAPABILITY, "OID_802_11_CAPABILITY"},
	{OID_802_11_REMOVE_KEY, "OID_802_11_REMOVE_KEY"},
	{OID_802_11_PRIVACY_FILTER, "OID_802_11_PRIVACY_FILTER"},
	{0, ""}
};

NEEDED_OIDS newoidsneeded[] = {
	{OID_DOT11_SCAN_REQUEST, "OID_DOT11_SCAN_REQUEST"},
	{OID_DOT11_EXTSTA_CAPABILITY, "OID_DOT11_EXTSTA_CAPABILITY"},
	{0, ""}
};

/**
 * This will be called ~7 seconds after a request to scan.  According to
 * the Windows documentation, you need to wait at least 6 seconds before
 * requesting scan data, which is where 7 seconds comes from. ;)
 *
 * It is also possible this will be called if we get a scan complete event
 * from the driver.
 **/
void cardif_windows_wireless_scan_timeout(context *ctx)
{
  DWORD BytesReturned = 0;
  UCHAR Buffer[65535];  // 64k of scan data is a *LOT*!
  PNDISPROT_QUERY_OID pQueryOid = NULL;
  PNDIS_802_11_BSSID_LIST_EX pBssidList = NULL;
  PNDIS_WLAN_BSSID_EX pBssidEx = NULL;
  PNDIS_802_11_SSID pSsid = NULL;
  UCHAR *ofs = NULL;
  char rssi = 0;
  int i = 0;
  char ssid[33];
  struct win_sock_data *sockData = NULL;
  LPVOID lpMsgBuf = NULL;
  wireless_ctx *wctx = NULL;
  DWORD lastError = 0;
  ULONG ielen = 0;
  uint8_t percentage = 0;
  int x = 0;
  float rate = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  if (ipc_events_scan_complete(ctx) != IPC_SUCCESS)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't send scan complete event to IPC listeners.\n");
  }

  timer_cancel(ctx, SCANCHECK_TIMER);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return;

  memset(&Buffer[0], 0x00, sizeof(Buffer));
  pQueryOid = (PNDISPROT_QUERY_OID)&Buffer[0];
  pQueryOid->Oid = OID_802_11_BSSID_LIST;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), (LPVOID)&Buffer[0],
					sizeof(Buffer), &BytesReturned) == FALSE)
  {
	  lastError = GetLastError();

	  if (lastError != ERROR_NOT_READY)
	  {
		  // If we are associated, then a passive scan failed.  So ignore it.
		  if (wctx->state != ASSOCIATED)
		  {
			ipc_events_error(ctx, IPC_EVENT_ERROR_GETTING_SCAN_DATA, ctx->desc);
		  }
  		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Attempt to get scan data results on interface '%s' failed!  Reason was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
	  }
	  else
	  {
		  debug_printf(DEBUG_INT, "The interface indicated it wasn't ready.  Ignoring scan attempt.\n");
	  }

	  return;
  }

  // Only clear our cache if we have new data.  This allows us to handle situations where
  // stale scan data provides a means to authenticate to a connection that associates slowly
  // (such as the IPW3945 with Trpz APs.)
  config_ssid_clear(wctx);


  pBssidList = (PNDIS_802_11_BSSID_LIST_EX)&pQueryOid->Data[0];

  debug_printf(DEBUG_INT, "Got %d result(s).\n", pBssidList->NumberOfItems);

  pBssidEx = (PNDIS_WLAN_BSSID_EX)&pBssidList->Bssid[0];
  ofs = (UCHAR *)pBssidEx;

  for (i = 0; i < (int)pBssidList->NumberOfItems; i++)
  {
	  pBssidEx = (PNDIS_WLAN_BSSID_EX)ofs;

	  pSsid = (PNDIS_802_11_SSID)&pBssidEx->Ssid;

	  memset(&ssid, 0x00, sizeof(ssid));
	  if (strncpy_s((void *)&ssid, sizeof(ssid), pSsid->Ssid, pSsid->SsidLength) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't make a copy of the SSID in %s() at %d!\n",
			  __FUNCTION__, __LINE__);
		  goto bad_strncpy;
	  }

	  rssi = pBssidEx->Rssi;

	  // According to the windows documentation, the RSSI should vary between
	  // -10 and -200 dBm.  So, we need to figure out a percentage based on that.

	  // However, many examples on the net show that valid ranges will run from -50 to -100.

	  percentage = (((rssi) + 100)*2);    // Make the dBm a positive number, and the lowest value
	  	                                    // equal to 0.  (So, the range will now be 0 - 190.)

	  if (percentage > 100) percentage = 100;  // Some cards may have a percentage > 100 depending on their sensativity.  In those cases, only return 100. ;)

	  config_ssid_add_ssid_name(wctx, ssid);
	  config_ssid_add_bssid(wctx, pBssidEx->MacAddress);
	  config_ssid_add_qual(wctx, 0, rssi, 0, percentage);

	  debug_printf(DEBUG_INT, "Found SSID : %s\t\t BSSID : %02x:%02x:%02x:%02x:%02x:%02x\t RSSI : %d\t 802.11 Type : %d\t Percentage : %d\n", ssid,
		  pBssidEx->MacAddress[0], pBssidEx->MacAddress[1], pBssidEx->MacAddress[2], pBssidEx->MacAddress[3],
		  pBssidEx->MacAddress[4], pBssidEx->MacAddress[5], rssi, pBssidEx->NetworkTypeInUse, percentage);

	  if (pBssidEx->NetworkTypeInUse == Ndis802_11OFDM5)
	  {
		  config_ssid_update_abilities(wctx, ABIL_DOT11_A);
	  }
	  else if (pBssidEx->NetworkTypeInUse == Ndis802_11FH)
	  {
		  config_ssid_update_abilities(wctx, ABIL_DOT11_STD);
	  }
	  else if ((pBssidEx->NetworkTypeInUse == Ndis802_11DS) || (pBssidEx->NetworkTypeInUse == Ndis802_11OFDM24))
	  {
		  // We need to look at the bit rates to decide what is supported here.  (This is icky!)
		  for (x = 0; x < 16; x++)
		  {
			  rate = ((pBssidEx->SupportedRates[x] & 0x7f)*0.5);

			  if ((rate == 1.0) || (rate == 2.0))
			  {
				  config_ssid_update_abilities(wctx, ABIL_DOT11_STD);
			  }
			  else if ((rate == 5.5) || (rate == 11.0))
			  {
				  config_ssid_update_abilities(wctx, ABIL_DOT11_B);
			  }
			  else if ((rate > 11.0) && (rate <= 54.0))
			  {
				  config_ssid_update_abilities(wctx, ABIL_DOT11_G);
			  }
		  }
	  }
	  else
	  {
		  debug_printf(DEBUG_NORMAL, "Unknown network type in use.  Type %d.\n", pBssidEx->NetworkTypeInUse);
	  }

	  if (pBssidEx->Privacy == 1) config_ssid_update_abilities(wctx, ABIL_ENC);

	  // At least one card tested returned a bogus IELength value.  So we need to check it against the structure
	  // length, and if it is invalid, we need to try to calculate the proper value.
	  if (pBssidEx->IELength > pBssidEx->Length)
	  {
		  if (pBssidEx->Length > sizeof(NDIS_WLAN_BSSID_EX))
		  {
			  ielen = pBssidEx->Length - sizeof(NDIS_WLAN_BSSID_EX);
		  }
		  else
		  {
			  ielen = 0;
		  }
	  }
	  else
	  {
		  ielen = pBssidEx->IELength;
	  }

	  if (ielen > 0) cardif_windows_wireless_parse_ies(ctx, (uint8_t *)&pBssidEx->IEs[sizeof(NDIS_802_11_FIXED_IEs)], ielen);

	  if ((ielen > 0) && (cardif_windows_wireless_find_ht_ie(ctx, (uint8_t *)&pBssidEx->IEs[sizeof(NDIS_802_11_FIXED_IEs)], ielen) == TRUE))
	  {
		  config_ssid_update_abilities(wctx, ABIL_DOT11_N);
	  }

bad_strncpy:
	  ofs += pBssidEx->Length;
  }

  UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);
  wctx->temp_ssid = NULL;

  return;
}

/**
 * \brief Do the Windows XP 'fake' passive scan.
 *
 * @param[in] ctx   The context that we are getting 'passive scan' data from.
 *
 * \retval XENONE on success.
 **/
int cardif_windows_wireless_xp_passive(context *ctx)
{
	wireless_ctx *wctx = NULL;
	struct found_ssids *ssids = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEGENERROR;

	if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE)) return XEGENERROR;

	wctx = (wireless_ctx *)ctx->intTypeData;

	//debug_printf(DEBUG_NORMAL, "Doing 'passive' scan!\n");
	cardif_windows_wireless_scan_timeout(ctx);

	UNSET_FLAG(wctx->flags, WIRELESS_PASV_SCANNING);

	// Walk the list, and generate OKC entries for anything that we might roam to.
	ssids = wctx->ssid_cache;

	while (ssids != NULL)
	{
		// If the SSID in the cache is one that matches the SSID we are currently on.
		if ((ssids->ssid_name != NULL) && (strcmp(ssids->ssid_name, wctx->cur_essid) == 0))
		{
			// We only care if it is a WPA2 network.
			if (ssids->rsn_ie != NULL)
			{
				pmksa_seen(ctx, ssids->mac, ssids->ssid_name);
			}
		}

		ssids = ssids->next;
	}

	pmksa_apply_cache(ctx);

	return XENONE;  // We always return XENONE for now, since failure to generate OKC entries isn't
					// a big deal.
}

/**
 * Tell the wireless card to scan for wireless networks.
 **/
int cardif_windows_wireless_scan(context *ctx, char passive)
{
  DWORD BytesReturned = 0;
  UCHAR Buffer[sizeof(NDIS_OID)+4];
  PNDISPROT_SET_OID pSetOid = NULL;
  struct win_sock_data *sockData = NULL;
  LPVOID lpMsgBuf = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  if (passive == TRUE)
  {
	  // Windows XP doesn't allow us to request a passive scan.  So, we just want to grab the latest
	  // data in the card's scan cache, and pray that it is doing passives all the time. ;)
	  return cardif_windows_wireless_xp_passive(ctx);
  }

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  memset(&Buffer, 0x00, sizeof(Buffer));
  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
  pSetOid->Oid = OID_802_11_BSSID_LIST_SCAN;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, (LPVOID)&Buffer[0], sizeof(NDISPROT_QUERY_OID)+4, 
					NULL, 0, &BytesReturned) == FALSE)
  {
	  //ipc_events_error(ctx, IPC_EVENT_ERROR_CANT_START_SCAN, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Unable to start a scan on interface '%s'!  (Your scan information may not be current.)  Reason was : %s\n", ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return -1;
  }

  // Once we had done that, we need to wait for at least 6 seconds to get full scan data back.
  // So set a timer to check in 8 seconds.
  timer_add_timer(ctx, SCANCHECK_TIMER, 8, NULL, cardif_windows_wireless_scan_timeout);
  return XENONE;
}

/**
 *  Get the list of IEs that we used to associate.
 *
 *  When this function is called, "ie_size" should be the size of the buffer defined by
 *  "ies".  On return, "ie_size" will be the length of the IE block copied in to the buffer.
 **/
int cardif_windows_wireless_get_ies(context *ctx, char *ies, int *ie_size)
{
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  QueryBuffer[65535];              // Unlikely that we would have a result this size!
    PNDISPROT_QUERY_OID pQueryOid = NULL;
	PNDIS_802_11_ASSOCIATION_INFORMATION pInfo = NULL;
	struct win_sock_data *sockData = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

	memset(&QueryBuffer, 0x00, sizeof(QueryBuffer));
	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_ASSOCIATION_INFORMATION;

	result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

    if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			debug_printf(DEBUG_INT, "IOCTL returned that no association information is available.\n");
			debug_printf(DEBUG_INT, "Are you associated to a network!?\n");
			return -1;
		}

		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Get association information on interface '%s' failed.  Reason was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

	pInfo = (PNDIS_802_11_ASSOCIATION_INFORMATION)&pQueryOid->Data[0];

	if (pInfo->RequestIELength > (*ie_size))
	{
		debug_printf(DEBUG_NORMAL, "Insufficient buffer space to store resulting IEs!\n");
		return -1;
	}

	memcpy(ies, &pQueryOid->Data[pInfo->OffsetRequestIEs], pInfo->RequestIELength);
	(*ie_size) = pInfo->RequestIELength;

	return XENONE;
}

/**
 *  Take a block of IE data specified by "in_ie" and parse it, looking for a
 *  WPA2 information element.  The WPA2 information element will be returned in 
 *  "out_ie", if the return value of the function is XENONE.
 *
 *  Since a WPA2 information element is a variable length field, we will determine
 *  that we are looking at a WPA2 IE by matching against the static fields that are found
 *  at the beginning of the IE.  The IE should be in the format of :
 *
 *  0x30 XX 0x01 0x00 0x00 0x0f 0xac GG  (Followed by variable length stuff.)
 *   
 *  The value for XX needs to be at least 8 for it to be a valid IE.
 **/
int cardif_windows_wireless_find_wpa2_ie(context *ctx, uint8_t *in_ie, uint16_t in_size,
										uint8_t *out_ie, uint8_t *out_size)
{
	const char wpa2oui[3] = {0x00, 0x0f, 0xac};
	unsigned int i = 0;
	char done = 0;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

	i = 0;
	done = FALSE;

	while ((i < in_size) && (done == FALSE))
	{
		if (in_ie[i] == 0x30)
		{
			// It may be a WPA 2 IE.
			if ((unsigned char)in_ie[i+1] >= 8)
			{
				// Looking good..
				if ((in_ie[i+2] == 0x01) && (in_ie[i+3] == 0x00))
				{
					if (memcmp(&in_ie[i+4], &wpa2oui, 3) == 0)
					{
						done = TRUE;
					}
				}
			}
		}

		if (done == FALSE) i+=(unsigned char)(in_ie[i+1]+2);
	}

	if (done == FALSE)
	{
		// If we are scanning, then not finding an IE is no big deal.  Otherwise, it is
		// probably an error worth reporting.
		if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
		{
			debug_printf(DEBUG_INT, "IE block didn't contain a valid WPA2 IE!\n");
		}
		else
		{
			//debug_printf(DEBUG_NORMAL, "IE block didn't contain a valid WPA2 IE!\n");
		}
		return -1;
	}
						
	debug_printf(DEBUG_INT, "WPA2 IE (%d) : ", in_ie[i+1]);
	debug_hex_printf(DEBUG_INT, &in_ie[i], in_ie[i+1]+2);

	(*out_size) = in_ie[i+1]+2;
	memcpy(out_ie, &in_ie[i], (*out_size));

	return XENONE;
}

/**
 * Get the WPA2 Information Element.
 **/
int cardif_windows_wireless_get_wpa2_ie(context *ctx, uint8_t *iedata, uint8_t *ielen)
{
	char ie_buf[65535];
	int ie_size = 65535;

	if (cardif_windows_wireless_get_ies(ctx, ie_buf, &ie_size) != XENONE)
		return -1;
	
	debug_printf(DEBUG_INT, "IEs returned (Length : %d) :\n", ie_size);
	debug_hex_printf(DEBUG_INT, ie_buf, ie_size);

	if (cardif_windows_wireless_find_wpa2_ie(ctx, ie_buf, ie_size, iedata, ielen) != XENONE)
		return -1;

  return XENONE;
}

/**
 * Scan through whatever was returned by the scan, and pull
 * out any interesting IEs.
 **/
void cardif_windows_wireless_parse_ies(context *ctx, uint8_t *iedata, uint16_t ielen)
{
  int i = 0;
  int wpalen = 0;
  uint8_t wpaie[255];
  uint8_t authtypes = 0;
  uint8_t abilities = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return;

  if (!xsup_assert((ielen > 0), "ielen > 0", FALSE))
    return;

  if (cardif_windows_wireless_find_wpa_ie(ctx, iedata, ielen, wpaie, &wpalen) == XENONE)
  {
	  authtypes = wpa_parse_auth_type(wpaie);
	  
	  if (authtypes != 0xff)
	  {
		  if (TEST_FLAG(authtypes, WPA_PSK)) abilities |= ABIL_WPA_PSK;
		  if (TEST_FLAG(authtypes, WPA_DOT1X)) abilities |= ABIL_WPA_DOT1X;
	  }

	  // We have a valid IE, save it.
	  abilities |= ABIL_WPA_IE;
	  config_ssid_update_abilities(ctx->intTypeData, abilities);
	  config_ssid_add_wpa_ie(ctx->intTypeData, wpaie, wpalen);
  }

  if (cardif_windows_wireless_find_wpa2_ie(ctx, iedata, ielen, wpaie, &wpalen) == XENONE)
  {
	  authtypes = wpa2_parse_auth_type(wpaie);

	  if (authtypes != 0xff)
	  {
		  if (TEST_FLAG(authtypes, RSN_PSK)) abilities |= ABIL_RSN_PSK;
		  if (TEST_FLAG(authtypes, RSN_DOT1X)) abilities |= ABIL_RSN_DOT1X;
	  }
	
      // We have a valid IE, save it.
	  abilities |= ABIL_RSN_IE;
	  config_ssid_update_abilities(ctx->intTypeData, abilities);
	  config_ssid_add_rsn_ie(ctx->intTypeData, wpaie, wpalen);
  }
}

/**
 * \brief Determine the version of Windows that is in use so that we can use the proper
 *        function calls.
 *
 * \retval 0 if we can't determine which wireless calls to use.
 * \retval 1 if we should use the XP/2k calls
 * \retval 2 if we should use the Vista/2008 calls
 **/
int cardif_windows_get_os_ver()
{
	OSVERSIONINFOEX winVer;

	winVer.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	if (GetVersionEx(&winVer) == 0)
	{
		debug_printf(DEBUG_NORMAL, "****  Unable to determine Windows version in use!\n");
		return 0;
	}

	// Major version of 6 is Vista or 2k8.  So use the new ioctls.
	if (winVer.dwMajorVersion == 6) return 2;

	if (winVer.dwMajorVersion == 5)
	{
		switch (winVer.dwMinorVersion)
		{
		case 0:
			debug_printf(DEBUG_INT, "Detected Windows 2000.     *****  It is likely that this won't work!!!  *****\n");
			return 1;
			break;

		case 1:
			debug_printf(DEBUG_INT, "Detected Windows XP.\n");
			return 1;
			break;

		case 2:
			debug_printf(DEBUG_NORMAL, "Detected Windows 2003 server or Windows XP 64 bit edition.   ***** It is likely that this won't work!!!! *****\n");
			return 1;
			break;

		default:
			debug_printf(DEBUG_NORMAL, "Unknown version of Windows.    ***** It is likely that this won't work!!!!! *****\n");
			return 0;
			break;
		}
	}

	return 0;  // Not sure what to do.
}
#if 0
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  QueryBuffer[4096];
    PNDISPROT_QUERY_OID pQueryOid = NULL;
	struct win_sock_data *sockData = NULL;
	LPVOID lpMsgBuf = NULL;
	DWORD *vals = NULL;
	int count = 0, i = 0, x = 0;
	int retval = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return 0;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return 0;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_GEN_SUPPORTED_LIST;

	result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

    if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			debug_printf(DEBUG_NORMAL, "IOCTL returned that it doesn't know how to enumerate OIDs!\n");
			return 0;
		}

		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_GETTING_BSSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Enum IOCTLs IOCTL failed on interface '%s'.  Error was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return 0;
    }

	vals = pQueryOid->Data;
	count = ((BytesReturned - sizeof(NDIS_OID)) / sizeof(DWORD));

	debug_printf(DEBUG_INT, "Found %d OIDs in the table.\n", count);
	
	x = -1;
	retval = 2;  // Assume we can handle the needed IOCTLs, until we decide otherwise.

	debug_printf(DEBUG_INT, "\n------- Checking for Current Gen IOCTLs -------\n");
	while (((++x) >= 0) && (newoidsneeded[x].oid != 0) && (retval == 2))
	{
		i = 0;

		while (((++i) <= count) && (newoidsneeded[x].oid != vals[i]));

		if (i <= count) 
		{
			debug_printf(DEBUG_INT, "Found IOCTL for %s.\n", newoidsneeded[x].oidname);
		} 
		else
		{
			retval = 0;
		}
	}

	if (retval == 2) goto done;

	x = -1;
	retval = 1;  // Assume we can handle the needed IOCTLs, until we decide otherwise.

	debug_printf(DEBUG_INT, "\n------- Checking for Last Gen IOCTLs -------\n");
	while (((++x) >= 0) && (oldoidsneeded[x].oid != 0) && (retval == 1))
	{
		i = 0;

		while (((++i) <= count) && (oldoidsneeded[x].oid != vals[i]));

		if (i <= count) 
		{
			debug_printf(DEBUG_INT, "Found IOCTL for %s.\n", oldoidsneeded[x].oidname);
		} 
		else
		{
			retval = 0;
		}
	}

done:
	return retval;
}
#endif

/**
 * \brief Check to see if the context supports the authmode requested.  If it does,
 *        it will return true, if not it will throw an error to the UI.
 *
 * @param[in] ctx   The context for the interface that we think the authmode is invalid for.
 * @param[in] authmode   The authmode as defined by the Windows headers.
 *
 * \retval TRUE if the authmode is supported.
 * \retval FALSE if the authmode isn't supported (this function will also send out a UI error message)
 **/
int cardif_windows_authmode_supported_in_ctx(context *ctx, DWORD authmode)
{
	int retval = TRUE;
	wireless_ctx *wctx = NULL;

	if (ctx->intType != ETH_802_11_INT) return retval;

	wctx = ctx->intTypeData;

	if (wctx == NULL) return retval;

	switch (authmode)
	{
	case Ndis802_11AuthModeWPA:
		if (!TEST_FLAG(wctx->enc_capa, DOES_WPA))
		{
			debug_printf(DEBUG_NORMAL, "Attempted to set the authentication mode to WPA when the card doesn't appear to support it.\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_NOT_SUPPORTED, "WPA");
			retval = FALSE;
		}
		break;

	case Ndis802_11AuthModeWPA2:
		if (!TEST_FLAG(wctx->enc_capa, DOES_WPA2))
		{
			debug_printf(DEBUG_NORMAL, "Attempted to set the authentication mode to WPA2 when the card doesn't appear to support it.\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_NOT_SUPPORTED, "WPA2");
			retval = FALSE;
		}
		break;
	}

	return retval;
}

/**
 * Set the authentication (as in 802.11, not 802.1X) mode that we will be using to
 * create an association with the AP.
 **/
int cardif_windows_set_auth_mode(context *ctx, DWORD authmode, int throwError)
{
  DWORD Bytes = 0;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DWORD)];  
  PNDISPROT_SET_OID pSetOid = NULL;
  struct win_sock_data *sockData = NULL;
  DWORD *mode = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];

  pSetOid->Oid = OID_802_11_AUTHENTICATION_MODE;
  mode = (DWORD *)&pSetOid->Data[0];

  (*mode) = authmode;
  SetLastError(0);

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &Bytes) == FALSE)
  {
	  // Only scream if we believe this should have worked.
	  if (GetLastError() != ERROR_NOT_READY)
	  {
		  if (throwError == TRUE)
		  {
			  // If the auth mode isn't supported the call below will throw the error to the UI.
			  if (cardif_windows_authmode_supported_in_ctx(ctx, authmode) == TRUE)
			  {
				debug_printf(DEBUG_NORMAL, "Attempt to set authentication mode for interface '%s' failed!\n",
					ctx->desc);
				ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_802_11_AUTH_MODE, ctx->desc);
			  }
		  }
	  }
	  else
	  {
		  debug_printf(DEBUG_NORMAL, "'%s' indicated it wasn't ready yet.  We will try again later.\n", ctx->desc);
	  }
	  return -1;
  }

  return XENONE;
}

/**
 * \brief Check to see if an encryption mode is included in what the context discovered about
 *        the interface.
 *
 * @param[in] ctx   The context for the interface that we want to check.
 * @param[in] encmode   The encryption mode that we attempted to enable.
 *
 * \retval TRUE if the encryption mode is supported
 * \retval FALSE if it is not (this function will send a message to the UI)
 **/
int cardif_windows_enc_supported_in_ctx(context *ctx, DWORD encmode)
{
	int retval = TRUE;
	wireless_ctx *wctx = NULL;

	if (ctx->intType != ETH_802_11_INT) return retval;

	wctx = ctx->intTypeData;

	if (wctx == NULL) return retval;

	switch (encmode)
	{
	case Ndis802_11Encryption1Enabled:
		if (!TEST_FLAG(wctx->flags, DOES_WEP104))
		{
			debug_printf(DEBUG_NORMAL, "Attempted to enable WEP encryption, but the interface doesn't seem to support it.\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_NOT_SUPPORTED, "WEP encryption");
			retval = FALSE;
		}
		break;

	case Ndis802_11Encryption2Enabled:
		if (!TEST_FLAG(wctx->flags, DOES_TKIP))
		{
			debug_printf(DEBUG_NORMAL, "Attempted to enable TKIP encryption, but the interface doesn't seem to support it.\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_NOT_SUPPORTED, "TKIP encryption");
			retval = FALSE;
		}
		break;

	case Ndis802_11Encryption3Enabled:
		if (!TEST_FLAG(wctx->flags, DOES_CCMP))
		{
			debug_printf(DEBUG_NORMAL, "Attempted to enable CCMP encryption, but the interface doesn't seem to support it.\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_NOT_SUPPORTED, "CCMP encryption");
			retval = FALSE;
		}
		break;
	}

	return retval;
}

/**
 * Set the encryption mode.  On Windows, this sets which encryption methods are allowed.
 *
 * From the Windows DDK documentation :
 *
 * Encryption modes define the set of cipher suites that can be enabled on the 802.11 device:
 *
 * Encryption1 
 * WEP encryption is supported and enabled on the device. The device either does not support TKIP and AES or these cipher suites are disabled.
 * The WEP cipher suite as defined through this OID uses either 40 bit or 104 bit key lengths. Other extended key lengths are not supported for the WEP cipher suite.
 *
 * Encryption2 
 * WEP and TKIP encryption are supported and enabled on the device. The device either does not support AES or this cipher suite is disabled. 
 *
 * Encryption3 
 * WEP, TKIP, and AES encryption are supported and enabled on the device.
 * The AES cipher suite as defined through this OID is AES-CCMP. If the device supports other variants of the AES cipher suite, it cannot advertise support for the Encryption3 encryption mode unless the device also supports AES-CCMP.
 **/
int cardif_windows_set_enc_mode(context *ctx, DWORD encmode, int throwError)
{
  DWORD BytesReturned = 0;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DWORD)];  
  PNDISPROT_SET_OID pSetOid = NULL;
  struct win_sock_data *sockData = NULL;
  DWORD *mode = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];

  pSetOid->Oid = OID_802_11_ENCRYPTION_STATUS;
  mode = (DWORD *)&pSetOid->Data[0];

  (*mode) = encmode;
  SetLastError(0);

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
  {
	  // Only scream if we believe this should have worked.
	  if (GetLastError() != ERROR_NOT_READY)
	  {
		  if (throwError == TRUE)
		  {
			  if (cardif_windows_enc_supported_in_ctx(ctx, encmode) == TRUE)
			  {
				debug_printf(DEBUG_NORMAL, "Attempt to set encryption mode for interface '%s' failed!\n",
					ctx->desc);
				ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_802_11_ENC_MODE, ctx->desc);
			  }
		  }
	  }
	  else
	  {
		  debug_printf(DEBUG_NORMAL, "'%s' indicated it wasn't ready yet.  We will try again later.\n", ctx->desc);
	  }
	  return -1;
  }

  return XENONE;
}

/**
 * Set the card in to infrastructure mode.  This will case all keys to be deleted.
 **/
int cardif_windows_set_infra_mode(context *ctx)
{
  DWORD BytesReturned = 0;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DWORD)];  
  PNDISPROT_SET_OID pSetOid = NULL;
  struct win_sock_data *sockData = NULL;
  DWORD *mode = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];

  pSetOid->Oid = OID_802_11_INFRASTRUCTURE_MODE;
  mode = (DWORD *)&pSetOid->Data[0];

  (*mode) = Ndis802_11Infrastructure;

  SetLastError(0);

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
  {
	  if (GetLastError() == ERROR_NOT_READY)  // The interface wasn't ready yet.
	  {
		  debug_printf(DEBUG_NORMAL, "Attempt to set infrastructure mode for interface '%s' failed.  The interface reported it isn't ready yet.\n");
	  }
	  else
	  {
		  debug_printf(DEBUG_NORMAL, "Attempt to set infrastructure mode for interface '%s' failed!  (Error : %d)\n",
			  ctx->desc, GetLastError());
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_802_11_INFRA_MODE, ctx->desc);
	  }
	  return -1;
  }

  return XENONE;
}

/**
 * Disable encryption on the wireless card.  This is used in cases
 * where we roam to a different AP and the card needs to have WEP
 * disabled.
 **/
int cardif_windows_wireless_enc_disable(context *ctx)
{
	return cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeOpen, TRUE);
}

/**
 *  Take a block of IE data specified by "in_ie" and parse it, looking for a
 *  HT (802.11n) information element.  
 **/
int cardif_windows_wireless_find_ht_ie(context *ctx, uint8_t *in_ie, unsigned int in_size)
{
	unsigned int i = 0;
	char done = 0;
	wireless_ctx *wctx = NULL;

	i = 0;
	done = FALSE;

	while ((i < in_size) && (done == FALSE))
	{
		if (in_ie[i] == 45)   // 45 = HT Capabilities IE which is only in 802.11n capable beacons.
		{
			done = TRUE;
		}
		if (done == FALSE) i+=(unsigned char)(in_ie[i+1]+2);
	}
					
	if (done == TRUE)
	{
		debug_printf(DEBUG_INT, "HT IE (%d) : ", in_ie[i+1]);
		debug_hex_printf(DEBUG_INT, &in_ie[i], in_ie[i+1]+2);
	}

	return done;
}

/**
 *  Take a block of IE data specified by "in_ie" and parse it, looking for a
 *  WPA1 information element.  The WPA information element will be returned in 
 *  "out_ie", if the return value of the function is XENONE.
 *
 *  Since a WPA1 information element is a variable length field, we will determine
 *  that we are looking at a WPA IE by matching against the static fields that are found
 *  at the beginning of the IE.  The IE should be in the format of :
 *
 *  0xdd XX 0x00 0x50 0xf2 0x01 0x01 0x00 0x00 0x50 0xf2  (Followed by variable length stuff.)
 *   
 *  The value for XX needs to be at least 11 for it to be a valid IE.
 **/
int cardif_windows_wireless_find_wpa_ie(context *ctx, uint8_t *in_ie, unsigned int in_size,
										uint8_t *out_ie, uint8_t *out_size)
{
	const char wpaoui[3] = {0x00, 0x50, 0xf2};
	unsigned int i = 0;
	char done = 0;
	wireless_ctx *wctx = NULL;

	i = 0;
	done = FALSE;

	while ((i < in_size) && (done == FALSE))
	{
		if (in_ie[i] == 0xdd)
		{
			// It may be a WPA 1 IE.
			if (in_ie[i+1] >= 11)
			{
				// Looking good..
				if (memcmp(&in_ie[i+2], &wpaoui[0], 3) == 0)
				{
					if ((in_ie[i+5] == 0x01) && (in_ie[i+6] == 0x01) && (in_ie[i+7] == 0x00))
					{
						// Very likely. ;)
						if (memcmp(&in_ie[i+8], &wpaoui[0], 3) == 0)
						{
							done = TRUE;
						}
					}
				}
			}
		}
		if (done == FALSE) i+=(unsigned char)(in_ie[i+1]+2);
	}

	if (done == FALSE)
	{
		wctx = (wireless_ctx *)ctx->intTypeData;

		if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

		// If we are scanning, then not finding an IE is no big deal.  Otherwise, it is
		// probably an error worth reporting.
		if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
		{
			debug_printf(DEBUG_INT, "IE block didn't contain a valid WPA1 IE!\n");
		}
		else
		{
			//debug_printf(DEBUG_NORMAL, "IE block didn't contain a valid WPA1 IE!\n");
		}
		return -1;
	}
						
	debug_printf(DEBUG_INT, "WPA1 IE (%d) : ", in_ie[i+1]);
	debug_hex_printf(DEBUG_INT, &in_ie[i], in_ie[i+1]+2);

	(*out_size) = in_ie[i+1]+2;
	memcpy(out_ie, &in_ie[i], (*out_size));

	return XENONE;
}

/**
 *  Generate the WPA1 Information Element
 **/
int cardif_windows_wireless_get_wpa_ie(context *ctx, 
				 char *iedata, int *ielen)
{
	uint8_t ie_buf[65535];
	unsigned int ie_size = 65535;
	uint8_t len = 0;

	(*ielen) = 0;

	if (cardif_windows_wireless_get_ies(ctx, ie_buf, &ie_size) != XENONE)
		return -1;
	
	debug_printf(DEBUG_INT, "IEs returned (Length : %d) :\n", (*ielen));
	debug_hex_printf(DEBUG_INT, ie_buf, *ielen);

	if (cardif_windows_wireless_find_wpa_ie(ctx, ie_buf, ie_size, iedata, &len) != XENONE)
		return -1;

	(*ielen) = len;

  return XENONE;
}

/**
 * Set encryption to open on the wireless card.
 **/
int cardif_windows_wireless_enc_open(context *ctx)
{
	return cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeOpen, TRUE);
}

/**
 * Set the SSID of the wireless card.
 **/
int cardif_windows_wireless_set_ssid(context *ctx, char *ssid_name)
{
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  Buffer[sizeof(NDIS_OID) + sizeof(NDIS_802_11_SSID)];
    PNDISPROT_SET_OID pSetOid = NULL;
	struct win_sock_data *sockData = NULL;
	PNDIS_802_11_SSID pSsid = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert((ssid_name != NULL), "ssid_name != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

  if (ctx->intType != ETH_802_11_INT)
    {
      // We want to verify that the interface is in fact, not wireless, and
      // not that we are in a situation where the interface has just been 
      // down.
      debug_printf(DEBUG_NORMAL, "This interface isn't wireless!\n");
      return XENOWIRELESS;
    } 

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_SSID;

	pSsid = (PNDIS_802_11_SSID)&pSetOid->Data[0];

	if (strncpy_s(pSsid->Ssid, sizeof(pSsid->Ssid), ssid_name, strlen(ssid_name)) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Failed to copy SSID in %s() at %d!\n",
			__FUNCTION__, __LINE__);
		return -1;
	}

	pSsid->SsidLength = strlen(ssid_name);
	SetLastError(0);

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
		// Only complain if we believe the card was ready when we asked for this.
		if (GetLastError() != ERROR_NOT_READY)
		{
			ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_SSID, ctx->desc);
			lpMsgBuf = GetLastErrorStr(GetLastError());
			debug_printf(DEBUG_NORMAL, "Set SSID IOCTL failed on interface '%s'.  Reason was : %s\n",
				ctx->desc, lpMsgBuf);
			LocalFree(lpMsgBuf);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "'%s' reported it wasn't ready.  We will try again later.\n");
		}
		return -1;
    }

	return XENONE;
}

/**
 * Set the Broadcast SSID (MAC address) of the AP we are connected to.
 **/
int cardif_windows_wireless_set_bssid(context *ctx, uint8_t *bssid)
{
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  Buffer[sizeof(NDIS_OID) + 6];
    PNDISPROT_SET_OID pSetOid = NULL;
	struct win_sock_data *sockData = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert((bssid != NULL), "bssid != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_BSSID;

	memcpy(&Buffer[sizeof(NDIS_OID)], bssid, 6);

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_BSSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Set BSSID IOCTL failed on interface '%s'.  Reason was : %s\n",
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

  return XENONE;
}


/**
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 * @param[in] ctx   The context for the interface we want to get the BSSID for.
 * @param[out] bssid_dest   The BSSID (MAC address) of the wireless device we are 
 *                          associated with.
 *
 * \retval XENONE on success
 * \retval -1 on error
 **/
int cardif_windows_wireless_get_bssid(context *ctx, 
				char *bssid_dest)
{
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  QueryBuffer[sizeof(NDIS_OID) + 6];
    PNDISPROT_QUERY_OID pQueryOid = NULL;
	struct win_sock_data *sockData = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert((bssid_dest != NULL), "bssid_dest != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_BSSID;

	result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

    if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			debug_printf(DEBUG_INT, "IOCTL returned that no BSSID is currently valid!\n");
			debug_printf(DEBUG_INT, "Are you associated to a network!?\n");
			return -1;
		}

		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_GETTING_BSSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Get BSSID IOCTL failed on interface '%s'.  Reason was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

	// Otherwise, pQueryOid->Data should contain the BSSID.
	memcpy(bssid_dest, pQueryOid->Data, 6);

	return XENONE;
}

/**
 * \brief Get the frequency of the current connection.
 *
 * @param[in] ctx   The context for the interface we want to get the BSSID for.
 * @param[out] freq   The frequency (in kHz) of the channel we are on.
 *
 * \retval XENONE on success
 * \retval -1 on error
 **/
int cardif_windows_wireless_get_freq(context *ctx, uint32_t *freq)
{
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  QueryBuffer[sizeof(NDIS_OID) + sizeof(NDIS_802_11_CONFIGURATION)];
    PNDISPROT_QUERY_OID pQueryOid = NULL;
	PNDIS_802_11_CONFIGURATION pConf = NULL;
	struct win_sock_data *sockData = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert((freq != NULL), "freq != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_CONFIGURATION;

	result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

    if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Get BSSID IOCTL failed on interface '%s'.  Reason was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

	// Otherwise, pQueryOid->Data should contain the BSSID.
	pConf = pQueryOid->Data;
	(*freq) = pConf->DSConfig;

	return XENONE;
}

/**
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 **/
int cardif_windows_wireless_get_ssid(context *ctx, char *ssid_name, unsigned int ssidsize)
{
    DWORD  BytesReturned = 0;
    DWORD  result = 0;
    UCHAR  QueryBuffer[sizeof(NDIS_OID) + sizeof(NDIS_802_11_SSID)];
    PNDISPROT_QUERY_OID pQueryOid = NULL;
	struct win_sock_data *sockData = NULL;
	PNDIS_802_11_SSID pSsid = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert((ssid_name != NULL), "ssid_name != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

  if (ctx->intType != ETH_802_11_INT)
    {
      // We want to verify that the interface is in fact, not wireless, and
      // not that we are in a situation where the interface has just been 
      // down.
      debug_printf(DEBUG_NORMAL, "This interface isn't wireless!\n");
      return XENOWIRELESS;
    } 

  // If we get here, and isWireless == FALSE, then we need to double
  // check that our interface is really not wireless.
#if 0
  if (ctx->intType != ETH_802_11_INT)
    {
      if (cardif_int_is_wireless(ctx) == TRUE)
		{
			SET_FLAG(ctx->flags, IS_WIRELESS);
		} 
	  else 
		{
			UNSET_FLAG(ctx->flags, IS_WIRELESS);
		}

      if (!TEST_FLAG(ctx->flags, IS_WIRELESS))
		{
			UNSET_FLAG(ctx->flags, WAS_DOWN);
		}
    }
#endif

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_SSID;

	result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

    if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			debug_printf(DEBUG_INT, "IOCTL returned that no SSID is currently valid!\n");
			debug_printf(DEBUG_INT, "Are you associated to a network!?\n");
			return -1;
		}

		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_GETTING_SSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Get SSID IOCTL failed on interface '%s'.  Reason was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

	pSsid = (PNDIS_802_11_SSID)&pQueryOid->Data[0];

	if (Strncpy(ssid_name, ssidsize, pSsid->Ssid, pSsid->SsidLength+1) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't copy SSID in %s() at %d!\n",
			__FUNCTION__, __LINE__);
		return -1;
	}

	ssid_name[pSsid->SsidLength+1] = 0x00;

  return XENONE;
}

/**
 *  This function is called when we roam, or disassociate.  It should
 *  reset the card to a state where it can associate with a new AP.
 *
 *  For Windows, the zero_keys value does nothing.
 **/
int cardif_windows_wireless_wep_associate(context *ctx, int zero_keys)
{
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

  debug_printf(DEBUG_INT, "(WEP Associate) Set infra mode.\n");
  if (cardif_windows_set_infra_mode(ctx) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set infrastructure mode on interface '%s' failed.\n",
		  ctx->desc);
	  return -1;
  }

  debug_printf(DEBUG_INT, "(WEP Associate) Set auth mode.\n");
  if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeOpen, TRUE) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set the authentication mode to Open failed on interface '%s'.\n",
		  ctx->desc);
	  return -1;
  }
  wctx->assoc_type = ASSOC_TYPE_OPEN;

  if ((ctx->conn->association.auth_type == AUTH_NONE) &&
	  (ctx->conn->association.txkey == 0))
  {
	  debug_printf(DEBUG_INT, "(WEP Associate) Disable encryption.\n");
	  if (cardif_windows_set_enc_mode(ctx, Ndis802_11EncryptionDisabled, TRUE) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Request to set encryption mode failed on interface '%s'.\n",
			  ctx->desc);
		  return -1;
	  }
  }
  else
  {
	debug_printf(DEBUG_INT, "(WEP Associate) Set encryption mode.\n");
	if (cardif_windows_set_enc_mode(ctx, Ndis802_11Encryption1Enabled, TRUE) != 0)
	{
	  debug_printf(DEBUG_NORMAL, "Request to set encryption mode failed on interface '%s'.\n",
		  ctx->desc);
	  return -1;
	}

	wctx->pairwiseKeyType = CIPHER_WEP104;

	debug_printf(DEBUG_INT, "(WEP Associate) Set any static keys that are configured.\n");
	set_static_wep_keys(ctx, &ctx->conn->association);
  }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

  debug_printf(DEBUG_INT, "(WEP Associate) Set SSID.\n");
  if (cardif_windows_wireless_set_ssid(ctx, wctx->cur_essid) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set the SSID failed on interface '%s'.\n", ctx->desc);
	  return -1;
  }

  return XENONE;
}

/**
 * Send a disassociate request to the AP we are currently connected to.
 **/
int cardif_windows_wireless_disassociate(context *ctx, int reason)
{
	wireless_ctx *wctx = NULL;
	int i = 0;
	char randomssid[31];

#if 1
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

	// This will clear any keys in the key cache.
	cardif_windows_set_infra_mode(ctx);

	for (i = 0; i < 30; i++)
	{
		randomssid[i] = (char)(((float)(rand() % 87)) + 35);
	}
	randomssid[30] = 0x00;

	cardif_windows_wireless_set_ssid(ctx, randomssid);

	// Clear out any async events that we might have for this context.
	cardif_windows_wmi_async_clear_by_ctx(ctx);

	// Set our association mode back to unknown.
	wctx->assoc_type = ASSOC_TYPE_UNKNOWN;

	memset(wctx->cur_bssid, 0x00, 6);

	// Sending a disassociate turns off the radio, which is probably not what we want!
#endif
#if 0
    DWORD  BytesReturned;
    DWORD  result;
    UCHAR  QueryBuffer[sizeof(NDISPROT_QUERY_OID)];
    PNDISPROT_QUERY_OID pQueryOid;
	struct win_sock_data *sockData;
	LPVOID lpMsgBuf;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	sockData = (struct win_sock_data *)ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_DISASSOCIATE;

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
			(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned) == FALSE)
	{
        debug_printf(DEBUG_NORMAL, "Disassociate failed.\n");
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }
#endif
    return XENONE;
}

// Windows uses higher order bits in the key index to determine what type of key it is.
// These defines just make the code a little more readable.
#define TX_KEY            BIT(31)
#define PAIRWISE_KEY      BIT(30)
#define MANUAL_RSC        BIT(29)
#define AUTHENTICATOR_KEY BIT(28)

/**
 * Set a WEP key.  Also, based on the index, we may change the transmit
 * key.
 **/
int cardif_windows_wireless_set_WEP_key(context *ctx, uint8_t *key, 
				  int keylen, int keyidx)
{
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR Buffer[sizeof(NDIS_OID)+sizeof(NDIS_802_11_WEP)+13];
	PNDISPROT_SET_OID pSetOid = NULL;
	PNDIS_802_11_WEP pKey = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE)) return -1;

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_ADD_WEP;

	pKey = (PNDIS_802_11_WEP)&pSetOid->Data[0];

	pKey->Length = FIELD_OFFSET(NDIS_802_11_WEP, KeyMaterial) + keylen;
	pKey->KeyIndex = (keyidx & 0x7f);

	if ((keyidx & 0x80) == 0x80) pKey->KeyIndex |= TX_KEY;

	pKey->KeyLength = keylen;

	memcpy(&pKey->KeyMaterial[0], key, keylen);

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_WEP_KEY, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Set WEP Key IOCTL failed on interface '%s'.  Reason was : %s\n",
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }
	
	return XENONE;
}

/**
 * Push an encryption key down to the driver/card.  Windows differentiates between WEP/TKIP/CCMP
 * by the length of the key data.  Because of this, the variable "alg" isn't used.  It is only
 * left here to keep this code similar to the other interface handlers.  (And will probably be
 * removed at some point in the future.)
 **/
int cardif_windows_wireless_set_key_ext(context *ctx, int alg, 
				   unsigned char *addr, int keyidx, int settx, 
				   char *seq,  int seqlen, char *key, 
				   int keylen)
{
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR Buffer[sizeof(NDIS_OID)+FIELD_OFFSET(NDIS_802_11_KEY, KeyMaterial) + 32];
	PNDISPROT_SET_OID pSetOid = NULL;
	PNDIS_802_11_KEY pKey = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE)) return -1;

	if (alg == ALG_WEP)
	{
		// The caller should call cardif_windows_wireless_set_wep directly, but this is
		// just in case they do something stupid. ;)
		return cardif_windows_wireless_set_WEP_key(ctx, key, keylen, keyidx);
	}

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

	memset(&Buffer[0], 0x00, sizeof(Buffer));

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_ADD_KEY;

	pKey = (PNDIS_802_11_KEY)&pSetOid->Data[0];
	pKey->Length = FIELD_OFFSET(NDIS_802_11_KEY, KeyMaterial) + keylen; 
	pKey->KeyIndex = keyidx;
	pKey->KeyLength = keylen;

	debug_printf(DEBUG_INT, "Key Index = %d\n", pKey->KeyIndex);
	debug_printf(DEBUG_INT, "Key Length = %d\n", pKey->KeyLength);

	if (alg == ALG_TKIP)
	{
		// Need to swap the MICs (back) so Windows can handle it the way it wants.
		wpa_common_swap_rx_tx_mic(key);
	}

	if (seq == NULL)
	{
		pKey->KeyIndex |= MANUAL_RSC;
		memset((UCHAR *)&pKey->KeyRSC, 0x00, sizeof(NDIS_802_11_KEY_RSC));
	}
	else
	{
		pKey->KeyIndex |= MANUAL_RSC;
		memcpy(&pKey->KeyRSC, seq, seqlen);
	}
		
	if (addr != NULL)
	{
		memcpy(pKey->BSSID, addr, 6);
	}
	else
	{
		memset(pKey->BSSID, 0xff, 6);
	}

	if (settx == TRUE)
	{
		debug_printf(DEBUG_INT, "TX key!\n");
		pKey->KeyIndex |= (TX_KEY | PAIRWISE_KEY);
		//pKey->KeyIndex |= TX_KEY;
	}

	memcpy(&pKey->KeyMaterial, key, keylen);

	debug_printf(DEBUG_INT, "Key : ");
	debug_hex_printf(DEBUG_INT, pKey->KeyMaterial, keylen);

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
		switch (alg)
		{
		case ALG_TKIP:
			ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_TKIP_KEY, ctx->desc);
			break;

		case ALG_CCMP:
			ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_CCMP_KEY, ctx->desc);
			break;

		default:
			ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_UNKNOWN_KEY, ctx->desc);
			break;
		}

		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Set key IOCTL failed on interface '%s'.  Reason was : %s\n", 
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

  return XENONE;
}

/**
 * Push a TKIP key down to the wireless card.
 **/
int cardif_windows_wireless_set_tkip_key(context *ctx, 
				   unsigned char *addr, int keyidx, int settx, 
				   char *key, int keylen)
{
    char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

	return cardif_windows_wireless_set_key_ext(ctx, ALG_TKIP, addr, keyidx, settx, 
				   seq, 6, key, keylen);
}

/**
 * Push a CCMP key down to the wireless card.
 **/
int cardif_windows_wireless_set_ccmp_key(context *ctx,
				   unsigned char *addr, int keyidx, int settx,
				   char *key, int keylen)
{
    char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

	return cardif_windows_wireless_set_key_ext(ctx, ALG_CCMP, addr, keyidx, settx, 
				   seq, 6, key, keylen);
}

/**
 *  Set the WPA IE that is in use for this interface.
 *    On Windows, we don't have the ability to send in an IE, so this function
 *    does nothing.
 **/
int cardif_windows_wireless_set_wpa_ie(context *ctx, 
				 unsigned char *wpaie, unsigned int wpalen)
{
  return XENONE;
}

/**
 * Convert our cipher designator to something that will be understood by
 * Windows.
 */
DWORD cardif_windows_wireless_cipher(int cipher)
{
  switch (cipher)
    {
    case CIPHER_NONE:
      return 0xffffffff;
      break;

    case CIPHER_WEP40:
      return Ndis802_11Encryption1Enabled;
      break;

    case CIPHER_TKIP:
      return Ndis802_11Encryption2Enabled;
      break;

    case CIPHER_WRAP:
      debug_printf(DEBUG_NORMAL, "WRAP is not supported!\n");
      return 0xffffffff;
      break;

    case CIPHER_CCMP:
      return Ndis802_11Encryption3Enabled;
      break;
      
    case CIPHER_WEP104:
      return Ndis802_11Encryption1Enabled;
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown cipher value of %d!  (Turning on everything.)\n", cipher);
      return Ndis802_11Encryption3Enabled;
      break;
    }
}

/**
 * Set all of the card settings that are needed in order to complete an
 * association, so that we can begin the authentication.
 **/
void cardif_windows_wireless_associate(context *ctx)
{
  struct config_globals *globals = NULL;
  wireless_ctx *wctx = NULL;
  DWORD enc_mode = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  debug_printf(DEBUG_INT, "(Associate) Set infra mode.\n");
  if (cardif_windows_set_infra_mode(ctx) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set infrastructure mode failed on interface '%s'.\n",
		  ctx->desc);
	  return;
  }

  if ((config_ssid_get_ssid_abilities(ctx->intTypeData) & ABIL_RSN_IE) ||
	  ((config_ssid_find_by_name(wctx, wctx->cur_essid) == NULL) &&
	  ((ctx->conn != NULL) && (ctx->conn->association.association_type == ASSOC_TYPE_WPA2))))
  {
	  wctx->assoc_type = ASSOC_TYPE_WPA2;
	  // We are doing WPA2.
	  if (ctx->conn->association.auth_type != AUTH_PSK)
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA2-802.1X)\n");
		if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeWPA2, TRUE) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set the authentication mode to WPA2-Enterprise on interface '%s'.\n",
				ctx->desc);
			return;
		}
	  }
	  else
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA2-PSK)\n");
		if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeWPA2PSK, TRUE) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Request to set the authentication mode to WPA2-PSK failed on interface '%s'.\n",
				ctx->desc);
			return;
		}
	  }

	  if (ctx->conn->association.pairwise_keys == 0)
	  {
		wctx->groupKeyType = wpa2_get_group_crypt(ctx);
		wctx->pairwiseKeyType = wpa2_get_pairwise_crypt(ctx);
		if (wctx->pairwiseKeyType == 0xff) 
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't determine cipher type.  Forcing to CCMP.\n");
		  wctx->pairwiseKeyType = CIPHER_CCMP;
		}
	  }
	  else
	  {
		  debug_printf(DEBUG_INT, "Key type hard set to %d.\n", ctx->conn->association.pairwise_keys);
		  if (ctx->conn->association.pairwise_keys & CRYPT_FLAGS_CCMP)
		  {
			  wctx->pairwiseKeyType = CIPHER_CCMP;
		  }
		  else if (ctx->conn->association.pairwise_keys & CRYPT_FLAGS_TKIP)
		  {
			  wctx->pairwiseKeyType = CIPHER_TKIP;
		  }
		  else if (ctx->conn->association.pairwise_keys & (CRYPT_FLAGS_WEP40 | CRYPT_FLAGS_WEP104))
		  {
			  wctx->pairwiseKeyType = CIPHER_WEP104;
		  }
	  }
  } else if ((config_ssid_get_ssid_abilities(ctx->intTypeData) & ABIL_WPA_IE) ||
	  	  ((config_ssid_find_by_name(wctx, wctx->cur_essid) == NULL) &&
		  ((ctx->conn != NULL) && (ctx->conn->association.association_type == ASSOC_TYPE_WPA1))))
  {
	  wctx->assoc_type = ASSOC_TYPE_WPA1;
	  // We are doing WPA1.
	  if (ctx->conn->association.auth_type != AUTH_PSK)
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA-802.1X)\n");
		if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeWPA, TRUE) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set the authentication mode to WPA-Enterprise on interface '%s'.\n",
				ctx->desc);
			return;
		}
	  }
	  else
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA-PSK)\n");
		if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeWPAPSK, TRUE) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set the authentication mode to WPA-PSK on interface '%s'.\n",
				ctx->desc);
			return;
		}		
	  }

	  if (ctx->conn->association.pairwise_keys == 0)
	  {
		wctx->groupKeyType = wpa_get_group_crypt(ctx);
		wctx->pairwiseKeyType = wpa_get_pairwise_crypt(ctx);
		if (wctx->pairwiseKeyType == 0xff) 
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't determine cipher type.  Forcing to TKIP.\n");
		  wctx->pairwiseKeyType = CIPHER_TKIP;
		}
	  }
	  else
	  {
		  debug_printf(DEBUG_INT, "Key type hard set to %d.\n", ctx->conn->association.pairwise_keys);
		  if (ctx->conn->association.pairwise_keys & CRYPT_FLAGS_CCMP)
		  {
			  wctx->pairwiseKeyType = CIPHER_CCMP;
		  }
		  else if (ctx->conn->association.pairwise_keys & CRYPT_FLAGS_TKIP)
		  {
			  wctx->pairwiseKeyType = CIPHER_TKIP;
		  }
		  else if (ctx->conn->association.pairwise_keys & (CRYPT_FLAGS_WEP40 | CRYPT_FLAGS_WEP104))
		  {
			  wctx->pairwiseKeyType = CIPHER_WEP104;
		  }
	  }
  }

  enc_mode = cardif_windows_wireless_cipher(wctx->pairwiseKeyType);

  debug_printf(DEBUG_INT, "(Associate) Set encryption mode. (%d, %d, %d)\n", enc_mode,
	  Ndis802_11Encryption2Enabled, Ndis802_11Encryption3Enabled);
  if (cardif_windows_set_enc_mode(ctx, enc_mode, TRUE) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set encryption mode failed on interface '%s'.\n",
		  ctx->desc);
	  return;
  }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  debug_printf(DEBUG_INT, "(Associate) Set SSID (%s).\n", wctx->cur_essid);
  if (cardif_windows_wireless_set_ssid(ctx, wctx->cur_essid) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set the SSID failed on interface '%s'.\n",
		  ctx->desc);
	  return;
  }

  return;
}

// Windows doesn't seem to distinguish between WEP40 and WEP104.  So, "DOES_WEP" defines both.
#define DOES_WEP   (DOES_WEP40 | DOES_WEP104)

/**
 * Determine the types of encryption supported.
 **/
void cardif_windows_enc_mode_supported(NDIS_802_11_ENCRYPTION_STATUS es, uint32_t *enc)
{
        switch (es)
        {
			// The values below should never come up in the results.
        case Ndis802_11EncryptionNotSupported:
        case Ndis802_11EncryptionDisabled:
		case Ndis802_11Encryption1KeyAbsent:
		case Ndis802_11Encryption2KeyAbsent:
		case Ndis802_11Encryption3KeyAbsent:
			break;

		default:
			debug_printf(DEBUG_NORMAL, "Unknown/Invalid encryption method.  (%d)\n", es);
                break;

        case Ndis802_11Encryption1Enabled:
                (*enc) |= (DOES_WEP);
                break;

        case Ndis802_11Encryption2Enabled:
				(*enc) |= (DOES_WEP | DOES_TKIP);
				break;

        case Ndis802_11Encryption3Enabled:
                (*enc) |= (DOES_WEP | DOES_TKIP | DOES_CCMP);
                break;
       }
}

/**
 * Determine the authentication modes supported.
 **/
void cardif_windows_auth_mode_supported(NDIS_802_11_AUTHENTICATION_MODE am, uint32_t *capa)
{
        switch (am)
        {
			// Don't currently care about these.
        case Ndis802_11AuthModeOpen:
        case Ndis802_11AuthModeShared:
        case Ndis802_11AuthModeAutoSwitch:
                break;

        case Ndis802_11AuthModeWPA:
        case Ndis802_11AuthModeWPAPSK:
        case Ndis802_11AuthModeWPANone:
				(*capa) |= DOES_WPA;
                break;

        case Ndis802_11AuthModeWPA2:
        case Ndis802_11AuthModeWPA2PSK:
				(*capa) |= DOES_WPA2;
                break;

        default:
                fprintf(stderr, "Unknown authentication mode %d!\n", am);
                break;
       }
}

/**
 * \brief Attempt to check the encryption capabilities on the interface.
 *
 * @param[in,out] ctx   The context for the interface that we are trying to determine the
 *                      encryption capabilities of.
 **/
void cardif_windows_wireless_enc_capabilities_secondary(context *ctx)
{
	wireless_ctx *wctx = NULL;

	if (ctx->intType != ETH_802_11_INT) return;

	wctx = (wireless_ctx *)ctx->intTypeData;

	// First, check encryption modes.
	if (cardif_windows_set_enc_mode(ctx, Ndis802_11Encryption3Enabled, FALSE) == 0)
	{
		wctx->enc_capa |= (DOES_WEP | DOES_TKIP | DOES_CCMP);
	}
	else if (cardif_windows_set_enc_mode(ctx, Ndis802_11Encryption2Enabled, FALSE) == 0)
	{
		wctx->enc_capa |= (DOES_WEP | DOES_TKIP);
	}
	else if (cardif_windows_set_enc_mode(ctx, Ndis802_11Encryption1Enabled, FALSE) == 0)
	{
		wctx->enc_capa |= DOES_WEP;
	}
	else
	{
		wctx->enc_capa = 0;
	}

	cardif_windows_set_enc_mode(ctx, Ndis802_11EncryptionDisabled, FALSE);
}

/** 
 * \brief Attempt to determine the authentication modes supported by the wireless interface.
 *
 * @param[in,out] ctx   The context for the interface we are attempting to determine the
 *                      authentication mode for.
 **/
void cardif_windows_wireless_auth_capabilities_secondary(context *ctx)
{
	wireless_ctx *wctx = NULL;

	if (ctx->intType != ETH_802_11_INT) return;

	wctx = (wireless_ctx *)ctx->intTypeData;

	// Then authentication modes.
	if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeWPA, FALSE) == 0)
	{
		wctx->enc_capa |= DOES_WPA;
	}

	if (cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeWPA2, FALSE) == 0)
	{
		wctx->enc_capa |= DOES_WPA2;
	}

	cardif_windows_set_auth_mode(ctx, Ndis802_11AuthModeOpen, FALSE);
}

/**
 * \brief Attempt the alternate way of getting the capabilities of the wireless interface.
 *
 * @param[in,out] ctx   The context for the interface that we are trying to determine the
 *                      capabilities of.
 **/
void cardif_windows_wireless_capabilities_secondary(context *ctx)
{
	if (ctx->intType != ETH_802_11_INT) return;

	cardif_windows_wireless_enc_capabilities_secondary(ctx);

	cardif_windows_wireless_auth_capabilities_secondary(ctx);
}

/**
 * \brief Get the capability structure for an interface from Windows.
 *
 * @param[in] ctx   The context for the interface that we want to get the capabilities for.
 * @param[out] pcapa   The capabilities specified by Windows for the OID_802_11_CAPABILITY IOCTL.
 * 
 * \retval XENONE on success
 **/
int cardif_windows_get_capability(context *ctx, PNDIS_802_11_CAPABILITY *pcapa)
{
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR QueryBuffer[1024];
	PNDISPROT_QUERY_OID pQueryOid = NULL;
	void *retCapa = NULL;
	int i = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_CAPABILITY;

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, &QueryBuffer[0],
				sizeof(QueryBuffer), &QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned) == FALSE)
	{
		return -1;   // Couldn't do malloc.  We don't want to scream here, just return an error code.  (There may be cases where this IOCTL failing is perfectly fine.)
	}

	retCapa = malloc(BytesReturned - sizeof(pQueryOid->Oid));
	if (retCapa == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return XEMALLOC;
	}

	memcpy(retCapa, pQueryOid->Data, (BytesReturned - sizeof(pQueryOid->Oid)));
	(*pcapa) = retCapa;

	return XENONE;
}


/**
 * Determine the encryption capabilities for this driver/interface.
 **/
void cardif_windows_wireless_enc_capabilities(context *ctx)
{
	PNDIS_802_11_CAPABILITY pCapa = NULL;
	int i = 0;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

	if (cardif_windows_get_capability(ctx, &pCapa) != XENONE)
	{
		debug_printf(DEBUG_INT, "Couldn't determine capabilities the normal way, trying the icky way.\n");

		// Attempt the secondary way. :-/
		cardif_windows_wireless_capabilities_secondary(ctx);
		return;
	}

	if (pCapa == NULL) return;

	for (i=0; i < (int)pCapa->NoOfAuthEncryptPairsSupported; i++)
	{
		cardif_windows_auth_mode_supported(pCapa->AuthenticationEncryptionSupported[i].AuthModeSupported, &wctx->enc_capa);
		cardif_windows_enc_mode_supported(pCapa->AuthenticationEncryptionSupported[i].EncryptStatusSupported, &wctx->enc_capa);
	}

	FREE(pCapa);
}

/**
 * Delete any keys that are currently installed in the driver/interface.
 **/
int cardif_windows_wireless_delete_key(context *ctx, int key_idx, int set_tx)
{
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR Buffer[sizeof(NDIS_OID)+sizeof(NDIS_802_11_REMOVE_KEY)];
	PNDISPROT_SET_OID pSetOid = NULL;
	PNDIS_802_11_REMOVE_KEY pRkey = NULL;
	LPVOID lpMsgBuf = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_REMOVE_KEY;

	pRkey = (PNDIS_802_11_REMOVE_KEY)&pSetOid->Data[0];
	pRkey->Length = sizeof(NDIS_802_11_REMOVE_KEY);
	pRkey->KeyIndex = 0;
	pRkey->KeyIndex = key_idx;
	
	if (set_tx == TRUE)
	{
		memcpy(pRkey->BSSID, &ctx->dest_mac[0], 6);
		pRkey->KeyIndex |= (1 << 30);
	}
	else
	{
		memset(pRkey->BSSID, 0xff, 6);
	}

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Remove Key IOCTL failed on interface '%s'.  Reason was : %s\n",
			ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

  return XENONE;
}

/**
 * Enable the filter that only allows for EAPoL frames to get through.
 **/
int cardif_windows_wireless_drop_unencrypted(context *ctx, char endis)
{
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR Buffer[sizeof(NDIS_OID)+sizeof(NDIS_802_11_PRIVACY_FILTER)];
	PNDISPROT_SET_OID pSetOid = NULL;
	DWORD *filter = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_PRIVACY_FILTER;

	filter = (DWORD *)&pSetOid->Data[0];

	if (endis == TRUE)
	{
		(*filter) = Ndis802_11PrivFilter8021xWEP;
	}
	else
	{
		(*filter) = Ndis802_11PrivFilterAcceptAll;
	}

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, &Buffer[0],
				sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't set privacy filter status for interface '%s'.\n",
			ctx->desc);
		return -1;
	}

	return XENONE;
}

/**
 *  Take the RSSI value that Windows returns, and convert it to a percentage.  This
 *  call will only return something valid if the interface is associated.  If the
 *  interface isn't associated, then this function will return -1.
 **/
int cardif_windows_wireless_get_percent(context *ctx)
{
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR QueryBuffer[1024];
	PNDISPROT_QUERY_OID pQueryOid = NULL;
	NDIS_802_11_RSSI *pRssi = NULL;
	int i = 0;
	int percentage = -1;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_802_11_RSSI;

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, &QueryBuffer[0],
				sizeof(QueryBuffer), &QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't determine the RSSI value for interface '%s'.\n",
			ctx->desc);
		return -1;
	}

	pRssi = (NDIS_802_11_RSSI *)&pQueryOid->Data[0];

	// According to the windows documentation, the RSSI should vary between
	// -10 and -200 dBm.  So, we need to figure out a percentage based on that.

	// However, many examples on the net show that valid ranges will run from -50 to -100.

	percentage = (((*pRssi) + 100)*2);    // Make the dBm a positive number, and the lowest value
		                                  // equal to 0.  (So, the range will now be 0 - 190.)

	if (percentage > 100) percentage = 100;  // Some cards may have a percentage > 100 depending on their sensativity.  In those cases, only return 100. ;)

	return percentage;
}

/**
 * \brief Set the operational state for the interface.
 *
 * The set_operstate call was originally intended to be used only with Linux, however it
 * is also a good place to implement calls for other OSes to control DHCP setting, or 
 * other IP address related setting calls.
 *
 * @param[in] ctx   The context for the interface whose operational state we want to change.
 * @param[in] state   The new state to put the interface in.
 *
 **/
void cardif_windows_wireless_set_operstate(context *ctx, uint8_t state)
{
	int retval = 0;
	int dhcpenabled = 0;
	char *curip = NULL;
	struct win_sock_data *sockData = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	if (state == XIF_OPER_UP) 
	{
		if (ctx->conn == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Somehow you managed to get to an \"interface up\""
				" on interface '%s' without a connection being defined?\n", ctx->desc);
			debug_printf(DEBUG_NORMAL, "Please send your configuration file (edited for "
				"passwords) to the list.\n");
			return;
		}

		if ((ctx->auths != 0) && (ctx->conn->ip.renew_on_reauth != TRUE))
		{
			// Do nothing.
			return;
		}

		ctx->auths++;

		switch (ctx->conn->ip.type)
		{
		case CONFIG_IP_USE_NONE:
			debug_printf(DEBUG_INT, "Not doing anything. ;)\n");
			break;

		case CONFIG_IP_USE_DHCP:
			cardif_windows_is_dhcp_enabled(ctx, &dhcpenabled);
			
			if (dhcpenabled == FALSE)  // If DHCP is already enabled, don't try to do it again.
			{
				sockData = (struct win_sock_data *)ctx->sockData;

				if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return;

				if (sockData->osver < 2)
				{
					// Windows XP and earlier
					if (win_ip_manip_enable_dhcp(ctx) != 0)
					{
						debug_printf(DEBUG_NORMAL, "Unable to enable DHCP!\n");
					}
				}
				else
				{
					debug_printf(DEBUG_INT, "Turning on DHCP.\n");
					retval = cardif_windows_wmi_enable_dhcp(ctx);
					if (retval == 94)
					{
						// Try again.
						retval = cardif_windows_wmi_enable_dhcp(ctx);
						if (retval != 0)
						{
							debug_printf(DEBUG_NORMAL, "Couldn't enable DHCP on interface '%s'.  Error was %d.\n", ctx->desc, retval);
							break;
						}
					}
					else if (retval != 0)
					{
						debug_printf(DEBUG_NORMAL, "Couldn't enable DHCP on interface '%s'.  Error was %d.\n", ctx->desc, retval);
						break;
					}
				}
			}

			debug_printf(DEBUG_NORMAL, "Requesting DHCP information for '%s'.\n", ctx->desc);
			if (ctx->auths == 1) //&& (ctx->intType == ETH_802_11_INT))
			{
				// If we are in force auth state, only do this if we don't have a 'valid' IP address.
				// 'Valid' addresses are all but 0.0.0.0 and 169.254.x.x
				if (ctx->statemachine->curState == S_FORCE_AUTH)
				{
					curip = cardif_get_ip(ctx);
					if ((curip == NULL) || (strcmp("0.0.0.0", curip) == 0) || (strncmp("169.254", curip, 7) == 0))
					{
						cardif_windows_release_renew(ctx);
					}
					else
					{
						debug_printf(DEBUG_NORMAL, "Skipping release/renew because interface '%s' already seems to have a valid address.\n", ctx->desc);
					}
				}
				else
				{
					//cardif_windows_release_renew(ctx);
					cardif_windows_renew_ip(ctx);
				}
			}
			else
			{
				cardif_windows_renew_ip(ctx);
			}
			break;

		case CONFIG_IP_USE_STATIC:
			if (ctx->auths > 1) return;   // We don't need to "renew" a static IP address.

			debug_printf(DEBUG_INT, "Using a static IP!\n");
			retval = cardif_windows_set_static_ip(ctx, ctx->conn->ip.ipaddr, ctx->conn->ip.netmask, ctx->conn->ip.gateway);
			if (retval != 0)
			{
				debug_printf(DEBUG_NORMAL, "Failed to request setting of a static IP address on interface '%s'!\n", ctx->desc);
				break;
			}
			break;

		default:
			debug_printf(DEBUG_NORMAL, "Invalid IP address setting type on interface '%s'.  Not sure what you are thinking!?\n", ctx->desc);
			break;
		}
	} else if (state == XIF_OPER_DORMANT)
	{
		/// XXX Make this behavior configurable!
		if ((ctx != NULL) && (ctx->conn != NULL))
		{
			switch (ctx->conn->ip.type)
			{
			case CONFIG_IP_USE_DHCP:
				cardif_windows_is_dhcp_enabled(ctx, &dhcpenabled);
			
				if (dhcpenabled == FALSE)  // If DHCP is already enabled, don't try to do it again.
				{
					cardif_windows_enable_dhcp(ctx);
				}

				debug_printf(DEBUG_INT, "Requesting lease renew.\n");
				cardif_windows_release_renew(ctx);
				break;
			}
		}
	}
}

/**
 * \breif Query the interface to see how many PMKIDs it supports.
 *
 * @param[in] ctx   The context for the interface we want to query.
 * 
 * \retval 0..255   The number of PMKIDs that are supported.
 **/
uint8_t cardif_windows_wireless_get_num_pmkids(context *ctx)
{
	PNDIS_802_11_CAPABILITY pCapa = NULL;
	uint8_t result;

	if (cardif_windows_get_capability(ctx, &pCapa) != XENONE)
	{
		debug_printf(DEBUG_INT, "Unable to determine the number of supported PMKIDs.  Returning 0.\n");
		return 0;
	}

	result = (uint8_t)pCapa->NoOfPMKIDs;
	return result;
}

/**
 * \brief Apply the PMKIDs that are currently in our cache.
 *
 * @param[in] ctx   The context for the interface that we want to apply our PMKID cache to.
 *
 * \retval TRUE on success
 * \retval FALSE on failure
 **/
int cardif_windows_wireless_apply_pmkids(context *ctx, pmksa_list *pmklist)
{
	wireless_ctx *wctx = NULL;
	NDIS_802_11_PMKID *pPMKids = NULL;
	uint8_t *pmkid_buf = NULL;
	int i = 0;
	int numelems = 0;
	pmksa_cache_element *cur = NULL;
	ULONG buflen = 0;
	struct win_sock_data *sockData = NULL;
	DWORD BytesReturned = 0;
	UCHAR *Buffer;
	PNDISPROT_SET_OID pSetOid = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return FALSE;

	if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE)) return FALSE;

	if (!xsup_assert((ctx->sockData != NULL), "ctx->sockData != NULL", FALSE)) return FALSE;

	wctx = ctx->intTypeData;

	sockData = ctx->sockData;

	if (wctx->pmkids_supported > 0)
	{
		for (i = (wctx->pmkids_supported-1); i >= 0; i--)
		{
			if (pmklist[i].cache_element != NULL) numelems++;
		}
	}

	buflen = FIELD_OFFSET(NDIS_802_11_PMKID, BSSIDInfo) + (numelems * sizeof(BSSID_INFO));
	Buffer = Malloc(buflen + sizeof(NDISPROT_SET_OID));
	if (Buffer == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store the PMKID cache we want to apply to interface '%s'!\n", ctx->desc);
		return FALSE;
	}

	pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
	pSetOid->Oid = OID_802_11_PMKID;

	pPMKids = (PNDIS_802_11_PMKID)pSetOid->Data;

	pPMKids->Length = buflen;
	pPMKids->BSSIDInfoCount = numelems;

	if ((wctx->pmkids_supported > 0) && (numelems > 0))
	{
		for (i = 1; i <= numelems; i++)
		{
			memcpy(pPMKids->BSSIDInfo[i-1].BSSID, pmklist[wctx->pmkids_supported-i].cache_element->authenticator_mac, 6);
			memcpy(pPMKids->BSSIDInfo[i-1].PMKID, pmklist[wctx->pmkids_supported-i].cache_element->pmkid, sizeof(NDIS_802_11_PMKID_VALUE));
		}
	}

	debug_printf(DEBUG_INT, "PMKSA set OID (%d) :\n", pPMKids->Length);
	debug_hex_dump(DEBUG_INT, pSetOid->Data, pPMKids->Length);

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, Buffer,
				(buflen + sizeof(NDISPROT_SET_OID)), NULL, 0, &BytesReturned) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't set PMKIDs for interface '%s'.\n",
			ctx->desc);
		FREE(Buffer);
		return FALSE;
	}
	
//	debug_printf(DEBUG_NORMAL, "%d PMKID(s) set for interface '%s'.\n", pPMKids->BSSIDInfoCount, ctx->desc);
	FREE(Buffer);
	return TRUE;
}

struct cardif_funcs cardif_windows_wireless_driver = {
  cardif_windows_wireless_scan,                       // .scan
  cardif_windows_wireless_disassociate,               // .disassociate
  cardif_windows_wireless_set_WEP_key,                // .set_wep_key
  cardif_windows_wireless_set_tkip_key,               // .set_tkip_key
  cardif_windows_wireless_set_ccmp_key,               // .set_ccmp_key
  cardif_windows_wireless_delete_key,                 // .delete_key
  cardif_windows_wireless_associate,                  // .associate
  cardif_windows_wireless_get_ssid,                   // .get_ssid
  cardif_windows_wireless_get_bssid,                  // .get_bssid
  NULL,                                               // .wpa_state
  NULL,                                               // .wpa
  cardif_windows_wireless_wep_associate,              // .wep_associate
  NULL,                                               // .countermeasures
  cardif_windows_wireless_drop_unencrypted,           // .drop_unencrypted
  cardif_windows_wireless_get_wpa_ie,                 // .get_wpa_ie
  cardif_windows_wireless_get_wpa2_ie,                // .get_wpa2_ie
  cardif_windows_wireless_enc_disable,                // .enc_disable
  cardif_windows_wireless_enc_capabilities,			  // .enc_capabilities
  cardif_windows_wireless_set_bssid,                  // .set_bssid
  cardif_windows_wireless_set_operstate,			  // .set_operstate
  NULL,												  // .set_linkmode
  cardif_windows_wireless_get_percent,                // .get_signal_percent
  cardif_windows_wireless_apply_pmkids,				  // .apply_pmkid_data
  cardif_windows_wireless_get_freq,                   // .get_freq
};

