/**
 * Windows OID_DOT11 * wireless interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_dot11.c
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
#include "cardif_windows_dot11.h"
#include "../../wireless_sm.h"
#include "../../timer.h"
#include "../../wpa.h"
#include "../../wpa2.h"

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

/**
 * This will be called ~7 seconds after a request to scan.  According to
 * the Windows documentation, you need to wait at least 6 seconds before
 * requesting scan data, which is where 7 seconds comes from. ;)
 **/
void cardif_windows_dot11_scan_timeout(context *ctx)
{
  DWORD BytesReturned;
  UCHAR Buffer[65535];  // 64k of scan data is a *LOT*!
  PNDISPROT_QUERY_OID pQueryOid;
  PNDIS_802_11_BSSID_LIST_EX pBssidList;
  PNDIS_WLAN_BSSID_EX pBssidEx;
  PNDIS_802_11_SSID pSsid;
  UCHAR *ofs = NULL;
  char rssi;
  int i;
  char ssid[33];
  struct win_sock_data *sockData = NULL;
  LPVOID lpMsgBuf;
  wireless_ctx *wctx = NULL;
  uint8_t percentage;

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
	  debug_printf(DEBUG_NORMAL, "Attempt to get scan data results failed!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_GETTING_SCAN_DATA, ctx->desc);
  		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
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

	  debug_printf(DEBUG_INT, "Found SSID : %s\n", ssid);
	  config_ssid_add_ssid_name(wctx, ssid);

	  debug_printf(DEBUG_INT, "BSSID : ");
	  debug_hex_printf(DEBUG_INT, pBssidEx->MacAddress, 6);
	  config_ssid_add_bssid(wctx, pBssidEx->MacAddress);

	  rssi = pBssidEx->Rssi;

	  // According to the windows documentation, the RSSI should vary between
	  // -10 and -200 dBm.  So, we need to figure out a percentage based on that.

	  // However, many examples on the net show that valid ranges will run from -50 to -100.

	  percentage = (((rssi) + 100)*2);    // Make the dBm a positive number, and the lowest value
	  	                                    // equal to 0.  (So, the range will now be 0 - 190.)

	  if (percentage > 100) percentage = 100;  // Some cards may have a percentage > 100 depending on their sensativity.  In those cases, only return 100. ;)

	  debug_printf(DEBUG_INT, "RSSI : %d\n", rssi);
	  config_ssid_add_qual(wctx, 0, rssi, 0, percentage);

	  debug_printf(DEBUG_INT, "Privacy : %d\n", pBssidEx->Privacy);
	  if (pBssidEx->Privacy == 1) config_ssid_update_abilities(wctx, ABIL_ENC);

	  cardif_windows_dot11_parse_ies(ctx, (uint8_t *)&pBssidEx->IEs[sizeof(NDIS_802_11_FIXED_IEs)], pBssidEx->IELength);

bad_strncpy:
	  ofs += pBssidEx->Length;
  }

  UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);

  return;
}

/**
 * \brief Determine if the power to the wireless interface is ON or not.
 *
 * @param[in] ctx   The context for the wireless interface we want to check.
 *
 * \retval TRUE   if the power is on
 * \retval FALSE  if the power is off, or we get an error.
 **/
int cardif_windows_dot11_is_power_on(context *ctx)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+4];
  PNDISPROT_QUERY_OID pQueryOid = NULL;
  struct win_sock_data *sockData = NULL;
  LPVOID lpMsgBuf = NULL;
  unsigned int *powered = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  memset(&Buffer, 0x00, sizeof(Buffer));
  pQueryOid = (PNDISPROT_QUERY_OID)&Buffer[0];
 
  pQueryOid->Oid = OID_DOT11_NIC_POWER_STATE;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, (LPVOID)&Buffer[0], sizeof(Buffer), 
					(LPVOID)&Buffer[0], sizeof(Buffer), &BytesReturned) == FALSE)
  {
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Couldn't determine if the interface is powered on interface '%s'.  Reason was : %s\n", ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return FALSE;
  }

  powered = &pQueryOid->Data[0];

  debug_printf(DEBUG_NORMAL, "Powered = %d\n", (*powered));

  if ((*powered) == 0) return FALSE;

  return TRUE;
}

int cardif_windows_dot11_reset(context *ctx)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DOT11_RESET_REQUEST)];
  PNDISPROT_SET_OID pSetOid = NULL;
  struct win_sock_data *sockData = NULL;
  LPVOID lpMsgBuf = NULL;
  PDOT11_RESET_REQUEST drr = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  memset(&Buffer, 0x00, sizeof(Buffer));
  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
 
  pSetOid->Oid = OID_DOT11_RESET_REQUEST;

  drr = pSetOid->Data;
  drr->bSetDefaultMIB = 0xffff;
  drr->dot11ResetType = dot11_reset_type_phy_and_mac;
  memcpy(drr->dot11MacAddress, ctx->source_mac, 6);

  debug_hex_dump(DEBUG_NORMAL, pSetOid->Data, sizeof(DOT11_RESET_REQUEST));

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, (LPVOID)&Buffer[0], sizeof(Buffer), 
					(LPVOID)&Buffer[0], sizeof(Buffer), &BytesReturned) == FALSE)
  {
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Couldn't reset interface '%s'.  Reason was : %s\n", ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return FALSE;
  }

  return TRUE;
}

/**
 * \brief Determine if the power to the wireless interface is ON or not.
 *
 * @param[in] ctx   The context for the wireless interface we want to check.
 *
 * \retval TRUE   if the power is on
 * \retval FALSE  if the power is off, or we get an error.
 **/
int cardif_windows_dot11_set_pwr_mgmt(context *ctx)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+4];
  PNDISPROT_SET_OID pSetOid = NULL;
  struct win_sock_data *sockData = NULL;
  LPVOID lpMsgBuf = NULL;
  unsigned int *powered = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  memset(&Buffer, 0x00, sizeof(Buffer));
  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
 
  pSetOid->Oid = OID_DOT11_POWER_MGMT_REQUEST;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, (LPVOID)&Buffer[0], sizeof(Buffer), 
					(LPVOID)&Buffer[0], sizeof(Buffer), &BytesReturned) == FALSE)
  {
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Couldn't set power saving on interface '%s'.  Reason was : %s\n", ctx->desc, lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return FALSE;
  }

  return TRUE;
}

int cardif_windows_dot11_get_extsta_capabilities(context *ctx, DOT11_EXTSTA_CAPABILITY *capa)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DOT11_EXTSTA_CAPABILITY)+1000];
  PNDISPROT_QUERY_OID pQueryOid;
  struct win_sock_data *sockData;
  LPVOID lpMsgBuf;
  PDOT11_EXTSTA_CAPABILITY pCapa;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  memset(&Buffer, 0x00, sizeof(Buffer));
  pQueryOid = (PNDISPROT_QUERY_OID)&Buffer[0];
 
  pQueryOid->Oid = OID_DOT11_EXTSTA_CAPABILITY;
  pCapa = pQueryOid->Data;

  pCapa->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  pCapa->Header.Revision = DOT11_EXTSTA_CAPABILITY_REVISION_1;
  pCapa->Header.Size = sizeof(DOT11_EXTSTA_CAPABILITY);

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, (LPVOID)&Buffer[0], sizeof(Buffer), 
					(LPVOID)&Buffer[0], sizeof(Buffer), &BytesReturned) == FALSE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't get interface capabilities!\n");
	  //ipc_events_error(ctx, IPC_EVENT_LOG_CANT_GET_CAPABILITIES, ctx->desc, NULL);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return -1;
  }

  memcpy(capa, &Buffer[sizeof(NDIS_OID)], sizeof(DOT11_EXTSTA_CAPABILITY));

  return XENONE;
}

int cardif_windows_dot11_get_mode_capabilities(context *ctx)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DOT11_OPERATION_MODE_CAPABILITY)+10];
  PNDISPROT_QUERY_OID pQueryOid;
  struct win_sock_data *sockData;
  LPVOID lpMsgBuf;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  memset(&Buffer, 0x00, sizeof(Buffer));
  pQueryOid = (PNDISPROT_QUERY_OID)&Buffer[0];
 
  pQueryOid->Oid = OID_DOT11_EXTSTA_CAPABILITY;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, (LPVOID)&Buffer[0], sizeof(Buffer), 
					(LPVOID)&Buffer[0], sizeof(Buffer), &BytesReturned) == FALSE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't get interface capabilities!\n");
	  //ipc_events_error(ctx, IPC_EVENT_LOG_CANT_GET_CAPABILITIES, ctx->desc, NULL);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return -1;
  }

  //memcpy(capa, &Buffer[sizeof(NDIS_OID)], sizeof(DOT11_EXTSTA_CAPABILITY));

  return XENONE;
}

/**
 * Tell the wireless card to scan for wireless networks.
 **/
int cardif_windows_dot11_scan(context *ctx, char passive)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DOT11_SCAN_REQUEST_V2)+32];
  PNDISPROT_SET_OID pSetOid;
  struct win_sock_data *sockData;
  LPVOID lpMsgBuf;
  DOT11_EXTSTA_CAPABILITY capa;
  PDOT11_SCAN_REQUEST_V2 pScanReq = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return XEMALLOC;

  debug_printf(DEBUG_NORMAL, "Starting scan......\n");
  if (passive == TRUE)
  {
	  // Windows XP doesn't do passive, so for now, return an error.
	  debug_printf(DEBUG_NORMAL, "NO PASSIVES HERE!\n");
	  return XECANTPASSIVE;
  }

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return XEMALLOC;

  /*
	cardif_windows_dot11_get_mode_capabilities(ctx);

  if (cardif_windows_dot11_get_extsta_capabilities(ctx, &capa) != XEMALLOC)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't get interface capabilities!\n");
	  return XEGENERROR;
  }
  else
  {
	  // Display some information.
	  debug_printf(DEBUG_NORMAL, "SSID Scan List Size = %ld\n", capa.uScanSSIDListSize);
	  debug_printf(DEBUG_NORMAL, "Desired SSID List Size = %ld\n", capa.uDesiredSSIDListSize);
	  debug_printf(DEBUG_NORMAL, "Desired BSSID List Size = %ld\n", capa.uDesiredBSSIDListSize);
  }
  debug_printf(DEBUG_NORMAL, "++++++++++++++++++++++++++++ Done!\n");
*/

  memset(&Buffer, 0x00, sizeof(Buffer));
  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];
 
  pSetOid->Oid = OID_DOT11_SCAN_REQUEST;
  
  pScanReq = pSetOid->Data;

  pScanReq->dot11BSSType = dot11_BSS_type_any;
  memset(pScanReq->dot11BSSID, 0xff, 6);  // Get everything.
  pScanReq->dot11ScanType = dot11_scan_type_auto;
  pSetOid->Data[0x0f] = 0xff;
  pSetOid->Data[0x18] = 0xff;
  pSetOid->Data[0x30] = 0xff;
//  pScanReq->bRestrictedScan = 0x10000;
  /*
  pScanReq->udot11SSIDsOffset = 128;
  pScanReq->uNumOfdot11SSIDs = 0x01;
  pScanReq->uRequestIDsOffset = 0x24;
*/
  debug_printf(DEBUG_NORMAL, "Scan data (%d) :\n", (sizeof(DOT11_SCAN_REQUEST_V2)+32));
  debug_hex_dump(DEBUG_NORMAL, pSetOid->Data, sizeof(DOT11_SCAN_REQUEST_V2)+32);

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, (LPVOID)&Buffer[0], sizeof(NDISPROT_QUERY_OID)+4, 
					NULL, 0, &BytesReturned) == FALSE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't start a scan!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_CANT_START_SCAN, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
	  return -1;
  }

  // Once we had done that, we need to wait for at least 6 seconds to get full scan data back.
  // So set a timer to check in 8 seconds.
  timer_add_timer(ctx, SCANCHECK_TIMER, 8, NULL, cardif_windows_dot11_scan_timeout);
  return XENONE;
}

/**
 *  Get the list of IEs that we used to associate.
 *
 *  When this function is called, "ie_size" should be the size of the buffer defined by
 *  "ies".  On return, "ie_size" will be the length of the IE block copied in to the buffer.
 **/
int cardif_windows_dot11_get_ies(context *ctx, char *ies, int *ie_size)
{
    DWORD  BytesReturned;
    DWORD  result;
    UCHAR  QueryBuffer[65535];              // Unlikely that we would have a result this size!
    PNDISPROT_QUERY_OID pQueryOid;
	PNDIS_802_11_ASSOCIATION_INFORMATION pInfo;
	struct win_sock_data *sockData;
	LPVOID lpMsgBuf;

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

        debug_printf(DEBUG_NORMAL, "Get association information failed.  (%x)\n", result);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
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
int cardif_windows_dot11_find_wpa2_ie(context *ctx, char *in_ie, int in_size,
										char *out_ie, int *out_size)
{
	const char wpa2oui[3] = {0x00, 0x0f, 0xac};
	unsigned int i;
	char done;
	wireless_ctx *wctx;

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
			if (in_ie[i+1] >= 8)
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
int cardif_windows_dot11_get_wpa2_ie(context *ctx, char *iedata, int *ielen)
{
	char ie_buf[65535];
	int ie_size = 65535;

	if (cardif_windows_dot11_get_ies(ctx, ie_buf, &ie_size) != XENONE)
		return -1;
	
	debug_printf(DEBUG_INT, "IEs returned (Length : %d) :\n", ie_size);
	debug_hex_printf(DEBUG_INT, ie_buf, ie_size);

	if (cardif_windows_dot11_find_wpa2_ie(ctx, ie_buf, ie_size, iedata, ielen) != XENONE)
		return -1;

  return XENONE;
}

/**
 * Scan through whatever was returned by the scan, and pull
 * out any interesting IEs.
 **/
void cardif_windows_dot11_parse_ies(context *ctx, uint8_t *iedata, int ielen)
{
  int i = 0;
  int wpalen;
  uint8_t wpaie[255];
  uint8_t abilities = 0;
  uint8_t authtypes = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return;

  if (!xsup_assert((ielen > 0), "ielen > 0", FALSE))
    return;

  if (!xsup_assert((ielen < 256), "ielen < 256", FALSE))
    return;

  if (cardif_windows_dot11_find_wpa_ie(ctx, iedata, ielen, wpaie, &wpalen) == XENONE)
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

  if (cardif_windows_dot11_find_wpa2_ie(ctx, iedata, ielen, wpaie, &wpalen) == XENONE)
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
 * Set the authentication (as in 802.11, not 802.1X) mode that we will be using to
 * create an association with the AP.
 **/
int cardif_windows_dot11_set_auth_mode(context *ctx, DWORD authmode)
{
  DWORD Bytes;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DOT11_AUTH_ALGORITHM_LIST)];  
  PNDISPROT_SET_OID pSetOid;
  struct win_sock_data *sockData;
  PDOT11_AUTH_ALGORITHM_LIST algList;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];

  pSetOid->Oid = OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM;
  algList = pSetOid->Data;

  algList->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  algList->Header.Revision = DOT11_AUTH_ALGORITHM_LIST_REVISION_1;
  algList->Header.Size = sizeof(DOT11_AUTH_ALGORITHM_LIST);
  algList->uNumOfEntries = 1;
  algList->uTotalNumOfEntries = 1;

  algList->AlgorithmIds[0] = authmode;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &Bytes) == FALSE)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to set authentication mode failed!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_802_11_AUTH_MODE, ctx->desc);
	  return -1;
  }

  return XENONE;
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
int cardif_windows_dot11_set_enc_mode(context *ctx, DWORD encmode)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DWORD)];  
  PNDISPROT_SET_OID pSetOid;
  struct win_sock_data *sockData;
  DWORD *mode;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];

  pSetOid->Oid = OID_802_11_ENCRYPTION_STATUS;
  mode = (DWORD *)&pSetOid->Data[0];

  (*mode) = encmode;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to set encryption mode failed!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_802_11_ENC_MODE, ctx->desc);
	  return -1;
  }

  return XENONE;
}

/**
 * Set the card in to infrastructure mode.  This will case all keys to be deleted.
 **/
int cardif_windows_dot11_set_infra_mode(context *ctx)
{
  DWORD BytesReturned;
  UCHAR Buffer[sizeof(NDIS_OID)+sizeof(DWORD)];  
  PNDISPROT_SET_OID pSetOid;
  struct win_sock_data *sockData;
  DWORD *mode;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return -1;

  pSetOid = (PNDISPROT_SET_OID)&Buffer[0];

  pSetOid->Oid = OID_802_11_INFRASTRUCTURE_MODE;
  mode = (DWORD *)&pSetOid->Data[0];

  (*mode) = Ndis802_11Infrastructure;

  if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE, 
					(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to set infrastructure mode failed!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_802_11_INFRA_MODE, ctx->desc);
	  return -1;
  }

  return XENONE;
}

/**
 * Disable encryption on the wireless card.  This is used in cases
 * where we roam to a different AP and the card needs to have WEP
 * disabled.
 **/
int cardif_windows_dot11_enc_disable(context *ctx)
{
	return cardif_windows_dot11_set_auth_mode(ctx, Ndis802_11AuthModeOpen);
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
int cardif_windows_dot11_find_wpa_ie(context *ctx, uint8_t *in_ie, unsigned int in_size,
										uint8_t *out_ie, uint8_t *out_size)
{
	const char wpaoui[3] = {0x00, 0x50, 0xf2};
	unsigned int i;
	char done;
	wireless_ctx *wctx;

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
int cardif_windows_dot11_get_wpa_ie(context *ctx, 
				 char *iedata, int *ielen)
{
	uint8_t ie_buf[65535];
	unsigned int ie_size = 65535;
	uint8_t len;

	(*ielen) = 0;

	if (cardif_windows_dot11_get_ies(ctx, ie_buf, &ie_size) != XENONE)
		return -1;
	
	debug_printf(DEBUG_INT, "IEs returned (Length : %d) :\n", (*ielen));
	debug_hex_printf(DEBUG_INT, ie_buf, *ielen);

	if (cardif_windows_dot11_find_wpa_ie(ctx, ie_buf, ie_size, iedata, &len) != XENONE)
		return -1;

	(*ielen) = len;

  return XENONE;
}

/**
 * Set encryption to open on the wireless card.
 **/
int cardif_windows_dot11_enc_open(context *ctx)
{
	return cardif_windows_dot11_set_auth_mode(ctx, Ndis802_11AuthModeOpen);
}

/**
 * Set the SSID of the wireless card.
 **/
int cardif_windows_dot11_set_ssid(context *ctx, char *ssid_name)
{
    DWORD  BytesReturned;
    DWORD  result;
    UCHAR  Buffer[sizeof(NDIS_OID) + sizeof(NDIS_802_11_SSID)];
    PNDISPROT_SET_OID pSetOid;
	struct win_sock_data *sockData;
	PNDIS_802_11_SSID pSsid;
	LPVOID lpMsgBuf;

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

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
			(LPVOID)&Buffer[0], sizeof(Buffer), NULL, 0, &BytesReturned) == FALSE)
	{
        debug_printf(DEBUG_NORMAL, "Set SSID IOCTL failed.\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_SSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

	return XENONE;
}

/**
 * Set the Broadcast SSID (MAC address) of the AP we are connected to.
 **/
int cardif_windows_dot11_set_bssid(context *ctx, uint8_t *bssid)
{
    DWORD  BytesReturned;
    DWORD  result;
    UCHAR  Buffer[sizeof(NDIS_OID) + 6];
    PNDISPROT_SET_OID pSetOid;
	struct win_sock_data *sockData;
	LPVOID lpMsgBuf;

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
        debug_printf(DEBUG_NORMAL, "Set BSSID IOCTL failed.\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_BSSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

  return XENONE;
}


/**
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 **/
int cardif_windows_dot11_get_bssid(context *ctx, 
				char *bssid_dest)
{
    DWORD  BytesReturned;
    DWORD  result;
    UCHAR  QueryBuffer[sizeof(NDIS_OID) + 6];
    PNDISPROT_QUERY_OID pQueryOid;
	struct win_sock_data *sockData;
	LPVOID lpMsgBuf;

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

        debug_printf(DEBUG_NORMAL, "Get BSSID IOCTL failed.  (%x)\n", result);
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_GETTING_BSSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

	// Otherwise, pQueryOid->Data should contain the BSSID.
	memcpy(bssid_dest, pQueryOid->Data, 6);

	return XENONE;
}

/**
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 **/
int cardif_windows_dot11_get_ssid(context *ctx, char *ssid_name, unsigned int ssidsize)
{
    DWORD  BytesReturned;
    DWORD  result;
    UCHAR  QueryBuffer[sizeof(NDIS_OID) + sizeof(NDIS_802_11_SSID)];
    PNDISPROT_QUERY_OID pQueryOid;
	struct win_sock_data *sockData;
	PNDIS_802_11_SSID pSsid;
	LPVOID lpMsgBuf;

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
			ctx->
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

        debug_printf(DEBUG_NORMAL, "Get SSID IOCTL failed.  (%x)\n", result);
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_GETTING_SSID, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
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
int cardif_windows_dot11_wep_associate(context *ctx, int zero_keys)
{
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

  debug_printf(DEBUG_INT, "(WEP Associate) Set infra mode.\n");
  if (cardif_windows_dot11_set_infra_mode(ctx) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set infrastructure mode failed.\n");
	  return -1;
  }

  debug_printf(DEBUG_INT, "(WEP Associate) Set auth mode.\n");
  if (cardif_windows_dot11_set_auth_mode(ctx, Ndis802_11AuthModeOpen) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set the authentication mode to Open failed.\n");
	  return -1;
  }
  wctx->assoc_type = ASSOC_TYPE_OPEN;

  if (ctx->conn->association.auth_type == AUTH_NONE)
  {
	  debug_printf(DEBUG_INT, "(WEP Associate) Disable encryption.\n");
	  if (cardif_windows_dot11_set_enc_mode(ctx, Ndis802_11EncryptionDisabled) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Request to set encryption mode failed.\n");
		  return -1;
	  }
  }
  else
  {
	debug_printf(DEBUG_INT, "(WEP Associate) Set encryption mode.\n");
	if (cardif_windows_dot11_set_enc_mode(ctx, Ndis802_11Encryption1Enabled) != 0)
	{
	  debug_printf(DEBUG_NORMAL, "Request to set encryption mode failed.\n");
	  return -1;
	}
  }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

  debug_printf(DEBUG_INT, "(WEP Associate) Set SSID.\n");
  if (cardif_windows_dot11_set_ssid(ctx, wctx->cur_essid) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set the SSID failed.\n");
	  return -1;
  }

  return XENONE;
}

/**
 * Send a disassociate request to the AP we are currently connected to.
 **/
int cardif_windows_dot11_disassociate(context *ctx, int reason)
{
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return -1;

	// Probably need to fix this to something else.

	// This will clear any keys in the key cache.
	cardif_windows_dot11_set_infra_mode(ctx);
	cardif_windows_dot11_set_ssid(ctx, "unlikelyssid");

	// Set our association mode back to unknown.
	wctx->assoc_type = ASSOC_TYPE_UNKNOWN;

	// Sending a disassociate turns off the radio, which is probably not what we want!
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
int cardif_windows_dot11_set_WEP_key(context *ctx, uint8_t *key, 
				  int keylen, int keyidx)
{
	struct win_sock_data *sockData;
	DWORD BytesReturned;
	UCHAR Buffer[sizeof(NDIS_OID)+sizeof(NDIS_802_11_WEP)+13];
	PNDISPROT_SET_OID pSetOid;
	PNDIS_802_11_WEP pKey;
	LPVOID lpMsgBuf;

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
        debug_printf(DEBUG_NORMAL, "Set WEP Key IOCTL failed.\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_SETTING_WEP_KEY, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
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
int cardif_windows_dot11_set_key_ext(context *ctx, int alg, 
				   unsigned char *addr, int keyidx, int settx, 
				   char *seq,  int seqlen, char *key, 
				   int keylen)
{
	struct win_sock_data *sockData;
	DWORD BytesReturned;
	UCHAR Buffer[sizeof(NDIS_OID)+FIELD_OFFSET(NDIS_802_11_KEY, KeyMaterial) + 32];
	PNDISPROT_SET_OID pSetOid;
	PNDIS_802_11_KEY pKey;
	LPVOID lpMsgBuf;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return -1;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE)) return -1;

	if (alg == ALG_WEP)
	{
		// The caller should call cardif_windows_dot11_set_wep directly, but this is
		// just in case they do something stupid. ;)
		return cardif_windows_dot11_set_WEP_key(ctx, key, keylen, keyidx);
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
        debug_printf(DEBUG_NORMAL, "Set Key IOCTL failed.\n");

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
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

  return XENONE;
}

/**
 * Push a TKIP key down to the wireless card.
 **/
int cardif_windows_dot11_set_tkip_key(context *ctx, 
				   unsigned char *addr, int keyidx, int settx, 
				   char *key, int keylen)
{
    char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

	return cardif_windows_dot11_set_key_ext(ctx, ALG_TKIP, addr, keyidx, settx, 
				   seq, 6, key, keylen);
}

/**
 * Push a CCMP key down to the wireless card.
 **/
int cardif_windows_dot11_set_ccmp_key(context *ctx,
				   unsigned char *addr, int keyidx, int settx,
				   char *key, int keylen)
{
    char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

	return cardif_windows_dot11_set_key_ext(ctx, ALG_CCMP, addr, keyidx, settx, 
				   seq, 6, key, keylen);
}

/**
 *  Set the WPA IE that is in use for this interface.
 *    On Windows, we don't have the ability to send in an IE, so this function
 *    does nothing.
 **/
int cardif_windows_dot11_set_wpa_ie(context *ctx, 
				 unsigned char *wpaie, unsigned int wpalen)
{
  return XENONE;
}

/**
 * Convert our cipher designator to something that will be understood by
 * Windows.
 */
DWORD cardif_windows_dot11_cipher(int cipher)
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
      debug_printf(DEBUG_NORMAL, "Unknown cipher value of %d!\n", cipher);
      return 0xff;
      break;
    }
}

/**
 * Set all of the card settings that are needed in order to complete an
 * association, so that we can begin the authentication.
 **/
void cardif_windows_dot11_associate(context *ctx)
{
  struct config_globals *globals;
  wireless_ctx *wctx;
  DWORD enc_mode;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  /*
  debug_printf(DEBUG_INT, "(Associate) Set infra mode.\n");
  if (cardif_windows_dot11_set_infra_mode(ctx) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set infrastructure mode failed.\n");
	  return;
  }*/

  if (config_ssid_get_ssid_abilities(ctx->intTypeData) & ABIL_RSN_IE)
  {
	  wctx->assoc_type = ASSOC_TYPE_WPA2;
	  // We are doing WPA2.
	  if (ctx->conn->association.auth_type != AUTH_PSK)
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA2-802.1X)\n");
		if (cardif_windows_dot11_set_auth_mode(ctx, DOT11_AUTH_ALGO_RSNA) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set the authentication mode to WPA2-Enterprise.\n");
			return;
		}
	  }
	  else
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA2-PSK)\n");
		if (cardif_windows_dot11_set_auth_mode(ctx, DOT11_AUTH_ALGO_RSNA_PSK) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Request to set the authentication mode to WPA2-PSK failed.\n");
			return;
		}
	  }

	  wctx->groupKeyType = wpa2_get_group_crypt(ctx);
	  wctx->pairwiseKeyType = wpa2_get_pairwise_crypt(ctx);

  } else if (config_ssid_get_ssid_abilities(ctx->intTypeData) & ABIL_WPA_IE)
  {
	  wctx->assoc_type = ASSOC_TYPE_WPA1;
	  // We are doing WPA1.
	  if (ctx->conn->association.auth_type != AUTH_PSK)
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA-802.1X)\n");
		if (cardif_windows_dot11_set_auth_mode(ctx, DOT11_AUTH_ALGO_WPA) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set the authentication mode to WPA-Enterprise.\n");
			return;
		}
	  }
	  else
	  {
		debug_printf(DEBUG_INT, "(Associate) Set auth mode.  (WPA-PSK)\n");
		if (cardif_windows_dot11_set_auth_mode(ctx, DOT11_AUTH_ALGO_WPA_PSK) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set the authentication mode to WPA-PSK.\n");
			return;
		}		
	  }

	  wctx->groupKeyType = wpa_get_group_crypt(ctx);
	  wctx->pairwiseKeyType = wpa_get_pairwise_crypt(ctx);
  }

  enc_mode = cardif_windows_dot11_cipher(wctx->pairwiseKeyType);

  debug_printf(DEBUG_INT, "(Associate) Set encryption mode.\n");
  if (cardif_windows_dot11_set_enc_mode(ctx, enc_mode) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set encryption mode failed.\n");
	  return;
  }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  debug_printf(DEBUG_INT, "(Associate) Set SSID.\n");
  if (cardif_windows_dot11_set_ssid(ctx, wctx->cur_essid) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Request to set the SSID failed.\n");
	  return;
  }

  return;
}

// Windows doesn't seem to distinguish between WEP40 and WEP104.  So, "DOES_WEP" defines both.
#define DOES_WEP   (DOES_WEP40 | DOES_WEP104)

/**
 * Determine the uncast encryption pairs
 **/
void cardif_windows_dot11_enc_pairs(context *ctx)
{
	struct win_sock_data *sockData;
	DWORD BytesReturned;
	UCHAR QueryBuffer[1024];
	PNDISPROT_QUERY_OID pQueryOid;
	PDOT11_AUTH_CIPHER_PAIR_LIST pCipherList;
	int i;
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE)) return;

	pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
	pQueryOid->Oid = OID_DOT11_SUPPORTED_UNICAST_ALGORITHM_PAIR;
	pCipherList = pQueryOid->Data;
	pCipherList->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	pCipherList->Header.Revision = DOT11_AUTH_CIPHER_PAIR_LIST_REVISION_1;
	pCipherList->Header.Size = sizeof(DOT11_AUTH_CIPHER_PAIR_LIST);

	// XXX Do this better!!!!
	pCipherList->uNumOfEntries = 20;
	pCipherList->uTotalNumOfEntries = 20;

	if (devioctl_blk(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE, &QueryBuffer[0],
				sizeof(QueryBuffer), &QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine the capabilities of this interface.\n");
		wctx->enc_capa = 0;
		return;
	}

	debug_printf(DEBUG_NORMAL, " ------------ uNumOfEntries = %d\n", pCipherList->uNumOfEntries);
	debug_printf(DEBUG_NORMAL, " ------------ uTotalNumOfEntries = %d\n", pCipherList->uTotalNumOfEntries);

	debug_printf(DEBUG_NORMAL, "Auth/Enc types : \n");
	for (i = 0; i < pCipherList->uTotalNumOfEntries; i++)
	{
		switch (pCipherList->AuthCipherPairs[i].AuthAlgoId)
		{
		case DOT11_AUTH_ALGO_80211_OPEN:
			debug_printf(DEBUG_NORMAL, "\tAuth : Open\n");
			break;

		case DOT11_AUTH_ALGO_80211_SHARED_KEY:
			debug_printf(DEBUG_NORMAL, "\tAuth : Shared\n");
			break;

		case DOT11_AUTH_ALGO_WPA:
			debug_printf(DEBUG_NORMAL, "\tAuth : WPA\n");
			wctx->enc_capa |= DOES_WPA;
			break;

		case DOT11_AUTH_ALGO_WPA_PSK:
			debug_printf(DEBUG_NORMAL, "\tAuth : WPA-PSK\n");
			wctx->enc_capa |= DOES_WPA;
			break;

		case DOT11_AUTH_ALGO_RSNA:
			debug_printf(DEBUG_NORMAL, "\tAuth : RSNA\n");
			wctx->enc_capa |= DOES_WPA2;
			break;

		case DOT11_AUTH_ALGO_RSNA_PSK:
			debug_printf(DEBUG_NORMAL, "\tAuth : RSNA\n");
			wctx->enc_capa |= DOES_WPA2;
			break;

		default:
			if ((pCipherList->AuthCipherPairs[i].AuthAlgoId >= DOT11_AUTH_ALGO_IHV_START) &&
				(pCipherList->AuthCipherPairs[i].AuthAlgoId <= DOT11_AUTH_ALGO_IHV_END))
			{
				debug_printf(DEBUG_NORMAL, "\tAuth : IHV (%d)\n", pCipherList->AuthCipherPairs[i].AuthAlgoId);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "\tAuth : Unknown (%d)\n", pCipherList->AuthCipherPairs[i].AuthAlgoId);
			}
			break;
		}

		switch (pCipherList->AuthCipherPairs[i].CipherAlgoId)
		{
		case DOT11_CIPHER_ALGO_NONE:
			debug_printf(DEBUG_NORMAL, "\t Enc : NONE\n");
			break;

		case DOT11_CIPHER_ALGO_WEP40:
			debug_printf(DEBUG_NORMAL, "\t Enc : WEP-40\n");
			wctx->enc_capa |= DOES_WEP40;
			break;

		case DOT11_CIPHER_ALGO_TKIP:
			debug_printf(DEBUG_NORMAL, "\t Enc : TKIP\n");
			wctx->enc_capa |= DOES_TKIP;
			break;

		case DOT11_CIPHER_ALGO_CCMP:
			debug_printf(DEBUG_NORMAL, "\t Enc : CCMP\n");
			wctx->enc_capa |= DOES_CCMP;
			break;

		case DOT11_CIPHER_ALGO_WEP104:
			debug_printf(DEBUG_NORMAL, "\t Enc : WEP-104\n");
			wctx->enc_capa |= DOES_WEP104;
			break;

		case DOT11_CIPHER_ALGO_WEP:
			debug_printf(DEBUG_NORMAL, "\t Enc : WEP (Any length)\n");
			wctx->enc_capa |= DOES_WEP;
			break;

		default:
			debug_printf(DEBUG_NORMAL, "\t Enc : Unknown/IHV (%d)\n", pCipherList->AuthCipherPairs[i].CipherAlgoId);
			break;
		}
	}
}


/**
 * Delete any keys that are currently installed in the driver/interface.
 **/
int cardif_windows_dot11_delete_key(context *ctx, int key_idx, int set_tx)
{
	struct win_sock_data *sockData;
	DWORD BytesReturned;
	UCHAR Buffer[sizeof(NDIS_OID)+sizeof(NDIS_802_11_REMOVE_KEY)];
	PNDISPROT_SET_OID pSetOid;
	PNDIS_802_11_REMOVE_KEY pRkey;
	LPVOID lpMsgBuf;

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
        debug_printf(DEBUG_NORMAL, "Remove Key IOCTL failed.\n");
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Reason was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
        return -1;
    }

  return XENONE;
}

/**
 * Enable the filter that only allows for EAPoL frames to get through.
 **/
int cardif_windows_dot11_drop_unencrypted(context *ctx, char endis)
{
	struct win_sock_data *sockData;
	DWORD BytesReturned;
	UCHAR Buffer[sizeof(NDIS_OID)+sizeof(NDIS_802_11_PRIVACY_FILTER)];
	PNDISPROT_SET_OID pSetOid;
	DWORD *filter;

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
		debug_printf(DEBUG_NORMAL, "Couldn't set privacy filter status.\n");
		return -1;
	}

	return XENONE;
}

/**
 *  Take the RSSI value that Windows returns, and convert it to a percentage.  This
 *  call will only return something valid if the interface is associated.  If the
 *  interface isn't associated, then this function will return -1.
 **/
int cardif_windows_dot11_get_percent(context *ctx)
{
	struct win_sock_data *sockData;
	DWORD BytesReturned;
	UCHAR QueryBuffer[1024];
	PNDISPROT_QUERY_OID pQueryOid;
	NDIS_802_11_RSSI *pRssi;
	int i;
	int percentage = -1;
	wireless_ctx *wctx;

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
		debug_printf(DEBUG_NORMAL, "Couldn't determine the RSSI value for interface %s.\n",
			ctx->desc);
		return -1;
	}

	pRssi = (NDIS_802_11_RSSI *)&pQueryOid->Data[0];

	// According to the windows documentation, the RSSI should vary between
	// -10 and -200 dBm.  So, we need to figure out a percentage based on that.

	// However, many examples on the net show that valid ranges will run from -50 to -100.

	percentage = (((*pRssi) + 100)*2);    // Make the dBm a positive number, and the lowest value
		                                  // equal to 0.  (So, the range will now be 0 - 190.)

//	percentage = (int)(((float)percentage/(float)190) * 100);  // And make it a percentage.

	return percentage;
}

struct cardif_funcs cardif_windows_dot11_driver = {
  cardif_windows_dot11_scan,                       // .scan
  cardif_windows_dot11_disassociate,               // .disassociate
  cardif_windows_dot11_set_WEP_key,                // .set_wep_key
  cardif_windows_dot11_set_tkip_key,               // .set_tkip_key
  cardif_windows_dot11_set_ccmp_key,               // .set_ccmp_key
  cardif_windows_dot11_delete_key,                 // .delete_key
  cardif_windows_dot11_associate,                  // .associate
  cardif_windows_dot11_get_ssid,                   // .get_ssid
  cardif_windows_dot11_get_bssid,                  // .get_bssid
  NULL,                                               // .wpa_state
  NULL,                                               // .wpa
  cardif_windows_dot11_wep_associate,              // .wep_associate
  NULL,                                               // .countermeasures
  cardif_windows_dot11_drop_unencrypted,           // .drop_unencrypted
  cardif_windows_dot11_get_wpa_ie,                 // .get_wpa_ie
  cardif_windows_dot11_get_wpa2_ie,                // .get_wpa2_ie
  cardif_windows_dot11_enc_disable,                // .enc_disable
  cardif_windows_dot11_enc_pairs,                  // .enc_capabilities
  cardif_windows_dot11_set_bssid,                  // .set_bssid
  NULL,												  // .set_operstate
  NULL,												  // .set_linkmode
  cardif_windows_dot11_get_percent,                // .get_signal_percent
};

