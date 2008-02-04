/**
 * Windows card interface implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows.c
 *
 * \author chris@open1x.org
 *
 * $Id: cardif_windows.c,v 1.1 2008/01/30 20:46:43 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:43 $
 **/

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>

#include <NtDDNdis.h>

// The nuiouser.h file is included with the Windows DDK.  Please 
// download the DDK and copy the file to the proper location.
#include "../../../vs2005/ndis_proto_driver/nuiouser.h"

#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../config_ssid.h"
#include "cardif_windows.h"
#include "../cardif.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../snmp.h"
#include "../../statemachine.h"
#include "../../wireless_sm.h"
#include "../../timer.h"
#include "../../event_core_win.h"
#include "../../interfaces.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "cardif_windows_wireless.h"
#include "cardif_windows_dot11.h"
#include "cardif_windows_wmi.h"
#include "wzc_ctrl.h"
#include "windows_eapol_ctrl.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

// This contains a pointer to the functions needed for wireless.  
struct cardif_funcs *wireless = NULL;

// Store values about what state our interface was in before we start messing
// with it.
struct int_starting_data *startup;

// The device node we use to communicate with the protocol layer.
char  NdisDev[] = "\\\\.\\\\Open1X";

/**
 * \brief Issue a non-blocking IOCTL request to Windows.  (And wait up to 7 seconds for an answer.)
 *
 * Since we opened the handle in non-blocking mode, we have to handle our ioctls in
 * non-blocking mode as well.  (Or, according to the Windows documentation, bad things
 * can happen.)  So, this is a "drop-in" replacement for the normal DeviceIoControl()
 * function that blocks for up to 1 second waiting for a response.
 *
 * @param[in] hDevice   A handle to the device that we want to execute the IOCTL 
 *                      against.
 * @param[in] dwIoCtl   A DWORD that specifies the IOCTL that we want to execute.
 * @param[in] lpInBuf   A pointer to a buffer that contains the data that the IOCTL
 *                      being executed needs.
 * @param[in] nInBufSiz   The size of the buffer specified by lpInBuf.
 * @param[out] lpOutBuf   A pointer to a buffer that will contain the results from the
 *                        IOCTL.
 * @param[out] nOutBufSiz   The size of the buffer specified by lpOutBuf.
 * @param[out] lpBytesReturned   A pointer to a DWORD that will contain the number of
 *                               bytes returned by the IOCTL.  (This will be the 
 *                               number of bytes in lpOutBuf that are valid.)
 *
 * \retval result  One of the result codes returned by the call to WaitForSingleObjectEx().
 **/
DWORD devioctl7(HANDLE hDevice, DWORD dwIoCtl, LPVOID lpInBuf, DWORD nInBufSiz,
                LPVOID lpOutBuf,  DWORD nOutBufSiz, LPDWORD lpBytesReturned)
{
   OVERLAPPED ovr;
   DWORD result;
   HANDLE ioctlEvent = INVALID_HANDLE_VALUE;

   if (hDevice == INVALID_HANDLE_VALUE)
   {
	   debug_printf(DEBUG_NORMAL, "Invalid handle value passed in to %s()!\n", __FUNCTION__);
		return WAIT_ABANDONED;
   }

   (*lpBytesReturned) = 0;

   memset(&ovr, 0x00, sizeof(OVERLAPPED));

   if (ioctlEvent == INVALID_HANDLE_VALUE)
   {
		ioctlEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
		if (ioctlEvent == INVALID_HANDLE_VALUE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't create event handle!\n");
			return 0xffffffff;
		}
   }
   else
   {
	   ResetEvent(ioctlEvent);
   }

   ovr.hEvent = ioctlEvent;

   if (!DeviceIoControl(hDevice, dwIoCtl, lpInBuf, nInBufSiz, lpOutBuf,
                        nOutBufSiz, lpBytesReturned, &ovr))
    {
		if (GetLastError() != 997)
		{
      debug_printf(DEBUG_INT, "Couldn't do IOCTL.\n");
	  //printf("Couldn't do IOCTL!\n");
	  debug_printf(DEBUG_INT, "Error : %d\n", GetLastError());
	  CloseHandle(ioctlEvent);
      return 0xffffffff;
		}
    }

    result = WaitForSingleObjectEx(ioctlEvent, 7000, FALSE);

        switch (result)
            {
            case WAIT_ABANDONED:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_ABANDONED\n");
				 //printf("IOCTL return WAIT_ABANDONED!\n");
                 break;

            case WAIT_IO_COMPLETION:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_IO_COMPLETION\n");
				 //printf("IOCTL returned WAIT_IO_COMPLETION\n");
                 break;

            case WAIT_OBJECT_0:
				 // Don't send any output here, to avoid cluttering the output.
                 //debug_printf(DEBUG_INT, "IOCTL returned WAIT_OBJECT_0\n");
                 break;

            case WAIT_TIMEOUT:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_TIMEOUT\n");
				 //printf("Timeout\n");
                 break;

            case WAIT_FAILED:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_FAILED\n");
				 //printf("Failed\n");
                 break;

            default:
                 debug_printf(DEBUG_INT, "IOCTL returned UNKNOWN value!\n");
				 //printf("Unknown.\n");
                 break;
            }

	CloseHandle(ioctlEvent);

    return result;
}

/**
 * \brief Issue a non-blocking IOCTL request to Windows.
 *
 * Since we opened the handle in non-blocking mode, we have to handle our ioctls in
 * non-blocking mode as well.  (Or, according to the Windows documentation, bad things
 * can happen.)  So, this is a "drop-in" replacement for the normal DeviceIoControl()
 * function that blocks for up to 1 second waiting for a response.
 *
 * @param[in] hDevice   A handle to the device that we want to execute the IOCTL 
 *                      against.
 * @param[in] dwIoCtl   A DWORD that specifies the IOCTL that we want to execute.
 * @param[in] lpInBuf   A pointer to a buffer that contains the data that the IOCTL
 *                      being executed needs.
 * @param[in] nInBufSiz   The size of the buffer specified by lpInBuf.
 * @param[out] lpOutBuf   A pointer to a buffer that will contain the results from the
 *                        IOCTL.
 * @param[out] nOutBufSiz   The size of the buffer specified by lpOutBuf.
 * @param[out] lpBytesReturned   A pointer to a DWORD that will contain the number of
 *                               bytes returned by the IOCTL.  (This will be the 
 *                               number of bytes in lpOutBuf that are valid.)
 *
 * \retval result  One of the result codes returned by the call to WaitForSingleObjectEx().
 **/
DWORD devioctl(HANDLE hDevice, DWORD dwIoCtl, LPVOID lpInBuf, DWORD nInBufSiz,
                LPVOID lpOutBuf,  DWORD nOutBufSiz, LPDWORD lpBytesReturned)
{
   OVERLAPPED ovr;
   DWORD result;
   HANDLE ioctlEvent = INVALID_HANDLE_VALUE;
   PNDISPROT_SET_OID oid = NULL;

   if (hDevice == INVALID_HANDLE_VALUE)
   {
	   debug_printf(DEBUG_NORMAL, "Invalid handle value passed in to %s()!\n", __FUNCTION__);
		return WAIT_ABANDONED;
   }

   if (lpInBuf == NULL)
   {
	   debug_printf(DEBUG_NORMAL, "Invalid buffer passed in to %s!\n", __FUNCTION__);
	   return WAIT_ABANDONED;
   }

   (*lpBytesReturned) = 0;

   memset(&ovr, 0x00, sizeof(OVERLAPPED));

   if (ioctlEvent == INVALID_HANDLE_VALUE)
   {
		ioctlEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
		if (ioctlEvent == INVALID_HANDLE_VALUE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't create event handle!\n");
			return 0xffffffff;
		}
   }
   else
   {
	   ResetEvent(ioctlEvent);
   }

   ovr.hEvent = ioctlEvent;

   SetLastError(0);   // Clear the last error so we don't get false positives.

   if (!DeviceIoControl(hDevice, dwIoCtl, lpInBuf, nInBufSiz, lpOutBuf,
                        nOutBufSiz, lpBytesReturned, &ovr))
    {
		if (GetLastError() != 997)
		{
			oid = (NDIS_OID *)lpInBuf;
	      debug_printf(DEBUG_INT, "Couldn't do IOCTL %04X. Error : %d\n", oid->Oid, GetLastError());
		  CloseHandle(ioctlEvent);
		  return 0xffffffff;
		}
    }

    result = WaitForSingleObjectEx(ioctlEvent, 1000, FALSE);

        switch (result)
            {
            case WAIT_ABANDONED:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_ABANDONED\n");
				 //printf("IOCTL return WAIT_ABANDONED!\n");
                 break;

            case WAIT_IO_COMPLETION:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_IO_COMPLETION\n");
				 //printf("IOCTL returned WAIT_IO_COMPLETION\n");
                 break;

            case WAIT_OBJECT_0:
				 // Don't send any output here, to avoid cluttering the output.
                 //debug_printf(DEBUG_INT, "IOCTL returned WAIT_OBJECT_0\n");
                 break;

            case WAIT_TIMEOUT:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_TIMEOUT\n");
				 //printf("Timeout\n");
                 break;

            case WAIT_FAILED:
                 debug_printf(DEBUG_INT, "IOCTL returned WAIT_FAILED\n");
				 //printf("Failed\n");
                 break;
            default:
                 debug_printf(DEBUG_INT, "IOCTL returned UNKNOWN value!\n");
				 //printf("Unknown.\n");
                 break;
            }

	CloseHandle(ioctlEvent);

    return result;
}

/**
 * \brief Issue an IOCTL, and block until there is a result.
 *
 * A simplified IOCTL call that blocks until it has a result.  Rather than returning
 * a detailed status value (like devioctl() does), it just returns true/false depending
 * on if the call was successful, or not.
 *
 * @param[in] hDevice   A handle to the device that we want to execute the IOCTL 
 *                      against.
 * @param[in] dwIoCtl   A DWORD that specifies the IOCTL that we want to execute.
 * @param[in] lpInBuf   A pointer to a buffer that contains the data that the IOCTL
 *                      being executed needs.
 * @param[in] nInBufSiz   The size of the buffer specified by lpInBuf.
 * @param[out] lpOutBuf   A pointer to a buffer that will contain the results from the
 *                        IOCTL.
 * @param[out] nOutBufSiz   The size of the buffer specified by lpOutBuf.
 * @param[out] lpBytesReturned   A pointer to a DWORD that will contain the number of
 *                               bytes returned by the IOCTL.  (This will be the 
 *                               number of bytes in lpOutBuf that are valid.)
 *
 * \retval TRUE if IOCTL was successful
 * \retval FALSE if IOCTL failed
 **/
int devioctl_blk(HANDLE devHandle, DWORD ioctlValue, LPVOID lpInBuf, DWORD nInBufSiz,
                LPVOID lpOutBuf,  DWORD nOutBufSiz, LPDWORD lpBytesReturned)
{
  DWORD result;

  // Make sure we have some valid values.
  if (devHandle == INVALID_HANDLE_VALUE) 
  {
	  debug_printf(DEBUG_INT, "Invalid handle passed in to %s()!\n", __FUNCTION__);
	  return FALSE;
  }

  if (lpBytesReturned == NULL) 
  {
	  debug_printf(DEBUG_INT, "Variable for 'BytesReturned' was NULL!\n", __FUNCTION__);
	  return FALSE;
  }

  result = devioctl(devHandle, ioctlValue, lpInBuf, nInBufSiz, lpOutBuf, nOutBufSiz,
					lpBytesReturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION) && (GetLastError() != 0))
  {
	  return FALSE;
  }

  return TRUE;
}

/**
 * \brief Set the protocol layer to listen for the multicast MAC address 
 *        used by 802.1X.  (01:80:c2:00:00:03)
 *
 * @param[in] devHandle   A handle to the device that we want to set the multicast
 *                        address on.
 * 
 * \retval TRUE on success
 * \retval FALSE on error
 **/
int SetMulticastAddress(HANDLE devHandle)
{
    DWORD  BytesReturned;
    DWORD  result;
    DWORD   test;
    UCHAR  QueryBuffer[sizeof(NDIS_OID)+6];
    PNDISPROT_QUERY_OID pQueryOid;

    pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
    pQueryOid->Oid = OID_802_3_MULTICAST_LIST;

	// The multicast MAC address defined by the standard.
    pQueryOid->Data[0] = 0x01;
    pQueryOid->Data[1] = 0x80;
    pQueryOid->Data[2] = 0xc2;
    pQueryOid->Data[3] = 0x00;
    pQueryOid->Data[4] = 0x00;
    pQueryOid->Data[5] = 0x03;

    result = devioctl(devHandle, IOCTL_NDISPROT_SET_OID_VALUE,
        (LPVOID)&QueryBuffer[0], sizeof(NDIS_OID)+6,
        (LPVOID)&QueryBuffer[0], sizeof(NDIS_OID)+6, &BytesReturned);

    if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
        return FALSE;
    }

	return TRUE;
}

/**
 * \brief Convert a windows error code to a displayable string.
 *
 * Rather than just showing an error code, we want to show a string.
 * This function will return a string to the last error that was
 * generated.  It is up to the caller to LocalFree() the result.
 *
 * @param[in] error   The windows error code that was returned from a previous
 *                    function call.
 *
 * \retval ptr to a displayable string that describes the error code.
 **/
LPVOID GetLastErrorStr(DWORD error)
{
	LPVOID lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
   				  FORMAT_MESSAGE_FROM_SYSTEM,
				  NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				  (LPTSTR) &lpMsgBuf, 0, NULL );

	return lpMsgBuf;
}

/**
 * \brief Get an handle to the "file" that the Open1X protocol handler
 *        presents.
 *
 * @param[in] devName   A pointer to a non-unicode version of the "file" name that
 *                      is presented by the protocol handler.
 *
 * \retval HANDLE a handle to the device, or INVALID_HANDLE_VALUE on error.
 **/
HANDLE GetHandle(char *devName)
{
		HANDLE retHandle = INVALID_HANDLE_VALUE;
		LPVOID lpMsgBuf = NULL;
		int result = 0;
		DWORD BytesWritten = 0;

		if (devName == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Invalid device name in %s()!\n", __FUNCTION__);
			return INVALID_HANDLE_VALUE;
		}

		retHandle = CreateFile(devName, 
							   FILE_READ_DATA | FILE_WRITE_DATA,
							   FILE_SHARE_READ | FILE_SHARE_WRITE,
							   NULL, OPEN_EXISTING, 
							   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
							   INVALID_HANDLE_VALUE);

		if (retHandle == INVALID_HANDLE_VALUE)
		{
			lpMsgBuf = GetLastErrorStr(GetLastError());

			fprintf(stderr, "Couldn't establish a connection to the Open1X "
				"protocol service!\n  Error was : %s", lpMsgBuf);

			LocalFree(lpMsgBuf);
		}

		if (devioctl7(retHandle, IOCTL_NDISPROT_BIND_WAIT, NULL, 0,
			NULL, 0, &BytesWritten) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Device handle bind wait failed.  Returned %d.  We will try to continue anyway.\n", result);
		}

		return retHandle;
}

// This function is found in mschapv2.c, but we need it here, so
// prototype it, and let the linker figure it out. ;)
char *to_unicode(char *);

/**
 *  \brief Bind an NDIS device to a specific device handle.  This allows
 *         us to perform read/write operations on the device.  (Basically,
 *         it lets us send and receive frames.)
 *
 * @param[in] devHandle   A handle created by a call to \ref GetHandle().  After this
 *                        call, the handle will refer to a specific interface, instead
 *                        of the "file" that connects to the protocol handler.
 *
 * @param[in] devName   A non-unicode string that identifies the device that we want
 *                      to bind to.
 *
 * \retval FALSE on error
 * \retval TRUE on success
 **/
int BindNDISDevice(HANDLE devHandle, char *devName)
{
	WCHAR *uniDevName = NULL;
	int NameLen = 0;
	DWORD retbytes = 0;
	DWORD result = 0;

	NameLen = strlen(devName);
	uniDevName = (WCHAR *)to_unicode(devName);

	debug_printf(DEBUG_INT, "Trying to bind to network interface : %ws\n",
			uniDevName);

	result = devioctl(devHandle, IOCTL_NDISPROT_OPEN_DEVICE,
					  uniDevName, NameLen * 2, NULL, 0, &retbytes);

	FREE(uniDevName);

	if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		return FALSE;
	}

	return TRUE;
}

/**
 *  \brief Determine if the named interface is wireless.
 *
 * @param[in] intname   A non-unicode string that identifies the device that we
 *                      want to check.
 *
 * \retval -1 on error
 * \retval FALSE if interface is no wireless
 * \retval TRUE if interface is wireless
 **/
char is_wireless(char *intname)
{
  int retVal;
  DWORD result, *state;
  UCHAR QueryBuffer[sizeof(NDIS_OID) + 4000];
  DWORD BytesReturned;
  PNDISPROT_QUERY_OID pQueryOid;
  LPVOID lpMsgBuf;
  HANDLE temphandle = INVALID_HANDLE_VALUE;

	temphandle = GetHandle((char *)&NdisDev);

	if (temphandle == INVALID_HANDLE_VALUE)
		return -1;

	if (BindNDISDevice(temphandle, intname) == 0)
	{
		ipc_events_error(NULL, IPC_EVENT_ERROR_FAILED_TO_BIND, intname);

		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Failed to bind interface %s to device "
			"handle.  Error was : %s\n", intname, lpMsgBuf);

		LocalFree(lpMsgBuf);
		CloseHandle(temphandle);
		return -1;
	}

  pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
  pQueryOid->Oid = OID_GEN_PHYSICAL_MEDIUM;

  result = devioctl(temphandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			// The IOCTL isn't supported.
			debug_printf(DEBUG_INT, "The IOCTL to determine if this interface is wireless "
					"does not appear to be implemented in this driver!  Assuming it is "
					"wired.\n");
			CloseHandle(temphandle);
			return FALSE;
		}

        debug_printf(DEBUG_NORMAL, "Get physical media type IOCTL failed on interface '%s'.\n", intname);

		// Assume the interface is wired, so we don't try to do anything fancy with it.
        return FALSE;
    }

  state = (DWORD *)&pQueryOid->Data[0];
  result = (*state);

#if 0
  if (result == NdisPhysicalMediumBluetooth)
  {
	  debug_printf(DEBUG_INT, "Interface appears to be BLUETOOTH!\n");
	  CloseHandle(temphandle);
	  return FALSE;
  }
#endif

  if ((result == NdisPhysicalMediumWirelessLan) || (result == NdisPhysicalMediumNative802_11))
    {
	  debug_printf(DEBUG_INT, "Interface appears to be wireless!\n");
	  CloseHandle(temphandle);
      return TRUE;
    } 
	
  debug_printf(DEBUG_INT, "Interface is wired, or unknown.\n");
  CloseHandle(temphandle);
  return FALSE;
}

/**
 *  \brief Obtain the hardware (MAC) address for the given interface.
 *
 * @param[in] devHandle   A handle for an interface that has been bound using the
 *                        BindNDISDevice() call.
 *
 * \retval NULL on error
 * \retval ptr to the MAC address for the interface specified by \ref devHandle.
 **/
char *getmac(HANDLE devHandle)
{
  PNDISPROT_QUERY_OID    pOidData = NULL;
  CHAR *pStr = NULL;
  char *mac = NULL;
  DWORD bytesreturned = 0, result = 0;

  pStr = Malloc(sizeof(NDISPROT_QUERY_OID)+6);
  if (pStr == NULL) 
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory!\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_MALLOC, __FUNCTION__);
	  return NULL;
  }

  pOidData = (PNDISPROT_QUERY_OID) pStr;
  pOidData->Oid = OID_802_3_CURRENT_ADDRESS;
  
  result = devioctl(devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
					pStr, (sizeof(NDISPROT_QUERY_OID)+6), 
					pStr, (sizeof(NDISPROT_QUERY_OID)+6),
					&bytesreturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
  {
	  debug_printf(DEBUG_NORMAL, "Unable to request the MAC address for an interface!\n");
	  return NULL;
  }

  mac = Malloc(6);
  if (mac == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store interface MAC address!\n");
	  return NULL;
  }

  memcpy(mac, pOidData->Data, 6);
  
  debug_printf(DEBUG_INT, "MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", pOidData->Data[0], pOidData->Data[1], pOidData->Data[2],
				pOidData->Data[3], pOidData->Data[4], pOidData->Data[5]);

  FREE(pStr);

  return mac;
}

/**
 * \brief Determine if the interface pointed to by "ctx" is wireless.
 *
 * @param[in] ctx   A pointer to the context that contains the interface to check
 *                  for wirelessness.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval TRUE on success
 * \retval FALSE on failure
 **/
int cardif_int_is_wireless(context *ctx)
{
  int retVal = 0;
  DWORD result = 0, *state = NULL;
  struct win_sock_data *sockData = NULL;
  UCHAR QueryBuffer[sizeof(NDIS_OID) + 4];
  DWORD BytesReturned = 0;
  PNDISPROT_QUERY_OID pQueryOid = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
  pQueryOid->Oid = OID_GEN_PHYSICAL_MEDIUM;

  result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			// The IOCTL isn't supported.
			debug_printf(DEBUG_INT, "The IOCTL to determine if this interface is wireless "
					"does not appear to be implemented in this driver!  Assuming it is "
					"wired.\n");
			return FALSE;
		}

		debug_printf(DEBUG_NORMAL, "Get physical media type IOCTL failed on interface '%s'.\n", ctx->desc);

		// Assume the interface is wired, so we don't try to do anything fancy with it.
        return FALSE;
    }

  state = (DWORD *)&pQueryOid->Data[0];
  result = (*state);

  if ((result == NdisPhysicalMediumWirelessLan) || (result == NdisPhysicalMediumNative802_11))
    {
	  debug_printf(DEBUG_INT, "Interface appears to be wireless!\n");
      return TRUE;
    } 
	
  debug_printf(DEBUG_INT, "Interface is wired, or unknown.\n");
  return FALSE;
}

/**
 * \brief Clear all keys, and accept unencrypted traffic again.
 *
 * @param[in] ctx   The context that contains the interface that we want to 
 *                  reset.
 **/
void cardif_windows_clear_keys(context *ctx)
{
	debug_printf(DEBUG_INT, "Allowing unencrypted frames again.\n");
	cardif_drop_unencrypted(ctx, 0);
 
	// In Windows, setting the card to infrastructure mode will automatically clear
	// all of the keys in the key cache.  This is more efficient than making an IOCTL
	// for every key we might have, and has the added bonus that it doesn't cause
	// bogus error messages when using the Intel 3945 driver! ;)

	cardif_windows_set_infra_mode(ctx);
}

/**
 * \brief Determine if an interface is currently associated. 
 *
 * @param[in] ctx   The context that contains the interface that we want to check
 *                  the association state of.
 *
 * \note If this call is made against an interface that isn't wireless, the result
 *       is undefined.  (Most likely, it will return IS_UNASSOCIATED.)
 *
 * \retval IS_ASSOCIATED if the interface is associated
 * \retval IS_UNASSOCIATED if the interface is not associated
 **/
int cardif_check_associated(context *ctx)
{
	UCHAR bssid_dest[6];

	if (cardif_windows_wireless_get_bssid(ctx, bssid_dest) == XENONE)
		return IS_ASSOCIATED;

	return IS_UNASSOCIATED;
}

/**
 * \brief We have a frame received event.  So handle it.
 *
 * @param[in] ctx   The context that contains the interface that received a frame.
 * @param[in] devHandle   The device handle for the interface that received a frame.
 *
 * \retval XENONE on success
 **/
int cardif_handle_frame(context *ctx, HANDLE devHandle)
{
	if (cardif_getframe(ctx) != XENOFRAMES)
	{
		if (ctx->intType != ETH_802_11_INT)
			eapol_execute(ctx);
	}

	return XENONE;
}

/**
 * \brief If there is a mismatch between the Windows description and the 
 *        one in our configuration file, we need to go through and rename stuff
 *        in memory.
 *
 * \note  All of the changes that happen in this function *ONLY* happen in memory.
 *        However, if a request to write the configuration file is issued the changed
 *        connection and interface configuration data will be committed to disk!!
 *
 * @param[in] confdesc   The description of the interface in the configuration.
 * @param[in] windesc   The description that Windows is providing us.
 **/
void cardif_windows_fixup_config(char *confdesc, char *windesc)
{
	struct config_connection *confcon = NULL;
	struct xsup_interfaces *confints = NULL;
	char *myconfdesc = NULL;

	confints = config_get_config_ints();
	if (confints == NULL)
	{
		// This should be virtually impossible!  (Unless the caller is being *REALLY* stupid! ;)
		debug_printf(DEBUG_NORMAL, "There was a request to fix some interface/connection issues, but there are no interfaces defined!?\n");
		return;
	}

	while ((confints != NULL) && (strcmp(confints->description, confdesc) != 0))
		confints = confints->next;  // This is okay because we don't want to free the pointer as it points to the master structure. ;)

	if (confints == NULL)
	{
		// This should also be virtually impossible!
		debug_printf(DEBUG_NORMAL, "There was a request to fix some interface/connection issues, but the interface that triggered it isn't in configuration memory!?\n");
		return;
	}

	// Make a copy of the "wrong" description, since we will probably overwrite it in the next set of commands. ;)
	myconfdesc = _strdup(confdesc);

	FREE(confints->description);
	confints->description = _strdup(windesc);  // Set the new interface name.  If a write configuration request is made, this *WILL* get written to the config!!

	confcon = config_get_connections();
	if (confcon == NULL)
	{
		debug_printf(DEBUG_NORMAL, "There are no connections defined to update.\n");
		FREE(myconfdesc);
		return;
	}

	while (confcon != NULL)
	{
		if (strcmp(confcon->device, myconfdesc) == 0)
		{
			// We need to rewrite this.
			FREE(confcon->device);
			confcon->device = _strdup(windesc);
		}

		confcon = confcon->next;
	}

	FREE(myconfdesc);
}

/**
 * \brief Set the wireless cardif_funcs structure to use the driver that the user
 *        has requested.
 *
 * \note This call is provided in Windows for completeness only.  It doesn't actually
 *       do anything.
 *
 * @param[in] driver   An integer that defines the driver to be used for this
 *                     interface.
 **/
void cardif_set_driver(char driver)
{
	// Windows only has one driver API interface.
}

//void cardif_windows_get_events(void *pValue);

/**
 * \brief Prepare an interface to send and receive frames.
 *
 * Do whatever is needed to get the interface in to a state that we can send
 * and recieve frames on the network.  Any information that we need to later
 * use should be stored in the context structure.
 *
 * @param[in] ctx   A pointer to the context that contains the interface that we
 *                  need to get ready to send and receive frames.
 * @param[in] driver   An integer that defines the driver to be used for this
 *                     interface.  (Not used on Windows!)
 *
 * \retval XEMALLOC on memory allocation failure
 * \retval XEGENERROR on generic error
 * \retval XENOSOCK if there is no socket available to work with
 * \retval XENONE on success
 **/
int cardif_init(context *ctx, char driver)
{
	struct config_globals *globals = NULL;
    struct win_sock_data *sockData = NULL;
	struct xsup_interfaces *confints = NULL;
	LPVOID lpMsgBuf = NULL;
	char *mac = NULL;
	char *intdesc = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return XEMALLOC;

    debug_printf(DEBUG_INIT | DEBUG_INT, "Initializing socket for interface %s..\n",
        	       ctx->intName);
  
	// Allocate memory for the things we need.
	ctx->sockData = (void *)Malloc(sizeof(struct win_sock_data));
	if (ctx->sockData == NULL)
	{
      debug_printf(DEBUG_NORMAL, "Error allocating memory!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_MALLOC, __FUNCTION__);
      return XEMALLOC;
    }

	sockData = ctx->sockData;

	// Indicate that we don't know the WMI index of this interface.
	sockData->wmiIntIdx = INVALID_WMI_IDX;

	sockData->devHandle = GetHandle(NdisDev);
	if (sockData->devHandle == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get a handle to device '%s'.  This interface may not exist on this system.\n", ctx->desc);
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_TO_GET_HANDLE, ctx->desc);
		return XEGENERROR;
	}

	sockData->hEvent = INVALID_HANDLE_VALUE;

	if (BindNDISDevice(sockData->devHandle, ctx->intName) == 0)
	{
		ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_TO_BIND, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Failed to bind interface %s to device "
			"handle.  Error was : %s\n", ctx->intName, lpMsgBuf);
		
		LocalFree(lpMsgBuf);
		CloseHandle(sockData->devHandle);
		return XENOSOCK;
	}

	mac = getmac(sockData->devHandle);
	if (mac == NULL)
	{
		ipc_events_error(ctx, IPC_EVENT_ERROR_GET_MAC, ctx->desc);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Couldn't get MAC address for "
			"interface %s!  Error was : %s\n", ctx->desc, lpMsgBuf);

		LocalFree(lpMsgBuf);
		CloseHandle(sockData->devHandle);
		return XENOSOCK;
	}

	memcpy(ctx->source_mac, mac, 6);

    if (cardif_int_is_wireless(ctx) == TRUE)
    {
	  debug_printf(DEBUG_INT, "Interface is wireless.\n");
	  ctx->intType = ETH_802_11_INT;

		// Disable WZC (if it is running.)
		if (wzc_ctrl_disable_wzc(ctx->intName) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Unable to disable WZC for interface %s.\n", ctx->intName);
		}

	  if (context_create_wireless_ctx((wireless_ctx **)&ctx->intTypeData, 0) != XENONE)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't create wireless context for interface '%s'!\n", ctx->desc);
		  ipc_events_error(ctx, IPC_EVENT_ERROR_CANT_CREATE_WIRELESS_CTX, ctx->desc);
		  FREE(mac);
		  return -1;
	  }
	  
      // If we have our destination set to AUTO, then preset our destination
      // address.
      if (globals->destination == DEST_AUTO)
		{
			cardif_GetBSSID(ctx, ctx->dest_mac);
		}

	  // And make sure we don't have any stray connections hanging around.
	  cardif_disassociate(ctx, 0);
    }
	else
	{
		// Disable the Windows 802.1X stack on a wired interface.
		if (windows_eapol_ctrl_disable(ctx->desc, ctx->intName) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Unable to configure the interface '%s'.\n", ctx->desc);
		}
	}


	if (SetMulticastAddress(sockData->devHandle) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't get driver layer to give us access to the "
			"needed multicast frames on interface '%s'!\n", ctx->desc);
		FREE(mac);
		return XENOSOCK;
	}

  ctx->sendframe = Malloc(FRAMESIZE);
  if (ctx->sendframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store frames "
		   "to be sent.\n");
	  ipc_events_malloc_failed(ctx);
	  FREE(mac);
      return XEMALLOC;
    }

  //wireless = &cardif_windows_wireless_driver;
#if 1
  switch (cardif_windows_use_new_ioctls(ctx))
  {
  case 0:
  case 1:
	debug_printf(DEBUG_INT, "It appears your card only supports the old interface.  Using that.\n");
	wireless = &cardif_windows_wireless_driver;
	break;

  case 2:
	debug_printf(DEBUG_INT, "It appears your card supports the new API!  Life is good!\n");
	wireless = &cardif_windows_dot11_driver;

	// Check to see if the power is on.
	cardif_windows_dot11_reset(ctx);
	cardif_windows_dot11_is_power_on(ctx);
	cardif_windows_dot11_set_pwr_mgmt(ctx);
	break;
  }
#endif

  //_beginthread(cardif_windows_get_events, 0, ctx);

  if (cardif_windows_wmi_get_idx(ctx, &intdesc) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't determine the WMI interface caption for interface '%s'!\n",
		  ctx->desc);
  }
  else
  {
	// Verify that we know about the interface.  MAC address, description, etc.
	confints = config_get_config_ints();

	while ((confints != NULL) && (memcmp(mac, confints->mac, 6) != 0))
		confints = confints->next;
	
	if (confints != NULL)  // If it isn't found, then we have nothing to worry about.
	{
		if (strcmp(confints->description, intdesc) != 0)
		{
			// The interface has a MAC address match, but a different description.
			// Rewrite the configuration data in memory to allow this interface to be used.
			debug_printf(DEBUG_NORMAL, "Interface '%s' has a MAC address match, but the descriptions don't match.  Attempting to fix...\n", intdesc);
			cardif_windows_fixup_config(confints->description, intdesc);

			FREE(ctx->desc);
			ctx->desc = _strdup(intdesc);
		}
	}
  }
  FREE(mac);
  FREE(intdesc);

  event_core_register(sockData->devHandle, ctx, &cardif_handle_frame, 2, "frame handler");

  return XENONE;
}

/**
 * \brief Tell the wireless card to start scanning for wireless networks.
 *
 * @param[in] ctx   The context for the interface that we want to start scanning.
 * @param[in] passive   Should it be a passive scan?  (Not supported on Windows!)
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_do_wireless_scan(context *ctx, char passive)
{
	wireless_ctx *wctx = NULL;
	int resval = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) 
    {
      debug_printf(DEBUG_INT, "No valid wireless calls struct! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

  wctx = (wireless_ctx *)ctx->intTypeData;
  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return XEMALLOC;

  // If we are already scanning, then we shouldn't get here, but go ahead 
  // and ignore it anyway.
  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING) )
    {
      debug_printf(DEBUG_INT, "Got a request to start a new scan when one is"
		   " already in progress!  Ignoring!\n");
      return XENONE;
    }

  SET_FLAG(wctx->flags, WIRELESS_SCANNING);

  // Don't clear the scan cache until we have new data.  This allows us to handle situations
  // where the association is slow, and happens while we are waiting for scan data.  (Such as
  // the behavior of the IPW3945 and Trpz APs.)

  resval = wireless->scan(ctx, passive);

  if (resval != XENONE)
  {
	  // We had an error trying to scan, so clear the scanning flag.
	  UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);
  }

  return resval;
}

/**
 * \brief Send a disassociate request.
 *
 * @param[in] ctx   The context for the interface that we want to send a disassociate
 *                  request for.
 * @param[in] reason_code   The reason code as identified by the 802.11 standards. (Not
 *                          used on Windows.)
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_disassociate(context *ctx, int reason_code)
{
  if (!xsup_assert((ctx != NULL), "thisint != NULL", FALSE))
    return XEMALLOC;

  debug_printf(DEBUG_NORMAL, "We have requested a disassociate on interface '%s'.\n", ctx->desc);

  if (wireless == NULL) return XEMALLOC;

  debug_printf(DEBUG_INT, "Called %s\n", __FUNCTION__);
  return wireless->disassociate(ctx, reason_code);
}

/**
 * \brief Return the socket number for functions that need it.
 *
 * @param[in] ctx   The context for the interface we want to get the socket number
 *                  from.
 *
 * \retval XENOSOCK because this isn't supported on Windows.
 **/
int cardif_get_socket(context *ctx)
{
	debug_printf(DEBUG_NORMAL, "%s() makes no sense for Windows!\n", __FUNCTION__);
	return XENOSOCK;
}

/**
 * \brief Clean up anything that was created during the initialization and operation
 *        of the interface.  This will be called before the program terminates.
 *
 * @param[in] ctx   The context for the interface that we want to clean up.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_deinit(context *ctx)
{
  uint16_t int16 = 0;
  struct win_sock_data *sockData = NULL;
  uint8_t all0s[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  FREE(ctx->sendframe);
  
  sockData = ctx->sockData;

  debug_printf(DEBUG_DEINIT | DEBUG_INT, "Cleaning up interface %s...\n", ctx->intName);

  if (ctx->intType == ETH_802_11_INT)
  {
    // Remove all of the keys that we have set.
    if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_clear_keys(ctx);

    debug_printf(DEBUG_DEINIT | DEBUG_INT, "Turning off WPA support/state.\n");

    // Clear the WPA IE.
    //cardif_set_wpa_ie(ctx, NULL, 0);

    if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_disable_wpa_state(ctx);

	if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_disassociate(ctx, 0);
  }

  if (CloseHandle(sockData->hEvent) == 0)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to close event handle.  Error was : %d\n", GetLastError());
  }

  FREE(sockData->frame);

  if (CloseHandle(sockData->devHandle) == 0)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to close device handle.  Error was : %d\n", GetLastError());
  }

  // Free the memory used for the Caption.
  FREE(sockData->caption);

  // Now clean up the memory.
  FREE(ctx->sockData);

  return XENONE;
}

/**
 * \brief Set a WEP key.  Also, based on the index, we may change the transmit
 *        key.
 *
 * @param[in] ctx   The context for the interface that we want to change the WEP key
 *                  on.
 * @param[in] key   A pointer to a byte array that identifies the key to be installed.
 * @param[in] keylen   The length of the key data pointed to by "key".
 * @param[in] index   The index for the key.  If (index & 0x80) then the key is a 
 *                    transmit key, and will be treated as such.
 *
 * \retval XEMALLOC on memory allocation error.
 * \retval XENONE on success
 **/
int cardif_set_wep_key(context *ctx, uint8_t *key, 
		       int keylen, int index)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((key != NULL), "key != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_wep_key == NULL) return XEMALLOC;

  return wireless->set_wep_key(ctx, key, keylen, index);
}

/**
 * \brief Set a TKIP key. 
 *
 * @param[in] ctx   The context that contains the interface that we want to set a
 *                  TKIP key on.
 * @param[in] addr   The BSSID (MAC address) of the AP that this key is set for.  If
 *                   the key is a broadcast key, it should be set to ff:ff:ff:ff:ff:ff.
 * @param[in] keyidex   The index that this key should be used in.
 * @param[in] settx   A TRUE or FALSE value that indicates if this key should be used
 *                    as the transmit key.
 * @param[in] key   A pointer to a string of bytes that represent the TKIP key to use.
 * @param[in] keylen   The number of bytes that make up the key.  (Should be 32 on TKIP.)
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_set_tkip_key(context *ctx, char *addr, int keyidx, int settx, 
						char *key, int keylen)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_tkip_key == NULL) return XEMALLOC;

  return wireless->set_tkip_key(ctx, (uint8_t *) addr, keyidx, settx, 
				key, keylen);
}

/**
 * \brief Set a CCMP (AES) key
 *
 * @param[in] ctx   The context that contains the interface that we want to set
 *                  a CCMP key on.
 * @param[in] addr   The BSSID (MAC address) of the AP that this key should be used
 *                   with.
 * @param[in] keyidx   The index for the key slot that this key should be used in.
 * @param[in] settx   A TRUE or FALSE value that identifies if this key should be used
 *                    as a transmit key.
 * @param[in] key   A pointer to a byte string that is to be used as the CCMP key.
 * @param[in] keylen   The length of the byte string pointed to by "key".  (This should
 *                     be 16.)
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_set_ccmp_key(context *ctx, char *addr, int keyidx,
			int settx, char *key, int keylen)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_ccmp_key == NULL) return XEMALLOC;

  return wireless->set_ccmp_key(ctx, (uint8_t *) addr, keyidx, settx,
				key, keylen);
}

/**
 * \brief Delete a key from an interface.
 *
 * @param[in] ctx   The context that contains the interface that we want to delete
 *                  a key from.
 * @param[in] key_idx   The index for the key that we want to delete.
 * @param[in] set_tx   A TRUE or FALSE value that identifies if this key was a
 *                     transmit key.
 **/
int cardif_delete_key(context *intdata, int key_idx, int set_tx)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return -1;

  if (wireless->delete_key == NULL) return -1;

  return wireless->delete_key(intdata, key_idx, set_tx);
}

/**
 * \brief Do whatever we need to do in order to associate based on the flags in
 *        the ssids_list struct.
 *
 * @param[in] ctx   The context that contains the interface that we want to try to
 *                  associate with.
 **/
void cardif_associate(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (wireless->associate == NULL) return;

  wireless->associate(ctx);
}

/**
 * \brief Request that the card/driver tell us which ESSID we are connected to.
 *
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 *
 * @param[in] ctx   The context that contains the interface that we want to get the
 *                  ESSID from.
 * @param[out] ssid_name   A buffer that is large enough to hold the resulting ESSID
 *                        name.
 * @param[in] ssidsize   The size of buffer that "ssid_name" points to.
 * 
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation error
 **/
int cardif_GetSSID(context *ctx, char *ssid_name, unsigned int ssidsize)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ssid_name != NULL), "ssid_name != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "No valid call to get SSID for this driver!"
		   "\n");
      return XEMALLOC;
    }

  if ((ctx == NULL) || (ssid_name == NULL)) 
  {
    debug_printf(DEBUG_INT, "NULL value passed to %s!\n", __FUNCTION__);
    return XEMALLOC;
  }

  return wireless->get_ssid(ctx, ssid_name, ssidsize);
}

/**
 * \brief Request that the card/driver return the BSSID (MAC Address) of the AP we
 *        are connected to.
 *
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 * @param[in] ctx   A context that contains the interface that we want to query to 
 *                  determine the BSSID of the interface.
 * @param[out] bssid_dest   A pointer to a buffer of at least 6 bytes that the BSSID
 *                          can be written to.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_GetBSSID(context *ctx, char *bssid_dest)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((bssid_dest != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	return cardif_windows_wireless_get_bssid(ctx, bssid_dest);
}

/**
 * \brief Determine if an interface is up or down.
 *
 * Set the flag in the state machine that indicates if this interface is up
 * or down.  If there isn't an interface, we should return an error.
 *
 * @param[in] ctx   A pointer to the context that contains the interface that we want
 *                  to determine the up/down state of.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval TRUE if the interface is up.
 * \retval FALSE if the interface is down.
 **/
int cardif_get_if_state(context *ctx)
{
  int retVal = 0;
  DWORD result = 0, *state = NULL;
  struct win_sock_data *sockData = NULL;
  UCHAR QueryBuffer[sizeof(NDIS_OID) + 4];
  DWORD BytesReturned = 0;
  PNDISPROT_QUERY_OID pQueryOid = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
  pQueryOid->Oid = OID_GEN_HARDWARE_STATUS;

  result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
        debug_printf(DEBUG_INT, "Get interface state IOCTL failed.  (%x) --  Assuming the interface is down.\n", result);

        return FALSE;
    }

  state = (DWORD *)&pQueryOid->Data[0];

  result = (*state);

  if (result == NdisHardwareStatusReady)
    {
      return TRUE;
    } 
	
  return FALSE;
}

/**
 * \brief Get the link state of an interface.
 *
 * Return the link state of the interface.  On Windows, this indicates that link is up/down
 * on a wired interface, but also indicates associated/unassociated state on wireless.
 *
 * @param[in] ctx   The context for the interface that we want to determine the link
 *                  state of an interface for.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval TRUE if link is up
 * \retval FALSE if link is down
 **/
int cardif_get_link_state(context *ctx)
{
  int retVal = 0;
  DWORD result = 0, *state = NULL;
  struct win_sock_data *sockData = NULL;
  UCHAR QueryBuffer[sizeof(NDIS_OID) + 4];
  DWORD BytesReturned = 0;
  PNDISPROT_QUERY_OID pQueryOid = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (TEST_FLAG(ctx->flags, INT_GONE)) return FALSE;  // The interface isn't there, so it can't be up. ;)

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
  pQueryOid->Oid = OID_GEN_MEDIA_CONNECT_STATUS;

  result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		// If we can't make this call, assume link is down.
		return FALSE;
    }

  state = (DWORD *)&pQueryOid->Data[0];

  result = (*state);

  if (result == 0)
    {
      return TRUE;
    } 
	
  return FALSE;
}

/**
 * \brief Manually check any events that need to be checked on Windows.
 *
 * @param[in] ctx   The context for the interface that we need to check for events.
 **/
void cardif_check_events(context *ctx)
{
	wireless_ctx *wctx = NULL;
	uint8_t link = 0, assoc = 0;

	TRACE

	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

#if 0
	//  It is possible that wctx will end up being NULL!
	//   You should test that it is valid before attempting to use it!
	wctx = (wireless_ctx *)ctx->intTypeData;

	link = cardif_get_link_state(ctx);
	assoc = cardif_check_associated(ctx);
	
	if ((link == TRUE) && (assoc == IS_ASSOCIATED))
	{
		// If this is a wired interface, we won't have a value for "wctx".  So be sure we don't
		// segfault.
		if (wctx != NULL)	
		{
			if (!TEST_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION))
				SET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);
		}
	}
	else
	{
		if (wctx != NULL) 
		{
			UNSET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);
			UNSET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);
	
			// *DO NOT* change the value of wctx->assoc_type here!  We should only
			// change that value when we go to UNASSOCIATED state!
		}
	}
#endif
}

/**
 * \brief Send a frame out a network interface.
 *
 * Send a frame out of the network card interface.  If there isn't an 
 * interface, we should return an error.  We should return a different error
 * if we have a problem sending the frame.
 *
 * @param[in] ctx   The context that contains the interface that we want to send a
 *                  frame out of.
 *
 * \retval XEMALLOC on memory allocation failure
 * \retval XEGENERROR a general error occurred
 * \retval XENONE on success
 **/
int cardif_sendframe(context *ctx)
{
  char nomac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  int retval = 0;
  struct win_sock_data *sockData = NULL;
  struct config_network *network_data  = NULL;
  uint16_t pad = 0;
  OVERLAPPED ovr;
  LPVOID lpMsgBuf = NULL;
  HANDLE hEvent = INVALID_HANDLE_VALUE;
  DWORD result = 0, success = 0, bwritten = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  if (ctx->send_size == 0) 
    {
      debug_printf(DEBUG_INT, "%s:%d -- Nothing to send!\n",
		   __FUNCTION__, __LINE__);
      return XENONE;
    }

  memset(&ovr, 0x00, sizeof(OVERLAPPED));

  hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (hEvent == INVALID_HANDLE_VALUE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't establish event handle for interface '%s'!\n", ctx->desc);
	  ipc_events_error(ctx, IPC_EVENT_ERROR_EVENT_HANDLE_FAILED, ctx->desc);
	  return XEGENERROR;
  }

  ovr.hEvent = hEvent;

  // The frame we are handed in shouldn't have a src/dest, so put it in.
  memcpy(&ctx->sendframe[0], &ctx->dest_mac[0], 6);
  memcpy(&ctx->sendframe[6], &ctx->source_mac[0], 6);

  if (ctx->conn != NULL)
    {
		if (memcmp(nomac, (char *)&ctx->conn->dest_mac[0], 6) != 0)
	  {
	    debug_printf(DEBUG_INT, "Static MAC address defined!  Using it!\n");
		memcpy(&ctx->sendframe[0], &ctx->conn->dest_mac[0], 6);
	  }
    }

  // Make sure the frame is large enough.
  if (ctx->send_size < 64)
    {
      pad = 64 - ctx->send_size;
      debug_printf(DEBUG_INT, "Padding frame to 64 bytes by adding %d byte"
		   "(s).\n", pad);
      memset(&ctx->sendframe[ctx->send_size+1], 0x00, pad);
      ctx->send_size += pad;
    }

  debug_printf(DEBUG_INT, "Frame to be sent (%d) : \n",
	       ctx->send_size);
  debug_hex_dump(DEBUG_INT, ctx->sendframe, ctx->send_size);

  snmp_dot1xSuppEapolFramesTx();

  if (WriteFile(sockData->devHandle, ctx->sendframe, ctx->send_size, &bwritten, &ovr) != 0)
  {
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SEND_FAILED, ctx->desc);
	  lpMsgBuf = GetLastErrorStr(GetLastError());
	  debug_printf(DEBUG_NORMAL, "Couldn't send frame to the authenticator on interface '%s'!   Error was : %s\n", 
		  ctx->desc, lpMsgBuf);
	  LocalFree(lpMsgBuf);
	  CloseHandle(hEvent);
	  retval = XEGENERROR;
  }

  result = WaitForSingleObjectEx(hEvent, 1000, FALSE);
  
  switch (result)
  {
  case WAIT_ABANDONED:
	  debug_printf(DEBUG_NORMAL, "WaitForSingleObjectEx() returned WAIT_ABANDONED!\n");
	  retval = XEGENERROR;
	  break;

  case WAIT_IO_COMPLETION:
	  debug_printf(DEBUG_NORMAL, "WAIT_IO_COMPLETION\n");
	  break;

  case WAIT_OBJECT_0:
	  // The send was probably successful.  Double check GetLastError() to be sure.
	  success = GetLastError();

	  // ERROR_IO_PENDING means that there is another handler waiting to be triggered
	  // on the same device.  Since we will always have a read handle pending, we should
	  // always get an ERROR_IO_PENDING following a send.
	  if ((success != ERROR_SUCCESS) && (success != ERROR_IO_PENDING))
	  {
		  ipc_events_error(ctx, IPC_EVENT_ERROR_SEND_FAILED, ctx->desc);
		  lpMsgBuf = GetLastErrorStr(success);
  		  debug_printf(DEBUG_NORMAL, "Send was not entirely successful in interface '%s'.  Error was : %s\n",
			  ctx->desc, lpMsgBuf);
		  LocalFree(lpMsgBuf);
		  result = XEGENERROR;
	  }
	
	  break;

  case WAIT_TIMEOUT:
	  success = GetLastError();

	  if ((success != ERROR_SUCCESS) && (success != ERROR_IO_PENDING))
	  {
		  lpMsgBuf = GetLastErrorStr(success);
		  debug_printf(DEBUG_NORMAL, "Attempt to send the frame timed out on interface '%s'!  Error was : %s\n", ctx->desc, lpMsgBuf);
		  LocalFree(lpMsgBuf);
		  ipc_events_error(ctx, IPC_EVENT_ERROR_SEND_FAILED, ctx->desc);
		  retval = XEGENERROR;
	  }
	  else
	  {
		  debug_printf(DEBUG_NORMAL, "Frame was delayed on interface '%s' while trying to be sent.  (This should be harmless.)\n", ctx->desc);
		  retval = XENONE;
	  }
	  break;

  case WAIT_FAILED:
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SEND_FAILED, ctx->desc);
	  lpMsgBuf = GetLastErrorStr(GetLastError());
	  debug_printf(DEBUG_NORMAL, "Wait for frame to be sent failed on interface '%s'!   Error was : %s\n", ctx->desc,
		  lpMsgBuf);
	  LocalFree(lpMsgBuf);
	  retval = XEGENERROR;
	  break;

  default:
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SEND_FAILED, ctx->desc);
	  lpMsgBuf = GetLastErrorStr(GetLastError());
	  debug_printf(DEBUG_NORMAL, "Unknown failure code returned on interface '%s'.   Error was : %s\n", 
		  ctx->desc, lpMsgBuf);
	  LocalFree(lpMsgBuf);
	  retval = XEGENERROR;
	  break;
  }

  CloseHandle(hEvent);

  memset(ctx->sendframe, 0x00, FRAMESIZE);
  ctx->send_size = 0;
  
  // Clear out the receive buffer so we don't accidently try to process it
  // again.
  if (ctx->recvframe != NULL)
    {
      memset(ctx->recvframe, 0x00, FRAMESIZE);
      ctx->recv_size = 0;
    }

  return retval;
}

/**
 * \brief Verify that the frame we got is something we care about.  If not, discard it.
 *
 * @param[in] ctx   The context that contains the interface that we want to receive
 *                  a frame on.
 *
 * \retval XENOFRAMES there are no frames available to process
 * \retval XEMALLOC there was a memory allocation error
 * \retval >0 the number of bytes returned
 *
 * \todo Fix up 888e check to allow preauth data to come through as well.
 **/
int cardif_getframe(context *ctx)
{
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
  struct config_globals *globals = NULL;
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return XEMALLOC;

  wctx = (wireless_ctx *)ctx->intTypeData;
  if (wctx != NULL)
  {
	if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
	{
		// This message would probably freak out most users, so only display
		// it in debug mode.
		debug_printf(DEBUG_INT, "Got a frame while scanning..  Checking if we can auth.\n");

		// If we already have information in the SSID cache about this network, then we should
		// cancel the scan in progress, and do the authentication.  Also, because we won't ever
		// have information in the scan cache about hidden networks, if we believe the network is
		// hidden, we should also move on. Otherwise, we should allow the scan to continue.
		debug_printf(DEBUG_INT, "Known SSID : %s\n", wctx->cur_essid);
		if ((config_ssid_ssid_known(wctx, wctx->cur_essid) == TRUE) || (TEST_FLAG(ctx->flags, CONFIG_NET_IS_HIDDEN)))
		{
			debug_printf(DEBUG_INT, "We know enough to authenticate.  Canceling scan.\n");
			timer_cancel(ctx, SCANCHECK_TIMER);
			UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);
			wireless_sm_change_state(ASSOCIATED, ctx);
		}
		else 
		{
			debug_printf(DEBUG_INT, "We don't know enough to complete an authentication.  Discarding.\n");
			ctx->recv_size = 0;
			return XENONE;
		}
	}
  }

  if ((ctx->recvframe == NULL)) return XENOFRAMES;

  // Make sure that the frame we got is for us..
  if ((memcmp(&ctx->source_mac[0], &ctx->recvframe[0], 6) == 0) ||
      ((memcmp(&ctx->recvframe[0], &dot1x_default_dest[0], 6) == 0) &&
       (memcmp(&ctx->recvframe[6], &ctx->source_mac[0], 6) != 0)))
    {
      // Since we now know this frame is for us, record the address it
      // came from.
      snmp_dot1xSuppLastEapolFrameSource((uint8_t *)&ctx->recvframe[6]);

	  switch (globals->destination)
		{
			case DEST_AUTO:
			// If it is a wired interface, only change the destination if
			// the recieved frame destination isn't the multicast address.
			if (ctx->intType != ETH_802_11_INT)
			{
				if (memcmp(&ctx->recvframe[0], dot1x_default_dest, 6) == 0)
				{
					break;
				}
				// Otherwise, fall through.
			}

			case DEST_SOURCE:
			if (memcmp(ctx->dest_mac, &ctx->recvframe[6], 6) != 0)
			{
				debug_printf(DEBUG_INT, "Changing destination mac to source on '%s'.\n", ctx->desc);
			}
			memcpy(ctx->dest_mac, &ctx->recvframe[6], 6);
			break;

			case DEST_MULTICAST:
			memcpy(ctx->dest_mac, dot1x_default_dest, 6);
			break;

			case DEST_BSSID:
			cardif_GetBSSID(ctx, ctx->dest_mac);
			break;

			default:
				debug_printf(DEBUG_NORMAL, "Unknown destination mode on interface '%s'!\n", ctx->desc);
			break;
	  }

	  // Make sure it is 888e.
	  if ((ctx->recvframe[12] != 0x88) || (ctx->recvframe[13] != 0x8e))
	  {
		  debug_printf(DEBUG_INT, "An invalid frame managed to sneak "
			  "through interface '%s'!  Killing it!\n", ctx->desc);
		  debug_hex_dump(DEBUG_INT, ctx->recvframe, 16);

		  FREE(ctx->recvframe);
		  ctx->recv_size = 0;

		  return XENOFRAMES;
	  }

	  debug_printf(DEBUG_INT, "Got Frame of size %d on interface '%s' : \n", ctx->recv_size, ctx->desc);
	  debug_hex_dump(DEBUG_INT, ctx->recvframe, ctx->recv_size);

	  snmp_dot1xSuppEapolFramesRx();

      return ctx->recv_size;
    }

  // Otherwise it isn't for us. 
  debug_printf(DEBUG_INT, "Got a frame, not for us.\n");
  debug_hex_dump(DEBUG_INT, ctx->recvframe, 16);

  return XENOFRAMES;
}

/**
 * \brief Set up an event handler to let us know when we got a frame from the network.
 *
 * @param[in] ctx   The context that contains the interface that we want to 
 *                  receive data on.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XEGENERROR on general error
 * \retval XENONE on success
 **/
int cardif_setup_recv(context *ctx)
{
  int newsize=0;  
  struct win_sock_data *sockData = NULL;
  uint8_t *resultframe = NULL;
  int resultsize = 0;
  struct config_globals *globals = NULL;
  LPVOID lpMsgBuf = NULL;
  ULONG breadd = 0;
  LPOVERLAPPED lovr;
  DWORD result = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  resultsize = FRAMESIZE; 

  lovr = event_core_get_ovr(sockData->devHandle);
  if (lovr == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "The device handle doesn't appear to have an event handler "
		  "registered on interface '%s'!\n", ctx->desc);
	  ipc_events_error(ctx, IPC_EVENT_ERROR_EVENT_HANDLE_FAILED, ctx->desc);
	  return XEMALLOC;
  }

  if (HasOverlappedIoCompleted(lovr) == FALSE)
  {
	  // The last I/O request we had set up never finished.  So, we don't want to schedule a 
	  // a new one.  (Or weird things happen.)
	  debug_printf(DEBUG_NORMAL, "Windows reported that an overlapped I/O had not completed on interface '%s' even though the object was signaled.  Please attempt your authentication again.  If the problem persists, please report it to the Open1X mailing list.\n",
		  ctx->desc);
	  return XENONE;
  }

  // Clear the existing frame storage buffer.  (If needed.)
//  FREE(sockData->frame);
  sockData->size = 0;


  if (sockData->frame == NULL)
    {
	  sockData->frame = Malloc(FRAMESIZE);
	  if (sockData->frame == NULL)
	  {
      debug_printf(DEBUG_INT, "Couldn't allocate memory for incoming frame!\n");
	  ipc_events_malloc_failed(ctx);
      return XEMALLOC;
	  }
    }

  if (sockData->hEvent == INVALID_HANDLE_VALUE)
  {
	// Establish an event that will trigger to let us know that we have data.
	sockData->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (sockData->hEvent == INVALID_HANDLE_VALUE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't create a valid event handle on interface '%s'!\n", ctx->desc);
		ipc_events_error(ctx, IPC_EVENT_ERROR_EVENT_HANDLE_FAILED, ctx->desc);
		FREE(sockData->frame);
		return XEGENERROR;
	}

	memset(lovr, 0x00, sizeof(OVERLAPPED));

    lovr->hEvent = sockData->hEvent;
    event_core_bind_hevent(sockData->devHandle, sockData->hEvent);
  }
  else
  {
	  if (ResetEvent(sockData->hEvent) == 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't reset event handler for interface '%s'.\n", ctx->desc);
		  FREE(sockData->frame);
		  return XEGENERROR;
	  }
	  lovr->hEvent = sockData->hEvent;
  }

  if (resultsize != FRAMESIZE) 
  {
	  debug_printf(DEBUG_NORMAL, "The desired frame size has change from when we originally set it.  This could indicate a memory corruption error.  Please report it to the Open1X mailing list!\n");
  }

  if (ReadFile(sockData->devHandle, sockData->frame, resultsize, &sockData->size, lovr) != 0)
  {
	  lpMsgBuf = GetLastErrorStr(GetLastError());
	  debug_printf(DEBUG_NORMAL, "Error setting up frame listener on interface '%s'.  Error was : %s\n", 
		  ctx->desc, lpMsgBuf);
	  LocalFree(lpMsgBuf);
	  FREE(sockData->frame);
	  return XEGENERROR;
  }

  return XENONE;
}

/**
 * \brief Set the state needed to associate to a WPA enabled AP, and actually
 *        do a WPA authentication.
 *
 * @param[in] ctx   The context that contains the interface that we want to enable 
 *                  WPA set for.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_enable_wpa_state(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->wpa_state == NULL) return XEMALLOC;

  debug_printf(DEBUG_INT, "WPA: Enabling WPA state on interface %s.\n", ctx->intName);

  return wireless->wpa_state(ctx, TRUE);
}

/**
 * \brief Clear the state needed to associate to a WPA enabled AP, and actually
 *        do a WPA authentication.
 *
 * @param[in] ctx   The context that contains the interface that we want to clear
 *                  WPA state on.
 *
 * \retval XEMALLOC a memory allocation error occurred
 * \retval XENONE on success
 **/
int cardif_disable_wpa_state(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->wpa_state == NULL) return XEMALLOC;

  return wireless->wpa_state(ctx, FALSE);
}

/**
 * \brief Enable WPA support on an interface.
 *
 * Windows already should have WPA enabled, so this function is only needed as a stub.
 *
 * @param[in] ctx   The context that contains the interface to enable WPA on.
 *
 * \retval XENONE always returned for Windows
 **/
int cardif_enable_wpa(context *ctx)
{
	return XENONE;
}

/**
 * \brief Call this when we roam to a different AP, or disassociate from an AP.
 *
 * @param[in] ctx   The context for the interface that we want to use WEP to 
 *                  associate with.
 *
 * \retval XEMALLOC on memory allocation errors
 * \retval XENONE on success
 **/
int cardif_wep_associate(context *ctx, int zeros)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (!config_ssid_using_wep(ctx->intTypeData))
    {
      debug_printf(DEBUG_INT, "Doing WPA/WPA2 mode! Not "
		   "setting/unsetting keys.\n");
      return XENONE;
    }

  return wireless->wep_associate(ctx, zeros); 
}

/**
 * \brief Validate an interface.  (Basically, see if it is an interface we know how to 
 *        deal with.
 *
 * @param[in] interf   A non-unicode string that identifies the interface to validate.
 *
 * \retval TRUE is always returned (for now)
 **/
int cardif_validate(char *interf)
{
	// This would require that we bind, and then unbind from an interface.  So, for now just
	// return TRUE.  (XXX Fix later.)
	return TRUE;

#if 0
  int retVal;
  DWORD result, *state;
  struct win_sock_data *sockData;
  UCHAR QueryBuffer[sizeof(NDIS_OID) + 4];
  DWORD BytesReturned;
  PNDISPROT_QUERY_OID pQueryOid;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  pQueryOid = (PNDISPROT_QUERY_OID)&QueryBuffer[0];
  pQueryOid->Oid = OID_GEN_MEDIA_SUPPORTED;

  result = devioctl(sockData->devHandle, IOCTL_NDISPROT_QUERY_OID_VALUE,
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer),
					(LPVOID)&QueryBuffer[0], sizeof(QueryBuffer), &BytesReturned);

  if ((result != WAIT_OBJECT_0) && (result != WAIT_IO_COMPLETION))
    {
		if (result == 0xffffffff)
		{
			// The IOCTL isn't supported.
			debug_printf(DEBUG_NORMAL, "The IOCTL to determine if this interface is ethernet "
					"does not appear to be implemented in this driver!  Assuming it is "
					"not.\n");
			return FALSE;
		}

        debug_printf(DEBUG_NORMAL, "Get physical media type IOCTL failed.  (%x)\n", result);

		// Assume the interface is wired, so we don't try to do anything fancy with it.
        return FALSE;
    }

  state = (DWORD *)&pQueryOid->Data[0];
  result = (*state);

  if (result == NdisMedium802_3)
    {
	  debug_printf(DEBUG_INT, "Interface appears to be ethernet!\n");
      return TRUE;
    } 
	
  debug_printf(DEBUG_INT, "Interface is not ethernet, or unknown.\n");
  return FALSE;
#endif
}

/**
 * \brief (en)/(dis)able countermeasures on this interface.
 *
 * @param[in] ctx   The context that contains the interface that we want to enable or
 *                  disable countermeasures for.
 * @param[in] endis   A TRUE or FALSE value that indicates if countermeasures should
 *                    be enabled (TRUE) or disabled (FALSE).
 *
 * \retval XEMALLOC a memory allocation error occurred
 * \retval XENONE on success
 **/
int cardif_countermeasures(context *ctx, char endis)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->countermeasures == NULL) return XEMALLOC;

  return wireless->countermeasures(ctx, endis);
}

/**
 * \brief (en)/(dis)able receiving of unencrypted frames on this interface.
 *
 * @param[in] ctx   The context that contains the interface that we want to enable
 *                  or disable receiving of unencrypted frames on.
 *
 * @param[in] endis   Should we drop unencrypted frames (TRUE), or accept them (FALSE)
 *
 * \retval XEMALLOC a memory allocation error occurred
 * \retval XENONE on success
 **/
int cardif_drop_unencrypted(context *ctx, char endis)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (config_ssid_using_wep(ctx->intTypeData)) return XENONE;
  
  return wireless->drop_unencrypted(ctx, endis);
}

/**
 * \brief Create a WPA1 Information Element (IE) that we can use to establish a 
 *        connection to the desired ESSID.
 * 
 * @param[in] ctx   A pointer to a context that contains the information we need to
 *                  properly build a WPA IE.
 * @param[out] iedata   A pointer to a buffer that will return the WPA IE to be used.
 * @param[out] ielen   The size of the resulting WPA IE.
 *
 * \warning  iedata should be at least 256 characters long to avoid accidently 
 *           overflowing the string!
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on sucess
 **/
int cardif_get_wpa_ie(context *ctx, char *iedata, int *ielen)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ielen != NULL), "ielen != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  return wireless->get_wpa_ie(ctx, iedata, ielen);
}

/**
 * \brief Create a WPA2 Information Element (IE) that we can use to establish a 
 *        connection to the desired ESSID.
 * 
 * @param[in] ctx   A pointer to a context that contains the information we need to
 *                  properly build a WPA2 IE.
 * @param[out] iedata   A pointer to a buffer that will return the WPA2 IE to be used.
 * @param[out] ielen   The size of the resulting WPA2 IE.
 *
 * \warning  iedata should be at least 256 characters long to avoid accidently 
 *           overflowing the string!
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on sucess
 **/
int cardif_get_wpa2_ie(context *intdata, char *iedata, int *ielen)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ielen != NULL), "ielen != NULL", FALSE))
    return XEMALLOC;

  if (!wireless)
    {
      debug_printf(DEBUG_NORMAL, "Invalid wireless function pointers.\n");
      return XEMALLOC;
    }

  if (iedata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid buffer for IE data! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

  if (!wireless->get_wpa2_ie)
    {
      debug_printf(DEBUG_NORMAL, "No valid function to get WPA2 IE!\n");
      return XEMALLOC;
    }

  return wireless->get_wpa2_ie(intdata, iedata, ielen);
}

/**
 * \brief Clear all keys currently applied to the card.
 *
 * This function should clear out all keys that have been applied to the card.
 * It should be indepentant of the type (WEP/TKIP/CCMP) of key that was
 * applied.
 *
 * @param[in] ctx   The context that contains the interface that we want to clear keys
 *                  from.
 *
 * \retval XENONE on success
 * \retval !XENONE on error
 **/
int cardif_clear_keys(context *ctx)
{
	// In Windows, setting the card to infrastructure mode will automatically clear
	// all of the keys in the key cache.  This is more efficient than making an IOCTL
	// for every key we might have, and has the added bonus that it doesn't cause
	// bogus error messages when using the Intel 3945 driver! ;)

	return cardif_windows_set_infra_mode(ctx);
}

/**
 * \brief Attempt to reassociate to the network we were previously connected to.
 *
 * @param[in] ctx   The context that contains the interface that we want to reassociate
 *                  on.
 * @param[in] reason   A reason code as identified by the 802.11 standards.
 **/
void cardif_reassociate(context *ctx, uint8_t reason)
{
	wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if (!config_ssid_using_wep(wctx))
    {
      debug_printf(DEBUG_INT, "SSID '%s' is WPA/WPA2 capable. WPA/WPA2 is "
		   "enabled on this connection.\n", wctx->cur_essid);
      
      // Since we are doing WPA/WPA2, we need to disassociate from 
      // the network, and reassociate with WPA/WPA2 set up.
      cardif_enable_wpa(ctx);
      cardif_enable_wpa_state(ctx);

      cardif_clear_keys(ctx);
    }

  cardif_associate(ctx);  
}

/**
 * \brief Disable encryption on the card.  (Set the interface to open mode.)
 *
 * @param[in] ctx   The context that contains the interface that we want to disable
 *                  encryption on.
 * 
 * \retval XEMALLOC on memory allocation error.
 * \retval XENONE on success
 **/
int cardif_enc_disable(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless->enc_disable == NULL) return XEMALLOC;

  return wireless->enc_disable(ctx);
}

/**
 * \brief Determine what abilities this card has.  (WPA, WPA2, TKIP, CCMP, WEP40, 
 *        etc.)
 *
 * @param[in] ctx   The context that contains the interface that we want to get
 *                  the capabilities for.
 **/
void cardif_get_abilities(context *ctx)
{
	wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		FALSE))
	return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (wireless == NULL) 
  {
	  wctx->enc_capa = 0;
	  return;
  }

  if (wireless->enc_capabilities == NULL)
    {
      wctx->enc_capa = 0;
      return;
    }

  wireless->enc_capabilities(ctx);
}

/**
 * \brief Change the BSSID that we are currently connected to.
 *
 * @param[in] ctx   The context that contains the interface that we want to change
 *                  the BSSID for.
 * @param[in] new_bssid   A pointer to a MAC address that will be the new BSSID we
 *                        are trying to connect to.
 **/
void cardif_setBSSID(context *ctx, uint8_t *new_bssid)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((new_bssid != NULL), "new_bssid != NULL", FALSE))
    return;

  if (!wireless->setbssid)
    {
      return;
    }

  wireless->setbssid(ctx, new_bssid);
}

/**
 * \brief Change the operstate of the interface.
 *
 * @param[in] ctx   The context that contains the interface that we want to change
 *                  the operstate on.
 * @param[in] newstate   The new operational state for this interface.
 **/
void cardif_operstate(context *ctx, uint8_t newstate)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (wireless == NULL) return;

  if (!wireless->set_operstate)
    {
      debug_printf(DEBUG_INT, "No function defined to set operstate. (This "
		   "is probably nothing to worry about.)\n");
      return;
    }

  wireless->set_operstate(ctx, newstate);
}

/**
 * \brief The passive scan timer expried.  So, we need to issue a scan request,
 *        and reset our timer to recheck the scan results periodically.
 *
 * @param[in] ctx   The context for the interface that we want to issue a passive 
 *                  scan on.
 * 
 * \note Windows does not support passive scanning!
 *
 * \todo On Linux, we get the scan data, but don't do anything with it yet.
 **/
void cardif_passive_scan_timeout(context *ctx)
{
  struct config_globals *globals = NULL;
  uint8_t *mac = NULL;
  char *ssid = NULL;
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

#if 0
#warning FINISH!  We get scan data results, but we still need to do something with them.
#endif

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if (!TEST_FLAG(wctx->flags, WIRELESS_PASV_SCANNING))
    {
     if (!TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
	{
	  timer_reset_timer_count(ctx, PASSIVE_SCAN_TIMER, 5);
	  cardif_do_wireless_scan(ctx, 1);
	  SET_FLAG(ctx->flags, WIRELESS_PASV_SCANNING);
	}
      else
	{
	  debug_printf(DEBUG_NORMAL, "Got a request to start a new passive scan on interface '%s'"
		  "when a previous one has not completed!\n", ctx->desc);
	}
    }
  else
    {
      // If the scanning flag is no longer set, then we need to make a decision
      // about how to associate.
		debug_printf(DEBUG_NORMAL, "Looking for the best network to connect to with interface '%s'.\n", ctx->desc);
      // Clear the passive scanning flag.
      UNSET_FLAG(ctx->flags, WIRELESS_PASV_SCANNING);

      // Reset the timer so that we scan again.
      
      globals = config_get_globals();
      
      if (!globals)
	{
	  debug_printf(DEBUG_NORMAL, "No global data!  Passive scanning will"
		       " be broken until the next time an authentication "
		       "completes.\n");
	}
      else
	{
	  debug_printf(DEBUG_INT, "Resetting passive scan timer.\n");
	  timer_reset_timer_count(ctx, PASSIVE_SCAN_TIMER, globals->passive_timeout);
	  
	}

      ssid = config_ssid_get_desired_ssid(ctx);

      if (ssid == NULL)
        {
          debug_printf(DEBUG_NORMAL, "No valid SSID was returned.  Either "
                       "there is something wrong with your configuration, or"
                       " the passive scan didn't find a network that is "
                       "currently configured.\n");
          return;
        }

      if (strcmp(ssid, wctx->cur_essid) != 0)
	{
	  debug_printf(DEBUG_NORMAL, "The best AP to connect to appears to be"
		       " in a different ESSID!  It is likely that your card"
		       " doesn't support the needed passive scanning flags."
		       "\n");
	  // Don't do anything with the result.
	} 
      else
	{
	  // We got a valid result.  So, see if it is a different AP.  If it
	  // is, then jump to it.
	  mac = config_ssid_get_mac(wctx);

          if (mac == NULL)
            {
              debug_printf(DEBUG_NORMAL, "Couldn't determine the MAC "
                           "address for the desired SSID found in a passive "
                           "scan.  You may not be associated to the best AP, "
                           "but your network should continue to work.\n");
              return;
            }

	  if (memcmp(ctx->dest_mac, mac, 6) != 0)
	    {
	      debug_printf(DEBUG_INT, "Jumpping to a BSSID with a better "
			   "signal.  (BSSID : ");
	      debug_hex_printf(DEBUG_INT, mac, 6);
	      debug_printf_nl(DEBUG_INT, ")\n");

	      // Then change our BSSIDs.
	      cardif_setBSSID(ctx, mac);
	    }
	  else
	    {
	      debug_printf(DEBUG_INT, "We are connected to the best "
			   "BSSID already.\n");
	    }
	}
    }
}

/**
 * \brief Use the device name to determine the MAC address of an interface.
 *
 *  Using the device name, allocate a temporary handle, query the MAC address, and
 *  return the MAC address.  (Be sure the handle is closed correctly when this function
 *  terminates!
 *
 * @param[in] intname   A non-unicode string that contains the interface name that
 *                      we want to check against.
 * @param[out] intmac   A pointer to a buffer that contains at least 6 bytes of space
 *                      that the MAC address can be stored in.
 *
 * \retval XEGENERROR on general error ("intmac" will be invalid)
 * \retval XENONE on success
 **/
int get_mac_by_name(char *intname, char *intmac)
{
	LPVOID lpMsgBuf = NULL;
	HANDLE temphandle = INVALID_HANDLE_VALUE;
	char *mac = NULL;

	temphandle = GetHandle((char *)&NdisDev);

	if (temphandle == INVALID_HANDLE_VALUE)
		return XEGENERROR;

	if (BindNDISDevice(temphandle, intname) == 0)
	{

		ipc_events_error(NULL, IPC_EVENT_ERROR_FAILED_TO_BIND, intname);
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Failed to bind interface %s to device "
			"handle.  Error was : %s\n", intname, lpMsgBuf);

		LocalFree(lpMsgBuf);
		CloseHandle(temphandle);
		return XEGENERROR;
	}

	mac = getmac(temphandle);
	if (mac == NULL)
	{
		lpMsgBuf = GetLastErrorStr(GetLastError());
		debug_printf(DEBUG_NORMAL, "Couldn't get MAC address for "
			"interface %s!   Error was : %s\n", intname, lpMsgBuf);

		LocalFree(lpMsgBuf);
		CloseHandle(temphandle);
		return XEGENERROR;
	}

	memcpy(intmac, mac, 6);
	FREE(mac);
	CloseHandle(temphandle);

	return XENONE;
};

/**
 * \brief Convert a unicode string to a standard ASCII string.
 *
 * @param[in] instr   A unicode string that we want to convert to a non-unicode string.
 *
 * \retval ptr to a non-unicode string on success
 * \retval NULL on failure
 **/
char *uni_to_ascii(wchar_t *instr)
{
	int needed_buf = 0, size = 0;
	char *resstr = NULL;

	if (instr == NULL) return NULL;

	// Determine how big of a buffer we need.
	needed_buf = WideCharToMultiByte(CP_UTF8, 0, instr, wcslen(instr), NULL, 0, NULL, NULL);
	needed_buf++;  // Make room for the \0.

	resstr = Malloc(needed_buf);
	if (resstr == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to convert a unicode string to ASCII.\n");
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	size = WideCharToMultiByte(CP_UTF8, 0, instr, wcslen(instr), resstr, needed_buf, NULL, NULL);
	 
	if (size != (needed_buf - 1))
	{
		debug_printf(DEBUG_NORMAL, "Couldn't convert unicode string to ASCII!\n");
                FREE(resstr);
		return NULL;
	}

	return resstr;
}

/**
 *  \brief Go through all known devices, query them for information needed, and populate
 *         the interface cache.
 *
 *  @param[in] devHandle   A handle to the "file" that is provided by the protocol
 *                         driver.
 **/
void ListDevs(HANDLE devHandle)
{
	PNDISPROT_QUERY_BINDING pQueryBinding = NULL;
	DWORD BytesWritten = 0, dw = 0;
	LPVOID lpMsgBuf = NULL;
	uint8_t mac[6];
	char *name = NULL, *desc = NULL;
	int size = 0;

	// Allocate enough memory to store the result.
	pQueryBinding = Malloc(1024);
	if (pQueryBinding == NULL)
	{
		printf("Couldn't allocate memory to store the binding structure!\n");
		ipc_events_malloc_failed(NULL);
		return;
	}

	pQueryBinding->BindingIndex = 0;

	while (devioctl_blk(devHandle, IOCTL_NDISPROT_QUERY_BINDING, 
			pQueryBinding, sizeof(NDISPROT_QUERY_BINDING),
			pQueryBinding, 1024,
			&BytesWritten) != 0)
	{
		name = uni_to_ascii((WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceNameOffset));

		desc = uni_to_ascii((WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceDescrOffset));

		if (get_mac_by_name(name, mac) == XENONE)
		{
			interfaces_add(name, desc, mac, is_wireless(name));
		}

		FREE(name);
		FREE(desc);

		pQueryBinding->BindingIndex++;
	}

	dw = GetLastError();

	if (dw != ERROR_NO_MORE_ITEMS)
	{
		lpMsgBuf = GetLastErrorStr(dw);
		debug_printf(DEBUG_NORMAL, "Error getting interface information.  Error was : %s\n", lpMsgBuf);
		ipc_events_error(NULL, IPC_EVENT_ERROR_GETTING_INT_INFO, NULL);
	}

	free(pQueryBinding);
}

void global_deinit();  ///< Forward decl for the case below where we need to bail out.

/**
 *  \brief Enumerate all of the interfaces that exist on this system, and use the results
 *         to build the interface cache.
 **/
void cardif_enum_ints()
{
	HANDLE devHandle = INVALID_HANDLE_VALUE;
	LPVOID lpMsgBuf = NULL;

	devHandle = GetHandle((char *)&NdisDev);

	if (devHandle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Couldn't establish a handle to the Open1X protocol handler.\n");
		fprintf(stderr, "Is it running?\n");
		global_deinit();
	}

	ListDevs(devHandle);

	if (CloseHandle(devHandle) == 0)
	{
		fprintf(stderr, "Couldn't close device handle to Open1X protocol "
				"handler.\n");

		lpMsgBuf = GetLastErrorStr(GetLastError());
		printf("Error was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
	}

	//interfaces_dump_cache();
}

/**
 * \brief Determine the signal strength (as a percentage) of the wireless connection.
 *
 * @param[in] ctx   The context for the interface that we want to check on the signal
 *                  strength for.
 * 
 * \retval -1 on error
 * \retval >=0 on success
 *
 * \note The value returned is a "best guess" based on what the underlying OS calls
 *       allow us to request.  It is possible that it will return a percentage greater
 *       than 100 on some cards.  As such, this indication should NOT be used for 
 *       anything that requires an accurate signal measurement.
 **/
int cardif_get_signal_strength_percent(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return -1;

  if (wireless == NULL) return -1;

  if (!wireless->get_signal_percent)
    {
      debug_printf(DEBUG_INT, "No function defined to get the signal strength!\n");
      return -1;
    }

  return wireless->get_signal_percent(ctx);
}

/**
 * \brief Get the primary DNS server used to resolve names.
 *
 * @param[in] ctx   The context for the interface that we want to ask about DNS servers.
 *
 * \retval NULL on error, or if there isn't a DNS set.
 * \retval ptr to an ASCII string that has the IP address of the DNS server
 **/
char *cardif_get_dns1(context *ctx)
{
	return NULL;
}

/**
 * \brief Get the secondary DNS server used to resolve names.
 *
 * @param[in] ctx   The context for the interface that we want to ask about DNS servers.
 *
 * \retval NULL on error, or if there isn't a DNS set.
 * \retval ptr to an ASCII string that has the IP address of the DNS server
 **/
char *cardif_get_dns2(context *ctx)
{
	return NULL;
}

/**
 * \brief Get the tertiary DNS server used to resolve names.
 *
 * @param[in] ctx   The context for the interface that we want to ask about DNS servers.
 *
 * \retval NULL on error, or if there isn't a DNS set.
 * \retval ptr to an ASCII string that has the IP address of the DNS server
 **/
char *cardif_get_dns3(context *ctx)
{
	return NULL;
}

/**
 * \brief Determine the OS specific name for a device based on the Windows
 *        description.
 *
 * @param[in] devdesc   The device description that we want to locate the OS specific
 *                      name for.
 *
 * \retval NULL on error, or interface not found
 * \retval ptr to OS specific name on success
 **/
char *cardif_windows_find_os_name_from_desc(wchar_t *devdesc)
{
	PNDISPROT_QUERY_BINDING pQueryBinding = NULL;
	DWORD BytesWritten = 0, dw = 0;
	LPVOID lpMsgBuf = NULL;
	uint8_t mac[6];
	char *name = NULL;
	char *desc = NULL;
	char *shortdesc = NULL;
	char *resstr = NULL;
	int size = 0;
	HANDLE devHandle = INVALID_HANDLE_VALUE;

	devHandle = GetHandle((char *)&NdisDev);
	if (devHandle == INVALID_HANDLE_VALUE) return NULL;

	shortdesc = uni_to_ascii(devdesc);
	if (shortdesc == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Failed to convert string '%ws' to ascii!\n", devdesc);
		CloseHandle(devHandle);
		return NULL;
	}

	// Allocate enough memory to store the result.
	pQueryBinding = Malloc(1024);
	if (pQueryBinding == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store the binding structure!\n");
		ipc_events_malloc_failed(NULL);
		CloseHandle(devHandle);
		return NULL;
	}

	pQueryBinding->BindingIndex = 0;

	while (devioctl_blk(devHandle, IOCTL_NDISPROT_QUERY_BINDING, 
			pQueryBinding, sizeof(NDISPROT_QUERY_BINDING),
			pQueryBinding, 1024,
			&BytesWritten) != 0)
	{
		name = uni_to_ascii((WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceNameOffset));

		desc = uni_to_ascii((WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceDescrOffset));

		if (name == NULL)
		{
			debug_printf(DEBUG_INT, "The device name returned from the IOCTL is NULL in %s() at %d!\n", __FUNCTION__, __LINE__);
		}
		else if (desc == NULL)
		{
			debug_printf(DEBUG_INT, "The device description returned from the IOCTL is NULL in %s() at %d!\n", __FUNCTION__, __LINE__);
		}
		else
		{
			debug_printf(DEBUG_INT, "Checking to see if interface '%s' matches '%s'.\n", desc, shortdesc);
		}

		if ((desc != NULL) && (shortdesc != NULL) && (strcmp(desc, shortdesc) == 0))
		{
			resstr = strdup(name);
		}

		FREE(name);
		FREE(desc);

		pQueryBinding->BindingIndex++;
	}

	dw = GetLastError();

	// Some drivers (such as the Cisco VPN adapter) cause the last error value to be
	// set to ERROR_PROC_NOT_FOUND instead of ERROR_NO_MORE_ITEMS like it should.  So,
	// we trap this case, and ignore it.
	if ((dw != ERROR_NO_MORE_ITEMS) && (resstr == NULL) && (dw != ERROR_PROC_NOT_FOUND))
	{
		lpMsgBuf = GetLastErrorStr(dw);
		ipc_events_error(NULL, IPC_EVENT_ERROR_GETTING_INT_INFO, shortdesc);
		debug_printf(DEBUG_NORMAL, "Error getting interface information!  Error was (%d) : %s\n", dw, lpMsgBuf);
	}

	CloseHandle(devHandle);
	free(pQueryBinding);
	FREE(shortdesc);

	return resstr;
}


/**
 * \brief Determine the device description based on the interface name.
 *
 * @param[in] intname   The OS specific interface name to search for.
 *
 * \retval NULL on error, or interface not found
 * \retval ptr to the interface description
 **/
char *cardif_find_description(char *intname)
{
	PNDISPROT_QUERY_BINDING pQueryBinding = NULL;
	DWORD BytesWritten = 0, dw = 0;
	LPVOID lpMsgBuf = NULL;
	uint8_t mac[6];
	char *name = NULL;
	char *desc = NULL;
	char *resstr = NULL;
	int size = 0;
	HANDLE devHandle = INVALID_HANDLE_VALUE;

	devHandle = GetHandle((char *)&NdisDev);
	if (devHandle == INVALID_HANDLE_VALUE) return NULL;

	// Allocate enough memory to store the result.
	pQueryBinding = Malloc(1024);
	if (pQueryBinding == NULL)
	{
		printf("Couldn't allocate memory to store the binding structure!\n");
		ipc_events_malloc_failed(NULL);
		CloseHandle(devHandle);
		return NULL;
	}

	pQueryBinding->BindingIndex = 0;

	while (DeviceIoControl(devHandle, IOCTL_NDISPROT_QUERY_BINDING,
			pQueryBinding, sizeof(NDISPROT_QUERY_BINDING),
			pQueryBinding, 1024,
			&BytesWritten, NULL) != 0)
	{
		name = uni_to_ascii((WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceNameOffset));

		desc = uni_to_ascii((WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceDescrOffset));

		if (strcmp(name, intname) == 0) 
		{
			resstr = strdup(desc);
		}

		FREE(name);
		FREE(desc);

		pQueryBinding->BindingIndex++;
	}

	dw = GetLastError();

	// Some drivers (such as the Cisco VPN adapter) cause the last error value to be
	// set to ERROR_PROC_NOT_FOUND instead of ERROR_NO_MORE_ITEMS like it should.  So,
	// we trap this case, and ignore it.
	if ((dw != ERROR_NO_MORE_ITEMS) && (resstr == NULL) && (dw != ERROR_PROC_NOT_FOUND))
	{
		lpMsgBuf = GetLastErrorStr(dw);
		printf("Error getting interface information!\n");
		ipc_events_error(NULL, IPC_EVENT_ERROR_GETTING_INT_INFO, NULL);
		printf("  Error was : %s\n", lpMsgBuf);
	}

	CloseHandle(devHandle);
	free(pQueryBinding);

	return resstr;
}

/**
 * \brief Get a string representation of an interface's MAC address based on the
 *        OS specific interface name.
 *
 * @param[in] intname   The OS specific interface name for the interface we want to
 *                      get information on.
 *
 * \retval NULL on error
 * \retval ptr to MAC address string on success
 **/
char *cardif_get_mac_str(char *intname)
{
	uint8_t mac[6];
	char *resmac = NULL;

	if (get_mac_by_name(intname, (char *)&mac) != 0) return NULL;

	resmac = Malloc(25);
	if (resmac == NULL) return NULL;

	sprintf(resmac, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
		mac[4], mac[5]);

	return resmac;
}

/**
 * \brief Determine if an interface is wireless based on it's OS specific interface
 *        name.
 *
 * @param[in] intname   The OS specific interface name that we want to check to see if
 *                      it is wireless.
 *
 * \retval TRUE if the interface is wireless
 * \retval FALSE if the interface is *NOT* wireless
 **/
int cardif_is_wireless_by_name(char *intname)
{
	return is_wireless(intname);
}

/**
 * \brief For the given interface context, cancel the I/O that may be pending on it.  This
 *        should keep us from getting anything weird happening on the interface while the machine
 *        transitions to/through a state where getting I/O could cause us confusion.
 *
 * @param[in] ctx   The context for the interface that we want to cancel I/O on.
 **/
void cardif_cancel_io(context *ctx)
{
	struct win_sock_data *sockData = NULL;

	debug_printf(DEBUG_INT, "Cancelling all pending I/O operations for device '%s'.\n", ctx->desc);

	sockData = ctx->sockData;

	CancelIo(sockData->devHandle);
}

/**
 * \brief For the given interface context, take any steps needed to restart the I/O.
 *
 * @param[in] ctx   The context for the interface that we want to restart I/O on.
 **/
void cardif_restart_io(context *ctx)
{
	debug_printf(DEBUG_INT, "Restarting I/O for device '%s'.\n", ctx->desc);
	cardif_setup_recv(ctx);
}
