/**
 * Windows WLAN API interface
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wlanapi_interface.c
 *
 * \author chris@open1x.org
 **/  
    
#include <windows.h>
#include <wlanapi.h>
    
#include "../../xsup_debug.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "wlanapi_interface.h"
#include "cardif_windows.h"
    
/**
 * \note Below we define entrypoints in to the wlanapi.dll when we could achive something similar by
 *       linking wlanapi.lib.  However, it is important to understand that if we want to remain backward
 *       compatible with versions of Windows that don't have the wlanapi, we can't link in wlanapi.lib.
 *       Doing so results in an error on the startup of the program that complains that wlanapi.dll can't
 *       be found.  So, we have to do it the hard way.
 *
 *       It is also worth noting that we do include wlanapi.h.  This is so that we can make use of the
 *       structure definitions without worrying about making copies of them.  This also means that we
 *       need to use slightly different function names for our code, since the "correct" function call
 *       names will already be prototyped in the header.
 **/ 
typedef DWORD(WINAPI * WlOpenHdl) (DWORD dwClientVersion, PVOID pReserved,
				    PDWORD pdwNegotiatedVersion,
				    PHANDLE phClientHandle);
typedef DWORD(WINAPI * WlEnumInts) (HANDLE hClientHandle, PVOID pReserved,
				     PWLAN_INTERFACE_INFO_LIST *
				     ppInterfaceList);
typedef DWORD(WINAPI * WlQueryInt) (HANDLE hClientHandle,
				     const GUID * pInterfaceGuid,
				     WLAN_INTF_OPCODE OpCode, PVOID pReserved,
				     PDWORD pdwDataSize, PVOID * ppData,
				     PWLAN_OPCODE_VALUE_TYPE
				     pWlanOpcodeValueType);
typedef DWORD(WINAPI * WlSetInt) (HANDLE hClientHandle,
				   const GUID * pInterfaceGuid,
				   WLAN_INTF_OPCODE OpCode, DWORD dwDataSize,
				   const PVOID pData, PVOID pReserved);
typedef DWORD(WINAPI * WlCloseHdl) (HANDLE hClientHandle, PVOID pReserved);
HMODULE wlapiModule;
WlOpenHdl WlanOpenHdl;		// Maps to WlanOpenHandle()
WlEnumInts WlanEnumInts;	// Maps to WlanEnumInterfaces()
WlQueryInt WlanQueryInt;	// Maps to WlanQueryInterface()
WlSetInt WlanSetInt;		// Maps to WlanSetInterface()
WlCloseHdl WlanCloseHdl;	// Maps to WlanCloseHandle()
int wlanapi_connected = FALSE;

/**
 * \brief Disconnect from the wlanapi.dll.
 **/ 
int wlanapi_interface_disconnect() 
{
	if (wlanapi_connected == FALSE)
		return WLANAPI_NOT_CONNECTED;
	FreeLibrary(wlapiModule);
	WlanOpenHdl = NULL;
	WlanEnumInts = NULL;
	WlanQueryInt = NULL;
	WlanSetInt = NULL;
	WlanCloseHdl = NULL;
	return WLANAPI_OK;
}


/**
 * \brief Establish a connection to the wlanapi.dll, and map all of the functions we may
 *        want to use.
 **/ 
int wlanapi_interface_connect() 
{
	wlapiModule = LoadLibraryA("wlanapi.dll");
	if (wlapiModule == NULL)
		return WLANAPI_NOT_AVAILABLE;
	wlanapi_connected = TRUE;
	WlanOpenHdl =
	    (WlOpenHdl) GetProcAddress(wlapiModule, "WlanOpenHandle");
	if (WlanOpenHdl == NULL)
		return WLANAPI_CANT_MAP;
	WlanEnumInts =
	    (WlEnumInts) GetProcAddress(wlapiModule, "WlanEnumInterfaces");
	if (WlanEnumInts == NULL)
		return WLANAPI_CANT_MAP;
	WlanQueryInt =
	    (WlQueryInt) GetProcAddress(wlapiModule, "WlanQueryInterface");
	if (WlanQueryInt == NULL)
		return WLANAPI_CANT_MAP;
	WlanSetInt =
	    (WlSetInt) GetProcAddress(wlapiModule, "WlanSetInterface");
	if (WlanOpenHdl == NULL)
		return WLANAPI_CANT_MAP;
	WlanCloseHdl =
	    (WlCloseHdl) GetProcAddress(wlapiModule, "WlanCloseHandle");
	if (WlanCloseHdl == NULL)
		return WLANAPI_CANT_MAP;
	return WLANAPI_OK;
}


/**
 * \brief Change the state of autoconfiguration to 'newstate'.
 *
 * @param[in] desc  The full description of the interface.  (Must include the "- Packet Scheduler Miniport" part.)
 * @param[in] newstate  Set to TRUE if autoconfiguration should be enabled, FALSE if it shouldn't.
 *
 * \retval int  One of the WLANAPI_* return values.
 **/ 
int wlanapi_interface_change_wzc_state(char *desc, BOOL newstate) 
{
	DWORD verInUse, size, rval;
	HANDLE wlanhdl;
	PWLAN_INTERFACE_INFO_LIST pIntList;
	BOOL * yn;
	int i, found = FALSE;
	char *temp = NULL;
	if (wlanapi_connected == FALSE)
		return WLANAPI_NOT_CONNECTED;
	if (WlanOpenHdl(2, NULL, &verInUse, &wlanhdl) != ERROR_SUCCESS)
		 {
		debug_printf(DEBUG_INT,
			      "Error getting handle to wlanapi.dll.\n");
		return WLANAPI_CALL_FAILED;
		}
	debug_printf(DEBUG_INT, "Using wlan API version : %d\n", verInUse);
	if (WlanEnumInts(wlanhdl, NULL, &pIntList) != ERROR_SUCCESS)
		 {
		debug_printf(DEBUG_INT,
			      "Error enumerating interfaces with wlan API!\n");
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_CALL_FAILED;
		}
	debug_printf(DEBUG_INT,
		       "The wlan API reports %d interface(s) found.\n",
		       pIntList->dwNumberOfItems);
	for (i = 0; i < pIntList->dwNumberOfItems; i++)
		 {
		temp =
		    uni_to_ascii(pIntList->InterfaceInfo[i].
				 strInterfaceDescription);
		if (strcmp(temp, desc) == 0)
			 {
			FREE(temp);
			found = TRUE;
			break;
			}
		FREE(temp);
		}
	if (found != TRUE)
		 {
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_INT_NOT_FOUND;
		}
	if ((rval =
	       WlanQueryInt(wlanhdl, &pIntList->InterfaceInfo[i].InterfaceGuid,
			    wlan_intf_opcode_autoconf_enabled, NULL, &size,
			    &yn, NULL)) != ERROR_SUCCESS)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to determine the autoconf state of interface '%s'!  (Error : %d)\n",
			      desc, rval);
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_CALL_FAILED;
		}
	
	    // See if we are already in the state we want to be in.
	    if ((*yn) == newstate)
		 {
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_ALREADY_SET;
		}
	(*yn) = newstate;
	if ((rval =
	       WlanSetInt(wlanhdl, &pIntList->InterfaceInfo[i].InterfaceGuid,
			  wlan_intf_opcode_autoconf_enabled, sizeof(BOOL), yn,
			  NULL)) != ERROR_SUCCESS)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to set the autoconf state on interface '%s'!  (Error :%d)\n",
			      desc, rval);
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_CALL_FAILED;
		}
	
	    // Verify that it is what we changed it to.
	    if ((rval =
		 WlanQueryInt(wlanhdl,
			      &pIntList->InterfaceInfo[i].InterfaceGuid,
			      wlan_intf_opcode_autoconf_enabled, NULL, &size,
			      &yn, NULL)) != ERROR_SUCCESS)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to determine the autoconf state of interface '%s'!  (Error : %d)\n",
			      desc, rval);
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_CALL_FAILED;
		}
	
	    // See if we are in the state we want to be in.
	    if ((*yn) == newstate)
		 {
		WlanCloseHdl(wlapiModule, NULL);
		return WLANAPI_OK;
		}
	return WLANAPI_DIDNT_TAKE;
}


/**
 * \brief Using the wlan API turn off WZC on the named interface.
 *
 * @param[in] desc   The description of the interface we want to disable WZC on.
 *
 * \retval int One of the WLANAPI_* return codes.
 **/ 
int wlanapi_interface_disable_wzc(char *desc) 
{
	return wlanapi_interface_change_wzc_state(desc, FALSE);
}


/**
 * \brief Using the wlan API turn on WZC on the named interface.
 *
 * @param[in] desc   The description of the interface we want to enable WZC on.
 *
 * \retval int One of the WLANAPI_* return codes.
 **/ 
int wlanapi_interface_enable_wzc(char *desc) 
{
	return wlanapi_interface_change_wzc_state(desc, TRUE);
}


