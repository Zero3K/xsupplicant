/**
 * Implementation for working with Windows Zero Config (WZC).
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wzc_ctrl.c
 *
 * \author chris@open1x.org
 **/

#include <windows.h>

#include "../../xsup_debug.h"
#include "wzc_ctrl.h"

HMODULE hMod;                       ///< The handle to the WZC DLL.
WZCEnumInts WZCEnumInterfaces;      ///< Pointer to the WZCEnumInterfaces() function call.
WZCQueryInts WZCQueryInterface;     ///< Pointer to the WZCQueryInterface() function call.
WZCSetInt WZCSetInterface;          ///< Pointer to the WZCSetInterface() function call.
int WZC_CTRL_Inited = FALSE;        ///< Were we able to init everything needed to control WZC.

/**
 * \brief Create the function pointers that will point to the WZC control routines.
 *
 * \retval 0 on success
 * \retval -1 if DLL couldn't be loaded.
 * \retval -2 if WZCEnumInterfaces couldn't be found.
 * \retval -3 if WZCQueryInterface couldn't be found.
 * \retval -4 if WZCSetInterface couldn't be found.
 **/
int wzc_ctrl_connect()
{
	hMod = LoadLibraryA("wzcsapi.dll");
	if (hMod == NULL) return -1;

	WZCEnumInterfaces = (WZCEnumInts) GetProcAddress(hMod, "WZCEnumInterfaces");
	if (WZCEnumInterfaces == NULL) return -2;

	WZCQueryInterface = (WZCQueryInts) GetProcAddress(hMod, "WZCQueryInterface");
	if (WZCQueryInterface == NULL) return -3;

	WZCSetInterface = (WZCSetInt) GetProcAddress(hMod, "WZCSetInterface");
	if (WZCSetInterface == NULL) return -4;

	WZC_CTRL_Inited = TRUE;

	return 0;
}


/**
 * \brief Disconnect from the WZC DLL that was loaded.
 *
 * \retval 0 on success, anything else on failure.
 **/
int wzc_ctrl_disconnect()
{
	FreeLibrary(hMod);

	return 0;
}

/**
 * \brief Disable (if needed) WZC.
 *
 * @param[in] guid   The GUID for the interface that we want to disable WZC on.
 *
 * \retval 0 if WZC was disabled, or if WZC was already disabled.
 * \retval -1 if WZC couldn't be disabled.
 **/
int wzc_ctrl_disable_wzc(char *guid)
{
	INTFS_KEY_TABLE Intfs;
	INTF_ENTRY Intf;
	int i = 0;
	DWORD outFlags;
	DWORD val;
	wchar_t *longver = NULL;

	if (WZC_CTRL_Inited == FALSE) return -1;  // We can't be sure if we disabled it or not.

	Intfs.dwNumIntfs = 0;
	Intfs.pIntfs = NULL;

	if (WZCEnumInterfaces(NULL, &Intfs) != ERROR_SUCCESS) 
	{
		debug_printf(DEBUG_NORMAL, "Unable to enumerate interfaces through Windows Zero Config.\n");
		return -1;
	}

	if (Intfs.dwNumIntfs == 0) 
	{
		debug_printf(DEBUG_NORMAL, "Windows Zero Config indicates that there are no interfaces that it is controlling.\n");
		return -1;
	}

	longver = (wchar_t *)malloc((strlen(guid)*2)+2);
	if (longver == NULL) return -1;

	if (MultiByteToWideChar(CP_ACP, 0, guid, strlen(guid), longver, ((strlen(guid)*2)+2)) <= 0)
	{
		free(longver);
		debug_printf(DEBUG_NORMAL, "Couldn't convert the string to unicode!\n");
		return -1;
	}

	if (longver == NULL) return -1;

	for (i= 0 ; i<Intfs.dwNumIntfs; i++)
	{
		if (Intfs.pIntfs[i].wszGuid != NULL)
		{
			if (wcsstr(longver, Intfs.pIntfs[i].wszGuid) != NULL) break;
		}
	}

	free(longver);

	if (i >= Intfs.dwNumIntfs)
	{
		debug_printf(DEBUG_NORMAL, "Unable to disable WZC control of requested interface!\n");
		return -1;
	}

	memset(&Intf, 0x00, sizeof(Intf));
	Intf.wszGuid = Intfs.pIntfs[i].wszGuid;
	Intf.dwCtlFlags = 0;
	outFlags = 0;
 
	// Query everything.
	val = WZCQueryInterface(NULL, 0xffffffff, &Intf, &outFlags);
	if (val != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Unable to query WZC for the needed interface.\n");
		return -1;
	}

	if (Intf.dwCtlFlags & INTFCTL_ENABLED)
	{
		// Disable WZC, and write it to the registry.
		Intf.dwCtlFlags &= (~INTFCTL_ENABLED);
		Intf.dwCtlFlags |= INTFCTL_VOLATILE;

		// Only change the flags we care about.
		if (WZCSetInterface(NULL, (INTFCTL_ENABLED | INTFCTL_VOLATILE), &Intf, &outFlags) != ERROR_SUCCESS)
		{	
			debug_printf(DEBUG_NORMAL, "Unable to instruct Windows Zero Config not to manage the interface!\n");
			return -1;
		}
	}

	return 0;   // Life is good.
}

/**
 * \brief Enable (if needed) WZC.
 *
 * @param[in] guid   The GUID for the interface that we want to enable WZC on.
 *
 * \retval 0 if WZC was disabled, or if WZC was already disabled.
 * \retval -1 if WZC couldn't be disabled.
 **/
int wzc_ctrl_enable_wzc(char *guid)
{
	INTFS_KEY_TABLE Intfs;
	INTF_ENTRY Intf;
	int i = 0;
	DWORD outFlags;
	DWORD val;
	wchar_t *longver = NULL;

	if (WZC_CTRL_Inited == FALSE) return -1;  // We can't be sure if we disabled it or not.

	Intfs.dwNumIntfs = 0;
	Intfs.pIntfs = NULL;

	if (WZCEnumInterfaces(NULL, &Intfs) != ERROR_SUCCESS) 
	{
		debug_printf(DEBUG_NORMAL, "Unable to enumerate interfaces through Windows Zero Config.\n");
		return -1;
	}

	if (Intfs.dwNumIntfs == 0) 
	{
		debug_printf(DEBUG_NORMAL, "Windows Zero Config indicates that there are no interfaces that it is controlling.\n");
		return -1;
	}

	longver = (wchar_t *)malloc((strlen(guid)*2)+2);
	if (longver == NULL) return -1;

	if (MultiByteToWideChar(CP_ACP, 0, guid, strlen(guid), longver, ((strlen(guid)*2)+2)) <= 0)
	{
		free(longver);
		debug_printf(DEBUG_NORMAL, "Couldn't convert the string to unicode!\n");
		return -1;
	}

	if (longver == NULL) return -1;

	for (i= 0 ; i<Intfs.dwNumIntfs; i++)
	{
		if (Intfs.pIntfs[i].wszGuid != NULL)
		{
			if (wcsstr(longver, Intfs.pIntfs[i].wszGuid) != NULL) break;
		}
	}

	free(longver);

	if (i >= Intfs.dwNumIntfs)
	{
		debug_printf(DEBUG_NORMAL, "Unable to enable WZC control of requested interface!\n");
		return -1;
	}

	memset(&Intf, 0x00, sizeof(Intf));
	Intf.wszGuid = Intfs.pIntfs[i].wszGuid;
	Intf.dwCtlFlags = 0;
	outFlags = 0;
 
	// Query everything.
	val = WZCQueryInterface(NULL, 0xffffffff, &Intf, &outFlags);
	if (val != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Unable to query WZC for the needed interface.\n");
		return -1;
	}

	if (Intf.dwCtlFlags & INTFCTL_ENABLED)
	{
		// Enable WZC, and write it to the registry.
		Intf.dwCtlFlags |= INTFCTL_ENABLED;
		Intf.dwCtlFlags |= INTFCTL_VOLATILE;

		// Only change the flags we care about.
		if (WZCSetInterface(NULL, (INTFCTL_ENABLED | INTFCTL_VOLATILE), &Intf, &outFlags) != ERROR_SUCCESS)
		{	
			debug_printf(DEBUG_NORMAL, "Unable to instruct Windows Zero Config to manage the interface!\n");
			return -1;
		}
	}

	return 0;   // Life is good.
}
