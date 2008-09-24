/**
 *  Make tweaks to windows to be sure that 802.1X is disabled for WIRED interfaces!
 *
 *  \file windows_eapol_ctrl.c
 *
 *  \author chris@open1x.org
 **/

#include <windows.h>
#include <stdio.h>
#include <netcon.h>

extern "C" {
#include "../../xsup_debug.h"
#include "windows_eapol_ctrl.h"
};

/*  The 104 bytes below are the default values used on wired interfaces in the registry key :
		HKLM\SOFTWARE\Microsoft\EAPOL\Parameters\Interfaces\{GUID}

	We need them to be able to create the entry in the event that the user has never touched the interface
	control panel for an interface that we want to control.   
	*/
uint8_t def1xregkey[104] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0d, 0x00, 
	0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 
	0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 0x11, 0x22, 0x33, 
	0x11, 0x22, 0x0d, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/**
 * \brief Tweak the registry to disable 802.1X on the wired interface specified by the GUID.  This call is
 *         used when the registry key(s) needed don't exist.  In this case, we create them using the hex
 *         string above modifed to turn off the WZC 802.1X supplicant.
 *
 * @param[in] guid   The GUID of the interface that we want to disable 802.1X on.
 *
 * \retval 0 on success  (need to bounce interfaces)
 * \retval 1 on success  (don't need to do anything, it was already done)
 * \retval -1 on error.
 **/
int windows_eapol_ctrl_new_disabled_reg_key(char *guid)
{
	DWORD size = 256;
	LONG result;
	HKEY phk;
	int i = 0;
	char *path_to_eapol = "SOFTWARE\\Microsoft\\EAPOL\\Parameters\\Interfaces\\";  // The GUID comes after that.
	char *fullpath = NULL;
	int myresult = 0;
	DWORD disposition;

	fullpath = (char *)Malloc(strlen(path_to_eapol)+strlen(guid)+2);
	if (fullpath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory needed to build the path to the registry key that controls 802.1X on wired interfaces!\n");
		return -1;
	}

	sprintf(fullpath, "%s%s", path_to_eapol, guid);

	result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, fullpath, 0, NULL, 0, (KEY_READ | KEY_WRITE), NULL, &phk, &disposition);
	if (result != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Unable to open path to key needed to disable 802.1X on a wired interface!  Attemping to create it.\n");
		FREE(fullpath);
		return -1;
	}

	FREE(fullpath);

	size = sizeof(def1xregkey);

	if (RegSetValueEx(phk, "1", NULL, REG_BINARY, (const BYTE *)&def1xregkey, size) != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Error writing the registry key that controls 802.1X state on wired interfaces.\n");
		RegCloseKey(phk);
		return -1;
	}

	RegCloseKey(phk);

	return myresult;
}

/**
 * \brief Tweak the registry to enable or disable 802.1X on the wired interface specified by the GUID.
 *
 * @param[in] guid   The GUID of the interface that we want to disable 802.1X on.
 *
 * \retval 0 on success  (need to bounce interfaces)
 * \retval 1 on success  (don't need to do anything, it was already done)
 * \retval -1 on error.
 **/
int windows_eapol_ctrl_toggle_in_reg(char *guid, int enable)
{
	unsigned char buffer[256];  // More than we need.
	DWORD size = 256;
	LONG result;
	HKEY phk;
	int i = 0;
	char *path_to_eapol = "SOFTWARE\\Microsoft\\EAPOL\\Parameters\\Interfaces\\";  // The GUID comes after that.
	char *fullpath = NULL;
	int myresult = 0;

	fullpath = (char *)Malloc(strlen(path_to_eapol)+strlen(guid)+2);
	if (fullpath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory needed to build the path to the registry key that controls 802.1X on wired interfaces!\n");
		return -1;
	}

	sprintf(fullpath, "%s%s", path_to_eapol, guid);

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, fullpath, 0, (KEY_READ | KEY_WRITE), &phk);
	if (result != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Unable to open path to key needed to disable 802.1X on a wired interface!  Attemping to create it.\n");
		FREE(fullpath);

		// If we are disabling and the reg data isn't there, we need to write it.  If we are enabling,
		// and it isn't there, then it is already enabled. ;)
		if (enable == FALSE)
		{
			return windows_eapol_ctrl_new_disabled_reg_key(guid);
		}
		else
		{
			return 1;
		}
	}

	FREE(fullpath);

	// For wired interfaces, the only thing configured should be "1".
	result = RegQueryValueEx(phk, "1", NULL, NULL, (LPBYTE)&buffer, &size);
	if (result != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Unable to query the key needed to determine the state of 802.1X on a wired interface!\n");
		RegCloseKey(phk);
		return -1;
	}

	if (enable == FALSE)
	{
		if (buffer[11] & 0x80)
		{
			debug_printf(DEBUG_INT, "802.1X is enabled on GUID %s.  Turning it off.\n", guid);

			buffer[11] &= (0x7f);  // Turn off the high bit.

			if (RegSetValueEx(phk, "1", NULL, REG_BINARY, (const BYTE *)&buffer, size) != ERROR_SUCCESS)
			{
				debug_printf(DEBUG_NORMAL, "Error writing the registry key that controls 802.1X state on wired interfaces.\n");
				RegCloseKey(phk);
				return -1;
			}

			debug_printf(DEBUG_INT, "802.1X enable/disable registry key has been updated.\n");
		}
		else
		{
			myresult = 1;
		}
	}
	else
	{
		if ((buffer[11] & 0x80) == 0x00)
		{
			debug_printf(DEBUG_INT, "802.1X is disabled on GUID %s.  Turning it on.\n", guid);

			buffer[11] |= (0x80);  // Turn on the high bit.

			if (RegSetValueEx(phk, "1", NULL, REG_BINARY, (const BYTE *)&buffer, size) != ERROR_SUCCESS)
			{
				debug_printf(DEBUG_NORMAL, "Error writing the registry key that controls 802.1X state on wired interfaces.\n");
				RegCloseKey(phk);
				return -1;
			}

			debug_printf(DEBUG_INT, "802.1X enable/disable registry key has been updated.\n");
		}
		else
		{
			myresult = 1;
		}
	}

	RegCloseKey(phk);

	return myresult;
}

// This method will enable/disable the network connection similar to the GUI code.
//    EnableConnection(L"Local Area Connection", true); 
//    
int EnableConnection(LPCWSTR wszName, int bEnable) {
    int result = FALSE;
    typedef void (__stdcall * LPNcFreeNetconProperties)(NETCON_PROPERTIES *pProps);
	typedef void (__stdcall * LPIEnumNetConnection_EnumConnections)(IEnumNetConnection *myobj, NETCONMGR_ENUM_FLAGS flags, IEnumNetConnection **ppEnum);
	LPNcFreeNetconProperties NcFreeNetconProperties;
    INetConnectionManager * pMan = 0; 
	HRESULT hres;
    IEnumNetConnection * pEnum = 0;  
    INetConnection * pCon = 0; 
    ULONG count; 
    int done = FALSE; 
	HMODULE hmod, hmod2;
    NETCON_PROPERTIES * pProps = 0; 

	hmod = LoadLibrary("netshell.dll");
	if (!hmod) { 
        return FALSE; 
	}

	NcFreeNetconProperties = (LPNcFreeNetconProperties)GetProcAddress(hmod, "NcFreeNetconProperties"); 

	if (!NcFreeNetconProperties ) {
		FreeLibrary(hmod);
        return FALSE; 
	}
 
    hres = CoCreateInstance(CLSID_ConnectionManager, 0, CLSCTX_ALL, IID_INetConnectionManager, (void**)&pMan); 

    if (SUCCEEDED(hres)) 
    { 
		hres = pMan->EnumConnections(NCME_DEFAULT, &pEnum);
        if (SUCCEEDED(hres)) 
        { 
			while (pEnum->Next(1, &pCon, &count) == S_OK && !done)
            { 
				pCon->GetProperties(&pProps);
                if (SUCCEEDED(hres)) 
                { 
                    if (wcsstr(pProps->pszwDeviceName,wszName) != NULL) 
                    { 
						if (bEnable) {
							result = (pCon->Connect() == S_OK);
							printf("Connect() : %ws!\n", wszName);
						} else {
							result = (pCon->Disconnect() == S_OK);
							printf("Disconnect() : %ws!\n", wszName);
						}
						done = TRUE; 
                    } 
                    NcFreeNetconProperties(pProps); 
                } 
				pCon->Release();
            } 
			pEnum->Release();
        } 
		pMan->Release();
    } 
    FreeLibrary(hmod); 

    return result;
}

/**
 * \brief Disable 802.1X on a wired interface.  This will unset a bit in a registry key, and
 *        bounce the interface.
 *
 * @param[in] osName   The OS description of the interface to work with.
 * @param[in] intName   The OS specific interface name to work with.
 *
 * \retval 0 on success
 * \retval -1 on failure.
 **/
extern "C" {
int windows_eapol_ctrl_disable(char *osName, char *intName)
{
	char *guid = NULL;
	LPWSTR intdesc = NULL;
	int llength = 0;

	guid = strstr(intName, "{");

	switch (windows_eapol_ctrl_toggle_in_reg(guid, FALSE))
	{
	default:
	case -1:
		debug_printf(DEBUG_NORMAL, "Unable to disable the registry entry for interface '%s'.\n", osName);
		return -1;
		break;

	case 1:
		return 0;  // Don't need to do anything.
		break;

	case 0:
		break;  // Do nothing.
	}

	llength = (strlen(osName)*2)+2;
	intdesc = (LPWSTR)Malloc(llength);
	if (intdesc == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store interface name!\n");
		return -1;
	}

	if (MultiByteToWideChar(CP_ACP, 0, osName, strlen(osName), intdesc, llength) <= 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't convert ASCII to wide!\n");
		free(intdesc);
		return -1;
	}

	// Disable the interface  (Bounce step #1.)
	if (EnableConnection(intdesc, FALSE) != TRUE) 
	{
		debug_printf(DEBUG_NORMAL, "Unable to disable the interface '%s'.\n", osName);
		free(intdesc);
		return -1;
	}

	// Enable the interface  (Bounce step #2.)
	if (EnableConnection(intdesc, TRUE) != TRUE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to enable the interface '%s'.\n", osName);
		free(intdesc);
		return -1;
	}

	free(intdesc);

	return 0;
}
};

/**
 * \brief Enable 802.1X on a wired interface.  This will set a bit in a registry key, and
 *        bounce the interface.
 *
 * @param[in] osName   The OS description of the interface to work with.
 * @param[in] intName   The OS specific interface name to work with.
 *
 * \retval 0 on success
 * \retval -1 on failure.
 **/
extern "C" {
int windows_eapol_ctrl_enable(char *osName, char *intName)
{
	char *guid = NULL;
	LPWSTR intdesc = NULL;
	int llength = 0;

	guid = strstr(intName, "{");

	switch (windows_eapol_ctrl_toggle_in_reg(guid, TRUE))
	{
	default:
	case -1:
		debug_printf(DEBUG_NORMAL, "Unable to disable the registry entry for interface '%s'.\n", osName);
		return -1;
		break;

	case 1:
		return 0;  // Don't need to do anything.
		break;

	case 0:
		break;  // Do nothing.
	}

	llength = (strlen(osName)*2)+2;
	intdesc = (LPWSTR)Malloc(llength);
	if (intdesc == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store interface name!\n");
		return -1;
	}

	if (MultiByteToWideChar(CP_ACP, 0, osName, strlen(osName), intdesc, llength) <= 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't convert ASCII to wide!\n");
		free(intdesc);
		return -1;
	}

	// Disable the interface  (Bounce step #1.)
	if (EnableConnection(intdesc, FALSE) != TRUE) 
	{
		debug_printf(DEBUG_NORMAL, "Unable to disable the interface '%s'.\n", osName);
		free(intdesc);
		return -1;
	}

	// Enable the interface  (Bounce step #2.)
	if (EnableConnection(intdesc, TRUE) != TRUE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to enable the interface '%s'.\n", osName);
		free(intdesc);
		return -1;
	}

	free(intdesc);

	return 0;
}
};
