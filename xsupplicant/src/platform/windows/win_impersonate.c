/**
 * \file win_impersonate.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <windows.h>
#include <wtsapi32.h>
#include <direct.h>
#include <errno.h>
#include <shlobj.h>

#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "win_impersonate.h"

HANDLE active_token = NULL;

/**
 * \brief Impersonate the user that has the active desktop.  This is used to get the
 *        path to the user specific configuration, user specific certs, etc.
 *
 * \retval IMPERSONATE_NO_ERROR on success
 **/
int win_impersonate_desktop_user()
{
	HANDLE desktopUserHandle = NULL;
	TCHAR szMyUsername[1024];
	DWORD usize = 1024;

	if (active_token != NULL) return IMPERSONATE_HANDLE_IN_USE;

	if (WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &desktopUserHandle) == FALSE) 
	{
		debug_printf(DEBUG_NORMAL, "Error getting desktop user token.  (Error : %d)\n", GetLastError());
		return IMPERSONATE_BAD_USER_TOKEN;
	}

	if (DuplicateTokenEx(desktopUserHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &active_token) == FALSE)
	{
		CloseHandle(desktopUserHandle);   // Clean it up.
		debug_printf(DEBUG_NORMAL, "Error duplicating desktop user token.  (Error : %d)\n", GetLastError());
		return IMPERSONATE_BAD_USER_TOKEN;
	}

	CloseHandle(desktopUserHandle);   // We are done with it.  We made a dup.

	if (ImpersonateLoggedOnUser(active_token) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't impersonate logged on user. (Error : %d)\n", GetLastError());
		CloseHandle(active_token);
		active_token = NULL;
		return IMPERSONATE_FAILURE;
	}

	if (GetUserName(szMyUsername, &usize) != 0)
	{
		debug_printf(DEBUG_CONTEXT, "Impersonating user: %s!\n", szMyUsername);
	}

	return IMPERSONATE_NO_ERROR;
}

/**
 * \brief Return the handle we are using to impersonate.
 *
 **/
HANDLE win_impersonate_get_impersonation_handle()
{
	return active_token;
}

/**
 * \brief Reset our impersonation back to what we were originally.
 **/
void win_impersonate_back_to_self()
{
	debug_printf(DEBUG_CONTEXT, "Impersonation terminated.\n");
	if (RevertToSelf() == 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to revert to self.  (Error : %d)\n", GetLastError());
	}

	CloseHandle(active_token);
	active_token = NULL;
}

/**
 * \brief Get the machine name for this machine.
 *
 * \retval NULL on error, otherwise the machine name.
 **/
char *win_impersonate_get_machine_name()
{
	char *machineName = NULL;
	DWORD mlen = 255;

	machineName = Malloc(mlen);
	if (machineName == NULL) return NULL;

	if (GetComputerNameExA(ComputerNamePhysicalDnsFullyQualified, machineName, &mlen))
	{
		return machineName;
	}
	else
	{
		return NULL;
	}

	return NULL;
}

/**
 * \brief Read the machine's key from the registry.
 *
 * @param[out] key   A pointer to a pointer containing the encrypted data from the registry.
 * @param[out] length  A pointer to a uint16_t that will return the length of the encrypted data.
 *
 * \retval XENONE on success, anything else is a failure.
 **/
int win_impersonate_get_encrypted_key(uint8_t **key, uint16_t *length)
{
	LONG result = 0;
	char *fullpath = "SECURITY\\Policy\\Secrets\\$MACHINE.ACC\\CurrVal";
	HKEY phk;
	uint8_t *buffer = NULL;
	DWORD size = 1024;

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, fullpath, 0, KEY_READ, &phk);
	if (result != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Failed to open the registry key for the domain secret!\n");
		return -1;
	}

	buffer = Malloc(size);
	if (buffer == NULL) 
	{
		RegCloseKey(phk);
		return -1;
	}

	result = RegQueryValueEx(phk, NULL, NULL, NULL, (LPBYTE)buffer, &size);
	if (result != ERROR_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL, "Unable to read the machine's domain secret blob.\n");
		RegCloseKey(phk);
		return -1;
	}
	
	RegCloseKey(phk);

	(*key) = buffer;
	(*length) = size;

	return XENONE;
}

/**
 * \brief Decrypt the machine's domain password with the machine's key.
 *
 * @param[in] encData   The encrypted version of the domain password.
 * @param[in] encLen   The length of the encrypted data.
 * @param[out] password   The cleartext version of the password.
 * @param[out] length   The length of the cleartext version of the password.
 *
 * \retval XENONE on success.  Anything is a failure.
 **/
int win_impersonate_decrypt_blob(uint8_t *encData, uint16_t encLen, uint8_t **password, uint16_t *length)
{
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	uint8_t *buffer = NULL;

	DataIn.cbData = encLen;
	DataIn.pbData = encData;

	if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, (CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE), &DataOut))
	{
		buffer = Malloc(DataOut.cbData+5);
		if (buffer == NULL) return -1;

		memcpy(buffer, DataOut.pbData, DataOut.cbData);

		(*length) = DataOut.cbData;
		(*password) = buffer;

		LocalFree(DataOut.pbData);

		return XENONE;
	}

	return -1;
}

/**
 * \brief Get the machine's domain password from the registry and decrypt it.
 *
 * \note This only works when the suppicant is running as a service because normal user accounts (even admins)
 *			don't have rights to read the necessary portion of the registry!
 *
 * \retval XENONE on success.
 **/
int win_impersonate_get_machine_password(uint8_t **password, uint16_t *length)
{
	uint8_t *encData = NULL;
	uint16_t encLen = 0;
	int result = 0;

	if ((result = win_impersonate_get_encrypted_key(&encData, &encLen)) != XENONE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to obtain encrypted domain key!\n");
		return result;
	}

#ifdef UNSAFE_DUMPS
	debug_printf(DEBUG_AUTHTYPES, "Encrypted key (%d) :\n", encLen);
	debug_hex_dump(DEBUG_AUTHTYPES, encData, encLen);
#endif

	if ((result = win_impersonate_decrypt_blob(encData, encLen, password, length)) != XENONE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to decrypt the domain key!\n");
		return result;
	}

#ifdef UNSAFE_DUMPS
	debug_printf(DEBUG_AUTHTYPES, "Decrypted key (%d) :\n", (*length));
	debug_hex_dump(DEBUG_AUTHTYPES, (*password), (*length));
#endif

	FREE(encData);

	return XENONE;
}


