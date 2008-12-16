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
#include "lsa_calls.h"
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
 * \brief Get the machine's domain password from the registry and decrypt it.
 *
 * \note This only works when the suppicant is running as a service because normal user accounts (even admins)
 *			don't have rights to read the necessary portion of the registry!
 *
 * \retval XENONE on success.
 **/
int win_impersonate_get_machine_password(uint8_t **password, uint16_t *length)
{
	int result = 0;

	if ((result = lsa_calls_decrypt_secret(password, length)) != XENONE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to decrypt the domain key!\n");
		return result;
	}

#ifdef UNSAFE_DUMPS
	debug_printf(DEBUG_AUTHTYPES, "Decrypted key (%d) :\n", (*length));
	debug_hex_dump(DEBUG_AUTHTYPES, (*password), (*length));
#endif

	return XENONE;
}


