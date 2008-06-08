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

#include "../../xsup_debug.h"
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

