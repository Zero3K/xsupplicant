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
#include "win_impersonate.h"

HANDLE active_token = NULL;

/**
 * \brief Get the path to the data store for the current user.  This will append a \xsupplicant directory
 *		to the "Documents and Settings\<username>\Application Data" directory if it doesn't already exist.
 *
 * \retval NULL on error, otherwise a path that can be used to store user data.
 **/
char *get_users_data_store_path()
{
	TCHAR szMyPath[MAX_PATH];
	char *path = NULL;

	if (win_impersonate_desktop_user() != IMPERSONATE_NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL, "Unable to impersonate the desktop user.  Cannot return the path to the local common app data.\n");
		return NULL;
	}

	if (FAILED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, szMyPath)))
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't determine the path to the local common app data.\n");
		  win_impersonate_back_to_self();			// Don't forget to go back to being ourselves on error!
		  return NULL;
	  }

	// While we are still impersonating, make sure the directory exists.
	path = Malloc(strlen(szMyPath) + 50);
	if (path == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory needed to store the supplicant's local data path.\n");
		win_impersonate_back_to_self();
		return NULL;
	}

	strcpy(path, szMyPath);
	strcat(path, "\\xsupplicant");

	if (_chdir(path))
	{
		// We couldn't chdir to our directory so it may not exist, but let's check.
		switch (errno)
		{
		case EINVAL:
			// Our buffer was invalid.
			debug_printf(DEBUG_NORMAL, "Invalid buffer passed to _chdir().\n");
			FREE(path);
			break;

		case ENOENT:
			// Nope, doesn't exist.  Create it.
			if (_mkdir(path))
			{
				debug_printf(DEBUG_NORMAL, "Unable to create the directory to store user specific data.  It may already exist, and you may not have rights to it.  (Attempted to create '%s'.)\n", path);
				FREE(path);
			}
			break;

		default:
			debug_printf(DEBUG_NORMAL, "Error changing to '%s'!\n", path);
			FREE(path);
			break;
		}
	}

	win_impersonate_back_to_self();
	return path;
}

/**
 * \brief Get the path to the data store for the machine.
 *
 * \todo IMPLEMENT!
 **/
char *get_machine_data_store_path()
{
	return NULL;
}

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

