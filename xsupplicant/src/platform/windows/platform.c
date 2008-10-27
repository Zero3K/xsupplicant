#include <windows.h>
#include <direct.h>
#include <errno.h>
#include <shlobj.h>

#include "../../xsup_debug.h"
#include "win_impersonate.h"
#include "../platform.h"

/**
 * \brief Get the path to the data store for the current user.  This will append a \xsupplicant directory
 *		to the "Documents and Settings\<username>\Application Data" directory if it doesn't already exist.
 *
 * \retval NULL on error, otherwise a path that can be used to store user data.
 **/
char *platform_get_users_data_store_path()
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
char *platform_get_machine_data_store_path()
{
	return NULL;
}
