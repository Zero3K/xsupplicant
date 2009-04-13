/**
*
* \file logon_creds.c
*
* Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
*
* \author chris@open1x.org
**/  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WINDOWS
#include "stdintwin.h"
#else				
#include <stdint.h>
#endif			

#include "xsup_common.h"
#include "../lib/libxsupconfig/xsupconfig.h"
#include "xsup_err.h"
#include "logon_creds.h"

/**
* The two variables below store the global username/password pair that can later be used by
*  EAP methods to complete the authentication.  These variables are populated by using a call 
*  across the IPC channel.  The primary intent of these variables is to allow for integration
*  with systems like GINA and PAM.
**/ 
char *logon_username = NULL;
char *logon_password = NULL;

/**
* \brief Store the username and/or password.
*
* @param[in] username   The new username to store.  (If it is NULL, the existing username isn't changed.)
* @param[in] password   The new password to store.  (If it is NULL, the existing password isn't changed.)
*
* \retval XENONE on success, anything else is an error.
**/ 
int logon_creds_store_username_and_password(char *username, char *password) 
{
	if (username != NULL)
		FREE(logon_username);

	logon_username = _strdup(username);

	if (password != NULL)
		FREE(logon_password);

	logon_password = _strdup(password);

	// For now, this function can't fail, but who knows in the future. ;)
	return XENONE;
}


/**
* \brief Flush the stored username and password credentials.
*
* \retval XENONE on success
**/ 
int logon_creds_flush_stored_creds() 
{
	FREE(logon_username);
	FREE(logon_password);

	return XENONE;
}


/**
* \brief Get a copy of the username that is currently stored.
*
* \warning This function returns the global pointer, so it shouldn't be freed!
*
* \retval ptr to the username, NULL on error (or no username available)
**/ 
char *logon_creds_get_username() 
{
	return logon_username;
}


/**
* \brief Get a copy of the password that is currently stored.
* 
* \warning This function returns the global pointer, so it shouldn't be freed!
*
* \retval ptr to the password, NULL on error (or no password available)
**/ 
char *logon_creds_get_password() 
{
	return logon_password;
}


/**
* \brief If a username is currently stored, return TRUE
*
* \retval TRUE if there is a stored username
* \retval FALSE if there is not.
**/ 
int logon_creds_username_available() 
{
	if (logon_username == NULL)
		return FALSE;

	return TRUE;
}


/**
* \brief If a password is currently stored, return TRUE
*
* \retval TRUE if there is a stored password
* \retval FALSE if there is not
**/ 
int logon_creds_password_available() 
{
	if (logon_password == NULL)
		return FALSE;

	return TRUE;
}



