/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/  
    
#ifndef _LOGON_CREDS_H_
int logon_creds_store_username_and_password(char *username, char *password);
int logon_creds_flush_stored_creds();
char *logon_creds_get_username();
char *logon_creds_get_password();
int logon_creds_username_available();
int logon_creds_password_available();

#endif				// _LOGON_CREDS_H_
