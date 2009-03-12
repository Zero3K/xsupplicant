/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/  
    
#ifndef _IPC_CALLOUT_HELPER_H_
#define _IPC_CALLOUT_HELPER_H_
int ipc_callout_helper_build_connection_list(uint8_t config_type,
					      xmlNodePtr baseNode);
int ipc_callout_helper_build_profile_list(uint8_t config_type,
					   xmlNodePtr baseNode);
int ipc_callout_helper_build_trusted_server_list(uint8_t config_type,
						  xmlNodePtr baseNode);
int ipc_callout_helper_can_use_logon_creds(context * ctx, char *conn_name);
unsigned int ipc_callout_helper_connection_needs_admin(struct config_connection
							*cur);
unsigned int ipc_callout_helper_count_connections(struct config_connection
						   *cur);
int ipc_callout_helper_is_profile_in_use(uint8_t config_type, char *name);
int ipc_callout_helper_is_trusted_server_in_use(uint8_t config_type,
						 char *name);
char *ipc_callout_helper_get_tsname_from_profile(config_profiles * cur);
void ipc_callout_helper_trusted_server_renamed_check_profiles(struct
							       config_profiles
							       *confprof,
							       char *oldname,
							       char *newname);

#endif				// _IPC_CALLOUT_HELPER_H_
