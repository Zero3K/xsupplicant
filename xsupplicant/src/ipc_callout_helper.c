/**
 * Routines for checking the "completeness" of a piece of the configuration.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_callout_helper.c
 *
 * \author chris@open1x.org
 *
 **/  
    
#ifdef WINDOWS
#include "stdintwin.h"
#else	/*  */
#include <stdint.h>
#endif	/*  */
    
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
    
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "ipc_callout.h"
#include "logon_creds.h"
#include "eap_sm.h"
#include "platform/platform.h"
#include "ipc_callout_helper.h"
    
/**
 * \brief Build a list of available connections for a certain type.
 *
 * @param[in] config_type   The list of connections in memory to return.
 * @param[in] baseNode   The base node to build on.
 *
 * \retval XENONE on success
 **/ 
int ipc_callout_helper_build_connection_list(uint8_t config_type,
					     xmlNodePtr baseNode) 
{
	struct config_connection *cur = NULL;
	xmlNodePtr t = NULL;
	char *temp = NULL;
	char res[100];
	int i = 0;
	int are_admin = 0;
	are_admin = platform_user_is_admin();
	cur = config_get_connections(config_type);
	while (cur != NULL)
		 {
		
		    // If we need to be admin, and aren't, skip this one.
		    if ((are_admin == FALSE)
			&& (ipc_callout_helper_connection_needs_admin(cur) ==
			    TRUE))
			 {
			cur = cur->next;
			continue;
			}
		t =
		    xmlNewChild(baseNode, NULL, (xmlChar *) "Connection", NULL);
		if (t == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		ipc_callout_convert_amp(cur->name, &temp);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Connection_Name",
		      (xmlChar *) temp) == NULL)
			 {
			free(temp);
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		free(temp);
		sprintf((char *)&res, "%d", config_type);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Config_Type",
		      (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		ipc_callout_convert_amp(cur->ssid, &temp);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "SSID_Name",
		      (xmlChar *) temp) == NULL)
			 {
			free(temp);
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		free(temp);
		sprintf((char *)&res, "%d", cur->priority);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Priority", (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		if (cur->association.association_type == ASSOC_AUTO)
			 {
			i = CONNECTION_ENC_UNKNOWN;
			}
		
		else if (cur->association.association_type != ASSOC_OPEN)
			 {
			i = CONNECTION_ENC_ENABLED;
			}
		
		else if ((cur->association.association_type == ASSOC_OPEN)
			 && (cur->association.txkey != 0))
			 {
			i = CONNECTION_ENC_ENABLED;
			}
		
		else if (cur->association.association_type == ASSOC_OPEN)	// Which it should!
		{
			if (cur->association.auth_type == AUTH_NONE)
				 {
				i = CONNECTION_ENC_NONE;
				}
			
			else
				 {
				i = CONNECTION_ENC_ENABLED;
				}
		}
		
		else		// Shouldn't ever get here!
		{
			i = CONNECTION_ENC_UNKNOWN;
		}
		sprintf((char *)&res, "%d", i);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Encryption",
		      (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		if (cur->association.auth_type == 0)
			 {
			
			    // We don't explicitly have an auth type, so try to figure it out.
			    if (cur->profile != NULL)
				 {
				
				    // We have a profile, so we should be doing 802.1X.
				    sprintf((char *)&res, "%d", AUTH_EAP);
				}
			
			else if ((cur->association.psk != NULL)
				 || (cur->association.psk_hex != NULL))
				 {
				
				    // We have a PSK, so we are probably doing WPA-PSK.
				    sprintf((char *)&res, "%d", AUTH_PSK);
				}
			
			else
				 {
				
				    // We don't know.  So return 0.
				    sprintf((char *)&res, "0");
			} }
		
		else
			 {
			sprintf((char *)&res, "%d",
				 cur->association.auth_type);
		}
		    if (xmlNewChild
				  (t, NULL,
					   (xmlChar *) "Authentication",
					   (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		sprintf((char *)&res, "%d",
			  cur->association.association_type);
		if (xmlNewChild
		      (t, NULL, (xmlChar *) "Association_Type",
		       (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		cur = cur->next;
		}
	return XENONE;
}


/**
 * \brief Build a list of profiles that are available based on the config_type value passed in.
 *
 * @param[in] config_type   One of the configuration types that we want to get the list from.
 * @param[in/out] baseNode   The XML node that we want to build the list on.
 *
 * \retval XENONE on success, anything is a valid input to an ipc_callout_error() call.
 **/ 
int ipc_callout_helper_build_profile_list(uint8_t config_type,
					  xmlNodePtr baseNode) 
{
	struct config_profiles *cur = NULL;
	char res[5];
	xmlNodePtr t = NULL;
	char *temp = NULL;
	cur = config_get_profiles(config_type);
	while (cur != NULL)
		 {
		t = xmlNewChild(baseNode, NULL, (xmlChar *) "Profile", NULL);
		if (t == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		ipc_callout_convert_amp(cur->name, &temp);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Profile_Name",
		      (xmlChar *) temp) == NULL)
			 {
			free(temp);
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		free(temp);
		sprintf((char *)&res, "%d", config_type);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Config_Type",
		      (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		cur = cur->next;
		}
	return XENONE;
}


/**
 * \brief Build an XML list of trusted servers we know about.
 *
 * @param[in] config_type   Identifies which trusted server list we should be looking at. (System level, or user level.)
 * @param[in] baseNode   The XML node pointer to build the list under.
 *
 * \retval XENONE on success, anything is an error code suitable for use in an ipc_callout_create_error().
 **/ 
int ipc_callout_helper_build_trusted_server_list(uint8_t config_type,
						 xmlNodePtr baseNode) 
{
	struct config_trusted_server *cur = NULL;
	char res[5];
	xmlNodePtr t = NULL;
	char *temp = NULL;
	struct config_trusted_servers *svrs = NULL;
	svrs = config_get_trusted_servers(config_type);
	if (svrs == NULL)
		return XENONE;
	cur = svrs->servers;
	while (cur != NULL)
		 {
		t = xmlNewChild(baseNode, NULL, (xmlChar *) "Server", NULL);
		if (t == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		ipc_callout_convert_amp(cur->name, &temp);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Server_Name",
		      (xmlChar *) temp) == NULL)
			 {
			free(temp);
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		free(temp);
		sprintf((char *)&res, "%d", config_type);
		if (xmlNewChild
		     (t, NULL, (xmlChar *) "Config_Type",
		      (xmlChar *) res) == NULL)
			 {
			return IPC_ERROR_CANT_ALLOCATE_NODE;
			}
		cur = cur->next;
		}
	return XENONE;
}


/**
 * \brief Determine if our desired connection can use logon credentials (assuming we have any).
 *
 * \retval TRUE if the configuration allows the use of logon credentials, and the needed credentials
 *					are available.
 *
 * \retval FALSE if no credentials are available, or the configuration doesn't allow the use of
 *					logon credentials.
 **/ 
int ipc_callout_helper_can_use_logon_creds(context * ctx, char *conn_name) 
{
	int login_creds = 0;
	struct config_profiles *myprof = NULL;
	struct config_connection *mycon = NULL;
	if ((logon_creds_username_available() == FALSE)
	      && (logon_creds_password_available() == FALSE))
		return FALSE;
	mycon = config_find_connection(CONFIG_LOAD_USER, conn_name);
	if (mycon == NULL)
		mycon = config_find_connection(CONFIG_LOAD_GLOBAL, conn_name);
	if (mycon == NULL)
		return FALSE;
	myprof = config_find_profile(CONFIG_LOAD_USER, mycon->profile);
	if (myprof == NULL)
		config_find_profile(CONFIG_LOAD_GLOBAL, mycon->profile);
	if (myprof == NULL)
		return FALSE;
	login_creds =
	    eap_sm_creds_required(myprof->method->method_num,
				  myprof->method->method_data);
	if ((TEST_FLAG(login_creds, EAP_REQUIRES_USERNAME))
	      && (logon_creds_username_available() == FALSE))
		return FALSE;
	if ((TEST_FLAG(login_creds, EAP_REQUIRES_PASSWORD))
	      && (logon_creds_password_available() == FALSE))
		return FALSE;
	if (TEST_FLAG(login_creds, EAP_REQUIRES_PIN))
		return FALSE;
	if (TEST_FLAG(login_creds, EAP_REQUIRES_TOKEN_CODE))
		return FALSE;
	return TRUE;
}


/**
 * \brief Determine if this connection needs administrative rights to be used.  Right now, it checks
 *			to see if machine authentication is enabled.  If it is, then the connection won't show up
 *			for normal users.
 *
 * @param[in] cur   A pointer to the connection structure we want to check.
 *
 * \retval TRUE if admin is needed
 * \retval FALSE if admin is NOT needed.
 **/ 
unsigned int ipc_callout_helper_connection_needs_admin(struct config_connection
						       *cur) 
{
	struct config_profiles *prof = NULL;
	struct config_eap_peap *peap = NULL;
	prof = config_find_profile(CONFIG_LOAD_USER, cur->profile);
	if (prof == NULL)
		prof = config_find_profile(CONFIG_LOAD_GLOBAL, cur->profile);
	if (prof == NULL)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Couldn't find the profile used by connection '%s'!\n",
			      cur->name);
		return FALSE;
		}
	if (prof->method == NULL)
		return FALSE;
	if (prof->method->method_num != EAP_TYPE_PEAP)
		return FALSE;	// We only do machine auth with PEAP right now.
	peap = prof->method->method_data;
	if (TEST_FLAG(peap->flags, FLAGS_PEAP_MACHINE_AUTH))
		return TRUE;
	return FALSE;
}


/**
 * \brief Count the number of connections found in a config_connection list.
 *
 * @param[in] cur   A pointer to the list that contains a connection information.
 *
 * \retval int  Number of connections in the list.
 **/ 
unsigned int ipc_callout_helper_count_connections(struct config_connection *cur)
    
{
	unsigned int count = 0;
	int are_admin = 0;
	int needs_admin = 0;
	are_admin = platform_user_is_admin();
	while (cur != NULL)
		 {
		needs_admin = ipc_callout_helper_connection_needs_admin(cur);
		if ((are_admin == FALSE) && (needs_admin == FALSE))
			 {
			count++;
			}
		
		else if (are_admin == TRUE)
			 {
			count++;
			}
		cur = cur->next;
		}
	return count;
}


/**
 * \brief Determine if a profile is in use in a specific connection list.
 *
 * @param[in] config_type   Should we be looking in the system level, or user level config?
 * @param[in] name   The name of the profile we are checking.
 *
 * \retval TRUE if the profile was found connected to a connection in the list.
 * \retval FALSE if the profile was not found in the connection list.
 **/ 
int ipc_callout_helper_is_profile_in_use(uint8_t config_type, char *name) 
{
	struct config_connection *cur = NULL;
	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL)
		cur = conf_connections;
	
	else
		cur = conf_user_connections;
	while ((cur != NULL)
		 && ((cur->profile == NULL)
		     || (strcmp(cur->profile, name) != 0)))
		 {
		cur = cur->next;
		}
	if (cur != NULL)
		 {
		
		    // We found something.
		    return TRUE;
		}
	return FALSE;
}


/**
 * \brief Based on the config_type determine if the named trusted server is in use by
 *        an existing profile.
 *
 * @param[in] config_type   One of CONFIG_LOAD_GLOBAL, or CONFIG_LOAD_USER.
 * @param[in] name   The name of the trusted server we want to look for.
 *
 * \retval TRUE if it is in use in this list.
 * \retval FALSE if it isn't in use in this list.
 **/ 
int ipc_callout_helper_is_trusted_server_in_use(uint8_t config_type,
						char *name) 
{
	struct config_profiles *cur = NULL;
	char *tsname = NULL;
	int done = FALSE;
	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL)
		cur = conf_profiles;
	
	else
		cur = conf_user_profiles;
	while ((cur != NULL) && (done == FALSE) && (name != NULL))
		 {
		tsname = NULL;
		tsname = ipc_callout_helper_get_tsname_from_profile(cur);
		if ((tsname != NULL) && (strcmp(name, tsname) == 0))
			 {
			done = TRUE;
			}
		
		else
			 {
			cur = cur->next;
			}
		}
	if (cur != NULL)
		 {
		
		    // We found something.
		    return TRUE;
		}
	return FALSE;
}


/**
 * \brief Return the trusted server name that is bound to a profile.
 *
 * \note DO NOT FREE the resulting pointer!  It is a pointer to the
 *       source string, not a copied string.
 *
 * @param[in] cur   The profile to get the trusted server name for.
 *
 * \retval NULL if it isn't found, ptr otherwise.
 **/ 
char *ipc_callout_helper_get_tsname_from_profile(config_profiles * cur) 
{
	char *tsname = NULL;
	switch (cur->method->method_num)
		 {
		
		    // Only TLS, TTLS, and PEAP use trusted servers, so ignore the rest.
	case EAP_TYPE_TLS:
		tsname =
		    ((struct config_eap_tls *)(cur->method->method_data))->
		    trusted_server;
		break;
	case EAP_TYPE_TTLS:
		tsname =
		    ((struct config_eap_ttls *)(cur->method->method_data))->
		    trusted_server;
		break;
	case EAP_TYPE_PEAP:
		tsname =
		    ((struct config_eap_peap *)(cur->method->method_data))->
		    trusted_server;
		break;
		}
	return tsname;
}

void ipc_callout_helper_trusted_server_renamed_check_profiles(struct
								config_profiles
								*confprof,
								char *oldname,
								char *newname) 
{
	char *tsname = NULL;
	while (confprof != NULL)
		 {
		tsname = NULL;
		
		    // We should only switch on methods that actually use a trusted server.
		    // Others should be ignored, and a default should NOT be implemented!
		    switch (confprof->method->method_num)
			 {
		case EAP_TYPE_TTLS:
			if (confprof->method->method_data != NULL)
				tsname =
				    ((struct config_eap_ttls *)(confprof->
								method->
								method_data))->
				    trusted_server;
			break;
		case EAP_TYPE_TLS:
			if (confprof->method->method_data != NULL)
				tsname =
				    ((struct config_eap_tls *)(confprof->
							       method->
							       method_data))->
				    trusted_server;
			break;
		case EAP_TYPE_PEAP:
			if (confprof->method->method_data != NULL)
				tsname =
				    ((struct config_eap_peap *)(confprof->
								method->
								method_data))->
				    trusted_server;
			break;
		case EAP_TYPE_FAST:
			if (confprof->method->method_data != NULL)
				tsname =
				    ((struct config_eap_fast *)(confprof->
								method->
								method_data))->
				    trusted_server;
			break;
			}
		if (tsname != NULL)
			 {
			if (strcmp(tsname, oldname) == 0)
				 {
				
				    // We should only switch on methods that actually use a trusted server.
				    // Others should be ignored, and a default should NOT be implemented!
				    switch (confprof->method->method_num)
					 {
				case EAP_TYPE_TTLS:
					if (confprof->method->method_data !=
					     NULL)
						 {
						FREE(((struct config_eap_ttls
							*)(confprof->method->
							   method_data))->
						      trusted_server);
						((struct config_eap_ttls
						   *)(confprof->method->
						      method_data))->
			     trusted_server = _strdup(newname);
						}
					break;
				case EAP_TYPE_TLS:
					if (confprof->method->method_data !=
					     NULL)
						 {
						FREE(((struct config_eap_tls
							*)(confprof->method->
							   method_data))->
						      trusted_server);
						((struct config_eap_tls
						   *)(confprof->method->
						      method_data))->
			      trusted_server = _strdup(newname);
						}
					break;
				case EAP_TYPE_PEAP:
					if (confprof->method->method_data !=
					     NULL)
						 {
						FREE(((struct config_eap_peap
							*)(confprof->method->
							   method_data))->
						      trusted_server);
						((struct config_eap_peap
						   *)(confprof->method->
						      method_data))->
			     trusted_server = _strdup(newname);
						}
					break;
				case EAP_TYPE_FAST:
					if (confprof->method->method_data !=
					     NULL)
						 {
						FREE(((struct config_eap_fast
							*)(confprof->method->
							   method_data))->
						      trusted_server);
						((struct config_eap_fast
						   *)(confprof->method->
						      method_data))->
			     trusted_server = _strdup(newname);
						}
					break;
					}
				}
			}
		confprof = confprof->next;
		}
}


