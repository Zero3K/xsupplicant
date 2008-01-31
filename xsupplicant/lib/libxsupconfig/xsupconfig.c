/**
 * Implementation for parsing configuration file, and storing needed data.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdlib.h>

#ifndef WINDOWS
#include <strings.h>
#endif

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "src/xsup_err.h"
#include "src/xsup_common.h"
#include "src/xsup_debug.h"
#include "xsupconfig_structs.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_devices.h"
#include "xsupconfig.h"
#include "xsupconfig_defaults.h"
#include "xsupconfig_structs.h"
#include "xsupconfig_parse.h"
#include "src/error_prequeue.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

char *forced_profile = NULL;

#define FREE_STRING(x) if (x != NULL) {free(x); x = NULL;}

/**
 * \brief Load an Xsupplicant configuration file in to memory.
 *
 * Load all of the configuration information in to memory.  
 *
 * @param[in] path_to_config   The full path to the configuration file to be loaded in to
 *                             memory.  (i.e. /etc/xsupplicant.conf)
 *
 * \retval XENONE on success
 **/
int config_setup(char *path_to_config)
{
  xmlDocPtr doc = NULL;
  xmlNode *root_element = NULL;

  TRACE 

  xsupconfig_devices_init();
  doc = loadConfig(path_to_config);
  if (doc == NULL)
    {
	  // DO NOT change this to xsupconfig_common_log(), since it will cause linker issues with libxsupgui!
	  if (xsup_common_in_startup() != TRUE)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't load configuration file '%s'!\n", path_to_config);
	  }

      return XECONFIGFILEFAIL;
    }

  root_element = xmlDocGetRootElement(doc);

  xsupconfig_parse(root_element, baselevel, NULL);

  // set the file name
  config_fname = _strdup(path_to_config);

  xmlFreeDoc(doc);
  xmlCleanupParser();

  return XENONE;
}

/**
 * \brief Return a pointer to the master structure that contains all of the
 *        connection configurations.
 *  
 * \retval NULL if there are no connections loaded in to memory.  (Indicates
 *         that either there are no connections defined in the configuration file
 *         or, the configuration file isn't loaded.)
 * \retval ptr to the connections structure.
 *
 * \warning You should *NOT* free the pointer that is returned from this function call.  It
 *          is *NOT* a copy of the connections structure, it is a pointer to the master
 *          configuration structure!  If you free it, bad stuff *WILL* happen.
 **/
struct config_connection *config_get_connections()
{
	return conf_connections;
}

/**
 * \brief Return a pointer to the master structure that contains all of the
 *        trusted server information.
 *  
 * \retval NULL if there are no trusted servers loaded in to memory.  (Indicates
 *         that either there are no trusted servers defined in the configuration file
 *         or, the configuration file isn't loaded.)
 * \retval ptr to the trusted servers structure.
 *
 * \warning You should *NOT* free the pointer that is returned from this function call.  It
 *       is *NOT* a copy of the connections structure, it is a pointer to the master
 *       configuration structure!  If you free it, bad stuff *WILL* happen.
 **/
struct config_trusted_servers *config_get_trusted_servers()
{
	return conf_trusted_servers;
}

/**
 * \brief Return a pointer to the master structure that contains all of the
 *        managed networks information.
 *  
 * \retval NULL if there are no managed networks loaded in to memory.  (Indicates
 *         that either there are no managed networks defined in the configuration file
 *         or, the configuration file isn't loaded.)
 * \retval ptr to the trusted servers structure.
 *
 * \warning You should *NOT* free the pointer that is returned from this function call.  It
 *       is *NOT* a copy of the connections structure, it is a pointer to the master
 *       configuration structure!  If you free it, bad stuff *WILL* happen.
 **/
struct config_managed_networks *config_get_managed_networks()
{
	return conf_managed_networks;
}

/**
 * \brief Change the head of the linked list for managed networks to point
 *        to something else.
 *
 * @param[in] nets   A pointer to the new head of the list.
 **/
void config_set_managed_networks(struct config_managed_networks *nets)
{
  conf_managed_networks = nets;
}


/**
 * \brief Return a pointer to the master structure that contains all of the
 *        profile configurations.
 *  
 * \retval NULL if there are no profiles loaded in to memory.  (Indicates
 *         that either there are no profiles defined in the configuration file
 *         or, the configuration file isn't loaded.
 *
 * \warning You should *NOT* free the pointer that is returned from this function call.  It
 *       is *NOT* a copy of the profiles structure, it is a pointer to the master
 *       profiles structure!  If you free it, bad stuff *WILL* happen.
 **/
struct config_profiles *config_get_profiles()
{
	return conf_profiles;
}

/**
 *  \brief Check the <Globals> part of the configuration to see if
 *         the user wants "friendly warnings" enabled.
 *
 *  \retval TRUE enable friendly warnings
 *  \retval FALSE disable friendly warnings
 **/
uint8_t config_get_friendly_warnings()
{
	TRACE

  if (TEST_FLAG(conf_globals->flags, 
		CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
    {
      // We don't want friendly warnings.
      return FALSE;
    }

  return TRUE;
}

/**
 *  \brief Return the value of the idleWhile timer.
 *  
 *  \retval 0..255 the number of seconds to count down on the idleWhile timer.
 *
 *  \note This will return either the value that was configured in the <Globals>
 *        section of the configuration file, or the default value defined by
 *        \ref IDLE_WHILE_TIMER.
 **/
uint8_t config_get_idleWhile()
{
	TRACE

  if (conf_globals->idleWhile_timeout == 0)
    {
      return IDLE_WHILE_TIMER;
    }
  
  return conf_globals->idleWhile_timeout;
}

/**
 *  \brief Create an empty config in memory.
 *
 *  \warning THIS FUNCTION SHOULD *NEVER* BE CALLED INSIDE OF XSUPPLICANT!!
 *			 IT IS PROVIDED SO THAT GUI INTERFACES CAN HAVE A File|New.. OPTION!
 **/
void config_create_new_config()
{
	TRACE

  config_fname = NULL;   // We don't know what the file name will be.

  // Populate the globals
  initialize_config_globals(&conf_globals);

  initialize_config_connections(&conf_connections);
}

/**
 *  \brief Change a password based on the phase 2 information for TTLS.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[in] password   The new value to set the password to for the EAP
 *                        type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int config_change_ttls_pwd(struct config_eap_method *meth, char *password)
{
	struct config_eap_ttls *ttls;
	void *ptr;

	ttls = (struct config_eap_ttls *)meth->method_data;
	if (ttls == NULL) return -1;

	switch (ttls->phase2_type)
	{
	case TTLS_PHASE2_PAP:
	case TTLS_PHASE2_CHAP:
	case TTLS_PHASE2_MSCHAP:
	case TTLS_PHASE2_MSCHAPV2:
		if (ttls->phase2_data == NULL)
		{
			ttls->phase2_data = Malloc(sizeof(struct config_pwd_only));
			if (ttls->phase2_data == NULL) return -1;
		}

		ptr = ((struct config_pwd_only *)(ttls->phase2_data))->password;
		if (ptr != NULL)
			FREE(((struct config_pwd_only *)(ttls->phase2_data))->password);

		((struct config_pwd_only *)(ttls->phase2_data))->password = _strdup(password);
		break;

	case TTLS_PHASE2_EAP:
		return config_change_pwd(ttls->phase2_data, password);
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown phase 2 authentication type %d!\n", ttls->phase2_type);
		break;
	}

	return XENONE;
}

/**
 *  \brief Change a password based on the EAP method structure.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[in] password   The new value to set the password to for the EAP
 *                        type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int config_change_pwd(struct config_eap_method *meth, char *password)
{
	void *ptr;

	if (password == NULL) return XENONE;   // Nothing to do.

	if (meth->method_data == NULL) return XEMALLOC;

	switch (meth->method_num)
	{
	case EAP_TYPE_MD5:
	case EAP_TYPE_LEAP:
	case EAP_TYPE_GTC:
		ptr = ((struct config_pwd_only *)(meth->method_data))->password;
		if (ptr != NULL)
			FREE(((struct config_pwd_only *)(meth->method_data))->password);

		((struct config_pwd_only *)(meth->method_data))->password = _strdup(password);
		break;

	case EAP_TYPE_TLS:
		ptr = ((struct config_eap_tls *)(meth->method_data))->user_key_pass;
		if (ptr != NULL)
			FREE(((struct config_eap_tls *)(meth->method_data))->user_key_pass);

		((struct config_eap_tls *)(meth->method_data))->user_key_pass = _strdup(password);
		break;

	case EAP_TYPE_SIM:
		ptr = ((struct config_eap_sim *)(meth->method_data))->password;
		if (ptr != NULL)
			FREE(((struct config_eap_sim *)(meth->method_data))->password);

		((struct config_eap_sim *)(meth->method_data))->password = _strdup(password);
		break;

	case EAP_TYPE_AKA:
		ptr = ((struct config_eap_aka *)(meth->method_data))->password;
		if (ptr != NULL)
			FREE(((struct config_eap_aka *)(meth->method_data))->password);

		((struct config_eap_aka *)(meth->method_data))->password = _strdup(password);
		break;

	case EAP_TYPE_MSCHAPV2:
		ptr = ((struct config_eap_mschapv2 *)(meth->method_data))->password;
		if (ptr != NULL)
			FREE(((struct config_eap_mschapv2 *)(meth->method_data))->password);

		((struct config_eap_mschapv2 *)(meth->method_data))->password = _strdup(password);
		break;

	case EAP_TYPE_PEAP:
		return config_change_pwd(((struct config_eap_peap *)(meth->method_data))->phase2, password);
		break;

	case EAP_TYPE_TTLS:
		return config_change_ttls_pwd(meth, password);
		break;

	case EAP_TYPE_FAST:
		return config_change_pwd(((struct config_eap_fast *)(meth->method_data))->phase2, password);
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Invalid EAP method requested!  (Type %d)\n",
			meth->method_num);
		break;
	}

	return XENONE;
}

/**
 *  \brief Given a profile name, set the password.
 *
 *  @param[in] prof_name  A string that indicates the profile name to use.
 *  @param[in] password   The new value to set the password to for the 
 *                        profile specified by 'prof_name'.
 *
 *  \retval XENONE on success
 **/
int config_set_pwd_on_profile(char *prof_name, char *password)
{
	struct config_profiles *prof;

	prof = config_find_profile(prof_name);
	if (prof == NULL) return -1;

	return config_change_pwd(prof->method, password);
}

/**
 * \brief Locate a connection based on the SSID that is mapped to it.
 *
 * @param[in] ssidname   The SSID name that we are looking for.
 *
 * \retval ptr to the connection (if found), NULL if the connection isn't found.
 **/
struct config_connection *config_find_connection_from_ssid(char *ssidname)
{
    struct config_connection *cur = NULL;

    if (!ssidname) return NULL;

  // Start at the top of the list.
  cur = conf_connections;

  while (cur != NULL)
    {
		if (cur->ssid != NULL)
		{
			if (strcmp(cur->ssid, ssidname) == 0) break;
		}

      cur = cur->next;
    }

  return cur;
}

/**
 * \brief Locate the priority value for a named connection.
 *
 * Given the connection name 'matchname', find the connection, and return the
 * connection priority that was assigned to it.
 *
 * \retval 0..255 The priority of the connection. (1 = Highest, 254 = Lowest, 255 = No priority)
 *
 **/
uint8_t config_get_network_priority(char *matchname)
{
  struct config_connection *cur = NULL;

  TRACE

  if (!matchname)
      return 0xff;

  // Start at the top of the list.
  cur = config_find_connection_from_ssid(matchname);

  if (!cur) return 0xff;

  return cur->priority;
}

/**
 *  \brief Set the forced profile value to be used later.
 *
 *  @param[in] profilename  The name of the profile to force
 *                          the supplicant to use.
 **/
void config_set_forced_profile(char *profilename)
{
	TRACE

  if (forced_profile != NULL) 
    {
      free(forced_profile);
      forced_profile = NULL;
    }

  if (profilename != NULL)
    {
      forced_profile = _strdup(profilename);
    }
}

/**
 * \brief Given a connection name, find the configuration information in memory.
 *
 * @param[in] matchname   The name of the connection to locate the configuration for.
 *
 * \retval ptr  A pointer to the connection information, or NULL on failure.
 **/
struct config_connection *config_find_connection(char *matchname)
{
  struct config_connection *cur;

  TRACE

  cur = conf_connections;

  if ((matchname == NULL) && (forced_profile == NULL))
    {
		debug_printf(DEBUG_CONFIG_PARSE, "No configuration name provided, and no forced profile provided!\n");
      return NULL;
    }

  // If we have a forced profile, then look for it first.
  if (forced_profile != NULL)
    {
      while ((cur != NULL) && (strcmp(cur->name, forced_profile) != 0))
	{
	  cur = cur->next;
	}

      // If a forced profile is defined, and not found, then we still
      // need to return.
      return cur;
    }

  while ((cur != NULL) && (strcmp(cur->name, matchname) != 0))
    {
      cur = cur->next;
    }
  
  // If we got a match, return it.
  if (cur != NULL)
    {
      return cur;
    }
  
  // Otherwise, look against the essid.
  cur = conf_connections;

  while (cur != NULL)
  {
    if ((cur->ssid == NULL) || (strcmp(cur->ssid,matchname) != 0)) 
	{
	  cur = cur->next;
	} else {
  	  break;
	}
  }
  
  // Do we have a match on ssid?
  if (cur != NULL)
  {
	return cur;
  }

  return NULL;
}

/**
 * \brief Free a single profile.
 *
 * @param[in] prof   A pointer to the profile that we want to free.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on failure
 **/
int delete_config_single_profile(struct config_profiles **prof)
{
  struct config_profiles *cur;

  if (prof == NULL) return XEMALLOC;

  if ((*prof) == NULL) return XEMALLOC;

  cur = (*prof);

  FREE_STRING(cur->name);
  FREE_STRING(cur->identity);
  FREE_STRING(cur->temp_password);
  FREE_STRING(cur->temp_username);
  delete_config_eap_method(&cur->method);

  free((*prof));

  return XENONE;
}

/** 
 * \brief Remove a profile from out linked list.
 * 
 * @param[in] profname  The name of the profile that we want to remove from 
 *                      the list.
 *
 * \retval XENONE on success
 * \retval XENOTHING_TO_DO if the connection didn't exist.
 **/
int config_delete_profile(char *profname)
{
  struct config_profiles *cur, *prev;

  TRACE

	if (profname == NULL) return XENOTHING_TO_DO;

	if (conf_profiles == NULL) return XENOTHING_TO_DO;

    if (strcmp(conf_profiles->name, profname) == 0)
      {
	// The first one is the one we want to remove.
	cur = conf_profiles;
	conf_profiles = cur->next;

	// Then, delete everything in that network.
	delete_config_single_profile(&cur);

	return XENONE;
      }

  // Otherwise, it will be somewhere else.
  cur = conf_profiles->next;
  prev = conf_profiles;

  while ((cur) && (strcmp(cur->name, profname) != 0))
    {
      cur = cur->next;
      prev = prev->next;
    }

  if ((cur) && (strcmp(cur->name, profname) == 0))
    {
      // We found the network to delete.
      prev->next = cur->next;

      delete_config_single_profile(&cur);
      return XENONE;
    }

  return XENOTHING_TO_DO;
}

/**
 * \brief Remove a connection from our linked list.
 *
 * @param[in] netname  The name of the connection to remove from the list.
 *
 * \retval XENONE on success
 * \retval XENOTHING_TO_DO if the connection didn't exist.
 **/
int config_delete_connection(char *netname)
{
  struct config_connection *cur, *prev;

  TRACE

  if (netname == NULL) return XENOTHING_TO_DO;

  if (conf_connections == NULL) return XENOTHING_TO_DO;

  if (strcmp(conf_connections->name, netname) == 0)
    {
      // The first one is the one we want to remove.
      cur = conf_connections;
      conf_connections = cur->next;

      // Then, delete everything in that network.
      delete_config_single_connection(&cur);

      return XENONE;
    }

  // Otherwise, it will be somewhere else.
  cur = conf_connections->next;
  prev = conf_connections;

  while ((cur) && (strcmp(cur->name, netname) != 0))
    {
      cur = cur->next;
      prev = prev->next;
    }

  if ((cur) && (strcmp(cur->name, netname) == 0))
    {
      // We found the network to delete.
      prev->next = cur->next;

      delete_config_single_connection(&cur);
      return XENONE;
    }
  
  return XENOTHING_TO_DO;
}

/**
 * \brief Remove an interface from our linked list.
 *
 * @param[in] intdesc  The description of the interface to remove from the list.
 *
 * \retval XENONE on success
 * \retval XENOTHING_TO_DO if the interface didn't exist.
 **/
int config_delete_interface(char *intdesc)
{
  struct xsup_interfaces *cur, *prev;

  TRACE

  if (conf_devices == NULL) return XENOTHING_TO_DO;

  cur = conf_devices->interf;

  if (cur == NULL) return XENOTHING_TO_DO;

  if (strcmp(cur->description, intdesc) == 0)
    {
      // The first one is the one we want to remove.
		conf_devices->interf = cur->next;

      // Then, delete everything in that network.
      delete_config_interface(&cur);

      return XENONE;
    }

  // Otherwise, it will be somewhere else.
  prev = cur;
  cur = cur->next;

  while ((cur) && (strcmp(cur->description, intdesc) != 0))
    {
      cur = cur->next;
      prev = prev->next;
    }

  if ((cur) && (strcmp(cur->description, intdesc) == 0))
    {
      // We found the network to delete.
      prev->next = cur->next;

      delete_config_interface(&cur);
      return XENONE;
    }
  
  return XENOTHING_TO_DO;
}

/**
 * \brief Remove a trusted server from our linked list.
 *
 * @param[in] svrname  The name of the trusted server to remove from the list.
 *
 * \retval XENONE on success
 * \retval XENOTHING_TO_DO if the server didn't exist.
 **/
int config_delete_trusted_server(char *svrname)
{
  struct config_trusted_server *cur, *prev;

  TRACE

  if (svrname == NULL) return XENOTHING_TO_DO;

  if (conf_trusted_servers == NULL) return XENOTHING_TO_DO;

  cur = conf_trusted_servers->servers;

  if (cur == NULL) return XENOTHING_TO_DO;

  if (strcmp(cur->name, svrname) == 0)
    {
      // The first one is the one we want to remove.
	  conf_trusted_servers->servers = cur->next;

      // Then, delete everything in that network.
      delete_config_trusted_server(&cur);

      return XENONE;
    }

  // Otherwise, it will be somewhere else.
  prev = cur;
  cur = cur->next;

  while ((cur) && (strcmp(cur->name, svrname) != 0))
    {
      cur = cur->next;
      prev = prev->next;
    }

  if ((cur) && (strcmp(cur->name, svrname) == 0))
    {
      // We found the one to delete.
      prev->next = cur->next;

      delete_config_trusted_server(&cur);
      return XENONE;
    }
  
  return XENOTHING_TO_DO;
}


/**
 * \brief Get a pointer to the config global information.  
 *
 * \retval ptr   Pointer to the structure that contains the variable
 *               settings from the <Globals> section of the configuration.
 *
 * \warning This pointer should *NEVER* be freed by any callers, or things will break!!!!!!
 **/
struct config_globals *config_get_globals()
{
	TRACE
  return conf_globals;
}

/**
 *  \brief Get a pointer to the information about the interfaces that we loaded
 *         from the configuration file.
 *
 *  \retval ptr   Pointer to the structure that contains the interfaces
 *                that were defined in the <Interface> section of the
 *                <Device> block.
 *
 *  \warning This pointer should *NEVER* be freed by any callers, or things will break!
 **/
struct xsup_interfaces *config_get_config_ints()
{
	TRACE

	// If we don't have any devices in the config file, then say so. ;)
	if (conf_devices == NULL) return NULL;

	return conf_devices->interf;
}

/**
 *  \brief Get the phase 2 password from TTLS.
 *
 *  @param[in] ttls   A pointer to the TTLS configuration structure that
 *                    contains the password you would like to find.
 *
 *  \retval password  The password from the phase 2 section of the
 *                    TTLS configuration.
 *  \retval NULL  Failure
 **/
char *config_get_ttls_pwd(struct config_eap_ttls *ttls)
{
	if (((struct config_pwd_only *)(ttls->phase2_data)) == NULL) return NULL;

	switch (ttls->phase2_type)
	{
	case TTLS_PHASE2_PAP:
		return ((struct config_pwd_only *)(ttls->phase2_data))->password;
		break;

	case TTLS_PHASE2_CHAP:
		return ((struct config_pwd_only *)(ttls->phase2_data))->password;
		break;

	case TTLS_PHASE2_MSCHAP:
		return ((struct config_pwd_only *)(ttls->phase2_data))->password;
		break;

	case TTLS_PHASE2_MSCHAPV2:
		return ((struct config_pwd_only *)(ttls->phase2_data))->password;
		break;

	case TTLS_PHASE2_EAP:
		return config_get_pwd_from_profile(ttls->phase2_data);
		break;

	case TTLS_PHASE2_UNDEFINED:
	default:
	  return NULL;
	  break;
	}

	return NULL;
}

/**
 *  \brief Get the password for an EAP method that is buried in a
 *         config_eap_method struct.
 *
 *  @param[in] meth   A structure that contains the EAP method configuration
 *                    data, and an integer that identifies the EAP method.
 *
 *  \retval ptr   The password from the EAP method specified by 'meth'.
 **/
char *config_get_pwd_from_profile(struct config_eap_method *meth)
{
	switch (meth->method_num)
	{
	case EAP_TYPE_MD5:
	case EAP_TYPE_GTC:
	case EAP_TYPE_LEAP:
		return ((struct config_pwd_only *)(meth->method_data))->password;
		break;

	case EAP_TYPE_OTP:
		return NULL;         // No password here.
		break;

	case EAP_TYPE_TLS:
		return ((struct config_eap_tls *)(meth->method_data))->user_key_pass;
		break;

	case EAP_TYPE_SIM:
		return ((struct config_eap_sim *)(meth->method_data))->password;
		break;

	case EAP_TYPE_TTLS:
		return config_get_ttls_pwd(((struct config_eap_ttls *)(meth->method_data)));
		break;	

	case EAP_TYPE_AKA:
		return ((struct config_eap_aka *)(meth->method_data))->password;
		break;

	case EAP_TYPE_PEAP:
		return config_get_pwd_from_profile((((struct config_eap_peap *)(meth->method_data))->phase2));
		break;

	case EAP_TYPE_MSCHAPV2:
		return ((struct config_eap_mschapv2 *)(meth->method_data))->password;
		break;

	case EAP_TYPE_FAST:
		return config_get_pwd_from_profile((((struct config_eap_fast *)(meth->method_data))->phase2));
		break;
	}

	return NULL;
}

/**
 *  \brief Get the inner username for an EAP method that is buried in a
 *         config_eap_method struct.
 *
 *  @param[in] meth   A structure that contains the EAP method configuration
 *                    data, and an integer that identifies the EAP method.
 *
 *  \retval ptr   The password from the EAP method specified by 'meth'.
 **/
char *config_get_inner_user_from_profile(struct config_eap_method *meth)
{
	switch (meth->method_num)
	{
	case EAP_TYPE_TTLS:
		return ((struct config_eap_ttls *)(meth->method_data))->inner_id;
		break;	

	case EAP_TYPE_PEAP:
		return ((struct config_eap_peap *)(meth->method_data))->identity;
		break;

	case EAP_TYPE_FAST:
		return ((struct config_eap_fast *)(meth->method_data))->innerid;
		break;

	default:
	case EAP_TYPE_MD5:
	case EAP_TYPE_GTC:
	case EAP_TYPE_LEAP:
	case EAP_TYPE_OTP:
	case EAP_TYPE_TLS:
	case EAP_TYPE_SIM:
	case EAP_TYPE_AKA:
	case EAP_TYPE_MSCHAPV2:
		return NULL;         // No inner username here.
		break;
	}

	return NULL;
}

/**
 * \brief Clean up any memory that we have used to store the configuration information.
 **/
void config_destroy()
{
	TRACE

  /* see if there really is something to cleanup */
  xsupconfig_devices_deinit(&conf_devices);
  delete_config_data();
}


//****************************************
// CONFIG QUERIES
//****************************************

/**
 * \brief Go through the profiles that we read from the configuration
 *        file, and locate the one named 'profile_name'.
 *
 * @param[in] profile_name   The name of the profile to locate.
 * 
 * \retval ptr   A pointer to the structure that contains the profile
 *               requested by 'profile_name'.
 * \retval NULL  The profile does not exist.
 *
 * \warning Do NOT free the resulting structure!  It is part of the
 *          master linked list of profiles.  Freeing it will cause
 *          bad things to happen!
 **/
struct config_profiles *config_find_profile(char *profile_name)
{
	struct config_profiles *cur;

	// There was a request to find nothing, so return nothing.
	if (profile_name == NULL) return NULL;

	debug_printf(DEBUG_CONFIG_PARSE, "Looking for profile '%s'!\n",
		profile_name);

	cur = conf_profiles;

	while ((cur != NULL) && (strcmp(cur->name, profile_name) != 0)) cur = cur->next;

	return cur;
}

//**********************************************
// Private functions for config parsing. Do 
// not call these from outside config code
//**********************************************

  /********************/
 /* CONFIG_TNC       */
/********************/

/**
 * \brief Clean up the memory used by the TNC portion of a
 *        configuration.
 *
 * @param[in] tmp_tnc  A double dereferenced pointer to the TNC
 *                     data stored in memory.
 **/
void delete_config_eap_tnc(struct config_eap_tnc **tmp_tnc)
{
  free(*tmp_tnc);
  *tmp_tnc = NULL;
}

/**
 * \brief Dump to the screen, all of the information that is stored
 *        in the TNC structure.
 *
 * @param[in] tmp_tnc  A pointer to the structure that contains the TNC 
 *                     information.
 **/
void dump_config_eap_tnc(struct config_eap_tnc *tmp_tnc)
{
  if (!tmp_tnc)
    return;

  printf("\t\t^ ^ ^ ^ ^ ^ eap-tnc ^ ^ ^ ^\n");
  printf("\t\t  Fragment Size : %d\n", tmp_tnc->frag_size);
  printf("\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");
}

/*******************/
/* CONFIG_FAST     */
/*******************/

/**
 * \brief Free all memory that was used to store the configuration
 *        for EAP-FAST.
 *
 * @param[in] tmp_fast  A double dereferenced pointer to the configuration
 *                      information that is stored in memory.
 **/
void delete_config_eap_fast(struct config_eap_fast **tmp_fast)
{
  if (*tmp_fast == NULL)
    return;

  FREE_STRING((*tmp_fast)->pac_location);
  FREE_STRING((*tmp_fast)->innerid);

  free (*tmp_fast);
  *tmp_fast = NULL;
}

/**
 * \brief Dump to the screen, all of the configuration information
 *        stored in memory about EAP-FAST.
 *
 * @param[in] fast  A pointer to the structure that contains all of the
 *                  information about EAP-FAST.
 **/
void dump_config_eap_fast(struct config_eap_fast *fast)
{
  if (!fast)
    return;

  printf("\t---------------eap-fast-------------\n");
  printf("\t  PAC File: \"%s\"\n", fast->pac_location);
  printf("\t  TLS Chunk Size: %d\n", fast->chunk_size);
  printf("\t  Provisioning: ");
  switch (fast->provision)
    {
    case RES_UNSET:
      printf("UNSET\n");
      break;
    case RES_YES:
      printf("YES\n");
      break;
    case RES_NO:
      printf("NO\n");
      break;
    }
  printf("\t  Inner ID: %s\n", fast->innerid);

  if (fast->phase2) dump_config_eap_method(fast->phase2, 1);

  printf("\t------------------------------------\n");
}

/**
 * \brief Dump to the screen, all of the information in memory about
 *        EAP-OTP.
 *
 *  Because EAP-OTP doesn't contain any configuration information, we
 *  will simply print a blank set of headers, so that caller knows that
 *  we are aware that we should use OTP.
 *
 *  @param[in] otp   A pointer to the structure that contains all of the
 *                   configuration information to be used with OTP.
 *
 *  @param[in] dumplevel   The phase that OTP will be used in.  This allows
 *                         the function to know how far to indent the output.
 **/
void dump_config_eap_otp(struct config_pwd_only *otp, int dumplevel)
{
  if (!otp)
    return;

  if (dumplevel == 0)
    {
      printf("\t--------------eap-otp---------------\n");
      printf("\t------------------------------------\n");
    }
  else
    {
      printf("\t^  ^  ^  ^  ^ eap-otp ^  ^  ^  ^  ^  ^\n");
      printf("\t^  ^  ^  ^  ^  ^  ^   ^  ^  ^  ^  ^  ^\n");
    }
}

  /*******************/
 /* CONFIG_TLS      */
/*******************/

/* take a pointer to a config_eap_tls and cleanly delete the structure
   then make it NULL */
/**
 *  \brief Clear out all of the information that is currently in memory
 *         that relates to EAP-TLS.
 *
 *  @param[in] tmp_tls   A double dereferenced pointer to the configuration
 *                       structure that contains all of the configuration
 *                       information about EAP-TLS.
 **/
void delete_config_eap_tls(struct config_eap_tls **tmp_tls)
{
  if (*tmp_tls == NULL)
    return;

  FREE_STRING((*tmp_tls)->user_cert);
  FREE_STRING((*tmp_tls)->crl_dir);  
  FREE_STRING((*tmp_tls)->user_key);
  FREE_STRING((*tmp_tls)->user_key_pass);
  FREE_STRING((*tmp_tls)->random_file);
  FREE_STRING((*tmp_tls)->sc.engine_id);
  FREE_STRING((*tmp_tls)->sc.opensc_so_path);
  FREE_STRING((*tmp_tls)->sc.key_id);
  FREE_STRING((*tmp_tls)->trusted_server);
  
  free (*tmp_tls);
  *tmp_tls = NULL;
}

/**
 * \brief Dump to the screen, all the configuration information
 *        in memory about EAP-TLS.
 *
 * @param[in] tls   A pointer to a structure that contains the configuration
 *                  information that is needed to use EAP-TLS.
 **/
void dump_config_eap_tls(struct config_eap_tls *tls)
{
  if (!tls)
    return;
  printf("\t---------------eap-tls--------------\n");
  printf("\t  TLS Cert: \"%s\"\n", tls->user_cert);
  printf("\t  TLS CRL Dir: \"%s\"\n", tls->crl_dir);
  printf("\t  TLS Key: \"%s\"\n", tls->user_key);
  printf("\t  TLS Key Pass: \"%s\"\n", tls->user_key_pass);
  printf("\t  TLS Chunk Size: %d\n", tls->chunk_size);
  printf("\t  TLS Random Source: \"%s\"\n", 
	       tls->random_file);
  printf("\t  TLS Session Resumption: ");
  switch (tls->session_resume)
    {
    case RES_UNSET:
      printf("UNSET\n");
      break;
    case RES_YES:
      printf("YES\n");
      break;
    case RES_NO:
      printf("NO\n");
      break;
    }
  printf("\t  Using Smartcard:\n");
  printf("\t\tEngine        : \"%s\"\n", tls->sc.engine_id);
  printf("\t\tOpensc SO_PATH: \"%s\"\n", tls->sc.opensc_so_path);
  printf("\t\tKey ID        : \"%s\"\n", tls->sc.key_id);
  //printf("\t\tCertificate ID: \"%s\"", tls.sc->cert_id);
  //printf("\t\tRoot Cert ID  : \"%s\"", tls.sc->root_id); 
  printf("\t------------------------------------\n");
}


  /*******************/
 /* CONFIG_PWD_ONLY */
/*******************/

/**
 * \brief Clean up memory for methods that only have a password,
 *        and use the config_pwd_only structure.
 *
 * @param[in] tmp_pwd   A pointer to a structure that contains a 
 *                      password.
 **/
void delete_config_pwd_only(struct config_pwd_only **tmp_pwd)
{
  if (*tmp_pwd == NULL)
    return;

  FREE_STRING((*tmp_pwd)->password);

  free (*tmp_pwd);
  *tmp_pwd = NULL;
}

/**
 * \brief Dump to the screen, the password stored in the config_pwd_only
 *        structure.
 *
 * @param[in] pwd  A pointer to a structure that contains the password to dump.
 * @param[in] method  A string that identifies the EAP method that we are dumpping
 *                    the password for.
 * @param[in] level   The phase that the password is used in.  This allows the 
 *                    output to be indented correctly in the output.
 **/
void dump_config_pwd_only(struct config_pwd_only *pwd, char *method, int level)
{
  if (pwd == NULL) return;

  if (level == 0) {
    printf("\t---------------%s--------------\n", method);
    printf("\t  %s Pass: \"%s\"\n", method, pwd->password);
    printf("\t------------------------------------\n");
  }else {
    printf("\t\t^ ^ ^  %s  ^ ^ ^\n", method);
    printf("\t\t  %s Pass: \"%s\"\n", method, pwd->password);
    printf("\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");    
  }
  
}


  /*******************/
 /* CONFIG_TTLS     */
/*******************/

//-------------
// TTLS_PHASE2
//------------

/**
 * \brief Clean up the memory used by phase 2 TTLS-EAP.
 *
 * @param[in] eapdata   A double dereferenced pointer to a 
 *                      structure that contains information about the
 *                      configuration of an EAP method.
 **/
void delete_config_ttls_eap(struct config_eap_method **eapdata)
{
  struct config_eap_method *tmp, *next;

  if (eapdata == NULL)
    {
      printf("%s() was passed a NULL pointer!\n", __FUNCTION__);
      return;
    }

  tmp = (*eapdata);

  if (tmp == NULL) return;

  while (tmp != NULL)
    {
      next = tmp->next;
      delete_config_eap_method(&tmp);
      tmp = next;
    }
}

/**
 *  \brief Clear the phase 2 configuration from memory.
 *
 *  @param[in] ttls   A pointer to a structure that contains configuration
 *                    information for EAP-TTLS.  This information will also
 *                    include the information we need to know to free the
 *                    phase 2 method(s).
 **/
void delete_config_ttls_phase2 (struct config_eap_ttls *ttls)
{
  if (ttls == NULL)
    return;
  switch (ttls->phase2_type) {
  case TTLS_PHASE2_PAP:
    delete_config_pwd_only((struct config_pwd_only **)&ttls->phase2_data);
    break;
  case TTLS_PHASE2_CHAP: 
    delete_config_pwd_only((struct config_pwd_only **)&ttls->phase2_data);
    break;
  case TTLS_PHASE2_MSCHAP:
    delete_config_pwd_only((struct config_pwd_only **)&ttls->phase2_data);
    break;
  case TTLS_PHASE2_MSCHAPV2:
    delete_config_pwd_only((struct config_pwd_only **)&ttls->phase2_data);
    break;
  case TTLS_PHASE2_EAP:
    delete_config_ttls_eap((struct config_eap_method **)&ttls->phase2_data);
    break;
  default:
    printf("AAAH! Trying to delete an undefined config"
	   " type in %s.\nNotify developers. Type: 0x%x\n", 
	   __FUNCTION__, ttls->phase2_type);
  }
}

/**
 * \brief Dump to the screen, all of the information about EAP methods that
 *        are configured to be used for phase 2 in EAP-TTLS.
 *
 * @param[in] phase2   A pointer to the phase 2 structure that contains
 *                     information about the EAP types to clear out of
 *                     memory.
 **/
void dump_config_ttls_eap(struct config_eap_method *phase2)
{
  struct config_eap_method *tmp;

  tmp = phase2;

  while (tmp != NULL)
    {
      switch(tmp->method_num)
	{
	case EAP_TYPE_MD5:
	  dump_config_pwd_only((struct config_pwd_only *)tmp->method_data, 
			       "EAP-MD5", 2);
	  break;

	case EAP_TYPE_TNC:
	  dump_config_eap_tnc((struct config_eap_tnc *)tmp->method_data);
	  break;

	default:
	  printf("Unknown TTLS phase 2 EAP method.  (%d)\n", tmp->method_num);
	  break;
	}
      tmp = tmp->next;
    }
}

/**
 * \brief Dump to the screen, all of the information we know about
 *        the configuration of phase 2 authentication for EAP-TTLS.
 *
 * @param[in] ttls   A pointer to a structure that contains information
 *                   about the configuration of EAP-TTLS.  This structure
 *                   will also contain the information needed to know how
 *                   to dump the phase 2 information.
 **/
void dump_config_ttls_phase2(struct config_eap_ttls *ttls) 
{
  if (ttls == NULL)
    return;

  switch (ttls->phase2_type) {
  case TTLS_PHASE2_PAP:
    dump_config_pwd_only((struct config_pwd_only *)ttls->phase2_data, 
			 "EAP-TTLS-PAP", 2);
    break;
  case TTLS_PHASE2_CHAP: 
    dump_config_pwd_only((struct config_pwd_only *)ttls->phase2_data,
			 "EAP-TTLS-CHAP", 2);
    break;
  case TTLS_PHASE2_MSCHAP:
    dump_config_pwd_only((struct config_pwd_only *)ttls->phase2_data,
			 "EAP-TTLS-MSCHAP", 2);
    break;
  case TTLS_PHASE2_MSCHAPV2:
    dump_config_pwd_only((struct config_pwd_only *)ttls->phase2_data,
			 "EAP-TTLS-MSCHAPv2", 2);
    break;
  case TTLS_PHASE2_EAP:
    dump_config_ttls_eap((struct config_eap_method *)ttls->phase2_data);
    break;
  default:
    printf("AAAH! Trying to dump an undefined config"
	   " type in %s.\nNotify developers. Type: 0x%x\n", 
	   __FUNCTION__, ttls->phase2_type);
  }
}

/**
 * \brief Clear from memory the EAP-TTLS configuration data.
 *
 * @param[in] tmp_ttls   A double dereferenced pointer to the memory that
 *                       contains the EAP-TTLS configuration information.
 **/
void delete_config_eap_ttls(struct config_eap_ttls **tmp_ttls)
{
  if (*tmp_ttls == NULL)
    return;

  FREE_STRING((*tmp_ttls)->user_cert);
  FREE_STRING((*tmp_ttls)->crl_dir);
  FREE_STRING((*tmp_ttls)->user_key);
  FREE_STRING((*tmp_ttls)->user_key_pass);
  FREE_STRING((*tmp_ttls)->random_file);  
  FREE_STRING((*tmp_ttls)->cncheck);
  FREE_STRING((*tmp_ttls)->trusted_server);
  FREE_STRING((*tmp_ttls)->inner_id);
  if ((*tmp_ttls)->phase2_data) 
    delete_config_ttls_phase2((*tmp_ttls));

  free (*tmp_ttls);
  *tmp_ttls = NULL;
}

/**
 * \brief Dump to the screen, all of the configuration information that
 *        is known about EAP-TTLS.
 *
 * @param[in] ttls  A pointer to a structure that contains all of the 
 *                  configuration options for EAP-TTLS.
 **/
void dump_config_eap_ttls(struct config_eap_ttls *ttls)
{
  if (!ttls) {
    return;
  }
  printf("\t---------------eap-ttls--------------\n");
  printf("\t  TTLS Cert: \"%s\"\n", ttls->user_cert);
  printf("\t  TTLS CRL Dir: \"%s\"\n", ttls->crl_dir);
  printf("\t  TTLS Key: \"%s\"\n", ttls->user_key);
  printf("\t  TTLS Key Pass: \"%s\"\n", ttls->user_key_pass);
  printf("\t  TTLS Chunk Size: %d\n", ttls->chunk_size);
  printf("\t  TTLS Random Source: \"%s\"\n", ttls->random_file);
  printf("\t  TTLS CN to Check : \"%s\"\n", ttls->cncheck);
  printf("\t  TTLS Exact CN Match : %s\n", ttls->cnexact ? "yes" : "no"); 
  printf("\t  TTLS Session Resumption: ");
  switch (ttls->session_resume)
    {
    case RES_UNSET:
      printf("UNSET\n");
      break;
    case RES_YES:
      printf("YES\n");
      break;
    case RES_NO:
      printf("NO\n");
      break;
    }
  switch (ttls->phase2_type) {
  case TTLS_PHASE2_PAP:
    printf("\t  TTLS phase2: pap\n");    
    break;
  case TTLS_PHASE2_CHAP:
    printf("\t  TTLS phase2: chap\n");    
    break;
  case TTLS_PHASE2_MSCHAP:
    printf("\t  TTLS phase2: mschap\n");    
    break;
  case TTLS_PHASE2_MSCHAPV2:
    printf("\t  TTLS phase2: mschapv2\n");        
    break;
  case TTLS_PHASE2_EAP:
    printf("\t  TTLS phase2: EAP\n");
    break;
  default:
    printf("\t  TTLS phase2: UNDEFINED\n");    
    break;
  }
  if (ttls->phase2_data) dump_config_ttls_phase2(ttls);
  else printf("No phase 2 defined?\n");
  printf("\t------------------------------------\n");
}

  /*******************/
 /* CONFIG_MSCHAPV2 */
/*******************/

/**
 * \brief Clear from memory all of the configuration information that was
 *        used for EAP-MSCHAPv2 authentication.
 *
 * @param[in] tmp_mschapv2   A double dereferenced pointer to the space in
 *                           memory that contains the configuration information
 *                           for EAP-MSCHAPv2.
 **/
void delete_config_eap_mschapv2(struct config_eap_mschapv2 **tmp_mschapv2)
{
  if (*tmp_mschapv2 == NULL)
    return;

  FREE_STRING((*tmp_mschapv2)->password);
  FREE_STRING((*tmp_mschapv2)->nthash);

  free (*tmp_mschapv2);
  *tmp_mschapv2 = NULL;
}

/**
 * \brief Dump to the screen, all of the configuration settings known for
 *        EAP-MSCHAPv2.
 *
 * @param[in] mschapv2  A pointer to the configuration data for EAP-MSCHAPv2.
 * @param[in] level   The phase that the EAP-MSCHAPv2 configuration data will be
 *                    used in.  This allows the function to indent the output
 *                    correctly.
 **/
void dump_config_eap_mschapv2(struct config_eap_mschapv2 *mschapv2, int level)
{
  if (!mschapv2)
    return;
  if (level == 0) {
    printf("\t---------------eap-mschapv2--------------\n");
    if (mschapv2->password != NULL)
      printf("\t  MSCHAPV2 Pass      : \"%s\"\n", mschapv2->password);

    if (mschapv2->nthash != NULL)
      printf("\t  MSCHAPV2 NtPwd Hash: \"%s\"\n", mschapv2->nthash);

    if (mschapv2->ias_quirk == TRUE)
      {
	printf("\t  MSCHAPV2 IAS Quirk : Yes\n");
      }
    else
      {
	printf("\t  MSCHAPV2 IAS Quirk : No\n");
      }
    printf("\t------------------------------------\n");
  }else {
  printf("\t\t^ ^ ^  eap-mschapv2  ^ ^ ^\n");
    printf("\t\t  MSCHAPV2 Pass      : \"%s\"\n", mschapv2->password);
    printf("\t\t  MSCHAPV2 NtPwd Hash: \"%s\"\n", mschapv2->nthash);
    if (mschapv2->ias_quirk == TRUE)
      {
	printf("\t\t  MSCHAPV2 IAS Quirk : Yes\n");
      }
    else
      {
	printf("\t\t  MSCHAPV2 IAS Quirk : No\n");
      }
  printf("\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");
  }

}


  /*******************/
 /* CONFIG_PEAP     */
/*******************/

/**
 * \brief Clear the memory used for the configuration of EAP-PEAP.
 *
 * @param[in] tmp_peap  A double dereferenced pointer to the block of 
 *                      memory that contains the configuration information
 *                      for EAP-PEAP.
 **/
void delete_config_eap_peap(struct config_eap_peap **tmp_peap)
{
  if (*tmp_peap == NULL)
    return;

  FREE_STRING((*tmp_peap)->identity);
  FREE_STRING((*tmp_peap)->user_cert);
  FREE_STRING((*tmp_peap)->crl_dir);
  FREE_STRING((*tmp_peap)->user_key)
  FREE_STRING((*tmp_peap)->user_key_pass);
  FREE_STRING((*tmp_peap)->random_file);
  FREE_STRING((*tmp_peap)->cncheck);
  FREE_STRING((*tmp_peap)->trusted_server);
  if ((*tmp_peap)->phase2)
    delete_config_eap_method(&(*tmp_peap)->phase2);

  free (*tmp_peap);
  *tmp_peap = NULL;
}

/**
 * \brief Dump to the screen, all of the known configuration options
 *        used by EAP-PEAP.
 *
 * @param[in] peap  A pointer to the memory where the PEAP configuration
 *                  data is stored.
 **/
void dump_config_eap_peap(struct config_eap_peap *peap)
{
  if (!peap)
    return;
  printf("\t---------------eap-peap--------------\n");
  printf("\t  PEAP phase 2 identity: \"%s\"\n", peap->identity);
  printf("\t  PEAP Cert: \"%s\"\n", peap->user_cert);
  printf("\t  PEAP CRL Dir: \"%s\"\n", peap->crl_dir);
  printf("\t  PEAP Key: \"%s\"\n", peap->user_key);
  printf("\t  PEAP Key Pass: \"%s\"\n", peap->user_key_pass);
  printf("\t  PEAP Chunk Size: %d\n", peap->chunk_size);
  printf("\t  PEAP Random Source: \"%s\"\n", peap->random_file);
  printf("\t  PEAP CN to Check : \"%s\"\n", peap->cncheck);
  printf("\t  PEAP Exact CN Match : %s\n", peap->cnexact ? "yes" : "no");  
  printf("\t  PEAP Session Resumption: ");
  switch (peap->session_resume)
    {
    case RES_UNSET:
      printf("UNSET\n");
      break;
    case RES_YES:
      printf("YES\n");
      break;
    case RES_NO:
      printf("NO\n");
      break;
    }
  printf("\t  Proper PEAPv1 Keying : %s\n", peap->proper_peapv1 ? "yes" : "no");

  if (peap->phase2) dump_config_eap_method(peap->phase2, 1);
  printf("\t------------------------------------\n");
}


  /*******************/
 /* CONFIG_SIM      */
/*******************/

/**
 * \brief  Clear out the memory that was used by the configuration for
 *         EAP-SIM.
 *
 * @param[in] tmp_sim  A double dereferenced pointer to the memory where the
 *                     EAP-SIM configuration is stored.
 **/
void delete_config_eap_sim(struct config_eap_sim **tmp_sim)
{
  if (*tmp_sim == NULL)
    return;

  FREE_STRING((*tmp_sim)->username);
  FREE_STRING((*tmp_sim)->password);

  free (*tmp_sim);
  *tmp_sim = NULL;
}

/**
 * \brief  Dump to the screen, all of the known configuration
 *         information to be used with an EAP-SIM authentication.
 *
 * @param[in] sim  A pointer to the memory where the EAP-SIM 
 *                 configuration is stored.
 *
 * @param[in] level  The phase that the EAP-SIM configuration will be 
 *                   used in.  This allows the function to properly
 *                   indent the output.
 **/
void dump_config_eap_sim(struct config_eap_sim *sim, int level)
{
  if (!sim)
    return;
  if (level == 0) {
    printf("\t---------------eap-sim--------------\n");
    printf("\t  SIM User: \"%s\"\n", sim->username);
    printf("\t  SIM Pass: \"%s\"\n", sim->password);
    printf("\t  SIM Auto Realm: %s\n", sim->auto_realm ? "yes" : "no");  
    printf("\t------------------------------------\n");
  } else {
    printf("\t\t^ ^ ^  eap-sim  ^ ^ ^\n");
    printf("\t\t  SIM User: \"%s\"\n", sim->username);
    printf("\t\t  SIM Pass: \"%s\"\n", sim->password);
    printf("\t\t  SIM Auto Realm: %s\n", sim->auto_realm ? "yes" : "no");  
    printf("\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");
  }
}

  /*******************/
 /* CONFIG_AKA      */
/*******************/

/**
 * \brief Clear the memory used by the EAP-AKA configuration data.
 *
 * @param[in] tmp_aka   A double dereferenced pointer to the memory that
 *                      was used to store the EAP-AKA configuration
 *                      information.
 **/
void delete_config_eap_aka(struct config_eap_aka **tmp_aka)
{
  if (*tmp_aka == NULL)
    return;

  FREE_STRING((*tmp_aka)->username);
  FREE_STRING((*tmp_aka)->password);

  free (*tmp_aka);
  *tmp_aka = NULL;
}

/**
 * \brief Dump to the screen, all of the configuration information that
 *        is known about EAP-AKA.
 *
 * @param[in] aka  A pointer to all of the known configuration information
 *                 about EAP-AKA.
 *
 * @param[in] level   The phase that EAP-AKA will be used in.  This allows
 *                    the function to properly indent the output.
 **/
void dump_config_eap_aka(struct config_eap_aka *aka, int level)
{
  if (!aka)
    return;
  if (level == 0) {
    printf("\t---------------eap-aka--------------\n");
    printf("\t  AKA User: \"%s\"\n", aka->username);
    printf("\t  AKA Pass: \"%s\"\n", aka->password);
    printf("\t  AKA Auto Realm: %s\n", aka->auto_realm ? "yes" : "no");  
    printf("\t------------------------------------\n");
  } else {
    printf("\t\t^ ^ ^  eap-aka  ^ ^ ^\n");
    printf("\t\t  AKA User: \"%s\"\n", aka->username);
    printf("\t\t  AKA Pass: \"%s\"\n", aka->password);
    printf("\t\t  AKA Auto Realm: %s\n", aka->auto_realm ? "yes" : "no");  
    printf("\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");
  }
}


  /*********************/
 /* CONFIG_EAP_METHOD */
/*********************/

/**
 * \brief Delete the EAP configuration specified by 'method'.
 *
 * @param[in] method   A double dereferenced pointer to the area in 
 *                     memory that contains the configuration information
 *                     about an EAP method.
 **/
void delete_config_eap_method(struct config_eap_method **method)
{
  if (method == NULL)
      return;

  if ((*method) == NULL)
      return;

  delete_config_eap_method(&(*method)->next);

  switch ((*method)->method_num) {
  case EAP_TYPE_TLS:
    delete_config_eap_tls((struct config_eap_tls **)&((*method)->method_data));
    break;
  case EAP_TYPE_MD5:
    delete_config_pwd_only((struct config_pwd_only **)&(*method)->method_data);
    break;
  case EAP_TYPE_PEAP:
    delete_config_eap_peap((struct config_eap_peap **)&(*method)->method_data);
    break;
  case EAP_TYPE_SIM:
    delete_config_eap_sim((struct config_eap_sim **)&(*method)->method_data);
    break;
  case EAP_TYPE_AKA:
    delete_config_eap_aka((struct config_eap_aka **)&(*method)->method_data);
    break;
  case EAP_TYPE_TTLS:
    delete_config_eap_ttls((struct config_eap_ttls **)&(*method)->method_data);
    break; 
  case EAP_TYPE_LEAP:
    delete_config_pwd_only((struct config_pwd_only **)&(*method)->method_data);
    break;
  case EAP_TYPE_MSCHAPV2:
    delete_config_eap_mschapv2((struct config_eap_mschapv2 **)&(*method)->method_data);
    break;
  case EAP_TYPE_OTP:
    // Nothing to clean up here.
    break;
  case EAP_TYPE_GTC:
    delete_config_pwd_only((struct config_pwd_only **)&(*method)->method_data);
    break;
  case EAP_TYPE_FAST:
    delete_config_eap_fast((struct config_eap_fast **)&(*method)->method_data);
    break;
  case EAP_TYPE_TNC:
    delete_config_eap_tnc((struct config_eap_tnc **)&(*method)->method_data);
    break;
  default:
    printf("AAAH! Trying to delete an undefined config"
	   " type in %s.\nNotify developers. Type: 0x%x\n", 
	   __FUNCTION__, (*method)->method_num);
  }
}

/**
 * \brief  Dump to the screen, all of the configuration information for the
 *         EAP method defined by 'method'.
 *
 * @param[in] method   A pointer to a structure in memory that contains information
 *                     about an EAP method's configuration, and an integer that
 *                     identifies the EAP method.
 *
 * @param[in] dumplevel   The phase that this EAP method will be used in.  This
 *                        allows the function to properly indent the output.
 **/
void dump_config_eap_method(struct config_eap_method *method, int dumplevel)
{
  if (method == NULL)
    return;

  switch ((method)->method_num) {
  case EAP_TYPE_TLS:
    dump_config_eap_tls((struct config_eap_tls *)((method)->method_data));
    break;
  case EAP_TYPE_MD5:
    dump_config_pwd_only((struct config_pwd_only *)(method)->method_data, 
			 "EAP-MD5", dumplevel);
    break;
  case EAP_TYPE_PEAP:
    dump_config_eap_peap((struct config_eap_peap *)(method)->method_data);
    break;

  case EAP_TYPE_TNC:
    dump_config_eap_tnc((struct config_eap_tnc *)(method)->method_data);
    break;

  case EAP_TYPE_SIM:
    dump_config_eap_sim((struct config_eap_sim *)(method)->method_data,
			dumplevel);
    break;
  case EAP_TYPE_AKA:
    dump_config_eap_aka((struct config_eap_aka *)(method)->method_data,
			dumplevel);
    break;
  case EAP_TYPE_FAST:
    dump_config_eap_fast((struct config_eap_fast *)(method)->method_data);
    break;
  case EAP_TYPE_TTLS:
    dump_config_eap_ttls((struct config_eap_ttls *)(method)->method_data);
    break; 
  case EAP_TYPE_LEAP:
    dump_config_pwd_only((struct config_pwd_only *)(method)->method_data,
			 "LEAP", dumplevel);
    break;
  case EAP_TYPE_OTP:
    dump_config_eap_otp((struct config_pwd_only *)(method)->method_data,
			 dumplevel);
    break;
  case EAP_TYPE_GTC:
    dump_config_pwd_only((struct config_pwd_only *)(method)->method_data,
			 "EAP-GTC", dumplevel);
    break;
  case EAP_TYPE_MSCHAPV2:
    dump_config_eap_mschapv2((struct config_eap_mschapv2 *)(method)->method_data,
			     dumplevel);
    break;
    
  default:
    printf("AAAH! Trying to dump an undefined config"
	   " type in %s\n.Notify developers. Type: 0x%x\n", 
	   __FUNCTION__, (method)->method_num);
  }

  dump_config_eap_method(method->next, dumplevel);
}

  /**********************/
 /* CONFIG_CONNECTION  */
/**********************/

/**
 * \brief Delete a single connection structure stored in memory.
 *
 * @param[in] tmp_conn   A double dereferenced pointer to the location
 *                       in memory where the connection data is stored.
 **/
void delete_config_single_connection(struct config_connection **tmp_conn)
{
  if (*tmp_conn == NULL)
    return;

  FREE_STRING((*tmp_conn)->name);
  FREE_STRING((*tmp_conn)->ssid);
  FREE_STRING((*tmp_conn)->profile);
  FREE_STRING((*tmp_conn)->device);

  delete_config_ip_data((*tmp_conn));
  delete_config_association((*tmp_conn));

  free ((*tmp_conn));
  (*tmp_conn) = NULL;
}

/**
 * \brief  Delete all of the connections in memory.
 *
 * @param[in] tmp_conn   A double dereferenced pointer to the head of
 *                       a linked list of connections to be cleared from
 *                       memory.
 **/
void delete_config_connections(struct config_connection **tmp_conn)
{
  struct config_connection *next, *cur;

  if (*tmp_conn == NULL)
    return;

  cur = (*tmp_conn);
  next = (*tmp_conn)->next;

  while (cur)
    {
      delete_config_single_connection(&cur);
      cur = next;
      if (next)
	{
	  next = next->next;
	}
    }

  *tmp_conn = NULL;
}

/**
 * \brief Allocate memory to store a new connection.
 *
 * @param[in] tmp_conn   A pointer to the pointer that will hold the new
 *                       connection node in a linked list.
 **/
void initialize_config_connections(struct config_connection **tmp_conn)
{
  if (*tmp_conn != NULL) {
    delete_config_connections(tmp_conn);
  }
  *tmp_conn = 
    (struct config_connection *)malloc(sizeof(struct config_connection));  
  if (*tmp_conn)
    {
      memset(*tmp_conn, 0, sizeof(struct config_connection));
      (*tmp_conn)->priority = DEFAULT_PRIORITY;
      SET_FLAG((*tmp_conn)->flags, CONFIG_NET_USE_OSC_TNC);
    }
}

/**
 * \brief Delete a single managed network stored in memory.
 *
 * @param[in] tmp_mn  A double dereferenced pointer to a location
 *                    in memory where the managed network data is
 *                    stored.
 **/
void delete_config_managed_network(struct config_managed_networks **tmp_mn)
{
  if ((*tmp_mn) == NULL)
    return;

  FREE_STRING((*tmp_mn)->ou);
  FREE_STRING((*tmp_mn)->key);
  FREE_STRING((*tmp_mn)->update_url);
  FREE_STRING((*tmp_mn)->last_update);

  FREE((*tmp_mn));
  (*tmp_mn) = NULL;
}

/**
 * \brief Delete all of the managed networks that are currently stored
 *        in memory.
 *
 * @param[in] head   The pointer to the head of the linked list that 
 *                   contains the managed networks information.
 **/
void delete_config_managed_networks(struct config_managed_networks **head)
{
  struct config_managed_networks *next, *cur;

  if (*head == NULL)
    return;

  cur = (*head);
  next = (*head)->next;

  while (cur)
    {
      delete_config_managed_network(&cur);
      cur = next;
      if (next != NULL)
	{
	  next = next->next;
	}
    }
}

/**
 * \brief Delete all information for a single interface in the linked list.
 *
 * @param[in] intdata   A double dereferenced pointer to the structure that we
 *                      need to free.
 **/
void delete_config_interface(struct xsup_interfaces **intdata)
{
	FREE((*intdata)->description);
	FREE((*intdata)->driver_type);

	FREE((*intdata));
}

/**
 * \brief Delete all of the devices that are currently stored
 *        in memory.
 *
 * @param[in] head   The pointer to the head of the linked list that 
 *                   contains the devices information.
 **/
void delete_config_devices(struct xsup_devices **head)
{
  struct xsup_interfaces *next, *cur;

  if (*head == NULL)
    return;

  cur = (*head)->interf;
  next = (*head)->interf->next;

  while (cur)
    {
      delete_config_interface(&cur);
      cur = next;
      if (next != NULL)
	{
	  next = next->next;
	}
    }

  free((*head));
}
  /***************************/
 /* CONFIG_TRUSTED_SERVERS  */
/***************************/

/**
 * \brief Delete a single trusted server structure stored in memory.
 *
 * @param[in] tmp_server   A double dereferenced pointer to the location
 *                         in memory where the trusted server data is stored.
 **/
void delete_config_trusted_server(struct config_trusted_server **tmp_server)
{
  if (*tmp_server == NULL)
    return;

  FREE_STRING((*tmp_server)->name);
  FREE_STRING((*tmp_server)->store_type);
  FREE_STRING((*tmp_server)->location);
  FREE_STRING((*tmp_server)->common_name);

  free ((*tmp_server));
  (*tmp_server) = NULL;
}

/**
 * \brief  Delete all of the trusted servers in memory.
 *
 * @param[in] tmp_servers   A double dereferenced pointer to the head of
 *                          a linked list of trusted servers to be cleared from
 *                          memory.
 **/
void delete_config_trusted_servers(struct config_trusted_servers **tmp_servers)
{
  struct config_trusted_server *next, *cur;

  if (*tmp_servers == NULL)
    return;

  cur = (*tmp_servers)->servers;
  next = (*tmp_servers)->servers->next;

  while (cur)
    {
      delete_config_trusted_server(&cur);
      cur = next;
      if (next != NULL)
		{
			next = next->next;
		}
    }

  FREE((*tmp_servers));
  *tmp_servers = NULL;
}

/**
 * \brief Dump to the screen, the encryption type that WPA/WPA2 will use.
 *
 * @param[in] crypt  A byte that identifies the encryption method that should be
 *                   used for encryption with WPA/WPA2.
 **/
void dump_config_network_wpa(uint8_t crypt)
{
  switch (crypt)
    {
    case CRYPT_WEP40:
      printf("WEP40\n");
      return;

    case CRYPT_TKIP:
      printf("TKIP\n");
      return;

    case CRYPT_WRAP:
      printf("WRAP\n");
      return;

    case CRYPT_CCMP:
      printf("CCMP\n");
      return;

    case CRYPT_WEP104:
      printf("WEP104\n");
      return;
    
    default:
      printf("NONE\n");
      return;
    }
}

/**
 * \brief Dump to the screen, the association block of a connection
 *        structure in memory.
 *
 * @param[in] conn   A pointer to memory that contains a connection that
 *                   we want to dump the association block of.
 **/
void dump_config_association(struct config_connection *conn)
{
	if (!conn) return;

	printf("\t------- Association Information -------\n");
	printf("\tAssociation Type    : %d\n", conn->association.association_type);
	printf("\tPairwise Key Type   : %02x\n", conn->association.pairwise_keys);
	printf("\tGroup Key Type      : %d\n", conn->association.group_keys);
	printf("\tAuthentication Type : %d\n", conn->association.auth_type);
	printf("\tStatic WEP TX Index : %d\n", conn->association.txkey);
	printf("\tWPA PSK             : %s\n", conn->association.psk);
	printf("\tWPA PSK (Hex)       : %s\n", conn->association.psk_hex);
	printf("\t---------------------------------------\n");
}

/**
 * \brief Free memory used by the association configuration.
 *
 * @param[in] conn   A connection configuration structure that contains the 
 *                   association data we want to free.
 **/
void delete_config_association(struct config_connection *conn)
{
	if (conn == NULL) return;  // Nothing to do.

	FREE(conn->association.psk);
	FREE(conn->association.psk_hex);
	FREE(conn->association.keys[1]);
	FREE(conn->association.keys[2]);
	FREE(conn->association.keys[3]);
	FREE(conn->association.keys[4]);
}

/**
 * \brief Free memory used by the IP configuration structures.
 *
 * @param[in] conn   A connection configuration sturcture that contains the
 *                   IP address data we want to free.
 **/
void delete_config_ip_data(struct config_connection *conn)
{
	if (conn == NULL) return; // Nothing to do.

	FREE(conn->ip.dns1);
	FREE(conn->ip.dns2);
	FREE(conn->ip.dns3);
	FREE(conn->ip.gateway);
	FREE(conn->ip.ipaddr);
	FREE(conn->ip.netmask);
	FREE(conn->ip.search_domain);
}

/**
 * \brief Dump all of the IP data from the configuration file.
 *
 * @param[in] conn  A pointer to a structure that contains the "<IP_Address>" block
 *                  data from the config file.
 **/
void dump_config_ip(struct config_connection *conn)
{
	printf("\t------------- IP Data -------------\n");
	printf("\tType         : %d\n", conn->ip.type);
	printf("\tRenew on Re. : %d\n", conn->ip.renew_on_reauth);
	printf("\tIP Address   : %s\n", conn->ip.ipaddr);
	printf("\tNetmask      : %s\n", conn->ip.netmask);
	printf("\tGateway      : %s\n", conn->ip.gateway);
	printf("\tDNS1         : %s\n", conn->ip.dns1);
	printf("\tDNS2         : %s\n", conn->ip.dns2);
	printf("\tDNS3         : %s\n", conn->ip.dns3);
	printf("\tSearch Domain: %s\n", conn->ip.search_domain);
	printf("\t-----------------------------------\n");
}

/**
 * \brief Dump all of the known information about a single connection.
 *
 * @param[in] conn   A pointer to a structure that contains the connection
 *                   we wish to display data for.
 **/
void dump_config_connections(struct config_connection *conn)
{
  if (!conn)
    return;
  printf("+-+-+-+-+  Network Name: \"%s\" +-+-+-+-+\n", conn->name);

  printf("  SSID: \"%s\"\n", conn->ssid);
  printf("  OU  : \"%s\"\n", conn->ou);

  if (TEST_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN))
  {
	  printf("  Hidden SSID : yes\n");
  }
  else
  {
	  printf("  Hidden SSID : no\n");
  }

  if (TEST_FLAG(conn->flags, CONFIG_NET_USE_OSC_TNC))
    {
      printf("  Use OSC TNC support : Yes\n");
    } 
  else
    {
      printf("  Use OSC TNC support : No\n");
    }

  if (TEST_FLAG(conn->flags, CONFIG_NET_DEST_MAC))
    printf("  DEST MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	   conn->dest_mac[0], conn->dest_mac[1], conn->dest_mac[2],
	   conn->dest_mac[3], conn->dest_mac[4], conn->dest_mac[5]);

  printf("  Priority  : %d\n", conn->priority);
  printf("  Device    : %s\n", conn->device);
  printf("  Profile   : %s\n", conn->profile);
  printf("  EAPoL Ver : %d\n", conn->force_eapol_ver);

  dump_config_association(conn);
  dump_config_ip(conn);

  if (conn->next)
    dump_config_connections(conn->next);
      
}


  /*******************/
 /* CONFIG_GLOBALS  */
/*******************/

/**
 * \brief Free all of the memory that is used by the configuration 
 *        information from the <Globals> section of the configuration.
 *
 * @param[in] tmp_globals   A double dereferenced pointer to the structure
 *                          in memory that contains the configuration information
 *                          from the <Globals> section of the configuration.
 **/
void delete_config_globals(struct config_globals **tmp_globals)
{
  if (*tmp_globals == NULL)
    return;

  FREE_STRING((*tmp_globals)->logpath);
  FREE_STRING((*tmp_globals)->ipc_group_name);
  FREE_STRING((*tmp_globals)->log_facility);
  
  free (*tmp_globals);
  *tmp_globals = NULL;
}

/**
 * \brief Point the config globals to a new structure.
 *
 * @param[in] new_globals   A pointer to the new structure that contains all
 *                          of our globals.
 *
 * \warning DO NOT free the memory used by the structure passed in.  This call
 *          doesn't copy the data, it simple changes an internal pointer to 
 *          point to the new data!
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory errors
 **/
int config_set_new_globals(struct config_globals *new_globals)
{
  if (new_globals == NULL) return XEMALLOC;

  conf_globals = new_globals;

  return XENONE;
}

/**
 * \brief Allocate the memory to be used to store the information from
 *        the <Globals> section of the configuration file.
 *
 * @param[in] tmp_globals   A pointer to the pointer that will contain
 *                          the configuration information from the <Globals>
 *                          portion of the configuration.
 **/
void initialize_config_globals(struct config_globals **tmp_globals)
{
  if (*tmp_globals != NULL) {
    delete_config_globals(tmp_globals);
  }
  *tmp_globals = 
    (struct config_globals *)malloc(sizeof(struct config_globals));  
  if (*tmp_globals)
    {
      memset(*tmp_globals, 0, sizeof(struct config_globals));
    
	  xsupconfig_defaults_set_globals((*tmp_globals));
    }
}

/**
 * \brief Dump to the screen, all of the configuration infomration
 *        from the "<Managed_Network>" section of the configuration.
 *
 * @param[in] nets   A pointer to the structure that contains the 
 *                   information from the "<Managed_Network>" section of
 *                   the configuration.
 **/
void dump_config_managed_network(struct config_managed_networks *nets)
{
	printf("\t---------- Managed Network -----------\n");
	printf("\tOU          : %s\n", nets->ou);
	printf("\tKey         : %s\n", nets->key);
	printf("\tSerial ID   : %d\n", nets->serialid);
	printf("\tUpdate URL  : %s\n", nets->update_url);
	printf("\tAuto Update : %d\n", nets->auto_update);
	printf("\tUpdate Freq.: %d\n", nets->update_freq);
	printf("\tLast Update : %s\n", nets->last_update);
	printf("\t--------------------------------------\n");
}

/**
 * \brief Dump to the screen, all of the configuration information
 *        from the "<Managed_Networks>" section of the configuration.
 *
 * @param[in] nets   A pointer to the structure that contains the 
 *                   information from the "<Managed_Networks>" section of the
 *                   configuration.
 **/
void dump_config_managed_networks(struct config_managed_networks *nets)
{
	printf("-!-!-!-!- Managed Networks -!-!-!-!-\n");
	while (nets != NULL)
	{
		dump_config_managed_network(nets);
		nets = nets->next;
	}
	printf("-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!\n");
}

/**
 * \brief Dump to the screen, all of the configuration information
 *        from the <Globals> section of the configuration.
 *
 * @param[in] globals   A pointer to the structure that contains the
 *                      information from the <Globals> section of the 
 *                      configuration.
 **/
void dump_config_globals(struct config_globals *globals)
{
  if (!globals) {
    printf("No Globals\n");
    return;
  }

  if (globals->logpath)
  {
    printf("Logpath: '%s'\n", globals->logpath);
	printf("Log level : %d\n", globals->loglevel);
  }

  if (globals->cached_credential_file)
	  printf("Cached Credential File : '%s'\n", globals->cached_credential_file);

  if (globals->log_facility)
    printf("Log Facility: '%s'\n", globals->log_facility);

  if (globals->ipc_group_name)
    printf("IPC Group Name : '%s' \n", globals->ipc_group_name);

  if (globals->auth_period != 0)
    printf("Auth Period: %d\n", globals->auth_period);

  if (globals->held_period != 0)
    printf("Held Period: %d\n", globals->held_period);

  if (globals->max_starts != 0)
    printf("Max Starts: %d\n", globals->max_starts);

  if (globals->stale_key_timeout != 0)
    printf("Stale Key Timeout: %d\n", globals->stale_key_timeout);

  if (globals->active_timeout != 0)
    printf("Active Scan Timeout: %d\n", globals->active_timeout);

  if (globals->idleWhile_timeout != 0)
    printf("Idle While Timeout: %d\n", globals->idleWhile_timeout);

  if (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
    {
      printf("Friendly Warnings : Yes\n");
    } else {
      printf("Friendly Warnings : No\n");
    }

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ASSOC_AUTO))
    {
      printf("Auto Association : Yes\n");
    } else {
      printf("Auto Association : No\n");
    }

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_FIRMWARE_ROAM))
    {
      printf("Roaming          : Firmware\n");
    } else {
      printf("Roaming          : Xsupplicant\n");
    }

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_PASSIVE_SCAN))
    {
      printf("Passive Scanning : Yes\n");
    } else {
      printf("Passive Scanning : No\n");
    }

  printf("Passive Scan Timeout : %d\n", globals->passive_timeout);

  printf("Association Timeout : %d\n", globals->assoc_timeout);

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ALLMULTI))
    printf("ALLMULTI is enabled!\n");
  else
    printf("ALLMULTI is disabled!\n");

  printf("Destination: ");
  switch (globals->destination)
    {
    case DEST_AUTO:
      printf("Auto\n");
      break;

    case DEST_BSSID:
      printf("BSSID\n");
      break;

    case DEST_MULTICAST:
      printf("Multicast\n");
      break;

    case DEST_SOURCE:
      printf("Source\n");
      break;
    }
}

  /*******************/
 /* CONFIG_DATA     */
/*******************/

/**
 * \brief Delete all of the configuration structures that were populated by
 *        reading the configuration file.
 **/
void delete_config_data()
{
  if (config_fname)
    free(config_fname);

  if (conf_globals)
    delete_config_globals(&conf_globals);

  if (conf_profiles)
	  delete_config_profiles(&conf_profiles);

  if (conf_connections)
    delete_config_connections(&conf_connections);

  if (conf_trusted_servers)
	  delete_config_trusted_servers(&conf_trusted_servers);

  if (conf_managed_networks)
    delete_config_managed_networks(&conf_managed_networks);

  if (conf_devices)
	  delete_config_devices(&conf_devices);
}

/**
 * \brief Dump all of the information we know from the <Devices>
 *        section of the configuration file.
 *
 * @param[in] data   A pointer to the structure that contains information
 *                   about the devices specified in the configuration file.
 **/
void dump_config_devices(struct xsup_devices *data)
{
	printf("*-*-*-*-*-* Devices *-*-*-*-*-*\n");
	xsupconfig_devices_dump(data);
	printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
}

/**
 * \brief Dump each trusted server in the linked list.
 *
 * @param[in] start   The head of the linked-list of servers that we want
 *                    to dump.
 **/
void dump_config_trusted_server(struct config_trusted_server *start)
{
	while (start != NULL)
	{
		printf("\t--------- Trusted Server ----------\n");
		printf("\tName        : %s\n", start->name);
		printf("\tStore Type  : %s\n", start->store_type);
		printf("\tLocation    : %s\n", start->location);
		printf("\tCommon Name : %s\n", start->common_name);

		printf("\t------------------------------------\n");

		start = start->next;
	}		
}

/**
 * \brief Dump all of the information we know from the "<Trusted_Servers>" 
 *        section of the configuration file.
 *
 * @param[in] ts   A pointer to a trusted servers structure that contains a
 *                 linked list of trusted servers that we want to dump.
 **/
void dump_config_trusted_servers(struct config_trusted_servers *ts)
{
	if (ts == NULL) return;

	printf("-!-!-!-!-! Trusted Servers !-!-!-!-!\n");
	dump_config_trusted_server(ts->servers);
	printf("-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!\n");
}

/**
 * \brief Dump to the screen, all of the information we know from the 
 *        <Profiles> section of the configuration file.
 *
 * @param[in] data   A pointer to the root of a linked list containing all
 *                   of the profiles defined in the configuration file.
 **/
void dump_config_profiles(struct config_profiles *data)
{
	struct config_profiles *cur;

	cur = data;

	printf("+-+-+-+-+-+ Profiles -+-+-+-+-+\n");
	while (cur != NULL)
	{
		printf("   ************ Profile *************\n");
		printf("    Name     : %s\n", cur->name);
		printf("    Identity : %s\n", cur->identity);
		printf("    OU       : %s\n", cur->ou);
		printf("    Compliance : %x\n", cur->compliance);
		dump_config_eap_method(cur->method, 0);
		printf("   **********************************\n");

		cur = cur->next;
	}
	printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
}

/**
 * \brief Dump to the screen, all of the information we know from the 
 *        <Plugins> section of the configuration file.
 *
 * @param[in] data   A pointer to the root of a linked list containing all
 *                   of the plugins defined in the configuration file.
 **/
void dump_config_plugins(struct config_plugins *data)
{
	struct config_plugins *cur = data;

	printf("+-+-+-+-+-+ Plugins -+-+-+-+-+\n");
	while (cur != NULL)
	{
		printf("   ************ Plugin *************\n");
		printf("    Name     : %s\n", cur->name);
		printf("    Path     : %s\n", cur->path);
		printf("   **********************************\n");

		cur = cur->next;
	}
	printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
}

/**
 * \brief Free all of the memory that was used by <Profiles> as a
 *        result of loading the configuration file.
 *
 * @param[in] prof  A double dereferenced pointer to the head of a 
 *                  linked list containing the profile information 
 *                  from the configuration file.
 **/
void delete_config_profiles(struct config_profiles **prof)
{
	struct config_profiles *cur, *next;

	cur = (*prof);

	while (cur != NULL)
	{
	  next = cur->next;
	  delete_config_single_profile(&cur);	
	  cur = next;
	}
}

/**
 * \brief Dump to the screen, all of the information that
 *        was read in from the configuration file.
 **/
void dump_config_data()
{
  printf("=-=-=-=-=-=-=-=-=-=-=-=-=\n");
  printf("Configuration File: %s\n", config_fname);
  dump_config_globals(conf_globals);
  dump_config_profiles(conf_profiles);
  dump_config_connections(conf_connections);
  dump_config_devices(conf_devices);
  dump_config_trusted_servers(conf_trusted_servers);
  dump_config_managed_networks(conf_managed_networks);
  dump_config_plugins(conf_plugins);
  printf("=-=-=-=-=-=-=-=-=-=-=-=-=\n");
}

/**
 * \brief Free the old global configuration structure, and replace
 *        it with a new one.
 *
 * @param[in] newglobs   The new configuration globals structure to use.
 **/
void reset_config_globals(struct config_globals *newglobs)
{
	if (newglobs == NULL) return;

	delete_config_globals(&conf_globals);
	conf_globals = newglobs;
}

/**
 * \brief Take a connection configuration structure and change it if it
 *        exists, or add it if it doesn't.
 *
 * @param[in] confconn   The connection data that we want to either change, or
 *                       add to the connection list.
 *
 * \retval XENONE on success
 * \retval XEGENERROR on general failure
 **/
int add_change_config_connections(struct config_connection *confconn)
{
	struct config_connection *cur = NULL, *prev = NULL;

	if (confconn == NULL) return XEGENERROR;

	// If we don't have any connections currently in memory.
	if (conf_connections == NULL)
	{
		conf_connections = confconn;

		return XENONE;
	}

	if (strcmp(conf_connections->name, confconn->name) == 0)
	{
		// The first node is the one we are changing.
		confconn->next = conf_connections->next;
		delete_config_single_connection(&conf_connections);
		conf_connections = confconn;
		return XENONE;
	}

	cur = conf_connections->next;
	prev = conf_connections;

	while ((cur != NULL) && (strcmp(cur->name, confconn->name) != 0))
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		// It is an addition.
		prev->next = confconn;
		return XENONE;
	}

	// Otherwise, we need to replace the node that cur points to.
	confconn->next = cur->next;
	prev->next = confconn;
	delete_config_single_connection(&cur);

	return XENONE;
}

/**
 * \brief Take a profile configuration structure and change it if it
 *        exists, or add it if it doesn't.
 *
 * @param[in] confprof   The profile data that we want to either change, or
 *                       add to the profile list.
 *
 * \retval XENONE on success
 * \retval XEGENERROR on general failure
 **/
int add_change_config_profiles(struct config_profiles *confprof)
{
	struct config_profiles *cur = NULL, *prev = NULL;

	if (confprof == NULL) return XEGENERROR;

	// If we don't have any profiles currently in memory.
	if (conf_profiles == NULL)
	{
		conf_profiles = confprof;

		return XENONE;
	}

	if (strcmp(conf_profiles->name, confprof->name) == 0)
	{
		// The first node is the one we are changing.
		confprof->next = conf_profiles->next;
		delete_config_single_profile(&conf_profiles);
		conf_profiles = confprof;
		return XENONE;
	}

	cur = conf_profiles->next;
	prev = conf_profiles;

	while ((cur != NULL) && (strcmp(cur->name, confprof->name) != 0))
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		// It is an addition.
		prev->next = confprof;
		return XENONE;
	}

	// Otherwise, we need to replace the node that cur points to.
	confprof->next = cur->next;
	prev->next = confprof;
	delete_config_single_profile(&cur);

	return XENONE;
}

/**
 * \brief Take a trusted server configuration structure and change it if it
 *        exists, or add it if it doesn't.
 *
 * @param[in] confts   The trusted server data that we want to either change, or
 *                     add to the trusted server list.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation error
 * \retval XEGENERROR on general failure
 **/
int add_change_config_trusted_server(struct config_trusted_server *confts)
{
	struct config_trusted_server *cur = NULL, *prev = NULL;

	if (confts == NULL) return XEGENERROR;

	if (conf_trusted_servers == NULL)
	{
		conf_trusted_servers = Malloc(sizeof(struct config_trusted_servers));
		if (conf_trusted_servers == NULL)
		{
			debug_printf(DEBUG_CONFIG_PARSE, "Couldn't allocate memory to store trusted servers structure!\n");
			return XEMALLOC;
		}
	}

	// If we don't have any trusted servers currently in memory.
	if (conf_trusted_servers->servers == NULL)
	{
		conf_trusted_servers->servers = confts;

		return XENONE;
	}

	cur = conf_trusted_servers->servers;

	if (strcmp(cur->name, confts->name) == 0)
	{
		// The first node is the one we are changing.
		confts->next = cur->next;
		delete_config_trusted_server(&cur);
		conf_trusted_servers->servers = confts;
		return XENONE;
	}

	cur = conf_trusted_servers->servers->next;
	prev = conf_trusted_servers->servers;

	while ((cur != NULL) && (strcmp(cur->name, confts->name) != 0))
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		// It is an addition.
		prev->next = confts;
		return XENONE;
	}

	// Otherwise, we need to replace the node that cur points to.
	confts->next = cur->next;
	prev->next = confts;
	delete_config_trusted_server(&cur);

	return XENONE;
}

/**
 * \brief Take an interface configuration structure and change it if it
 *        exists, or add it if it doesn't.
 *
 * @param[in] confif   The interface data that we want to either change, or
 *                     add to the interface list.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation error
 * \retval XEGENERROR on general failure
 **/
int add_change_config_interface(struct xsup_interfaces *confif)
{
	struct xsup_interfaces *cur = NULL, *prev = NULL;

	if (confif == NULL) return XEGENERROR;

	if (conf_devices == NULL)
	{
		conf_devices = Malloc(sizeof(struct xsup_devices));
		if (conf_devices == NULL)
		{
			debug_printf(DEBUG_CONFIG_PARSE, "Couldn't allocate memory to store interface structure!\n");
			return XEMALLOC;
		}
	}

	// If we don't have any interfaces currently in memory.
	if (conf_devices->interf == NULL)
	{
		conf_devices->interf = confif;

		return XENONE;
	}

	cur = conf_devices->interf;

	if (strcmp(cur->description, confif->description) == 0)
	{
		// The first node is the one we are changing.
		confif->next = cur->next;
		delete_config_interface(&cur);
		conf_devices->interf = confif;
		return XDATACHANGED;
	}

	cur = conf_devices->interf->next;
	prev = conf_devices->interf;

	while ((cur != NULL) && (strcmp(cur->description, confif->description) != 0))
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		// It is an addition.
		prev->next = confif;
		return XENONE;
	}

	// Otherwise, we need to replace the node that cur points to.
	confif->next = cur->next;
	prev->next = confif;
	delete_config_interface(&cur);

	return XDATACHANGED;
}

/**
 * \brief Take a managed network configuration structure and change it if it
 *        exists, or add it if it doesn't.
 *
 * @param[in] confmn   The managed network data that we want to either change, or
 *                     add to the managed network list.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation error
 * \retval XEGENERROR on general failure
 **/
int add_change_config_managed_network(struct config_managed_networks *confmn)
{
	struct config_managed_networks *cur = NULL, *prev = NULL;

	if (confmn == NULL) 
	{
		debug_printf(DEBUG_CONFIG_PARSE | DEBUG_CONFIG_WRITE, "Nothing passed in to %s()!\n", __FUNCTION__);
		return XEGENERROR;
	}

	// If we don't have any profiles currently in memory.
	if (conf_managed_networks == NULL)
	{
		conf_managed_networks = confmn;
		
		return XENONE;
	}

	if (strcmp(conf_managed_networks->ou, confmn->ou) == 0)
	{
		// The first node is the one we are changing.
		confmn->next = conf_managed_networks->next;
		delete_config_managed_networks(&conf_managed_networks);
		conf_managed_networks = confmn;
		return XENONE;
	}

	cur = conf_managed_networks->next;
	prev = conf_managed_networks;

	while ((cur != NULL) && (strcmp(cur->ou, confmn->ou) != 0))
	{
		prev = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		// It is an addition.
		prev->next = confmn;
		return XENONE;
	}

	// Otherwise, we need to replace the node that cur points to.
	confmn->next = cur->next;
	prev->next = confmn;
	delete_config_managed_networks(&cur);

	return XENONE;
}

/**
 * \brief Locate the interface structure from the configuration file given the interface description.
 *
 * @param[in] intdesc   The interface description.
 *
 * \retval NULL if the interface isn't found, otherwise, a pointer to the structure containing the
 *              interface data for the 'interface description'.
 **/
struct xsup_interfaces *config_find_int(char *intdesc)
{
	struct xsup_interfaces *cur = NULL;

	if (intdesc == NULL) return NULL;    // If we asked for nothing, return nothing.

	cur = config_get_config_ints();

	while ((cur != NULL) && (strcmp(cur->description, intdesc) != 0))
	{
		cur = cur->next;
	}

	return cur;
}

