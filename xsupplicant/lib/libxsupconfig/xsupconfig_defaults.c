/**
 * Create structures used for the configuration, and set their defaults.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_defaults.c
 *
 * \author chris@open1x.org
 **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "xsupconfig.h"
#include "xsupconfig_defaults.h"

/**
 * \brief Set a globals structure to all of it's defaults.
 *
 * @param[in] toset   A pointer to the globals structure that we want to
 *                    set defaults on.
 *
 * \note This call will only set values that wouldn't be properly set
 *       by doing a memset() and setting everything to 0s.
 **/
void xsupconfig_defaults_set_globals(config_globals *toset)
{
  toset->flags = CONFIG_GLOBALS_ALLMULTI | CONFIG_GLOBALS_ASSOC_AUTO | 
	  			 CONFIG_GLOBALS_FIRMWARE_ROAM | CONFIG_GLOBALS_DETECT_ON_STARTUP |
				 CONFIG_GLOBALS_ROLL_LOGS | CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF |
				 CONFIG_GLOBALS_PASSIVE_SCAN;
  toset->active_timeout = RESCAN_TIMEOUT;
  toset->assoc_timeout = ASSOCIATION_TIMEOUT;
  toset->idleWhile_timeout = IDLE_WHILE_TIMER;
  toset->passive_timeout = PASSIVE_TIMEOUT;
  toset->stale_key_timeout = STALE_KEY_WARN_TIMEOUT;
  toset->held_period = HELD_STATE_TIMEOUT;
  toset->auth_period = AUTHENTICATION_TIMEOUT;
  toset->max_starts = MAX_STARTS;
  toset->logs_to_keep = OLD_LOGS_TO_KEEP;				// Default to keeping 3 logs around.
  toset->size_to_roll = LOG_SIZE_TO_ROLL;				// Roll logs when they reach 10 megs.
  toset->dead_connection_timeout = DEAD_CONN_TIMEOUT;   
  toset->logtype = LOGGING_FILE;
}

/**
 * \brief Create a managed network structure, and populate it with it's defaults.
 *
 * @param[in,out] mnet   A double dereferenced pointer that will be populated with
 *                       a config_managed_networks structure that has all values
 *                       set to defaults.
 *
 * \retval DEFAULTS_SUCCESS on success
 * \retval DEFAULTS_MALLOC_ERR on failure
 **/
int xsupconfig_defaults_create_managed_network(config_managed_networks **mnet)
{
	(*mnet) = malloc(sizeof(config_managed_networks));
	if ((*mnet) == NULL)
	{
		printf("Couldn't allocate memory to store managed networks!\n");
		return DEFAULTS_MALLOC_ERR;
	}

	memset((*mnet), 0x00, sizeof(config_managed_networks));

	return DEFAULTS_SUCCESS;
}

/**
 * \brief Create an interface structure and populate it with it's default values.
 *
 * @param[in,out] newint   A double dereference pointer that will be populated with
 *                         an xsup_interfaces structure that has all it's values set
 *                         to defaults.
 *
 * \retval DEFAULTS_SUCCESS on success
 * \retval DEFAULTS_MALLOC_ERR on failure
 **/
int xsupconfig_defaults_create_interface(config_interfaces **newint)
{
    (*newint) = malloc(sizeof(struct xsup_interfaces));
    if ((*newint) == NULL)
	{
	  printf("Couldn't allocate memory to store interface setting configuration!");
	  return DEFAULTS_MALLOC_ERR;
	}

    memset((*newint), 0x00, sizeof(config_interfaces));

	return DEFAULTS_SUCCESS;
}

/**
 * \brief Create a trusted server structure and populate it with it's default values.
 *
 * @param[in,out] newts   A double dereferenced pointer that will be populated with 
 *                        a config_trusted_server structure that has all it's values
 *                        set to defaults.
 *
 * \retval DEFAULTS_SUCCESS on success
 * \retval DEFAULTS_MALLOC_ERR on failure
 **/
int xsupconfig_defaults_create_trusted_server(config_trusted_server **newts)
{
    (*newts) = malloc(sizeof(struct config_trusted_server));
	if ((*newts) == NULL)
	{
		printf("Couldn't allocate memory to store a trusted server configuration!\n");
		return DEFAULTS_MALLOC_ERR;
	}
	
    memset((*newts), 0x00, sizeof(struct config_trusted_server));

	return DEFAULTS_SUCCESS;
}

/**
 * \brief Create a connection structure and populate it with it's default values.
 *
 * @param[in,out] newcon   A double dereferenced pointer that will be populated with
 *                         a config_connection structure that has all it's values set
 *                         to defaults.
 *
 * \retval DEFAULTS_SUCCESS on success
 * \retval DEFAULTS_MALLOC_ERR on failure
 **/
int xsupconfig_defaults_create_connection(config_connection **newcon)
{
  (*newcon) = malloc(sizeof(struct config_connection));
  if ((*newcon) == NULL)
  {
	  printf("Couldn't allocate memory to store connections!\n");
	  return DEFAULTS_MALLOC_ERR;
  }

  memset((*newcon), 0x00, sizeof(struct config_connection));

  (*newcon)->priority = DEFAULT_PRIORITY; // 0xff;

  return DEFAULTS_SUCCESS;
}
/**
 * \brief Create a profile structure and populate it with it's default values.
 *
 * @param[in,out] newcon   A double dereferenced pointer that will be populated with
 *                         a config_connection structure that has all it's values set
 *                         to defaults.
 *
 * \retval DEFAULTS_SUCCESS on success
 * \retval DEFAULTS_MALLOC_ERR on failure
 **/
int xsupconfig_defaults_create_profile(config_profiles **newprofile)
{
  (*newprofile) = malloc(sizeof(struct config_profiles));
  if ((*newprofile) == NULL)
  {
	  printf("Couldn't allocate memory to store connections!\n");
	  return DEFAULTS_MALLOC_ERR;
  }

  memset((*newprofile), 0x00, sizeof(struct config_profiles));

  (*newprofile)->compliance = 0xffffffff;  // Default compliance to ON.

  return DEFAULTS_SUCCESS;
}

/**
 * \brief Create a plugin structure and populate it with it's default values.
 *
 * @param[in,out] newplugin   A double dereferenced pointer that will be populated with
 *                         a config_plugin structure that has all it's values set
 *                         to defaults.
 *
 * \retval DEFAULTS_SUCCESS on success
 * \retval DEFAULTS_MALLOC_ERR on failure
 **/
int xsupconfig_defaults_create_plugin(config_plugins **newplugin)
{
  (*newplugin) = malloc(sizeof(struct config_plugins));
  if ((*newplugin) == NULL)
  {
	  printf("Couldn't allocate memory to store plugin!\n");
	  return DEFAULTS_MALLOC_ERR;
  }

  memset((*newplugin), 0x00, sizeof(struct config_plugins));

  return DEFAULTS_SUCCESS;
}
