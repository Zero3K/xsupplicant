/*******************************************************************
 * \file plugins.h
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author galimorerpg@users.sourceforge.net
 *
 *******************************************************************/

#ifndef _XSUP_PLUGINS_H
#define _XSUP_PLUGINS_H

#ifdef WINDOWS
#include "stdintwin.h"
#endif // WINDOWS

#ifndef WINDOWS
#include <stdint.h>
#endif // WINDOWS

enum plugin_status
  {
    PLUGIN_LOAD_SUCCESS,
    PLUGIN_LOAD_FAILURE,
    PLUGIN_UNLOAD_SUCCESS,
    PLUGIN_UNLOAD_FAILURE, 
    PLUGIN_NOT_ALLOCATED,
    PLUGIN_ALREADY_INITIALIZED,
    PLUGIN_NOT_LOADED
  };

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
/*int xsupconfig_defaults_create_plugin(config_plugins **newplugin)
{
  (*newplugin) = malloc(sizeof(struct config_plugins));
  if ((*newplugin) == NULL)
  {
	  printf("Couldn't allocate memory to store plugin!\n");
	  return DEFAULTS_MALLOC_ERR;
  }

  memset((*newplugin), 0x00, sizeof(struct config_plugins));

  return DEFAULTS_SUCCESS;
}*/

#define LOG_HOOK_FULL_DEBUG 1

int plugin_hook_trouble_ticket_dump_file(char *path);
int plugin_hook_full_debug_log(char *msg);
int registered_debug_loggers();
uint8_t load_plugins();
uint8_t unload_plugins();

#endif // _XSUP_PLUGINS_H
