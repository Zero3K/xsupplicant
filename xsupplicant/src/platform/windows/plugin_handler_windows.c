/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file plugin_handler_windows.c
 *
 * \author galimorerpg@cvs.sourceforge.net
 *
 **/
#include <windows.h>
#include "../plugin_handler.h"
#include "xsupconfig_structs.h"
#include "../../xsup_debug.h"
#include "../../plugins.h"
#include <string.h>

void *platform_plugin_entrypoint(struct config_plugins *plugin, char *function_name)
{
  void *function = NULL;

  if(plugin == NULL)
    return NULL;

  if(function_name == NULL)
    return NULL;

  if(plugin->handle == NULL)
    return NULL;

  function = GetProcAddress(plugin->handle, function_name);
      
  if(function == NULL)
    {
      //printf("Error retreiving '%s' from plugin '%s': %s\n", function_name, plugin->name, platform_plugin_error(plugin));
      return NULL;
    }

  return function;
}

uint8_t platform_plugin_load(struct config_plugins *plugin)
{
	char *full_path = NULL;

  if(plugin == NULL)
    return PLUGIN_NOT_ALLOCATED;

  if(plugin->handle != NULL)
    {
      debug_printf(DEBUG_PLUGINS, "Uninitialized or already loaded plugin!\n");
      return PLUGIN_ALREADY_INITIALIZED;
    }

  if ((strstr(plugin->path, "\\") != NULL) || (strstr(plugin->path, "..") != NULL))
  {
	  debug_printf(DEBUG_NORMAL, "Plugin '%s' attempted to load via a relative path.  Not loading!\n", plugin->name);
	  return PLUGIN_LOAD_FAILURE;
  }

  full_path = Malloc(strlen(plugin->path)+100);
  if (full_path == NULL) return PLUGIN_LOAD_FAILURE;
  
  sprintf(full_path, "Modules\\%s", plugin->path);
  debug_printf(DEBUG_PLUGINS, "Attempting to load '%s'.\n", full_path);

  plugin->handle = LoadLibrary(full_path);
  free(full_path);

  if(plugin->handle == NULL)
    {
      debug_printf(DEBUG_PLUGINS, "Error loading plugin '%s': %s\n", plugin->name, platform_plugin_error(plugin));
      return PLUGIN_LOAD_FAILURE;
    }
  
  return PLUGIN_LOAD_SUCCESS;
}

uint8_t platform_plugin_unload(struct config_plugins *plugin)
{
  if(plugin == NULL)
    return PLUGIN_NOT_ALLOCATED;

  if(plugin->handle == NULL)
    return PLUGIN_NOT_LOADED;

  if(FreeLibrary(plugin->handle) == 0)
    {
      debug_printf(DEBUG_PLUGINS, "Error unloading plugin '%s': %s\n", plugin->name, platform_plugin_error(plugin));
      return PLUGIN_UNLOAD_FAILURE;
    }
  
  plugin->handle = NULL;
  
  return PLUGIN_UNLOAD_SUCCESS;
}

char *platform_plugin_error(struct config_plugins *plugin)
{
  return NULL;//ErrorString(GetLastError());
}
