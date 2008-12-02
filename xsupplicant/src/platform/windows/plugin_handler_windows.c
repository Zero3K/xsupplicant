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
  if(plugin == NULL)
    return PLUGIN_NOT_ALLOCATED;

  if(plugin->handle != NULL)
    {
      debug_printf(DEBUG_PLUGINS, "Uninitialized or already loaded plugin!\n");
      return PLUGIN_ALREADY_INITIALIZED;
    }
  
  plugin->handle = LoadLibrary(plugin->path);
  
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
