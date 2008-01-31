/*******************************************************************
 * \file plugins.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author galimorerpg@users.sourceforge.net
 *
 *******************************************************************/


#ifdef WINDOWS
#include <windows.h>
#include <shlwapi.h>
#include "stdintwin.h"
#include "libcrashdump/crashdump.h"

#define  strdup  _strdup
#endif // WINDOWS

#include <stdio.h>
#include <stdlib.h>
#include "plugins.h"
#include "xsup_debug.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "platform/plugin_handler.h"



struct config_plugins *conf_plugins = NULL;

// Returns the # of plugins loaded
uint8_t load_plugins()
{  
#ifdef WINDOWS
  struct config_plugins *plugin = (struct config_plugins *)calloc(1, sizeof(struct config_plugins));
  void (*initialize)()          = NULL;
  uint8_t plugins_loaded        = 0;

  // XXX Temporary for excalibur_ga
  char *cwd = NULL;
  char *diagnose_logfile = NULL;
  int diagnose_logfile_size = 0;
#ifdef WINDOWS
  TCHAR win_path[_MAX_PATH];
  HMODULE app_handle = GetModuleHandle(NULL);


#ifdef _UNICODE
  debug_printf(DEBUG_NORMAL, "Warning: Code in %s:%d is not unicode-safe.\n", __FUNCTION__, __LINE__);
#endif

  // Locate the XSupplicant service so we can get a relative path
  // Passing NULL allows us to retrieve the handle of the currently running process
  memset(win_path, 0x0, _MAX_PATH);

  if(app_handle == NULL)
      debug_printf(DEBUG_NORMAL, "Warning: Unable to locate the install path for XSupplicant: %d\n", GetLastError());
  else
  {
    GetModuleFileName(app_handle, win_path, _MAX_PATH);
    PathRemoveFileSpec(win_path);
	PathAddBackslash(win_path);
    cwd = strdup(win_path);
  }
	// = szModulePath;*/
#endif // WINDOWS

  conf_plugins = plugin;
  
  // Add BirdDog to the list of plugins to load
  conf_plugins->name = strdup("BirdDog");
  conf_plugins->path = calloc(1, sizeof(cwd) + 256);
  strcat(conf_plugins->path, cwd);
  strcat(conf_plugins->path, "Modules\\BirdDog.dll");

  // Add PostureDiagnose to the list of plugins to load
  conf_plugins->next = (struct config_plugins *)calloc(1, sizeof(struct config_plugins));
  conf_plugins->next->name = strdup("PostureDiagnose");
  conf_plugins->next->path = calloc(1, sizeof(cwd) + 256);
  strcat(conf_plugins->next->path, cwd);
  strcat(conf_plugins->next->path, "Modules\\PostureDiagnose.dll");

  // Add the PostureDiagnoseLog.log file to the list of things to be collected by troubleticket/crash reporter.
  diagnose_logfile_size = (strlen(cwd) * 2) + (strlen("Modules\\IMCs\\OESEngine\\PostureDiagnoseLog.log") * 2) + 16;
  diagnose_logfile = calloc(1, diagnose_logfile_size);
  strcat(diagnose_logfile, cwd);
  strcat(diagnose_logfile, "Modules\\IMCs\\OESEngine\\PostureDiagnoseLog.log");

  free(cwd);
  cwd = NULL;

  if(diagnose_logfile != NULL)
  {
#ifdef WINDOWS
    crashdump_add_file(diagnose_logfile, 1);
#else
    #warning Need to implement crash dump file handling for this platform.
#endif // WINDOWS

    free(diagnose_logfile);
    diagnose_logfile = NULL;
  }

#ifdef WINDOWS
  // XXX Fix this later
  crashdump_add_file("C:\\supdetlog.log", 0);
#else
  #warning Need to implement crash dump file handling for this platform.
#endif // WINDOWS

  while(plugin != NULL)
    {
      debug_printf(DEBUG_NORMAL, "Loading Plugin '%s' from '%s'.\n", plugin->name, plugin->path);

      if(platform_plugin_load(plugin) == PLUGIN_LOAD_SUCCESS)
	{
	  debug_printf(DEBUG_NORMAL, "Loaded plugin '%s' at 0x%x\n", plugin->name, plugin->handle);

	  initialize = platform_plugin_entrypoint(plugin, "initialize");

	  if(initialize != NULL)
	    {
	      (*initialize)();
	      plugins_loaded++;
	    }
	  else 
	    {
	      debug_printf(DEBUG_PLUGINS, "Error initializing plugin '%s' : %s", plugin->name, platform_plugin_error(plugin));
	      platform_plugin_unload(plugin);
	    }
	}
      else
	{
	  debug_printf(DEBUG_PLUGINS, "Plugin '%s' failed to load from '%s'.\n", plugin->name, plugin->path);
	}

      plugin = plugin->next;
    }

  return plugins_loaded;
#endif // WINDOWS
}

uint8_t unload_plugins()
{
  struct config_plugins *plugin = conf_plugins;
  void (*cleanup)() = NULL;
  uint8_t plugins_unloaded = 0;

  while(plugin != NULL)
    {
      debug_printf(DEBUG_PLUGINS, "Unloading Plugin '%s' ('%s') from 0x%x.\n", plugin->name, plugin->path, plugin->handle);

      cleanup = (void *)platform_plugin_entrypoint(plugin, "cleanup");

      if(cleanup != NULL)
	{
	  (*cleanup)();
	}
      else
	{
	  debug_printf(DEBUG_PLUGINS, "Error cleaning up plugin '%s' : %s", plugin->name, platform_plugin_error(plugin));
	}
      
      if(platform_plugin_unload(plugin) == PLUGIN_UNLOAD_SUCCESS)
        {
          debug_printf(DEBUG_PLUGINS, "Unloaded plugin '%s'.\n", plugin->name, plugin->handle);	  
	  plugins_unloaded++;
	}
      else
        {
          debug_printf(DEBUG_PLUGINS, "Plugin '%s' loaded at 0x%x from '%s' failed to unload.\n", plugin->name, plugin->handle, plugin->path);
        }

      FREE(plugin->name);
      FREE(plugin->path);

      plugin = plugin->next;
    }

  // Temporary for excalibur_ga
  if(conf_plugins != NULL)
  {
        FREE(conf_plugins->name);
        FREE(conf_plugins->path);
        FREE(conf_plugins);

	  conf_plugins = NULL;
  }

  return plugins_unloaded;
}

// Warning: Do not debug_printf from this function.
// It hooks in at the debug_printf layer, so you'll end up in a loop ;)
void log_hook_full_debug(char *msg) 
{
  struct config_plugins *plugin = conf_plugins;
  void (*hook)(char *msg);

  if(msg != NULL) 
    {
      //printf("[PLUGIN HOOK ] %s:\n\t %s\n", __FUNCTION__, msg);

      while(plugin != NULL)
	{

	  if(plugin->handle != NULL) 
	    {
	      hook = (void *)platform_plugin_entrypoint(plugin, "log_hook_full_debug");
	      
          if(hook != NULL)
		    (*hook)(msg);
	    }

	  plugin = plugin->next;
	}
    }
}

// XXX TODO - OS-specific path handling will need to be added to this function.
int plugin_hook_trouble_ticket_dump_file(char *path) 
{
  struct config_plugins *plugin = conf_plugins;
  int (*hook)(char *logfile) = NULL;
  int total_failures         = 0;
  char *plugin_logfile       = NULL;

  if(path != NULL) 
    {
      while(plugin != NULL)
	{

	  if(plugin->handle != NULL) 
	    {
	      hook = (void *)platform_plugin_entrypoint(plugin, "plugin_hook_trouble_ticket_dump_file");
	      
	      if(hook != NULL)
		  {
			  if(path == NULL)
			  {
				  debug_printf(DEBUG_PLUGINS, "Error: Plugin temporary path is NULL in %s:%d.\n", __FUNCTION__, __LINE__);

				  // Improvise... there's no reason we can't still dump the file.
				  path = "\\";
			  }

			plugin_logfile = calloc(1, strlen(path) + strlen(plugin->name) + 64);

			strcat(plugin_logfile, path);
			strcat(plugin_logfile, "\\");
			strcat(plugin_logfile, plugin->name);
			strcat(plugin_logfile, ".log");

			if((*hook)(plugin_logfile) != 0)
			{
			   total_failures++;
			}
			else
			{
			  #ifdef WINDOWS
				// The dump succeeded, add this file to the trouble ticket zip.
				// and set the unlink flag to 1 so the file gets deleted.
				crashdump_add_file(plugin_logfile, 1);
			  #else
                                #warning Need to implement crash dump file handlingfor this platform.
                          #endif // WINDOWS

			}
		  }
	      else
		  {
			//printf("Hook NULL for plugin in %s\n", __FUNCTION__);
			total_failures++;
		  }
	    }

	  plugin = plugin->next;
	}
    }
  // Will be 0 if everything succeeded
  return total_failures;
}

int registered_debug_loggers()
{
  return 1;
}
