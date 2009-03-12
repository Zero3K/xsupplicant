/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file plugin_handler_linux.c
 *
 * \author galimorerpg@cvs.sourceforge.net
 *
 *******************************************************************/

#include "plugin_handler.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_debug.h"
#include "plugins.h"
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

// Don't use debug_printf here - it'll cause recursion in debug_printf plugin hooks. ;)
void *platform_plugin_entrypoint(struct config_plugins *plugin,
				 char *function_name)
{
	void *function = NULL;

	if (plugin == NULL)
		return NULL;

	if (function_name == NULL)
		return NULL;

	if (plugin->handle == NULL)
		return NULL;

	function = dlsym(plugin->handle, function_name);

	if (function == NULL) {
		printf("Error retreiving '%s' from plugin '%s': %s\n",
		       function_name, plugin->name, dlerror());
		return NULL;
	}

	return function;
}

uint8_t platform_plugin_load(struct config_plugins * plugin)
{
	if (plugin == NULL)
		return PLUGIN_NOT_ALLOCATED;

	if (plugin->handle != NULL) {
		debug_printf(DEBUG_PLUGINS,
			     "Uninitialized or already loaded plugin!\n");
		return PLUGIN_ALREADY_INITIALIZED;
	}

	plugin->handle = dlopen(plugin->path, RTLD_LAZY);

	if (plugin->handle == NULL) {
		debug_printf(DEBUG_PLUGINS, "Error loading plugin '%s': %s\n",
			     plugin->name, dlerror());
		return PLUGIN_LOAD_FAILURE;
	}

	return PLUGIN_LOAD_SUCCESS;
}

uint8_t platform_plugin_unload(struct config_plugins * plugin)
{
	if (plugin == NULL)
		return PLUGIN_NOT_ALLOCATED;

	if (plugin->handle == NULL)
		return PLUGIN_NOT_LOADED;

	if (dlclose(plugin->handle) < 0) {
		debug_printf(DEBUG_PLUGINS, "Error unloading plugin '%s': %s\n",
			     plugin->name, dlerror());
		return PLUGIN_UNLOAD_FAILURE;
	}

	plugin->handle = NULL;

	return PLUGIN_UNLOAD_SUCCESS;
}

char *platform_plugin_error(struct config_plugins *plugin)
{
	return dlerror();
}
