/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file plugin_handler.h
 *
 * \author seventhguardian@gmail.com
 **/
#ifndef _PLUGIN_HANDLER_H_
#define _PLUGIN_HANDLER_H_
#include "libxsupconfig/xsupconfig_vars.h"

#ifdef WIN32
#include "../stdintwin.h"
#endif // WIN32

#ifndef WIN32
#include <stdint.h>
#endif // WIN32

void *platform_plugin_entrypoint(struct config_plugins *plugin, char *function_name);
uint8_t platform_plugin_load(struct config_plugins *plugin);
uint8_t platform_plugin_unload(struct config_plugins *plugin);
char *platform_plugin_error(struct config_plugins *plugin);

#endif // _PLUGIN_HANDLER_H_

