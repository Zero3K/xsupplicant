/**
 * \file plugins.h
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author galimorerpg@users.sourceforge.net
 *
 **/

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

#define LOG_HOOK_FULL_DEBUG 1

int plugin_hook_trouble_ticket_dump_file(char *path);
int plugin_hook_full_debug_log(char *msg);
int registered_debug_loggers();
uint8_t load_plugins();
uint8_t unload_plugins();
void log_hook_full_debug(char *msg);

#endif // _XSUP_PLUGINS_H
