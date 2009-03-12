/**
 * Header for all possible functions that can be provided through a PLUGIN_TYPE_LOGGING
 *	plugin.
 *
 * \note It is not necessary to include this file in your plugin unless you want to.  It's
 *			main purpose is to track different entry points, and document them for other
 *			developers to use.
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_vars.h
 *
 * \author chris@open1x.org
 *
 **/  
#ifndef XSUPPLUGIN_LOGGING_TYPE_H_
#define XSUPPLUGIN_LOGGING_TYPE_H_
void log_hook_full_debug(char *msg);

#endif				// XSUPPLUGIN_LOGGING_TYPE_H_
    
