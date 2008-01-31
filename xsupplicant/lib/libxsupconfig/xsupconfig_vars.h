/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_vars.h
 *
 * \author chris@open1x.org
 *
 **/
#ifndef __XSUPCONFIG_VARS_H__
#define __XSUPCONFIG_VARS_H__

struct config_globals         *conf_globals;
struct xsup_devices           *conf_devices;
struct config_profiles        *conf_profiles;
struct config_plugins         *conf_plugins;
struct config_connection      *conf_connections;
struct config_trusted_servers *conf_trusted_servers;
struct config_managed_networks *conf_managed_networks;
char                          *config_fname;

#endif // __XSUPCONFIG_VARS_H__



