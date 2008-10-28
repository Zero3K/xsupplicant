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

struct config_globals         *conf_globals;			///< System level : Global configuration variables.
struct xsup_devices           *conf_devices;			///< System level : Devices that have been seen in this machine.
struct config_profiles        *conf_profiles;			///< System level : Profiles that can be bound to system level connections.
struct config_profiles		  *conf_user_profiles;		///< User level : Profiles that can be bound to user level connections.
struct config_plugins         *conf_plugins;			///< System level : Information on engine level plugins.
struct config_connection      *conf_connections;		///< System level : Connections defined by the administrator.
struct config_connection	  *conf_user_connections;	///< User level : Connections defined by the current user.
struct config_trusted_servers *conf_trusted_servers;	///< System level : Trusted servers defined by the administrator.
struct config_trusted_servers *conf_user_trusted_servers; ///< User level : Trusted servers defined by the current user.

char                          *config_fname;

#endif // __XSUPCONFIG_VARS_H__



