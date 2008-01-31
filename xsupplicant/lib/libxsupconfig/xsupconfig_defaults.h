/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_defaults.h
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_defaults.h,v 1.3 2007/09/24 06:20:24 galimorerpg Exp $
 * $Date: 2007/09/24 06:20:24 $
 */

#ifndef __XSUPCONFIG_DEFAULTS_H__
#define __XSUPCONFIG_DEFAULTS_H__

#define DEFAULTS_SUCCESS         0
#define DEFAULTS_MALLOC_ERR     -1

void xsupconfig_defaults_set_globals(config_globals *);
int xsupconfig_defaults_create_managed_network(config_managed_networks **);
int xsupconfig_defaults_create_interface(config_interfaces **);
int xsupconfig_defaults_create_trusted_server(config_trusted_server **);
int xsupconfig_defaults_create_connection(config_connection **);
int xsupconfig_defaults_create_profile(config_profiles **);
int xsupconfig_defaults_create_plugin(config_plugins **);

#endif // __XSUPCONFIG_DEFAULTS_H__
