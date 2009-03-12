/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_plugin.h
 *
 * \author galimorerpg@users.sourceforge.net
 *
 **/

#ifndef __XSUPCONFIG_PARSE_PLUGIN_H__
#define __XSUPCONFIG_PARSE_PLUGIN_H__

extern parser plugin[];

void *xsupconfig_parse_plugin(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_PLUGIN_H__
