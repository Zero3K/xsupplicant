/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_plugins.h
 *
 * \author galimorerpg@users.sourceforge.net
 *
 **/

#ifndef __XSUPCONFIG_PARSE_PLUGINS_H__
#define __XSUPCONFIG_PARSE_PLUGINS_H__

extern parser plugins[];

void *xsupconfig_parse_plugins(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_PLUGINS_H__
