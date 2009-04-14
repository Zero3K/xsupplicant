/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_globals.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_GLOBALS_H__
#define __XSUPCONFIG_PARSE_GLOBALS_H__

extern parser globals[];

void *xsupconfig_parse_build_globals(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_GLOBALS_H__
