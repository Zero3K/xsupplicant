/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_interface.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_INTERFACE_H__
#define __XSUPCONFIG_PARSE_INTERFACE_H__

extern parser interf[];

void *xsupconfig_parse_interface(void **, uint8_t, xmlNodePtr);

#endif // __XSUPCONFIG_PARSE_INTERFACE_H__
