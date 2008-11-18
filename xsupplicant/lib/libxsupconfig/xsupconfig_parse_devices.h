/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_devices.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_DEVICES_H__
#define __XSUPCONFIG_PARSE_DEVICES_H__

extern parser devices[];

void *xsupconfig_parse_devices(void **, uint8_t, xmlNodePtr);

#endif // __XSUPCONFIG_PARSE_DEVICES_H__
