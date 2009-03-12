/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_connections.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_CONNECTIONS_H__
#define __XSUPCONFIG_PARSE_CONNECTIONS_H__

extern parser connections[];
extern parser user_connections[];

void *xsupconfig_parse_connections(void **, uint8_t, xmlNodePtr);
void *xsupconfig_parse_user_connections(void **, uint8_t, xmlNodePtr);

#endif				//__XSUPCONFIG_PARSE_CONNECTIONS_H__
