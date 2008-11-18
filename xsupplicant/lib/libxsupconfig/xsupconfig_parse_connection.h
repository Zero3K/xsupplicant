/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_connection.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_CONNECTION_H__
#define __XSUPCONFIG_PARSE_CONNECTION_H__

extern parser connection[];
extern parser user_connection[];

void *xsupconfig_parse_connection(void **, uint8_t, xmlNodePtr);
void *xsupconfig_parse_user_connection(void **, uint8_t, xmlNodePtr);

#endif //__XSUPCONFIG_PARSE_CONNECTION_H__
