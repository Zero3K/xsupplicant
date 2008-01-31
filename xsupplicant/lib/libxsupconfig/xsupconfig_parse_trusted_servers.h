/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_trusted_servers.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_TRUSTED_SERVERS_H__
#define __XSUPCONFIG_PARSE_TRUSTED_SERVERS_H__

extern parser trusted_servers[];

void *xsupconfig_parse_trusted_servers(void **, xmlNodePtr);

#endif // __XSUPCONFIG_PARSE_TRUSTED_SERVERS_H__
