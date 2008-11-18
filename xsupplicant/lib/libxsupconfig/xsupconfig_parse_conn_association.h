/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_conn_association.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_CONN_ASSOCIATION_H__
#define __XSUPCONFIG_PARSE_CONN_ASSOCIATION_H__

extern parser conn_association[];

void *xsupconfig_parse_conn_association(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_CONN_ASSOCIATION_H__
