/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_peap.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_PEAP_H__
#define __XSUPCONFIG_PARSE_EAP_PEAP_H__

extern parser eap_peap[];

void *xsupconfig_parse_eap_peap(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_PEAP_H__
