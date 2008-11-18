/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_tls.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_TLS_H__
#define __XSUPCONFIG_PARSE_EAP_TLS_H__

extern parser eap_tls[];

void *xsupconfig_parse_eap_tls(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_TLS_H__
