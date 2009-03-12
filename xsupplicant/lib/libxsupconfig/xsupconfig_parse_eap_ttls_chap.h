/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls_chap.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_TTLS_CHAP_H__
#define __XSUPCONFIG_PARSE_EAP_TTLS_CHAP_H__

extern parser eap_ttls_chap[];

void *xsupconfig_parse_eap_ttls_chap(void **, uint8_t, xmlNodePtr node);

#endif				// __XSUPCONFIG_PARSE_EAP_TTLS_CHAP_H__
