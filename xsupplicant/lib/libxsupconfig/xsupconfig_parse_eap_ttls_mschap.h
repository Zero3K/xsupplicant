/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls_mschap.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_TTLS_MSCHAP_H__
#define __XSUPCONFIG_PARSE_EAP_TTLS_MSCHAP_H__

extern parser eap_ttls_mschap[];

void *xsupconfig_parse_eap_ttls_mschap(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_EAP_TTLS_MSCHAP_H__
