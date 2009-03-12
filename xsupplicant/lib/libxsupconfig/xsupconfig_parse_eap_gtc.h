/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_gtc.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_GTC_H__
#define __XSUPCONFIG_PARSE_EAP_GTC_H__

extern parser eap_gtc[];

void *xsupconfig_parse_eap_gtc(void **, uint8_t, xmlNodePtr);
void *xsupconfig_parse_phase2_gtc(void **, void **, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_EAP_GTC_H__
