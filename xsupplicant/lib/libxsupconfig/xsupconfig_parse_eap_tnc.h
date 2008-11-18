/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_tnc.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_TNC_H__
#define __XSUPCONFIG_PARSE_EAP_TNC_H__

extern parser eap_tnc[];

void *xsupconfig_parse_eap_tnc(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_TNC_H__
