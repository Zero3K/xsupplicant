/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_mschapv2.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_MSCHAPV2_H__
#define __XSUPCONFIG_PARSE_EAP_MSCHAPV2_H__

extern parser eap_mschapv2[];

void *xsupconfig_parse_eap_mschapv2(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_MSCHAPV2_H__
