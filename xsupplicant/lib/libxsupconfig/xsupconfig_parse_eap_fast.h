/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_fast.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_FAST_H__
#define __XSUPCONFIG_PARSE_EAP_FAST_H__

extern parser eap_fast[];

void *xsupconfig_parse_eap_fast(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_FAST_H__
