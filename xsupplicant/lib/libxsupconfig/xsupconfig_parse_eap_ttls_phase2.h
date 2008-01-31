/**
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls_phase2.h
 *
 * \author chris@open1x.org
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_TTLS_PHASE2_H__
#define __XSUPCONFIG_PARSE_EAP_TTLS_PHASE2_H__

extern parser ttls_phase2[];

void *xsupconfig_parse_eap_ttls_phase2(void **, xmlNodePtr);
void *xsupconfig_parse_eap_ttls_phase2_eap(void **, xmlNodePtr);

#endif // __XSUPCONFIG_PARSE_EAP_TTLS_PHASE2_H__
