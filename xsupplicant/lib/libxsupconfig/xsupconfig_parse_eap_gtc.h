/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * File: xsupconfig_parse_eap_gtc.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_GTC_H__
#define __XSUPCONFIG_PARSE_EAP_GTC_H__

extern parser eap_gtc[];

void *xsupconfig_parse_eap_gtc(void **, xmlNodePtr);
void *xsupconfig_parse_phase2_gtc(void **, void **, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_GTC_H__
