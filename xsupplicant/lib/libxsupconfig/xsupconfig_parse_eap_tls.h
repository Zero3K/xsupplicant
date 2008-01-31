/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * File: xsupconfig_parse_eap_tls.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_TLS_H__
#define __XSUPCONFIG_PARSE_EAP_TLS_H__

extern parser eap_tls[];

void *xsupconfig_parse_eap_tls(void **, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_TLS_H__
