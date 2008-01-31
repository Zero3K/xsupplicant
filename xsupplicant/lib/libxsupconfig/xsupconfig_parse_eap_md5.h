/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * File: xsupconfig_parse_eap_md5.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_MD5_H__
#define __XSUPCONFIG_PARSE_EAP_MD5_H__

extern parser eap_md5[];

void *xsupconfig_parse_eap_md5(void **, xmlNodePtr);
void *xsupconfig_parse_ttls_eap_md5(void **, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_MD5_H__
