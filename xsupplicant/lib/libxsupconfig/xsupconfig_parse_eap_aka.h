/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_aka.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_AKA_H__
#define __XSUPCONFIG_PARSE_EAP_AKA_H__

extern parser eap_aka[];

void *xsupconfig_parse_eap_aka(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_EAP_AKA_H__
