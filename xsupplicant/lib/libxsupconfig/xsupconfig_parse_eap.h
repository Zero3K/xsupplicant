/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_H__
#define __XSUPCONFIG_PARSE_EAP_H__

extern parser eap[];

typedef struct {
	char *name;
	int eap_num;
	parser *parsedata;
	void *(*init_method) (void **, uint8_t, xmlNodePtr);
} eap_methods;

void *xsupconfig_parse_eap(void **, uint8_t, xmlNodePtr);
eap_methods *xsupconfig_parse_eap_get_method(eap_methods *, char *);

#endif				// __XSUPCONFIG_PARSE_EAP_H__
