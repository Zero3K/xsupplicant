/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * File: xsupconfig_parse_eap.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_PARSE_EAP_H__
#define __XSUPCONFIG_PARSE_EAP_H__

extern parser eap[];

typedef struct {
	char *name;
	int eap_num;
	parser *parsedata;
	void *(*init_method)(void **, xmlNodePtr);
} eap_methods;

void *xsupconfig_parse_eap(void **, xmlNodePtr);
eap_methods *xsupconfig_parse_eap_get_method(eap_methods *, char *);

#endif // __XSUPCONFIG_PARSE_EAP_H__
