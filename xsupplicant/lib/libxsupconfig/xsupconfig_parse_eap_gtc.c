/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_gtc.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#include <strings.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_eap_gtc.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_phase2_gtc(void **dest, void **attr, xmlNodePtr node)
{
	struct config_eap_method *meth = NULL;

#ifdef PARSE_DEBUG
	printf("Parse phase 2 GTC!\n");
#endif

	(*dest) = malloc(sizeof(struct config_eap_method));
	if ((*dest) == NULL) {
		printf
		    ("Couldn't allocate memory to store phase 2 EAP-GTC!  (Line %ld)"
		     "\n", xsupconfig_parse_get_line_num());
		exit(2);
	}

	meth = (*dest);
	memset(meth, 0x00, sizeof(struct config_eap_method));

	meth->method_num = EAP_TYPE_GTC;
	meth->method_data = malloc(sizeof(struct config_pwd_only));
	if (meth->method_data == NULL) {
		printf
		    ("Couldn't allocate memory to store phase 2 EAP-GTC data! "
		     "(Line %ld)\n", xsupconfig_parse_get_line_num());
		exit(2);
	}

	memset(meth->method_data, 0x00, sizeof(struct config_pwd_only));

	return meth->method_data;
}

void *xsupconfig_parse_eap_gtc(void **attr, uint8_t config_type,
			       xmlNodePtr node)
{
	struct config_eap_method *meth = NULL;

	meth = (*attr);

	if (meth == NULL) {
		meth = xsupconfig_alloc_method(meth, "EAP-GTC");
		(*attr) = meth;
	} else {
		meth = xsupconfig_alloc_method(meth, "EAP-GTC");
	}

	if (meth == NULL)
		return NULL;

#ifdef PARSE_DEBUG
	printf("Parsing method 'EAP-GTC'.\n");
#endif

	meth->method_num = EAP_TYPE_GTC;
	meth->method_data = malloc(sizeof(struct config_pwd_only));
	if (meth->method_data == NULL) {
		printf
		    ("Couldn't allocate memory to store EAP-GTC data in network!"
		     " (Line %ld)\n", xsupconfig_parse_get_line_num());
		exit(2);
	}

	memset(meth->method_data, 0x00, sizeof(struct config_pwd_only));

	return meth->method_data;
}

void *xsupconfig_parse_eap_gtc_password(void **attr, uint8_t config_type,
					xmlNodePtr node)
{
	struct config_pwd_only *gtc = NULL;
	char *value = NULL;

	gtc = (*attr);

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("Password for EAP-GTC is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0)) {
		xmlFree(value);
		gtc->password = NULL;
	} else {
		gtc->password = _strdup(value);
		xmlFree(value);
	}

	return gtc;
}

void *xsupconfig_parse_eap_gtc_enc_password(void **attr, uint8_t config_type,
					    xmlNodePtr node)
{
	struct config_pwd_only *gtc = NULL;
	char *value = NULL;
	uint16_t size = 0;

	gtc = (*attr);

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("Password for EAP-GTC is '%s'!\n", value);
#endif

	if (pwcrypt_decrypt
	    (config_type, (uint8_t *) value, strlen(value),
	     (uint8_t **) & gtc->password, &size) != 0) {
		xmlFree(value);
		gtc->password = NULL;
		return gtc;
	}

	if ((gtc->password != NULL) && (strlen(gtc->password) == 0)) {
		FREE(gtc->password);
	}

	xmlFree(value);

	return gtc;
}

parser eap_gtc[] = {
	{"Password", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_eap_gtc_password}
	,
	{"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_eap_gtc_enc_password}
	,
	{"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing}
	,

	{NULL, NULL, FALSE, 0, NULL}
};
