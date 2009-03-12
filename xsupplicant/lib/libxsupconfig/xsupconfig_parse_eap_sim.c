/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_sim.c
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
#include "xsupconfig_parse_eap_sim.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_sim(void **attr, uint8_t config_type,
			       xmlNodePtr node)
{
	struct config_eap_method *meth = NULL;

	meth = (*attr);

	if (meth == NULL) {
		meth = xsupconfig_alloc_method(meth, "EAP-SIM");
		(*attr) = meth;
	} else {
		meth = xsupconfig_alloc_method(meth, "EAP-SIM");
	}

	if (meth == NULL)
		return NULL;

#ifdef PARSE_DEBUG
	printf("Parsing method 'EAP-SIM'.\n");
#endif

	meth->method_num = EAP_TYPE_SIM;
	meth->method_data = malloc(sizeof(struct config_eap_sim));
	if (meth->method_data == NULL) {
		printf("Couldn't allocate memory to store EAP-SIM data."
		       "  (Line %ld)\n", xsupconfig_parse_get_line_num());
		exit(2);
	}

	memset(meth->method_data, 0x00, sizeof(struct config_eap_sim));

	return meth->method_data;
}

void *xsupconfig_parse_eap_sim_password(void **attr, uint8_t config_type,
					xmlNodePtr node)
{
	struct config_eap_sim *sim = NULL;
	char *value = NULL;

	value = (char *)xmlNodeGetContent(node);

	sim = (*attr);

#ifdef PARSE_DEBUG
	printf("Password for EAP-SIM is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0)) {
		xmlFree(value);
		sim->password = NULL;
	} else {
		sim->password = _strdup(value);
		xmlFree(value);
	}

	return sim;
}

void *xsupconfig_parse_eap_sim_enc_password(void **attr, uint8_t config_type,
					    xmlNodePtr node)
{
	struct config_eap_sim *sim = NULL;
	char *value = NULL;
	uint16_t size = 0;

	value = (char *)xmlNodeGetContent(node);

	sim = (*attr);

#ifdef PARSE_DEBUG
	printf("Password (Encrypted) for EAP-SIM is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0)) {
		xmlFree(value);
		return sim;
	}

	if (pwcrypt_decrypt
	    (config_type, (uint8_t *) value, strlen(value),
	     (uint8_t **) & sim->password, &size) != 0) {
		xmlFree(value);
		sim->password = NULL;
		return sim;
	}

	if ((sim->password != NULL) && (strlen(sim->password) == 0)) {
		FREE(sim->password);
	}

	xmlFree(value);

	return sim;
}

void *xsupconfig_parse_eap_sim_reader(void **attr, uint8_t config_type,
				      xmlNodePtr node)
{
	struct config_eap_sim *sim = NULL;
	char *value = NULL;

	value = (char *)xmlNodeGetContent(node);

	sim = (*attr);

#ifdef PARSE_DEBUG
	printf("Reader for EAP-SIM  is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0)) {
		xmlFree(value);
		sim->reader = NULL;
	} else {
		sim->reader = _strdup(value);
		xmlFree(value);
	}

	return sim;
}

void *xsupconfig_parse_eap_sim_auto_realm(void **attr, uint8_t config_type,
					  xmlNodePtr node)
{
	struct config_eap_sim *sim = NULL;
	uint8_t result = 0;
	char *value = NULL;

	value = (char *)xmlNodeGetContent(node);

	sim = (*attr);

#ifdef PARSE_DEBUG
	printf("Auto Realm for EAP-SIM is '%s'!\n", value);
#endif

	result = xsupconfig_common_yesno(value);

	if (result == 1) {
		sim->auto_realm = TRUE;
	} else if (result == 0) {
		sim->auto_realm = FALSE;
	} else {
		xsupconfig_common_log
		    ("Invalid value for 'Auto_Realm', using default of no.  (Line %ld)"
		     "\n", xsupconfig_parse_get_line_num());
		sim->auto_realm = FALSE;
	}

	xmlFree(value);

	return sim;
}

parser eap_sim[] = {
	{"Password", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_eap_sim_password}
	,
	{"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_eap_sim_enc_password}
	,
	{"Auto_Realm", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_eap_sim_auto_realm}
	,
	{"Reader", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_eap_sim_reader}
	,
	{"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing}
	,

	{NULL, NULL, FALSE, 0, NULL}
};
