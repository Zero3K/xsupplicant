/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls_phase2.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_eap.h"
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse_eap_ttls_pap.h"
#include "xsupconfig_parse_eap_ttls_chap.h"
#include "xsupconfig_parse_eap_ttls_mschap.h"
#include "xsupconfig_parse_eap_ttls_mschapv2.h"
#include "xsupconfig_parse_eap_md5.h"
#include "xsupconfig_parse_eap_tnc.h"
#include "xsupconfig_parse_eap_ttls_phase2.h"

typedef struct {
	char *name;
	int type_num;
	parser *parsedata;
	void *(*init_method) (void **, uint8_t, xmlNodePtr);
} ttls_phase2_methods;

eap_methods ttls_eap_meths[] = {
	{"MD5", EAP_TYPE_GTC, eap_md5, xsupconfig_parse_eap_md5},
	{"md5", EAP_TYPE_GTC, eap_md5, xsupconfig_parse_eap_md5},
	{"tnc", EAP_TYPE_TNC, eap_tnc, xsupconfig_parse_eap_tnc},
	{"TNC", EAP_TYPE_TNC, eap_tnc, xsupconfig_parse_eap_tnc},
	{NULL, 0, NULL, NULL}
};

ttls_phase2_methods ttls_p2_meths[] = {
	{"pap", TTLS_PHASE2_PAP, eap_ttls_pap, xsupconfig_parse_eap_ttls_pap},
	{"chap", TTLS_PHASE2_CHAP, eap_ttls_chap,
	 xsupconfig_parse_eap_ttls_chap},
	{"ms-chap", TTLS_PHASE2_MSCHAP, eap_ttls_mschap,
	 xsupconfig_parse_eap_ttls_mschap},
	{"ms-chapv2", TTLS_PHASE2_MSCHAPV2, eap_ttls_mschapv2,
	 xsupconfig_parse_eap_ttls_mschapv2},
	{"EAP", TTLS_PHASE2_EAP, NULL, xsupconfig_parse_eap_ttls_phase2_eap},
	{NULL, 0, NULL, NULL}
};

ttls_phase2_methods *xsupconfig_parse_eap_ttls_phase2_get_method(int methnum)
{
	int i = 0;

	while (ttls_p2_meths[i].name != NULL) {
		if (ttls_p2_meths[i].type_num == methnum)
			break;
		i++;
	}

	return &ttls_p2_meths[i];
}

void *xsupconfig_parse_eap_ttls_phase2(void **attr, uint8_t config_type,
				       xmlNodePtr node)
{
	struct config_eap_ttls *cur = NULL;
	ttls_phase2_methods *meths = NULL;
	struct phase2_data *temp = NULL;

#if PARSE_DEBUG
	printf("Parse EAP-TTLS phase 2..\n");
#endif

	cur = (*attr);

	meths = xsupconfig_parse_eap_ttls_phase2_get_method(cur->phase2_type);

	if (meths->name == NULL) {
		xsupconfig_common_log
		    ("Invalid EAP-TTLS phase 2 type '%d' requested!\n",
		     cur->phase2_type);
		return NULL;
	}

	cur->phase2_type = meths->type_num;

	// Go ahead and parse the EAP data.
	if (meths->init_method != NULL) {
		if (meths->type_num != TTLS_PHASE2_EAP) {
			meths->init_method((void **)&cur, config_type,
					   node->children);
			temp = cur->phase2_data;
			xsupconfig_parse(node->children, meths->parsedata,
					 OPTION_ANY_CONFIG, (void **)&temp);
			if (temp == NULL)
				FREE(cur->phase2_data);
		} else {
			// Process EAP.
			meths->init_method((void **)&cur, config_type,
					   node->children);
		}
	} else {
		xsupconfig_common_log
		    ("No method was available to init method!  (Fix the code!)\n");
	}

	return (*attr);
}

void *xsupconfig_parse_eap_ttls_phase2_eap(void **attr, uint8_t config_type,
					   xmlNodePtr node)
{
	xmlNodePtr t = NULL;
	char *value = NULL;
	struct config_eap_ttls *ttls = NULL;
	eap_methods *meth = NULL;

#ifdef PARSE_DEBUG
	printf("Parse TTLS phase 2..\n");
#endif

	t = xsupconfig_common_find_node(node, "EAP");
	if (t == NULL) {
		xsupconfig_common_log
		    ("EAP-TTLS phase 2 configuration doesn't contain a valid EAP type to use!\n");
		return NULL;
	}
	// Start by finding the EAP type we will be using.
	t = xsupconfig_common_find_node(t->children, "Type");
	if (t == NULL) {
		xsupconfig_common_log
		    ("EAP-TTLS phase 2 configuration data doesn't contain a valid EAP type to use!\n");
		return NULL;
	}

	value = (char *)xmlNodeGetContent(t);
#ifdef PARSE_DEBUG
	printf("EAP Type : %s\n", value);
#endif

	ttls = (*attr);

	meth =
	    xsupconfig_parse_eap_get_method((eap_methods *) & ttls_eap_meths,
					    value);

	xmlFree(value);

	if (meth->name == NULL) {
		xsupconfig_common_log
		    ("Invalid EAP-TTLS phase 2 method '%s' requested!\n",
		     value);
		return NULL;
	}

	if (meth->init_method != NULL) {
		// Go ahead and parse the EAP data.
		meth->init_method(&ttls->phase2_data, config_type, t->children);
		xsupconfig_parse(t, meth->parsedata, config_type,
				 &((struct config_eap_method *)(ttls->
								phase2_data))->
				 method_data);
	} else {
		xsupconfig_common_log("No init method available!\n");
	}

	return (*attr);
}
