/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_peap_phase2.c
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
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse_eap.h"

#include "xsupconfig_parse_eap_gtc.h"
#include "xsupconfig_parse_eap_mschapv2.h"
#include "xsupconfig_parse_eap_tnc.h"

eap_methods peap_p2_meths[] = {
	{ "GTC", EAP_TYPE_GTC, eap_gtc, xsupconfig_parse_eap_gtc},
	{ "gtc", EAP_TYPE_GTC, eap_gtc, xsupconfig_parse_eap_gtc},
	{ "MSCHAPV2", EAP_TYPE_MSCHAPV2, eap_mschapv2, xsupconfig_parse_eap_mschapv2},
	{ "MSCHAPv2", EAP_TYPE_MSCHAPV2, eap_mschapv2, xsupconfig_parse_eap_mschapv2},
	{ "mschapv2", EAP_TYPE_MSCHAPV2, eap_mschapv2, xsupconfig_parse_eap_mschapv2},
	{ "tnc", EAP_TYPE_TNC, eap_tnc, xsupconfig_parse_eap_tnc},
	{ "TNC", EAP_TYPE_TNC, eap_tnc, xsupconfig_parse_eap_tnc},

	{NULL, 0, NULL, NULL}};

void *xsupconfig_parse_eap_peap_phase2_eap(void **attr, uint8_t config_type, xmlNodePtr node)
{
	xmlNodePtr t = NULL;
	char *value = NULL;
	struct config_eap_peap *peap = NULL;
	eap_methods *meth = NULL;

#ifdef PARSE_DEBUG
  printf("Parse PEAP phase 2..\n");
#endif

  // Start by finding the EAP type we will be using.
  t = xsupconfig_common_find_node(node->children, "Type");
  if (t == NULL)
  {
	  xsupconfig_common_log("PEAP phase 2 configuration data doesn't contain a valid EAP type to use!\n");
	  return NULL;
  }

  value = (char *)xmlNodeGetContent(t);
#ifdef PARSE_DEBUG
  printf("EAP Type : %s\n", value);
#endif

  peap = (*attr);

  meth = xsupconfig_parse_eap_get_method((eap_methods *)&peap_p2_meths, value);
  xmlFree(value);

  if (meth->name == NULL)
  {
	  xsupconfig_common_log("Invalid phase 2 EAP method '%s' requested!\n", value);
	  return NULL;
  }

  if (meth->init_method != NULL)
  {
	// Go ahead and parse the EAP data.
	meth->init_method((void **)&peap->phase2, config_type, node->children);

	xsupconfig_parse(node->children, meth->parsedata, config_type, &peap->phase2->method_data);
  }
  else
  {
	  xsupconfig_common_log("No init method available!  (This is a parser error!)\n");
  }

  return (*attr);
}

parser peap_phase2[] = {
  {"EAP", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_phase2_eap},

  {NULL, NULL, FALSE, 0, NULL}};
