/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap.c
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

#include "xsupconfig_parse_eap_ttls.h"
#include "xsupconfig_parse_eap_aka.h"
#include "xsupconfig_parse_eap_fast.h"
#include "xsupconfig_parse_eap_gtc.h"
#include "xsupconfig_parse_eap_md5.h"
#include "xsupconfig_parse_eap_mschapv2.h"
#include "xsupconfig_parse_eap_otp.h"
#include "xsupconfig_parse_eap_peap.h"
#include "xsupconfig_parse_eap_sim.h"
#include "xsupconfig_parse_eap_tls.h"
#include "xsupconfig_parse_eap_tnc.h"
#include "xsupconfig_parse_leap.h"
#include "xsupconfig_parse_eap_psk.h"

eap_methods meths[] = {
	{ "TTLS", EAP_TYPE_TTLS, eap_ttls, xsupconfig_parse_eap_ttls},
	{ "ttls", EAP_TYPE_TTLS, eap_ttls, xsupconfig_parse_eap_ttls},
	{ "AKA", EAP_TYPE_AKA, eap_aka, xsupconfig_parse_eap_aka},
	{ "aka", EAP_TYPE_AKA, eap_aka, xsupconfig_parse_eap_aka},
	{ "FAST", EAP_TYPE_FAST, eap_fast, xsupconfig_parse_eap_fast},
	{ "fast", EAP_TYPE_FAST, eap_fast, xsupconfig_parse_eap_fast},
	{ "GTC", EAP_TYPE_GTC, eap_gtc, xsupconfig_parse_eap_gtc},
	{ "gtc", EAP_TYPE_GTC, eap_gtc, xsupconfig_parse_eap_gtc},
	{ "MD5", EAP_TYPE_MD5, eap_md5, xsupconfig_parse_eap_md5},
	{ "md5", EAP_TYPE_MD5, eap_md5, xsupconfig_parse_eap_md5},
	{ "MSCHAPV2", EAP_TYPE_MSCHAPV2, eap_mschapv2, xsupconfig_parse_eap_mschapv2},
	{ "MSCHAPv2", EAP_TYPE_MSCHAPV2, eap_mschapv2, xsupconfig_parse_eap_mschapv2},
	{ "mschapv2", EAP_TYPE_MSCHAPV2, eap_mschapv2, xsupconfig_parse_eap_mschapv2},
	{ "OTP", EAP_TYPE_OTP, eap_otp, xsupconfig_parse_eap_otp},
	{ "otp", EAP_TYPE_OTP, eap_otp, xsupconfig_parse_eap_otp},
	{ "PEAP", EAP_TYPE_PEAP, eap_peap, xsupconfig_parse_eap_peap},
	{ "peap", EAP_TYPE_PEAP, eap_peap, xsupconfig_parse_eap_peap},
	{ "SIM", EAP_TYPE_SIM, eap_sim, xsupconfig_parse_eap_sim},
	{ "sim", EAP_TYPE_SIM, eap_sim, xsupconfig_parse_eap_sim},
	{ "TLS", EAP_TYPE_TLS, eap_tls, xsupconfig_parse_eap_tls},
	{ "tls", EAP_TYPE_TLS, eap_tls, xsupconfig_parse_eap_tls},
	{ "LEAP", EAP_TYPE_LEAP, leap, xsupconfig_parse_leap},
	{ "leap", EAP_TYPE_LEAP, leap, xsupconfig_parse_leap},
	{ "PSK", EAP_TYPE_PSK, eap_psk, xsupconfig_parse_eap_psk},
	{ "psk", EAP_TYPE_PSK, eap_psk, xsupconfig_parse_eap_psk},

	{NULL, 0, NULL, NULL}};

eap_methods *xsupconfig_parse_eap_get_method(eap_methods *eaplist, char *method_name)
{
	int i = 0;

	while (eaplist[i].name != NULL)
	{
		if (strcmp(eaplist[i].name, method_name) == 0) break;
		i++;
	}

	return &eaplist[i];
}

void *xsupconfig_parse_eap(void **attr, xmlNodePtr node)
{
	xmlNodePtr t = NULL;
	char *value = NULL;
	struct config_profiles *cur = NULL;
	eap_methods *meth = NULL;

#ifdef PARSE_DEBUG
  printf("Parse EAP..\n");
#endif

  // Start by finding the EAP type we will be using.
  t = xsupconfig_common_find_node(node->children, "Type");
  if (t == NULL)
  {
	  xsupconfig_common_log("EAP configuration data starting at line %ld doesn't contain a valid EAP type to use!\n",
		  xsupconfig_parse_get_line_num());
	  return NULL;
  }

  value = (char *)xmlNodeGetContent(t);
#ifdef PARSE_DEBUG
  printf("EAP Type : %s\n", value);
#endif

  cur = (*attr);

  meth = xsupconfig_parse_eap_get_method((eap_methods *)&meths, value);

  if (meth->name == NULL)
  {
	  xsupconfig_common_log("Invalid EAP method '%s' requested at line %ld.\n", value,
		  xsupconfig_parse_get_line_num());
	  free(value);
	  return NULL;
  }

  free(value);

  // Go ahead and parse the EAP data.
  meth->init_method((void **)&cur->method, node->children);
  xsupconfig_parse(node->children, meth->parsedata, &cur->method->method_data);

  return (*attr);
}
