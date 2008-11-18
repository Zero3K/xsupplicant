/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls_mschapv2.c
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
#include "xsupconfig_structs.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_eap_ttls_mschapv2.h"
#include "xsupconfig_common.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_ttls_mschapv2(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;

  ttls = (*attr);

  if (ttls == NULL)
    {
      xsupconfig_common_log("Invalid TTLS phase 1!  You cannot have TTLS phase 2 data without"
	     " having a phase 1!  (This is likely a bug in the parser code!)"
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  ttls->phase2_data = malloc(sizeof(struct config_pwd_only));
  if (ttls->phase2_data == NULL)
    {
      printf("Couldn't allocate memory to store MSCHAPv2 configuration for "
	     "EAP-TTLS!  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(ttls->phase2_data, 0x00, sizeof(struct config_pwd_only));

  return ttls->phase2_data;
}

void *xsupconfig_parse_eap_ttls_mschapv2_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_pwd_only *mschapv2;
  char *value;

  mschapv2 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("MSCHAPv2 Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		mschapv2->password = NULL;
	}
	else
	{
		mschapv2->password = value;
	}

  return mschapv2;
}

void *xsupconfig_parse_eap_ttls_enc_mschapv2_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_pwd_only *mschapv2 = NULL;
  char *value   = NULL;
  uint16_t size = 0;

  mschapv2 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("MSCHAPv2 Password : %s\n", value);
#endif

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&mschapv2->password, &size) != 0)
  {
	  free(value);
	  mschapv2->password = NULL;
	  return mschapv2;
  }

  if ((mschapv2->password != NULL) && (strlen(mschapv2->password) == 0))
  {
	  FREE(mschapv2->password);
  }

  free(value);

  return mschapv2;
}

parser eap_ttls_mschapv2[] = {
  {"Password", NULL, FALSE, OPTION_ANY_CONFIG,
   &xsupconfig_parse_eap_ttls_mschapv2_password},
  {"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_enc_mschapv2_password}};
