/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls_mschap.c
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
#include "xsupconfig_parse_eap_ttls_mschap.h"
#include "xsupconfig_common.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_ttls_mschap(void **attr, uint8_t config_type, xmlNodePtr node)
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
      printf("Couldn't allocate memory to store MSCHAP configuration for "
	     "EAP-TTLS!  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(ttls->phase2_data, 0x00, sizeof(struct config_pwd_only));

  return ttls->phase2_data;
}

void *xsupconfig_parse_eap_ttls_mschap_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_pwd_only *mschap;
  char *value;

  mschap = (*attr);
  
  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("MSCHAP Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		mschap->password = NULL;
	}
	else
	{
		mschap->password = value;
	}

  return mschap;
}

void *xsupconfig_parse_eap_ttls_enc_mschap_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_pwd_only *mschap = NULL;
  char *value = NULL;
  uint16_t size = 0;

  mschap = (*attr);
  
  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("MSCHAP Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return mschap;
	}

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&mschap->password, &size) != 0)
  {
	  free(value);
	  mschap->password = NULL;
	  return mschap;
  }

  if ((mschap->password != NULL) && (strlen(mschap->password) == 0))
  {
	  FREE(mschap->password);
  }
  
  free(value);

  return mschap;
}

parser eap_ttls_mschap[] = {
  {"Password", NULL, FALSE, OPTION_ANY_CONFIG,
   &xsupconfig_parse_eap_ttls_mschap_password},
  {"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_enc_mschap_password}};

