/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_aka.c
 *
 * \authors chris@open1x.org
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
#include "xsupconfig_parse_eap_aka.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_aka(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-AKA");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-AKA");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-AKA'.\n");
#endif

  meth->method_num = EAP_TYPE_AKA;
  meth->method_data = malloc(sizeof(struct config_eap_aka));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-AKA!"
	     " (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_eap_aka));
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_aka_username(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_aka *aka = NULL;
  char *value = NULL;

  aka = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Username for EAP-AKA is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		aka->username = NULL;
	}
	else
	{
		aka->username = value;
	}

  return aka;
}

void *xsupconfig_parse_eap_aka_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_aka *aka = NULL;
  char *value = NULL;

  aka = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-AKA is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		aka->password = NULL;
	}
	else
	{
		aka->password = value;
	}

  return aka;
}

void *xsupconfig_parse_eap_aka_enc_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_aka *aka = NULL;
  char *value = NULL;
  uint16_t size = 0;

  aka = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-AKA is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return aka;
	}

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&aka->password, &size) != 0)
  {
	  free(value);
	  aka->password = NULL;
	  return aka;
  }

  if ((aka->password != NULL) && (strlen(aka->password) == 0))
  {
	  FREE(aka->password);
  }

  free(value);

  return aka;
}

void *xsupconfig_parse_eap_aka_reader(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_aka *aka = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  aka = (*attr);

#ifdef PARSE_DEBUG
  printf("Reader for EAP-AKA  is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		aka->reader = NULL;
	}
	else
	{
		aka->reader = value;
	}

  return aka;
}

void *xsupconfig_parse_eap_aka_auto_realm(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_aka *aka = NULL;
  uint8_t result = 0;
  char *value = NULL;

  aka = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Auto Realm for EAP-AKA is '%s'!\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value for 'Auto_Realm', (Line %ld) using default of "
	     "no.\n", xsupconfig_parse_get_line_num());
      aka->auto_realm = FALSE;
    }
  else
    {
      aka->auto_realm = result;
    }

  FREE(value);

  return aka;
}

parser eap_aka[] = {
  {"Username", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_aka_username},
  {"Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_aka_password},
  {"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_aka_enc_password},
  {"Auto_Realm", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_aka_auto_realm},
  {"Reader", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_aka_reader},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, 0, NULL}};
