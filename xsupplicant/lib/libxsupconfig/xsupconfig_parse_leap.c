/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_leap.c
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
#include "xsupconfig_parse_leap.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_leap(void **attr, xmlNodePtr node)
{
  struct config_eap_method *meth;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "LEAP");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "LEAP");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'LEAP'.\n");
#endif

  meth->method_num = EAP_TYPE_LEAP;
  meth->method_data = malloc(sizeof(struct config_pwd_only));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store LEAP data.  "
	     "(Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_pwd_only));
  
  return meth->method_data;
}

void *xsupconfig_parse_leap_password(void **attr, xmlNodePtr node)
{
  struct config_pwd_only *leap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  leap = (*attr);

#ifdef PARSE_DEBUG
  printf("Password for LEAP is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		leap->password = NULL;
	}
	else
	{
		leap->password = value;
	}

  return leap;
}

void *xsupconfig_parse_leap_enc_password(void **attr, xmlNodePtr node)
{
  struct config_pwd_only *leap = NULL;
  char *value = NULL;
  uint16_t size = 0;

  value = (char *)xmlNodeGetContent(node);

  leap = (*attr);

#ifdef PARSE_DEBUG
  printf("Password for LEAP is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return leap;
	}

  if (pwcrypt_decrypt((uint8_t *)value, strlen(value), (uint8_t **)&leap->password, &size) != 0)
  {
	  free(value);
	  leap->password = NULL;
	  return leap;
  }

  free(value);

  return leap;
}

parser leap[] = {
  {"Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_leap_password},
  {"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_leap_enc_password},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, 0, NULL}};
