/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_md5.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_eap_md5.c,v 1.4 2007/10/20 08:10:13 galimorerpg Exp $
 * $Date: 2007/10/20 08:10:13 $
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
#include "xsupconfig_parse_eap_md5.h"
#include "pwd_crypt.h"

#define TTLS_PHASE2_EAP  5

void *xsupconfig_parse_ttls_eap_md5(void **attr, xmlNodePtr node)
{
  struct config_eap_ttls *ttls = NULL;
  struct config_eap_method *eap, *cur = NULL;

  ttls = (*attr);
  
  if (ttls == NULL)
    {
      xsupconfig_common_log("Invalid TTLS phase 1!  You cannot have phase 2 data without "
	     "having a phase 1!  (This is likely a bug in the parser code!)  Line %ld.\n",
		 xsupconfig_parse_get_line_num());
      exit(2);
    }

  if (ttls->phase2_data == NULL)
  {
      ttls->phase2_data = malloc(sizeof(struct config_eap_method));
      if (ttls->phase2_data == NULL)
	{
	  printf("Couldn't allocate memory to store TTLS-EAP-MD5 data! "
		 "(Line %ld)\n", xsupconfig_parse_get_line_num());
	  exit(2);
	}

	  memset(ttls->phase2_data, 0x00, sizeof(struct config_eap_method));

      eap = ttls->phase2_data;
  }
  else
  {
	cur = ttls->phase2_data;
	while (cur->next != NULL) cur = cur->next;

	cur->next = malloc(sizeof(struct config_eap_method));
	if (cur->next == NULL)
	{
		printf("Couldn't allocate memory to store TTLS-EAP-MD5 data! "
			"(Line %ld)\n", xsupconfig_parse_get_line_num());
		exit(2);
	}

	memset(cur->next, 0x00, sizeof(struct config_eap_method));

	eap = cur->next;
  }

  eap->method_num = EAP_TYPE_MD5;
  eap->method_data = malloc(sizeof(struct config_pwd_only));
  if (eap->method_data == NULL)
    {
      printf("Couldn't allocate memory to store TTLS-EAP-MD5 data!  (Line %ld)"
	     "\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(eap->method_data, 0x00, sizeof(struct config_pwd_only));

  return eap->method_data;
}

void *xsupconfig_parse_eap_md5(void **attr, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-MD5");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-MD5");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-MD5'.\n");
#endif

  meth->method_num = EAP_TYPE_MD5;
  meth->method_data = malloc(sizeof(struct config_pwd_only));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-MD5!"
	     " (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_pwd_only));
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_md5_password(void **attr, xmlNodePtr node)
{
  struct config_pwd_only *md5 = NULL;
  char *value = NULL;

  md5 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-MD5 is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		md5->password = NULL;
	}
	else
	{
		md5->password = value;
	}

  return md5;
}

void *xsupconfig_parse_eap_md5_enc_password(void **attr, xmlNodePtr node)
{
  struct config_pwd_only *md5 = NULL;
  char *value = NULL;
  uint16_t size = 0;

  md5 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-MD5 is '%s'!\n", value);
#endif

  	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return md5;
	}

  if (pwcrypt_decrypt((uint8_t *)value, strlen(value), (uint8_t **)&md5->password, &size) != 0)
  {
	  free(value);
	  md5->password = NULL;
	  return md5;
  }

  if ((md5->password != NULL) && (strlen(md5->password) == 0))
  {
	  FREE(md5->password);
  }

  free(value);

  return md5;
}

parser eap_md5[] = {
  {"Password", NULL, FALSE, &xsupconfig_parse_eap_md5_password},
  {"Encrypted_Password", NULL, FALSE, &xsupconfig_parse_eap_md5_enc_password},
  {"Type", NULL, FALSE, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, NULL}};
