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

void *xsupconfig_parse_eap_psk(void **attr, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-PSK");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-PSK");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-PSK'.\n");
#endif

  meth->method_num = EAP_TYPE_PSK;
  meth->method_data = malloc(sizeof(struct config_pwd_only));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-PSK!"
	     " (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_pwd_only));
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_psk_password(void **attr, xmlNodePtr node)
{
  struct config_pwd_only *psk = NULL;
  char *value = NULL;

  psk = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-PSK is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		psk->password = NULL;
	}
	else
	{
		psk->password = value;
	}

  return psk;
}

void *xsupconfig_parse_eap_psk_enc_password(void **attr, xmlNodePtr node)
{
  struct config_pwd_only *psk = NULL;
  char *value = NULL;
  uint16_t size = 0;

  psk = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-PSK is '%s'!\n", value);
#endif

  	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return psk;
	}

  if (pwcrypt_decrypt((uint8_t *)value, strlen(value), (uint8_t **)&psk->password, &size) != 0)
  {
	  free(value);
	  psk->password = NULL;
	  return psk;
  }

  if ((psk->password != NULL) && (strlen(psk->password) == 0))
  {
	  FREE(psk->password);
  }

  free(value);

  return psk;
}

parser eap_psk[] = {
  {"Password", NULL, FALSE, &xsupconfig_parse_eap_psk_password},
  {"Encrypted_Password", NULL, FALSE, &xsupconfig_parse_eap_psk_enc_password},
  {"Type", NULL, FALSE, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, NULL}};
