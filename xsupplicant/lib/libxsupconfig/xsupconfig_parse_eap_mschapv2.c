/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_mschapv2.c
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
#include "xsupconfig_parse_eap_mschapv2.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_mschapv2(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-MSCHAPv2");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-MSCHAPv2");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-MSCHAPv2'.\n");
#endif

  meth->method_num = EAP_TYPE_MSCHAPV2;
  meth->method_data = malloc(sizeof(struct config_eap_mschapv2));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-MSCHAPv2 data in network "
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_eap_mschapv2));
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_mschapv2_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_mschapv2 *mscv2 = NULL;
  char *value = NULL;

  mscv2 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-MSCHAPv2 is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		mscv2->password = NULL;
	}
	else
	{
		mscv2->password = value;
	}

  return mscv2;
}

void *xsupconfig_parse_eap_mschapv2_enc_password(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_mschapv2 *mscv2 = NULL;
  char *value = NULL;
  uint16_t size = 0;


  mscv2 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Password for EAP-MSCHAPv2 is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return mscv2;
	}

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&mscv2->password, &size) != 0)
  {
	  free(value);
	  mscv2->password = NULL;
	  return mscv2;
  }

  if ((mscv2->password != NULL) && (strlen(mscv2->password) == 0))
  {
	  FREE(mscv2->password);
  }

  free(value);

  return mscv2;
}

void *xsupconfig_parse_eap_mschapv2_nt_pwd_hash(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_mschapv2 *mscv2 = NULL;
  char *value = NULL;

  mscv2 = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("NT Password Hash for EAP-MSCHAPv2 is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		mscv2->nthash = NULL;
	}
	else
	{
		mscv2->nthash = value;
	}

  return mscv2;
}

void *xsupconfig_parse_eap_mschapv2_ias_quirk(void **attr, uint8_t config_type, xmlNodePtr node)
{
  char *value = NULL;
  struct config_eap_mschapv2 *mscv2 = NULL;
  uint8_t result = 0;

  mscv2 = (struct config_eap_mschapv2 *)(*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("IAS Quirk : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);
 
    if (result == 1)
    {
      SET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_IAS_QUIRK);
    }
  else if (result == 0)
    {
      UNSET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_IAS_QUIRK);
    }
  else
    {
		xsupconfig_common_log("Unknown value for <IAS_Quirk> at line %ld.  Using default of NO.",
			xsupconfig_parse_get_line_num());
      UNSET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_IAS_QUIRK);
    }

  FREE(value);

  return mscv2;
}

void *xsupconfig_parse_eap_mschapv2_volatile(void **attr, unsigned char config_type, xmlNodePtr node)
{
  char *value = NULL;
  struct config_eap_mschapv2 *mscv2 = NULL;
  uint8_t result = 0;

  mscv2 = (struct config_eap_mschapv2 *)(*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Volatile : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);
 
    if (result == 1)
    {
      SET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_VOLATILE);
    }
  else if (result == 0)
    {
      UNSET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_VOLATILE);
    }
  else
    {
		xsupconfig_common_log("Unknown value for Volatile at line %ld.  Using default of NO.",
			xsupconfig_parse_get_line_num());
      UNSET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_VOLATILE);
    }

  FREE(value);

  return mscv2;
}

parser eap_mschapv2[] = {
  {"Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_mschapv2_password},
  {"Encrypted_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_mschapv2_enc_password},
  {"NT_Password_Hash", NULL, FALSE, OPTION_ANY_CONFIG,
   &xsupconfig_parse_eap_mschapv2_nt_pwd_hash},
  {"IAS_Quirk", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_mschapv2_ias_quirk},
  {"Volatile", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_mschapv2_volatile},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, 0, NULL}};
