/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_ttls.c
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
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_eap_ttls.h"
#include "xsupconfig_parse_eap_ttls_phase2.h"
#include "xsupconfig_common.h"
#include "pwd_crypt.h"

multichoice inner_method[] = {
  { 1, "pap"},
  { 1, "PAP"},
  { 2, "chap"},
  { 2, "CHAP"},
  { 3, "mschap"},
  { 3, "MSCHAP"},
  { 4, "mschapv2"},
  { 4, "MSCHAPV2"},
  { 4, "MSCHAPv2"},
  { 5, "eap"},
  { 5, "EAP"},
  { -1, NULL}};

void *xsupconfig_parse_eap_ttls(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-TTLS");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-TTLS");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-TTLS'.\n");
#endif

  meth->method_num = EAP_TYPE_TTLS;
  meth->method_data = malloc(sizeof(struct config_eap_ttls));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-TTLS data!"
	     "  (Line %ld)\n",
	     xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_eap_ttls));

  ((struct config_eap_ttls *)(meth->method_data))->validate_cert = TRUE;
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_ttls_user_cert(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS User Certificate : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->user_cert = NULL;
	}
	else
	{
		ttls->user_cert = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_crl_dir(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS CRL Directory : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->crl_dir = NULL;
	}
	else
	{
		ttls->crl_dir = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_user_key_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS User Key File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->user_key = NULL;
	}
	else
	{
		ttls->user_key = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_user_key_pass(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS User Key Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->user_key_pass = NULL;
	}
	else
	{
		ttls->user_key_pass = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_enc_user_key_pass(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls = NULL;
  char *value = NULL;
  uint16_t size = 0;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS User Key Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return ttls;
	}

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&ttls->user_key_pass, &size) != 0)
  {
	  free(value);
	  ttls->user_key_pass = NULL;
	  return ttls;
  }

  free(value);

  return ttls;
}

void *xsupconfig_parse_eap_ttls_cnexact(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  uint8_t result;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Exact Common Name Check : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Exact_Common_Name'!  Will use the "
             "default value of no.  (Line %ld)\n", xsupconfig_parse_get_line_num());
      ttls->cnexact = FALSE;
    }
  else
    {
      ttls->cnexact = result;
    }

  FREE(value);

  return ttls;
}

void *xsupconfig_parse_eap_ttls_session_resume(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  uint8_t result;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Session Resumption : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Session_Resume'!  Will use the "
	     "default value of no.  (Line %ld)\n", xsupconfig_parse_get_line_num());
      ttls->session_resume = FALSE;
    }
  else
    {
      ttls->session_resume = result;
    }
  
  FREE(value);
  return ttls;
}

void *xsupconfig_parse_eap_ttls_validate_cert(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls = NULL;
  uint8_t result = 0;
  char *value = 0;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Validate Certificate : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Validate_Certificate'!  Will use the "
	     "default value of yes.  (Line %ld)\n", xsupconfig_parse_get_line_num());
	  ttls->validate_cert = TRUE;
    }
  else
    {
		ttls->validate_cert = result;
    }
  
  FREE(value);
  return ttls;
}

void *xsupconfig_parse_eap_ttls_chunk_size(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;
  
  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Chunk Size : %s\n", value);
#endif

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to 'Chunk_Size' is not a number!  Using "
	     "default!  (Line %ld)\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      ttls->chunk_size = atoi(value);
    }

  FREE(value);

  return ttls;
}

void *xsupconfig_parse_eap_ttls_cncheck(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Common Name : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->cncheck = NULL;
	}
	else
	{
		ttls->cncheck = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_random_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Random File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->random_file = NULL;
	}
	else
	{
		ttls->random_file = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_inner_id(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Inner ID : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->inner_id = NULL;
	}
	else
	{
		ttls->inner_id = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_trusted_server(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Trusted Server : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		ttls->trusted_server = NULL;
	}
	else
	{
		ttls->trusted_server = value;
	}

  return ttls;
}

void *xsupconfig_parse_eap_ttls_inner_method(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  int8_t result;
  char *value;

  ttls = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TTLS Inner Method : %s\n", value);
#endif

  result = xsupconfig_common_select_from_list(inner_method, value);

  if (result < 0)
    {
      xsupconfig_common_log("Invalid TTLS inner method '%s'.  Defaulting to PAP.  (Line %ld)"
	     "\n", (char *)value, xsupconfig_parse_get_line_num());
      ttls->phase2_type = 1;
    }
  else
    {
      ttls->phase2_type = result;
    }

  FREE(value);

  return ttls;
}

parser eap_ttls[] = {
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},   // So we don't complain about the option we already consumed.
  {"User_Certificate", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_user_cert},
  {"CRL_Directory", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_crl_dir},
  {"User_Key_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_user_key_file},
  {"User_Key_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_user_key_pass},
  {"Encrypted_User_Key_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_enc_user_key_pass},
  {"Session_Resume", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_session_resume},
  {"Chunk_Size", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_chunk_size},
  {"Random_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_random_file},
  {"Inner_Method", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_inner_method},
  {"Common_Name", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_cncheck},
  {"Exact_Common_Name", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_cnexact},
  {"Inner_ID", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_inner_id},
  {"Trusted_Server", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_trusted_server},
  {"Validate_Certificate", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_validate_cert},
  {"Phase2", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_ttls_phase2},

  {NULL, NULL, FALSE, 0, NULL}};
