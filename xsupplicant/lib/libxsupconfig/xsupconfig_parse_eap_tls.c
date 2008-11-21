/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_tls.c
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
#include "xsupconfig_parse_eap_tls.h"
#include "xsupconfig_common.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_tls(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-TLS");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-TLS");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-TLS'.\n");
#endif

  meth->method_num = EAP_TYPE_TLS;
  meth->method_data = malloc(sizeof(struct config_eap_tls));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-TLS data."
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_eap_tls));

  return meth->method_data;
}

void *xsupconfig_parse_eap_tls_user_cert(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS User Certificate : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->user_cert = NULL;
	}
	else
	{
		tls->user_cert = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_crl_dir(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS CRL Directory : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->crl_dir = NULL;
	}
	else
	{
		tls->crl_dir = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_user_key_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS User Key File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->user_key = NULL;
	}
	else
	{
		tls->user_key = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_user_key_pass(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS User Key Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->user_key_pass = NULL;
	}
	else
	{
		tls->user_key_pass = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_enc_user_key_pass(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;
  uint16_t size = 0;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS (Encrypted) User Key Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		return tls;
	}

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&tls->user_key_pass, &size) != 0)
  {
	  free(value);
	  tls->user_key_pass = NULL;
	  return tls;
  }

  if ((tls->user_key_pass != NULL) && (strlen(tls->user_key_pass) == 0))
  {
	  FREE(tls->user_key_pass);
  }

  free(value);

  return tls;
}

void *xsupconfig_parse_eap_tls_session_resume(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS Session Resumption : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      tls->session_resume = TRUE;
    }
  else if (result == 0)
    {
      tls->session_resume = FALSE;
    }
  else
    {
      xsupconfig_common_log("Invalid value was passed for 'Session_Resume'!  Will use the "
	     "default value of no.  (Line %ld)\n", xsupconfig_parse_get_line_num());
      tls->session_resume = FALSE;
    }

  FREE(value);

  return tls;
}

void *xsupconfig_parse_eap_tls_chunk_size(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);
  
  tls = (*attr);

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
      tls->chunk_size = atoi(value);
    }

  FREE(value);

  return tls;
}

void *xsupconfig_parse_eap_tls_random_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  tls = (*attr);

#ifdef PARSE_DEBUG
  printf("TLS Random File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->random_file = NULL;
	}
	else
	{
		tls->random_file = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_engine_id(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("TLS Engine ID : %s\n", value);
#endif

  tls = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->sc.engine_id = NULL;
	}
	else
	{
		tls->sc.engine_id = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_trusted_server(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Trusted Server : %s\n", value);
#endif

  tls = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->trusted_server = NULL;
	}
	else
	{
		tls->trusted_server = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_opensc_path(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("OpenSC Path : %s\n", value);
#endif

  tls = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->sc.opensc_so_path = NULL;
	}
	else
	{
		tls->sc.opensc_so_path = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_key_id(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Key ID : %s\n", value);
#endif

  tls = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		tls->sc.key_id = NULL;
	}
	else
	{
		tls->sc.key_id = value;
	}

  return tls;
}

void *xsupconfig_parse_eap_tls_store_type(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *tls = NULL;
  char *value = NULL;
  xmlChar *content = NULL;

  content = xmlNodeGetContent(node);
  value = _strdup(content);
  xmlFree(content);

#ifdef PARSE_DEBUG
  printf("Store Type : %s\n", value);
#endif

  tls = (*attr);

  if ((value == NULL) || (strlen(value) == 0))
  {
	tls->store_type = NULL;
	if (value != NULL) free(value);
  }
  else
  {
	  tls->store_type = value;
  }

  return tls;
}

parser eap_tls[] = {
  {"User_Certificate", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_user_cert},
  {"CRL_Directory", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_crl_dir},
  {"User_Key_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_user_key_file},
  {"User_Key_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_user_key_pass},
  {"Encrypted_User_Key_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_enc_user_key_pass},
  {"Session_Resume", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_session_resume},
  {"Chunk_Size", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_chunk_size},
  {"Random_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_random_file},
  {"Engine_ID", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_engine_id},
  {"OpenSC_Lib_Path", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_opensc_path},
  {"Key_ID", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_key_id},
  {"Trusted_Server", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_trusted_server},
  {"Store_Type", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tls_store_type},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  // Add Certificate_ID and Root_Certificate_ID if they are ever implemented.

  {NULL, NULL, FALSE, 0, NULL}};
