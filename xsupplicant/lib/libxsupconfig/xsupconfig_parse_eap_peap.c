/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_peap.c
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
#include "xsupconfig_parse_eap_peap.h"
#include "xsupconfig_parse_eap_peap_phase2.h"
#include "xsupconfig_parse_eap_mschapv2.h"
#include "xsupconfig_parse_eap_gtc.h"
#include "xsupconfig_common.h"
#include "pwd_crypt.h"

void *xsupconfig_parse_eap_peap(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-PEAP");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-PEAP");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-PEAP'.\n");
#endif

  meth->method_num = EAP_TYPE_PEAP;
  meth->method_data = malloc(sizeof(struct config_eap_peap));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-PEAP data."
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_eap_peap));

  ((struct config_eap_peap *)(meth->method_data))->force_peap_version = 0xff;
  SET_FLAG(((struct config_eap_peap *)(meth->method_data))->flags, FLAGS_PEAP_VALIDATE_SERVER_CERT);
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_peap_user_cert(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP User Certificate : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->user_cert = NULL;
	}
	else
	{
		peap->user_cert = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_crl_dir(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP CRL Directory : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->crl_dir = NULL;
	}
	else
	{
		peap->crl_dir = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_user_key_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP User Key File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->user_key = NULL;
	}
	else
	{
		peap->user_key = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_user_key_pass(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP User Key Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->user_key_pass = NULL;
	}
	else
	{
		peap->user_key_pass = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_enc_user_key_pass(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tls *peap = NULL;
  char *value = NULL;
  uint16_t size = 0;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP (Encrypted) User Key Password : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		xmlFree(value);
		return peap;
	}

  if (pwcrypt_decrypt(config_type, (uint8_t *)value, strlen(value), (uint8_t **)&peap->user_key_pass, &size) != 0)
  {
	  xmlFree(value);
	  peap->user_key_pass = NULL;
	  return peap;
  }

  xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_machine_auth(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  uint8_t result = 0;
  char *value = NULL;
 
	if (!(config_type & OPTION_GLOBAL_CONFIG_ONLY))
	{
		printf("Attempted to use a global config option in a user config!  Ignoring!\n");
		return (*attr);
	}

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("Machine Authentication : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);
 
    if (result == 1)
    {
      SET_FLAG(peap->flags, FLAGS_PEAP_MACHINE_AUTH);
    }
  else if (result == 0)
    {
      UNSET_FLAG(peap->flags, FLAGS_PEAP_MACHINE_AUTH);
    }
  else
    {
		xsupconfig_common_log("Unknown value for <Machine_Authentication_Mode> at line %ld.  Using default of NO.",
			xsupconfig_parse_get_line_num());
      UNSET_FLAG(peap->flags, FLAGS_PEAP_MACHINE_AUTH);
    }
  
  xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_session_resume(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  uint8_t result = 0;
  char *value = NULL;
 
  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Session Resumption : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Session_Resume'!  Will use the "
	     "default value of no.  (Config line %ld)\n",
	     xsupconfig_parse_get_line_num());
      UNSET_FLAG(peap->flags, EAP_TLS_FLAGS_SESSION_RESUME);
    }
  else
    {
		if (result == 1)
			SET_FLAG(peap->flags, EAP_TLS_FLAGS_SESSION_RESUME);
		else
			UNSET_FLAG(peap->flags, EAP_TLS_FLAGS_SESSION_RESUME);
    }
  
  xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_proper_v1_keying(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP proper PEAP v1 keying : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Proper_PEAP_V1_Keying'!  Will use "
	     "the default value of no.  (Config line %ld)\n",
	     xsupconfig_parse_get_line_num());
	  UNSET_FLAG(peap->flags, FLAGS_PEAP_PROPER_PEAPV1_KEYS);
    }
  else
    {
		if (result == 1)
			SET_FLAG(peap->flags, FLAGS_PEAP_PROPER_PEAPV1_KEYS);
		else
			UNSET_FLAG(peap->flags, FLAGS_PEAP_PROPER_PEAPV1_KEYS);
    }

  xmlFree(value);

  return peap;
}

void *xsupconfig_parse_peap_validate_cert(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP certificate validation : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Validate_Certificate'!  Will use "
	     "the default value of yes.  (Config line %ld)\n",
	     xsupconfig_parse_get_line_num());
	  SET_FLAG(peap->flags, FLAGS_PEAP_VALIDATE_SERVER_CERT);
    }
  else
    {
		if (result == TRUE)
			SET_FLAG(peap->flags, FLAGS_PEAP_VALIDATE_SERVER_CERT);
		else
			UNSET_FLAG(peap->flags, FLAGS_PEAP_VALIDATE_SERVER_CERT);
    }

  xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_chunk_size(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);
  
  peap = (*attr);

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
      peap->chunk_size = atoi(value);
    }

  xmlFree(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_random_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Random File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->random_file = NULL;
	}
	else
	{
		peap->random_file = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_force_peap_version(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_eap_peap *peap = NULL;
	char *value = NULL;

	value = (char *)xmlNodeGetContent(node);

	peap = (*attr);

#ifdef PARSE_DEBUG
	printf("Force PEAP version to %s.\n", value);
#endif

	if (xsupconfig_common_is_number(value) != TRUE)
	{
		xsupconfig_common_log("Value specified for 'Force_PEAP_Version' is invalid!  It is set to '%s', but "
				"should be a number.  (Line %ld)\n", value, xsupconfig_parse_get_line_num());
	}
	else
	{
		peap->force_peap_version = atoi(value);
	}

	xmlFree(value);

	return peap;
}

void *xsupconfig_parse_eap_peap_innerid(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Phase 2 Identity : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->identity = NULL;
	}
	else
	{
		peap->identity = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_peap_trusted_server(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_peap *peap = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Trusted Server : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		peap->trusted_server = NULL;
	}
	else
	{
		peap->trusted_server = _strdup(value);
	}
	xmlFree(value);

  return peap;
}

void *xsupconfig_parse_peap_logon_creds(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_eap_peap *peap = NULL;
	char *value = NULL;
	uint8_t result = 0;

	peap = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Use logon creds : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);
 
    if (result == 1)
    {
      SET_FLAG(peap->flags, FLAGS_PEAP_USE_LOGON_CREDS);
    }
  else if (result == 0)
    {
      UNSET_FLAG(peap->flags, FLAGS_PEAP_USE_LOGON_CREDS);
    }
  else
    {
		xsupconfig_common_log("Unknown value for <Use_Logon_Credentials> at line %ld.  Using default of NO.",
			xsupconfig_parse_get_line_num());
      UNSET_FLAG(peap->flags, FLAGS_PEAP_USE_LOGON_CREDS);
    }

  xmlFree(value);

  return peap;
}

parser eap_peap[] = {
  {"User_Certificate", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_user_cert},
  {"CRL_Directory", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_crl_dir},
  {"User_Key_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_user_key_file},
  {"User_Key_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_user_key_pass},
  {"Encrypted_User_Key_Password", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_enc_user_key_pass},
  {"Session_Resume", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_session_resume},
  {"Chunk_Size", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_chunk_size},
  {"Random_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_random_file},
  {"Machine_Authentication_Mode", NULL, FALSE, OPTION_GLOBAL_CONFIG_ONLY, &xsupconfig_parse_eap_peap_machine_auth},
  {"Proper_PEAP_V1_Keying", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_proper_v1_keying},
  {"Inner_ID", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_peap_innerid},
  {"Force_PEAP_Version", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_force_peap_version},
  {"Trusted_Server", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_peap_trusted_server},
  {"Validate_Certificate", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_peap_validate_cert},
  {"Use_Logon_Credentials", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_peap_logon_creds},
  {"Phase2", (struct conf_parse_struct *)&peap_phase2, TRUE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, 0, NULL}};
