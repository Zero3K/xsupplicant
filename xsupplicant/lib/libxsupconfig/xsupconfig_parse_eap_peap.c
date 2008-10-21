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

void *xsupconfig_parse_eap_peap(void **attr, xmlNodePtr node)
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
  ((struct config_eap_peap *)(meth->method_data))->validate_cert = TRUE;
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_peap_user_cert(void **attr, xmlNodePtr node)
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
		free(value);
		peap->user_cert = NULL;
	}
	else
	{
		peap->user_cert = value;
	}

  return peap;
}

void *xsupconfig_parse_eap_peap_crl_dir(void **attr, xmlNodePtr node)
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
		free(value);
		peap->crl_dir = NULL;
	}
	else
	{
		peap->crl_dir = value;
	}

  return peap;
}

void *xsupconfig_parse_eap_peap_user_key_file(void **attr, xmlNodePtr node)
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
		free(value);
		peap->user_key = NULL;
	}
	else
	{
		peap->user_key = value;
	}

  return peap;
}

void *xsupconfig_parse_eap_peap_user_key_pass(void **attr, xmlNodePtr node)
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
		free(value);
		peap->user_key_pass = NULL;
	}
	else
	{
		peap->user_key_pass = value;
	}

  return peap;
}

void *xsupconfig_parse_eap_peap_enc_user_key_pass(void **attr, xmlNodePtr node)
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
		free(value);
		return peap;
	}

  if (pwcrypt_decrypt((uint8_t *)value, strlen(value), (uint8_t **)&peap->user_key_pass, &size) != 0)
  {
	  free(value);
	  peap->user_key_pass = NULL;
	  return peap;
  }

  free(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_session_resume(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  uint8_t result;
  char *value;
 
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
      peap->session_resume = FALSE;
    }
  else
    {
      peap->session_resume = result;
    }
  
  FREE(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_cnexact(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Exact CN Match : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Exact_Common_Name'!  Will use the "
             "default value of no.  (Config line %ld)\n",
	     xsupconfig_parse_get_line_num());
      peap->cnexact = FALSE;
    }
  else
    {
      peap->cnexact = result;
    }

  FREE(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_proper_v1_keying(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  uint8_t result;
  char *value;

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
      peap->proper_peapv1 = FALSE;
    }
  else
    {
      peap->proper_peapv1 = result;
    }

  FREE(value);

  return peap;
}

void *xsupconfig_parse_peap_validate_cert(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  uint8_t result;
  char *value;

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
      peap->validate_cert = TRUE;
    }
  else
    {
      peap->validate_cert = result;
    }

  FREE(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_chunk_size(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  char *value;

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

  FREE(value);

  return peap;
}

void *xsupconfig_parse_eap_peap_random_file(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Random File : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		peap->random_file = NULL;
	}
	else
	{
		peap->random_file = value;
	}

  return peap;
}

void *xsupconfig_parse_force_peap_version(void **attr, xmlNodePtr node)
{
	struct config_eap_peap *peap;
	char *value;

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

	FREE(value);

	return peap;
}

void *xsupconfig_parse_eap_peap_innerid(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Phase 2 Identity : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		peap->identity = NULL;
	}
	else
	{
		peap->identity = value;
	}

  return peap;
}

void *xsupconfig_parse_peap_trusted_server(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Trusted Server : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		peap->trusted_server = NULL;
	}
	else
	{
		peap->trusted_server = value;
	}

  return peap;
}

void *xsupconfig_parse_eap_peap_cncheck(void **attr, xmlNodePtr node)
{
  struct config_eap_peap *peap;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  peap = (*attr);

#ifdef PARSE_DEBUG
  printf("PEAP Common Name : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		peap->cncheck = NULL;
	}
	else
	{
		peap->cncheck = value;
	}

  return peap;
}

parser eap_peap[] = {
  {"User_Certificate", NULL, FALSE, &xsupconfig_parse_eap_peap_user_cert},
  {"CRL_Directory", NULL, FALSE, &xsupconfig_parse_eap_peap_crl_dir},
  {"User_Key_File", NULL, FALSE, &xsupconfig_parse_eap_peap_user_key_file},
  {"User_Key_Password", NULL, FALSE, &xsupconfig_parse_eap_peap_user_key_pass},
  {"Encrypted_User_Key_Password", NULL, FALSE, &xsupconfig_parse_eap_peap_enc_user_key_pass},
  {"Session_Resume", NULL, FALSE, &xsupconfig_parse_eap_peap_session_resume},
  {"Chunk_Size", NULL, FALSE, &xsupconfig_parse_eap_peap_chunk_size},
  {"Random_File", NULL, FALSE, &xsupconfig_parse_eap_peap_random_file},
  {"Common_Name", NULL, FALSE, &xsupconfig_parse_eap_peap_cncheck},
  {"Exact_Common_Name", NULL, FALSE, &xsupconfig_parse_eap_peap_cnexact},
  {"Proper_PEAP_V1_Keying", NULL, FALSE, 
   &xsupconfig_parse_eap_peap_proper_v1_keying},
  {"Inner_ID", NULL, FALSE, &xsupconfig_parse_eap_peap_innerid},
  {"Force_PEAP_Version", NULL, FALSE, &xsupconfig_parse_force_peap_version},
  {"Trusted_Server", NULL, FALSE, &xsupconfig_parse_peap_trusted_server},
  {"Validate_Certificate", NULL, FALSE, &xsupconfig_parse_peap_validate_cert},
  {"Phase2", (struct conf_parse_struct *)&peap_phase2, TRUE, xsupcommon_do_nothing},
  {"Type", NULL, FALSE, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, NULL}};
