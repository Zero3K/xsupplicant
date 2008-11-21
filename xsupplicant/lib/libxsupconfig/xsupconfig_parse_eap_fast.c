/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_fast.c
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
#include "xsupconfig_parse_eap_fast.h"
#include "xsupconfig_parse_eap_fast_phase2.h"

void *xsupconfig_parse_eap_fast(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_method *meth = NULL;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-FAST");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-FAST");
  }

  if (meth == NULL) return NULL;


#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-FAST'.\n");
#endif

  meth->method_num = EAP_TYPE_FAST;
  meth->method_data = malloc(sizeof(struct config_eap_fast));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-FAST data in network! "
	     " (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_eap_fast));

  ((struct config_eap_fast *)(meth->method_data))->provision_flags = EAP_FAST_PROVISION_ALLOWED | EAP_FAST_PROVISION_AUTHENTICATED;

  return meth->method_data;
}

void *xsupconfig_parse_eap_fast_provision(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Allow provisioning : %s\n", value);
#endif

  fast = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
		SET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_ALLOWED);
    }
  else if (result == 0)
    {
		UNSET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_ALLOWED);
    }
  else
    {
      xsupconfig_common_log("Invalid value was passed for 'Allow_Provision'!  (Line %ld)\n"
	     "   Will use the default value of yes.\n",
	     xsupconfig_parse_get_line_num());
		SET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_ALLOWED);
    }

  FREE(value);

  return fast;
}

void *xsupconfig_parse_eap_fast_pac_file(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL; 
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("PAC file location : %s\n", value);
#endif

  fast = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		fast->pac_location = NULL;
	}
	else
	{
	    fast->pac_location = value;
	}

  return fast;
}

void *xsupconfig_parse_eap_fast_innerid(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Inner ID : %s\n", value);
#endif

  fast = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		fast->innerid = NULL;
	}
	else
	{
		fast->innerid = value;
	}

  return fast;
}

void *xsupconfig_parse_eap_fast_chunk_size(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Chunk Size : %s\n", value);
#endif

  fast = (*attr);

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to 'Chunk_Size' is not a number!  (Line %ld)\n"
	     "  Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      fast->chunk_size = atoi(value);
    }

  FREE(value);

  return fast;
}

void *xsupconfig_parse_eap_fast_allow_anon_provision(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Allow anonymous provisioning : %s\n", value);
#endif

  fast = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
		SET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_ANONYMOUS);
    }
  else if (result == 0)
    {
		UNSET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_ANONYMOUS);
    }
  else
    {
      xsupconfig_common_log("Invalid value was passed for 'Allow_Anonymous_Provision'!  (Line %ld)\n"
	     "   Will use the default value of no.\n",
	     xsupconfig_parse_get_line_num());
		UNSET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_ANONYMOUS);
    }

  FREE(value);

  return fast;
}

void *xsupconfig_parse_eap_fast_allow_auth_provision(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Allow authenticated provisioning : %s\n", value);
#endif

  fast = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
		SET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED);
    }
  else if (result == 0)
    {
		UNSET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED);
    }
  else
    {
      xsupconfig_common_log("Invalid value was passed for 'Allow_Authenticated_Provision'!  (Line %ld)\n"
	     "   Will use the default value of yes.\n",
	     xsupconfig_parse_get_line_num());
		SET_FLAG(fast->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED);
    }

  FREE(value);

  return fast;
}

void *xsupconfig_parse_eap_fast_trusted_server(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  fast = (*attr);

#ifdef PARSE_DEBUG
  printf("FAST Trusted Server : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		fast->trusted_server = NULL;
	}
	else
	{
		fast->trusted_server = value;
	}

  return fast;
}

void *xsupconfig_parse_eap_fast_validate_cert(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_fast *fast = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  fast = (*attr);

#ifdef PARSE_DEBUG
  printf("FAST certificate validation : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Validate_Certificate'!  Will use "
	     "the default value of yes.  (Config line %ld)\n",
	     xsupconfig_parse_get_line_num());
      fast->validate_cert = TRUE;
    }
  else
    {
      fast->validate_cert = result;
    }

  FREE(value);

  return fast;
}

parser eap_fast[] = {
  {"Allow_Provision", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_provision},
  {"Allow_Anonymous_Provision", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_allow_anon_provision},
  {"Allow_Authenticated_Provision", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_allow_auth_provision},
  {"PAC_File", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_pac_file},
  {"Chunk_Size", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_chunk_size},
  {"Inner_ID", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_innerid},
  {"Trusted_Server", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_trusted_server},
  {"Validate_Certificate", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_fast_validate_cert},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},
  {"Phase2", (struct conf_parse_struct *)&fast_phase2, TRUE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, 0, NULL}};
