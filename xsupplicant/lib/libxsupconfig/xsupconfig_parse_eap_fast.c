/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_fast.c
 *
 * \authors chris@open1x.org
 *
 * $Id: xsupconfig_parse_eap_fast.c,v 1.4 2007/10/20 08:10:13 galimorerpg Exp $
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
#include "xsupconfig_parse_eap_fast.h"
#include "xsupconfig_parse_eap_fast_phase2.h"

void *xsupconfig_parse_eap_fast(void **attr, xmlNodePtr node)
{
  struct config_eap_method *meth;

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
  
  return meth->method_data;
}

void *xsupconfig_parse_eap_fast_provision(void **attr, xmlNodePtr node)
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
      fast->provision = RES_YES;
    }
  else if (result == 0)
    {
      fast->provision = RES_NO;
    }
  else
    {
      xsupconfig_common_log("Invalid value was passed for 'Allow_Provision'!  (Line %ld)\n"
	     "   Will use the default value of yes.\n",
	     xsupconfig_parse_get_line_num());
      fast->provision = RES_YES;
    }

  FREE(value);

  return fast;
}

void *xsupconfig_parse_eap_fast_pac_file(void **attr, xmlNodePtr node)
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

void *xsupconfig_parse_eap_fast_innerid(void **attr, xmlNodePtr node)
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


void *xsupconfig_parse_eap_fast_chunk_size(void **attr, xmlNodePtr node)
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

parser eap_fast[] = {
  {"Allow_Provision", NULL, FALSE, &xsupconfig_parse_eap_fast_provision},
  {"PAC_File", NULL, FALSE, &xsupconfig_parse_eap_fast_pac_file},
  {"Chunk_Size", NULL, FALSE, &xsupconfig_parse_eap_fast_chunk_size},
  {"Inner_ID", NULL, FALSE, &xsupconfig_parse_eap_fast_innerid},
  {"Type", NULL, FALSE, xsupcommon_do_nothing},
  {"Phase2", (struct conf_parse_struct *)&fast_phase2, TRUE, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, NULL}};
