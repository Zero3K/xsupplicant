/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_tnc.c
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

#include "src/xsup_common.h"
#include "xsupconfig.h"
#include "xsupconfig_structs.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_eap_tnc.h"

void *xsupconfig_parse_eap_tnc(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_ttls *ttls;
  struct config_eap_method *eap, *cur;

  ttls = (*attr);

  if (ttls == NULL)
    {
      printf("Invalid TTLS phase 1!  You cannot have phase 2 data without "
             "having a phase 1!  (This is likely a bug in the parser code!)"
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  if (ttls->phase2_data == NULL)
  {
      ttls->phase2_data = malloc(sizeof(struct config_eap_method));
      if (ttls->phase2_data == NULL)
        {
          printf("Couldn't allocate memory to store TTLS-EAP-TNC data! "
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
		printf("Couldn't allocate memory to store TTLS-EAP-TNC data! "
			"(Line %ld)\n", xsupconfig_parse_get_line_num());
		exit(2);
	}

	memset(cur->next, 0x00, sizeof(struct config_eap_method));

	eap = cur->next;
  }

  eap->method_num = EAP_TYPE_TNC;
  eap->method_data = malloc(sizeof(struct config_eap_tnc));
  if (eap->method_data == NULL)
    {
      printf("Couldn't allocate memory to store TTLS-EAP-TNC data! (Line %ld)"
	     "\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(eap->method_data, 0x00, sizeof(struct config_eap_tnc));

  return eap->method_data;
}

void *xsupconfig_parse_eap_tnc_chunk_size(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_eap_tnc *tnc;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  tnc = (*attr);

#ifdef PARSE_DEBUG
  printf("Chunk Size for TNC is '%s'!\n", value);
#endif

  if (xsupconfig_common_is_number(value) == 0)
    {
      printf("Value assigned to 'Chunk_Size' is not a number!  Using "
	     "default!  (Line %ld)\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      tnc->frag_size = atoi(value);
    }

  FREE(value);

  return tnc;
}

parser eap_tnc[] = {
  {"Chunk_Size", NULL, FALSE, OPTION_ANY_CONFIG, &xsupconfig_parse_eap_tnc_chunk_size},
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, 0, NULL}};
