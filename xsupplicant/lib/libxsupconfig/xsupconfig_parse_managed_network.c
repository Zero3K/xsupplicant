/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_managed_network.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_managed_network.c,v 1.4 2007/10/20 08:10:13 galimorerpg Exp $
 * $Date: 2007/10/20 08:10:13 $
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_common.h"
#include "xsupconfig_defaults.h"
#include "src/xsup_err.h"

void *xsupconfig_parse_managed_network(void **attr, xmlNodePtr node)
{
	struct config_managed_networks *cur;

#if PARSE_DEBUG
  printf("Parse a managed network..\n");
#endif

	if (conf_managed_networks == NULL)
	{
		if (xsupconfig_defaults_create_managed_network(&conf_managed_networks) != XENONE)
		{
			printf("Couldn't create managed networks structure!\n");
			return NULL;
		}

		cur = conf_managed_networks;
	}
	else
	{
		cur = conf_managed_networks;

		while (cur->next != NULL) cur = cur->next;

		if (xsupconfig_defaults_create_managed_network(&cur->next) != XENONE)
		{
			printf("Couldn't create managed networks structure!\n");
			return NULL;
		}

		cur = cur->next;
	}

	return cur;
}

void *xsupconfig_parse_managed_network_ou(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("OU = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		cur->ou = NULL;
	}
	else
	{
		cur->ou = value;
	}

  return cur;
}

void *xsupconfig_parse_managed_network_key(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Key = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		cur->key = NULL;
	}
	else
	{
		cur->key = value;
	}

  return cur;
}

void *xsupconfig_parse_managed_network_update_url(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Update URL = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		cur->update_url = NULL;
	}
	else
	{
		cur->update_url = value;
	}

  return cur;
}

void *xsupconfig_parse_managed_network_last_update(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Last Update = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		cur->last_update = NULL;
	}
	else
	{
		cur->last_update = value;
	}

  return cur;
}

void *xsupconfig_parse_managed_network_auto_update(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Auto Update : %s\n", value);
#endif

  cur = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result < 0)
  {
	printf("Unknown value for Auto_Update! (Line %ld)\n   Using "
		"default of 'YES'.\n", xsupconfig_parse_get_line_num());
	cur->auto_update = TRUE;
  }
  else
  {
	  cur->auto_update = result;
  }

  FREE(value);

  return cur;
}

void *xsupconfig_parse_managed_network_update_freq(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Update Freq : %s\n", value);
#endif

  cur = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      printf("Value assigned to Update_Frequency is not a number!  (Line %ld)\n"
	     "   Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
		cur->update_freq = atoi(value);
    }

  FREE(value);

  return cur;
}

void *xsupconfig_parse_managed_network_serial_id(void **attr, xmlNodePtr node)
{
  struct config_managed_networks *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Serial ID : %s\n", value);
#endif

  cur = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      printf("Value assigned to Serial_ID is not a number!  (Line %ld)\n"
	     "   Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
		cur->serialid = atol(value);
    }

  FREE(value);

  return cur;
}

parser managed_network[] = {
	{"OU", NULL, FALSE, xsupconfig_parse_managed_network_ou},
	{"Key", NULL, FALSE, xsupconfig_parse_managed_network_key},
	{"Serial_ID", NULL, FALSE, xsupconfig_parse_managed_network_serial_id},
	{"Update_URL", NULL, FALSE, xsupconfig_parse_managed_network_update_url},
	{"Auto_Update", NULL, FALSE, xsupconfig_parse_managed_network_auto_update},
	{"Update_Frequency", NULL, FALSE, xsupconfig_parse_managed_network_update_freq},
	{"Last_Update", NULL, FALSE, xsupconfig_parse_managed_network_last_update},

    {NULL, NULL, FALSE, NULL}};
