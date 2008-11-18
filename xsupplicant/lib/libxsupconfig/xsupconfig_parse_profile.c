/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_profile.c
 *
 * \author chris@open1x.org
 *
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
#include "xsupconfig_parse_eap.h"
#include "xsupconfig_parse_profile_compliance.h"

void *xsupconfig_parse_profile(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_profiles *cur = NULL;

#if PARSE_DEBUG
  printf("Parse a profile..\n");
#endif

	if (conf_profiles == NULL)
	{
		if (xsupconfig_defaults_create_profile(&conf_profiles) != 0)
		{
			printf("Couldn't allocate memory to store configuration profiles!\n");
			return NULL;
		}

		cur = conf_profiles;
	}
	else
	{
		cur = conf_profiles;

		while (cur->next != NULL) cur = cur->next;

		if (xsupconfig_defaults_create_profile(&cur->next) != 0)
		{
			printf("Couldn't allocate memory to store additional configuration profiles!\n");
			return NULL;
		}

		cur = cur->next;
	}

	return cur;
}

void *xsupconfig_parse_user_profile(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_profiles *cur = NULL;

#if PARSE_DEBUG
  printf("Parse a profile..\n");
#endif

	if (conf_user_profiles == NULL)
	{
		if (xsupconfig_defaults_create_profile(&conf_user_profiles) != 0)
		{
			printf("Couldn't allocate memory to store configuration profiles!\n");
			return NULL;
		}

		cur = conf_user_profiles;
	}
	else
	{
		cur = conf_user_profiles;

		while (cur->next != NULL) cur = cur->next;

		if (xsupconfig_defaults_create_profile(&cur->next) != 0)
		{
			printf("Couldn't allocate memory to store additional configuration profiles!\n");
			return NULL;
		}

		cur = cur->next;
	}

	return cur;
}

void *xsupconfig_parse_profile_name(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_profiles *cur = NULL;
  struct config_profiles *check = NULL;
  char *value = NULL;
  char *original = NULL;
  char *newname = NULL;
  int done = 0, len = 0;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Name = %s\n", value);
#endif

  cur = (*attr);

	if (xsup_common_in_startup() == TRUE)
	{
	  original = _strdup(value);

	  while (done == 0)
	  {
		  check = conf_profiles;
		  if (check != NULL)
			{
			  // Make sure we don't already have it.
			  while (check != NULL)
			  {
				  if (check->name != NULL)
				  {
					  if (strcmp(check->name, value) == 0) break;
				  }	

				  check = check->next;
			  }

			  if (check != NULL)
			  {
				  if (newname != NULL)
				  {
					  free(newname);
					  newname = NULL;
				  }

				  len = strlen(value) + strlen(" (dup)") + 1;
				  newname = malloc(strlen(value) + strlen(" (dup)") + 1);
				  if (newname == NULL)
				  {
					 xsupconfig_common_log("Couldn't allocate memory to store duplicate profile!\n");
				  }
				  else
				  {
					  memset(newname, 0x00, len);
					  strcpy(newname, value);
					  strcat(newname, " (dup)");

					  // Then, replace value.
					  free(value);
					  value = newname;
					  newname = NULL;
				  }
			  }
			  else
			  {
				  // We have a valid name.
				  done = 1;
			  }
		  }
		  else
		  {
			  // There is nothing to check, so it must be legit.
			  done = 1;
		  }
	}

	  if (strcmp(original, value) != 0)
	  {
		  xsupconfig_common_log("There was a duplicate profile named '%s'.  The duplicate has been renamed '%s'.   If you had any connections that you intended to use this duplicate profile, they will not work as expected!", original, value);
	  }

	  free(original);
	}
	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		cur->name = NULL;
	}
	else
	{
		cur->name = value;
	}

  return cur;
}

void *xsupconfig_parse_profile_identity(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_profiles *cur;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Identity = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		cur->identity = NULL;
	}
	else
	{
		cur->identity = value;
	}

  return cur;
}

void *xsupconfig_parse_profile_volatile(void **attr, uint8_t config_type, xmlNodePtr node)
{
  char *value = NULL;
  struct config_profiles *prof = NULL;
  uint8_t result = 0;

  prof = (struct config_profiles *)(*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Volatile : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);
 
    if (result == 1)
    {
      SET_FLAG(prof->flags, CONFIG_VOLATILE_PROFILE);
    }
  else if (result == 0)
    {
      UNSET_FLAG(prof->flags, CONFIG_VOLATILE_PROFILE);
    }
  else
    {
		xsupconfig_common_log("Unknown value for Volatile at line %ld.  Using default of NO.",
			xsupconfig_parse_get_line_num());
      UNSET_FLAG(prof->flags, CONFIG_VOLATILE_PROFILE);
    }

  FREE(value);

  return prof;
}

parser profile[] = {
	{"Name", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_profile_name},
	{"Identity", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_profile_identity},
	{"EAP", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_eap},
	{"Volatile", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_profile_volatile},
	{"Compliance", compliance, TRUE, OPTION_ANY_CONFIG, xsupconfig_parse_profile_compliance},

    {NULL, NULL, FALSE, 0, NULL}};
