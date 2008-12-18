/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_plugin.c
 *
 * \author galimorerpg@users.sourceforge.net
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

void *xsupconfig_parse_plugin(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_plugins *cur = NULL;

#if PARSE_DEBUG
  printf("Parse a plugin..\n");
#endif

	if (conf_plugins == NULL)
	{
		if (xsupconfig_defaults_create_plugin(&conf_plugins) != 0)
		{
			printf("Couldn't allocate memory to store configuration plugins!\n");
			return NULL;
		}

		cur = conf_plugins;
	}
	else
	{
		cur = conf_plugins;

		while (cur->next != NULL) cur = cur->next;

		if (xsupconfig_defaults_create_plugin(&cur->next) != 0)
		{
			printf("Couldn't allocate memory to store additional configuration plugins!\n");
			return NULL;
		}

		cur = cur->next;
	}

	return cur;
}


void *xsupconfig_parse_plugin_name(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_plugins *cur = NULL;
  struct config_plugins *check = NULL;
  char *value = NULL;
  char *original = NULL;
  char *newname = NULL;
  int done = 0, len = 0;

  value = (char *)xmlNodeGetContent(node);
  original = _strdup(value);
  xmlFree(value);
  value = original;
  original = NULL;

#ifdef PARSE_DEBUG
  printf("Name = %s\n", value);
#endif

  cur = (*attr);

	if (xsup_common_in_startup() == TRUE)
	{
	  original = _strdup(value);

	  while (done == 0)
	  {
		  check = conf_plugins;
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
					 xsupconfig_common_log("Couldn't allocate memory to store duplicate plugin!\n");
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
		  xsupconfig_common_log("There was a duplicate plugin named '%s'.  The duplicate has been renamed '%s'.", original, value);
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

void *xsupconfig_parse_plugin_path(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_plugins *cur = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Path = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		xmlFree(value);
		cur->path = NULL;
	}
	else
	{
		cur->path = _strdup(value);
		xmlFree(value);
	}

  return cur;
}

void *xsupconfig_parse_plugin_enabled(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_plugins *cur = NULL;
  uint8_t result = 0;
  char *value = NULL;
 
  value = (char *)xmlNodeGetContent(node);

  cur = (*attr);

#ifdef PARSE_DEBUG
  printf("Plugin Enabled : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      xsupconfig_common_log("Invalid value was passed for 'Enabled'!  Will use the "
	     "default value of yes.  (Config line %ld)\n",
	     xsupconfig_parse_get_line_num());
      cur->enabled = TRUE;
    }
  else
    {
      cur->enabled = result;
    }
  
  xmlFree(value);

  return cur;
}

void *xsupconfig_parse_plugin_desc(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_plugins *cur = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Description = %s\n", value);
#endif

  cur = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		xmlFree(value);
		cur->description = NULL;
	}
	else
	{
		cur->description = _strdup(value);
		xmlFree(value);
	}

  return cur;
}

parser plugin[] = {
	{"Name", NULL, FALSE, OPTION_GLOBAL_CONFIG_ONLY, xsupconfig_parse_plugin_name},
	{"Path", NULL, FALSE, OPTION_GLOBAL_CONFIG_ONLY, xsupconfig_parse_plugin_path},
	{"Enabled", NULL, FALSE, OPTION_GLOBAL_CONFIG_ONLY, xsupconfig_parse_plugin_enabled},
	{"Description", NULL, FALSE, OPTION_GLOBAL_CONFIG_ONLY, xsupconfig_parse_plugin_desc},
	{NULL, NULL, FALSE, 0, NULL}};
