/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_trusted_server.c
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
#include "xsupconfig_vars.h"
#include "src/xsup_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig.h"
#include "xsupconfig_structs.h"
#include "xsupconfig_parse_trusted_server.h"
#include "xsupconfig_common.h"
#include "xsupconfig_defaults.h"
#include "src/xsup_err.h"

void *xsupconfig_parse_trusted_server(void **attr, xmlNodePtr node)
{
  struct config_trusted_servers *myservers = NULL;
  struct config_trusted_server *myserver = NULL;

  myservers = (*attr);

#ifdef PARSE_DEBUG
  printf("Building trusted server config.\n");
#endif

  if (myservers->servers == NULL)
    {
		if (xsupconfig_defaults_create_trusted_server(&myservers->servers) != XENONE)
		{
			printf("Couldn't allocate memory to store a trusted server configuration!"
				"  (Line %ld)\n", xsupconfig_parse_get_line_num());
			exit(1);
		}

	  myserver = myservers->servers;
    }
  else
    {
	  myserver = myservers->servers;

      while (myserver->next != NULL) myserver = myserver->next;

	  if (xsupconfig_defaults_create_trusted_server(&myserver->next) != XENONE)
	  {
		  printf("Couldn't allocate memory to store a trusted server configuration!"
			  "  (Line %ld)\n", xsupconfig_parse_get_line_num());
		  exit(1);
	  }

      myserver = myserver->next;
    }

  return myserver;
}

void *xsupconfig_parse_trusted_server_name(void **attr, xmlNodePtr node)
{
  struct config_trusted_server *myserver = NULL;
  struct config_trusted_server *check = NULL;
  char *value = NULL;
  char *original = NULL;
  char *newname = NULL;
  int done = 0, len = 0;

  value = (char *)xmlNodeGetContent(node);

  myserver = (*attr);

#ifdef PARSE_DEBUG
  printf("Trusted server name is '%s'!\n", value);
#endif

	if (xsup_common_in_startup() == TRUE)
	{
	  original = _strdup(value);

	  while (done == 0)
	  {
		  check = NULL;
		  if (conf_trusted_servers != NULL)
		  {
			check = conf_trusted_servers->servers;
		  }

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
					 xsupconfig_common_log("Couldn't allocate memory to store duplicate trusted server!\n");
				  }
				  else
				  {
					  memset(newname, 0x00, len);
					  strcpy(newname, value);
					  strcat(newname, " (dup)");

					  // Then, replace "value".
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
		  xsupconfig_common_log("There was a duplicate trusted server named '%s'.  The duplicate has been renamed '%s'.  Any connections that use this trusted server may not work as expected.  You should verify those connections.", original, value);
	  }

	  free(original);
	}

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myserver->name = NULL;
	}
	else
	{
		myserver->name = value;
	}

  return myserver;
}

void *xsupconfig_parse_trusted_server_type(void **attr, xmlNodePtr node)
{
  struct config_trusted_server *myserver;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  myserver = (*attr);

#ifdef PARSE_DEBUG
  printf("Trusted server store type is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myserver->store_type = NULL;
	}
	else
	{
		myserver->store_type = value;
	}

  return myserver;
}

/**
 * \brief Parse a <Location> tag for a trusted server block.
 *
 * @param[in] attr   Points to the active structure that we are populating in memory.  It should
 *                   by type cast to the proper type for manipulation.
 * @param[in] node   Points to the <Location> node that we are currently processing.
 *
 * \warning Multiple <Location> tags can be specified in a <Trusted_Server> block.  Be sure that anything
 *			you do in this function doesn't destroy data that may already exist!
 *
 * \retval ptr to the active configuration structure that we are populating in memory.
 **/
void *xsupconfig_parse_trusted_server_location(void **attr, xmlNodePtr node)
{
  struct config_trusted_server *myserver = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  myserver = (*attr);

#ifdef PARSE_DEBUG
  printf("Trusted server store location is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		// Since we can have more than one location in a trusted server, we should just free the
		// "value" variable.  If we set myserver->location to NULL, then we would end up leaking memory
		// and making a big mess.  ;)
		free(value);
	}
	else
	{
		myserver->num_locations++;
		myserver->location = realloc(myserver->location, myserver->num_locations*(sizeof(myserver->location)));
		myserver->location[myserver->num_locations-1] = value;
	}

  return myserver;
}

void *xsupconfig_parse_trusted_server_cn(void **attr, xmlNodePtr node)
{
  struct config_trusted_server *myserver;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  myserver = (*attr);

#ifdef PARSE_DEBUG
  printf("Trusted server CN is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myserver->common_name = NULL;
	}
	else
	{
		myserver->common_name = value;
	}

  return myserver;
}

void *xsupconfig_parse_trusted_server_ecn(void **attr, xmlNodePtr node)
{
  struct config_trusted_server *myserver = NULL;
  uint8_t result = 0;
  char *value = NULL;

  myserver = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Trusted server Exact Common Name : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      printf("Invalid value was passed for 'Exact_Common_Name'!  Will use the "
             "default value of no.  (Line %ld)\n",
	     xsupconfig_parse_get_line_num());
	  myserver->exact_common_name = FALSE;
    }
  else
    {
		myserver->exact_common_name = result;
    }

  FREE(value);

  return myserver;
}

void *xsupconfig_parse_volatile(void **attr, xmlNodePtr node)
{
  struct config_trusted_server *myserver = NULL;
  uint8_t result = 0;
  char *value = NULL;

  myserver = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Volatile : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result > 1)
    {
      printf("Invalid value was passed for 'Volatile'!  Will use the "
             "default value of no.  (Line %ld)\n",
	     xsupconfig_parse_get_line_num());
	  UNSET_FLAG(myserver->flags, CONFIG_VOLATILE_SERVER);
    }
  else
    {
		SET_FLAG(myserver->flags, CONFIG_VOLATILE_SERVER);
    }

  FREE(value);

  return myserver;
}

parser trusted_server[] = {
  {"Name", NULL, FALSE, xsupconfig_parse_trusted_server_name},
  {"Store_Type", NULL, FALSE, xsupconfig_parse_trusted_server_type},
  {"Location", NULL, FALSE, xsupconfig_parse_trusted_server_location},
  {"Common_Name", NULL, FALSE, xsupconfig_parse_trusted_server_cn},
  {"Volatile", NULL, FALSE, xsupconfig_parse_volatile},
  {"Exact_Common_Name", NULL, FALSE, xsupconfig_parse_trusted_server_ecn},

  {NULL, NULL, FALSE, NULL}};
