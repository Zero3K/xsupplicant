/**
 * Implementation for converting variables that make up the <Trusted_Server> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_trusted_server.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfwrite_trusted_server.c,v 1.5 2007/10/22 03:29:06 galimorerpg Exp $
 * $Date: 2007/10/22 03:29:06 $
 **/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <libxml/parser.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "src/xsup_common.h"

#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "xsupconfwrite.h"
#include "xsupconfwrite_common.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_TS_DEBUG 1


/**
 * \brief Take the variables that are part of the config_trusted_server structure, and
 *        convert them to be a tree of XML nodes that libxml2 can work with.
 *
 * @param[in] cts  A config_trusted_server structure that contains all of the
 *                 variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Trusted_Server> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_trusted_server_create_tree(struct config_trusted_server *cts, 
													 char write_all)
{
	xmlNodePtr tsnode = NULL;
	char *temp = NULL;
	int i = 0;
	
	if (cts == NULL) return NULL;

	// Create the root node for the <Trusted_Server> block.
	tsnode = xmlNewNode(NULL, (xmlChar *)"Trusted_Server");
	if (tsnode == NULL)
	{
#ifdef WRITE_TS_CONFIG
		printf("Couldn't allocate memory to store <Trusted_Server> block!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (cts->name != NULL))
	{
		xsupconfwrite_convert_amp(cts->name, &temp);
		if (xmlNewChild(tsnode, NULL, (xmlChar *)"Name", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_TS_CONFIG
			printf("Couldn't allocate memory to store <Name> node!\n");
#endif
			xmlFreeNode(tsnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (cts->common_name != NULL))
	{
		xsupconfwrite_convert_amp(cts->common_name, &temp);
		if (xmlNewChild(tsnode, NULL, (xmlChar *)"Common_Name", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_TS_CONFIG
			printf("Couldn't allocate memory to store <Common_Name> node!\n");
#endif
			xmlFreeNode(tsnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (cts->store_type != NULL))
	{
		xsupconfwrite_convert_amp(cts->store_type, &temp);
		if (xmlNewChild(tsnode, NULL, (xmlChar *)"Store_Type", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_TS_CONFIG
			printf("Couldn't allocate memory to store <Store_Type> node!\n");
#endif
			free(temp);
			xmlFreeNode(tsnode);
			return NULL;
		}

		free(temp);
	}

	for (i = 0; i < cts->num_locations; i++)
	{
		if ((write_all == TRUE) || (cts->location[i] != NULL))
		{
			xsupconfwrite_convert_amp(cts->location[i], &temp);
			if (xmlNewChild(tsnode, NULL, (xmlChar *)"Location", (xmlChar *)temp) == NULL)
			{
#ifdef WRITE_TS_CONFIG
				printf("Couldn't allocate memory to store <Location> node!\n");
#endif
				free(temp);
				xmlFreeNode(tsnode);
				return NULL;
			}

			free(temp);
		}
	}

	if ((write_all == TRUE) || (TEST_FLAG(cts->flags, CONFIG_VOLATILE_SERVER)))
	{
		if (TEST_FLAG(cts->flags, CONFIG_VOLATILE_SERVER))
		{
			if (xmlNewChild(tsnode, NULL, (xmlChar *)"Volatile", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_TS_CONFIG
				printf("Couldn't allocate memory to store <Volatile> node!\n");
#endif
				xmlFreeNode(tsnode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(tsnode, NULL, (xmlChar *)"Volatile", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_TS_CONFIG
				printf("Couldn't allocate memory to store <Volatile> node!\n");
#endif
				xmlFreeNode(tsnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (cts->exact_common_name != FALSE))
	{
		if (cts->exact_common_name != FALSE)
		{
			if (xmlNewChild(tsnode, NULL, (xmlChar *)"Exact_Common_Name", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_TS_CONFIG
				printf("Couldn't allocate memory to store <Exact_Common_Name> node!\n");
#endif
				xmlFreeNode(tsnode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(tsnode, NULL, (xmlChar *)"Exact_Common_Name", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_TS_CONFIG
				printf("Couldn't allocate memory to store <Exact_Common_Name> node!\n");
#endif
				xmlFreeNode(tsnode);
				return NULL;
			}
		}
	}

	return tsnode;
}
