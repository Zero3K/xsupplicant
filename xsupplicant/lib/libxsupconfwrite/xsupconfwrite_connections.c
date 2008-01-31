/**
 * Implementation for converting variables that make up the <Connections> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_connections.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfwrite_connections.c,v 1.4 2007/10/22 03:39:04 galimorerpg Exp $
 * $Date: 2007/10/22 03:39:04 $
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

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "xsupconfwrite_connection.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_CONNECTIONS_CONFIG 1


/**
 * \brief Create the <Connections> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] cons        A config_connection structure that contains all of the
 *                        variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Connections> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_connections_create_tree(struct config_connection *cons, 
									 char write_all)
{
	xmlNodePtr consnode = NULL;
	xmlNodePtr connode = NULL;
	struct config_connection *cur = NULL;

	if (cons == NULL) return NULL;

	// Create the root node for the <Connections> block.
	consnode = xmlNewNode(NULL, (xmlChar *)"Connections");
	if (consnode == NULL)
	{
#ifdef WRITE_CONNECTIONS_CONFIG
		printf("Couldn't allocate memory to store <Connections> block!\n");
#endif
		return NULL;
	}

	cur = cons;

	while (cur != NULL)
	{
		connode = xsupconfwrite_connection_create_tree(cur, write_all);
		if (connode == NULL)
		{
#ifdef WRITE_CONNECTIONS_CONFIG
			printf("Couldn't create <Connection> block!\n");
#endif
			xmlFreeNode(consnode);
			return NULL;
		}

		if (xmlAddChild(consnode, connode) == NULL)
		{
#ifdef WRITE_CONNECTIONS_CONFIG
			printf("Couldn't add <Connection> node to the <Connections> block!\n");
#endif
			xmlFreeNode(consnode);
			xmlFreeNode(connode);
			return NULL;
		}

		cur = cur->next;
	}

	return consnode;
}
