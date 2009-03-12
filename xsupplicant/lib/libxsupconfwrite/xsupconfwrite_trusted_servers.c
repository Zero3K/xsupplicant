/**
 * Implementation for converting variables that make up the <Trusted_Servers> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_trusted_servers.c
 *
 * \author chris@open1x.org
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
#include "xsupconfwrite_trusted_server.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_TSS_DEBUG 1

/**
 * \brief Take the variables that are part of the config_trusted_servers structure, and
 *        convert them to be a tree of XML nodes that libxml2 can work with.
 *
 * @param[in] cts  A config_trusted_servers structure that contains all of the
 *                 variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Trusted_Servers> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_trusted_servers_create_tree(struct
						     config_trusted_servers *
						     cts, char write_all,
						     char write_to_disk)
{
	xmlNodePtr tssnode = NULL;
	xmlNodePtr tsnode = NULL;
	struct config_trusted_server *cur = NULL;

	if (cts == NULL)
		return NULL;

	// Create the root node for the <Trusted_Servers> block.
	tssnode = xmlNewNode(NULL, (xmlChar *) "Trusted_Servers");
	if (tssnode == NULL) {
#ifdef WRITE_TSS_CONFIG
		printf
		    ("Couldn't allocate memory to store <Trusted_Servers> block!\n");
#endif
		return NULL;
	}

	cur = cts->servers;

	while (cur != NULL) {
		if ((!TEST_FLAG(cur->flags, CONFIG_VOLATILE_SERVER))
		    || (write_to_disk == FALSE)) {
			tsnode =
			    xsupconfwrite_trusted_server_create_tree(cur,
								     write_all);
			if (tsnode == NULL) {
#ifdef WRITE_TSS_CONFIG
				printf
				    ("Couldn't allocate memory to store <Trusted_Server> block!\n");
#endif
				xmlFreeNode(tssnode);
				return NULL;
			}

			if (xmlAddChild(tssnode, tsnode) == NULL) {
#ifdef WRITE_TSS_CONFIG
				printf
				    ("Couldn't allcoate memory to store <Trusted_Server> node!\n");
#endif
				xmlFreeNode(tssnode);
				xmlFreeNode(tsnode);
				return NULL;
			}
		}

		cur = cur->next;
	}

	return tssnode;
}
