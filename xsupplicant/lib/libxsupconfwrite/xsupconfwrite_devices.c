/**
 * Implementation for creating the libxml2 node tree that contains the <Devices>
 * block.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_devices.c
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

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "libxsupconfig/xsupconfig_devices.h"
#include "xsupconfwrite.h"
#include "xsupconfwrite_interface.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_DEVICES_DEBUG 1

/**
 * \brief Take the variables and structures that are part of the xsup_devices 
 *        structure, and convert them to be a tree of XML nodes that libxml2 
 *        can work with.
 *
 * @param[in] conf_devs   A config_devices structure that contains all of the
 *                        variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Devices> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_devices_create_tree(struct xsup_devices * conf_devs,
					     char write_all)
{
	xmlNodePtr devicesnode = NULL;
	xmlNodePtr intNode = NULL;
	struct xsup_interfaces *cur = NULL;

	if (conf_devs == NULL)
		return NULL;

	// Create the root node for the <Devices> block.
	devicesnode = xmlNewNode(NULL, (xmlChar *) "Devices");
	if (devicesnode == NULL) {
#ifdef WRITE_DEVICES_DEBUG
		printf("Couldn't allocate memory to create <Devices> tree!\n");
#endif
		return NULL;
	}

	cur = conf_devs->interf;

	while (cur != NULL) {
		intNode = xsupconfwrite_interface_create_tree(cur, write_all);
		if (intNode == NULL) {
			free(devicesnode);
			return NULL;
		}

		if (xmlAddChild(devicesnode, intNode) == NULL) {
			free(devicesnode);
			return NULL;
		}

		cur = cur->next;
	}

	return devicesnode;
}
