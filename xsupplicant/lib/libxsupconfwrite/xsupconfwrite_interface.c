/**
 * Implementation for converting variables that make up the <Interface> subsection of
 * <Devices> to the libxml2 format that can be written to disk, or manipulated in 
 * other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_interface.c
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
#include "xsupconfwrite_common.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_INTERFACE_DEBUG 1

/**
 * \brief Take the variables and structures that are part of the xsup_interfaces
 *        structure, and convert them to be a tree of XML nodes that libxml2 
 *        can work with.
 *
 * @param[in] conf_int  An xsup_interfaces structure that contains all of the
 *                      variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Interface> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_interface_create_tree(struct xsup_interfaces *conf_int,
									           char write_all)
{
	xmlNodePtr intnode = NULL;
	char *mac_str = NULL;
	char *temp = NULL;

	if (conf_int == NULL) return NULL;

	// Create the root node for the <Interface> block.
	intnode = xmlNewNode(NULL, (xmlChar *)"Interface");
	if (intnode == NULL)
	{
#ifdef WRITE_INTERFACE_DEBUG
		printf("Couldn't allocate memory to create <Interface> tree!\n");
#endif  
		return NULL;
	}

	if ((write_all == TRUE) || (conf_int->description != NULL))
	{
		xsupconfwrite_convert_amp(conf_int->description, &temp);
		if (xmlNewChild(intnode, NULL, (xmlChar *)"Description", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_INTERFACE_DEBUG
			printf("Couldn't create <Description> node!\n");
#endif
			xmlFreeNode(intnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (conf_int->driver_type != NULL))
	{
		if (xmlNewChild(intnode, NULL, (xmlChar *)"Type", (xmlChar *)conf_int->driver_type) == NULL)
		{
#ifdef WRITE_INTERFACE_DEBUG
			printf("Couldn't create <Type> node!\n");
#endif
			xmlFreeNode(intnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (conf_int->default_connection != NULL))
	{
		if (xmlNewChild(intnode, NULL, (xmlChar *)"Default_Connection", (xmlChar *)conf_int->default_connection) == NULL)
		{
#ifdef WRITE_INTERFACE_DEBUG
			printf("Couldn't create <Default_Connection> node!\n");
#endif
			xmlFreeNode(intnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (TEST_FLAG(conf_int->flags, CONFIG_INTERFACE_IS_WIRELESS)))
	{
		if (TEST_FLAG(conf_int->flags, CONFIG_INTERFACE_IS_WIRELESS))
		{
			if (xmlNewChild(intnode, NULL, (xmlChar *)"Wireless", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_INTERFACE_DEBUG
				printf("Couldn't create <Wireless> node!\n");
#endif
				xmlFreeNode(intnode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(intnode, NULL, (xmlChar *)"Wireless", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_INTERFACE_DEBUG
				printf("Couldn't create <Wireless> node!\n");
#endif
				xmlFreeNode(intnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (TEST_FLAG(conf_int->flags, CONFIG_INTERFACE_DONT_MANAGE)))
	{
		if (TEST_FLAG(conf_int->flags, CONFIG_INTERFACE_DONT_MANAGE))
		{
			if (xmlNewChild(intnode, NULL, "Manage", "no") == NULL)
			{
#ifdef WRITE_INTERFACE_DEBUG
				printf("Couldn't create <Manage> node!\n");
#endif
				xmlFreeNode(intnode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(intnode, NULL, "Manage", "yes") == NULL)
			{
#ifdef WRITE_INTERFACE_DEBUG
				printf("Couldn't create <Manage> node!\n");
#endif
				xmlFreeNode(intnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (memcmp(conf_int->mac, "\0x00\0x00\0x00\0x00\0x00\0x00", 6) != 0))
	{
		mac_str = mac2str((char *)conf_int->mac);
		if (mac_str == NULL)
		{
#ifdef WRITE_INTERFACE_DEBUG
			printf("Failed to convert a MAC address to a string!\n");
#endif
			xmlFreeNode(intnode);
			return NULL;
		}

		if (xmlNewChild(intnode, NULL, (xmlChar *)"MAC", (xmlChar *)mac_str) == NULL)
		{
#ifdef WRITE_INTERFACE_DEBUG
			printf("Couldn't create <MAC> node!\n");
#endif
			xmlFreeNode(intnode);
			free(mac_str);
			return NULL;
		}
		free(mac_str);
	}

	return intnode;
}
