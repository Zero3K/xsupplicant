/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_managed_networks.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfigwrite_managed_networks.c,v 1.3 2007/10/17 07:00:41 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:41 $
 **/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <libxml/parser.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_MANAGED_NETWORKS_CONFIG 1

/**
 * \brief Create the "<Managed_Network>" block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] profs  A config_profiles structure that contains all of the
 *                   variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the "<Managed_Network>" tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_managed_network_create_tree(struct config_managed_networks *nets, 
													 char write_all)
{
	xmlNodePtr netnode = NULL;
	char tempstatic[100];
	
	if (nets == NULL) return NULL;

	// Create the root node for the <Managed_Network> block.
	netnode = xmlNewNode(NULL, "Managed_Network");
	if (netnode == NULL)
	{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
		printf("Couldn't allocate memory to store <Managed_Network> block!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (nets->ou != NULL))
	{
		if (xmlNewChild(netnode, NULL, "OU", nets->ou) == NULL)
		{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
			printf("Couldn't allocate memory to store <OU> node!\n");
#endif
			xmlFreeNode(netnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (nets->key != NULL))
	{
		if (xmlNewChild(netnode, NULL, "Key", nets->key) == NULL)
		{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
			printf("Couldn't allocate memory to store <Key> node!\n");
#endif
			xmlFreeNode(netnode);
			return NULL;
		}
	}

	// We should *ALWAYS* write a Serial_ID.
	sprintf((char *)&tempstatic, "%ld", nets->serialid);
	if (xmlNewChild(netnode, NULL, "Serial_ID", tempstatic) == NULL)
	{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
		printf("Couldn't allocate memory to store <Serial_ID> node!\n");
#endif
		xmlFreeNode(netnode);
		return NULL;
	}

	if ((write_all == TRUE) || (nets->update_url != NULL))
	{
		if (xmlNewChild(netnode, NULL, "Update_URL", nets->update_url) == NULL)
		{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
			printf("Couldn't allocate memory to store <Update_URL> node!\n");
#endif
			xmlFreeNode(netnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (nets->auto_update != 1))
	{
		if (nets->auto_update != 1)
		{
			if (xmlNewChild(netnode, NULL, "Auto_Update", "no") == NULL)
			{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
				printf("Couldn't allocate memory to store <Auto_Update> node!\n");
#endif
				xmlFreeNode(netnode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(netnode, NULL, "Auto_Update", "yes") == NULL)
			{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
				printf("Couldn't allocate memory to store <Auto_Update> node!\n");
#endif
				xmlFreeNode(netnode);
				return NULL;
			}
		}
	}

	// We should *ALWAYS* write an update freq.
	sprintf((char *)&tempstatic, "%d", nets->update_freq);
	if (xmlNewChild(netnode, NULL, "Update_Frequency", tempstatic) == NULL)
	{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
		printf("Couldn't allocate memory to store <Update_Frequency> node!\n");
#endif
		xmlFreeNode(netnode);
		return NULL;
	}

	if ((write_all == TRUE) || (nets->last_update != NULL))
	{
		if (xmlNewChild(netnode, NULL, "Last_Update", nets->last_update) == NULL)
		{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
			printf("Couldn't allocate memory to store <Last_Update> node!\n");
#endif
			xmlFreeNode(netnode);
			return NULL;
		}
	}

	return netnode;
}

/**
 * \brief Create the "<Managed_Networks>" block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] profs  A config_managed_networks structure that contains all of the
 *                   variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the "<Managed_Networks>" tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_managed_networks_create_tree(struct config_managed_networks *nets, 
											 		  char write_all)
{
	xmlNodePtr netsnode = NULL;
	xmlNodePtr netnode = NULL;
	struct config_managed_networks *cur = NULL;
	
	if (nets == NULL) return NULL;

	// Create the root node for the <Managed_Networks> block.
	netsnode = xmlNewNode(NULL, "Managed_Networks");
	if (netsnode == NULL)
	{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
		printf("Couldn't allocate memory to store <Managed_Networks> block!\n");
#endif
		return NULL;
	}

	cur = nets;

	while (cur != NULL)
	{
		netnode = xsupconfwrite_managed_network_create_tree(cur, write_all);
		if (netnode == NULL)
		{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
			printf("Couldn't create <Managed_Network> block!\n");
#endif
			xmlFreeNode(netsnode);
			return NULL;
		}

		if (xmlAddChild(netsnode, netnode) == NULL)
		{
#ifdef WRITE_MANAGED_NETWORKS_CONFIG
			printf("Couldn't add <Managed_Networks> child node!\n");
#endif
			xmlFreeNode(netsnode);
			xmlFreeNode(netnode);
			return NULL;
		}

		cur = cur->next;
	}

	return netsnode;
}
