/**
 * Implementation for converting variables that make up the FAST configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_fast.c
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
#include "xsupconfwrite_common.h"
#include "xsupconfwrite_eap.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_EAP_FAST_DEBUG 1


/**
 * \brief Create an EAP-FAST block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] chap2data  A config_eap_fast structure that contains all of the
 *                       variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the EAP-FAST configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_fast_create_tree(struct config_eap_fast *fastdata, uint8_t config_type,
									   	          char write_all)
{
	xmlNodePtr fastnode = NULL;
	xmlNodePtr eapnode = NULL;
	xmlNodePtr p2node = NULL;
	char tempstatic[10];
	char *temp = NULL;
		
	if (fastdata == NULL) return NULL;

	fastnode = xsupconfwrite_common_newSibling(NULL, "Type", "FAST");
	if (fastnode == NULL)
	{
#ifdef WRITE_EAP_FAST_DEBUG
		printf("Couldn't create <Type> node for FAST!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (fastdata->pac_location != NULL))
	{
		if (xsupconfwrite_common_newSibling(fastnode, "PAC_File", fastdata->pac_location) == NULL)
		{
#ifdef WRITE_EAP_FAST_DEBUG
			printf("Couldn't create <PAC_File> node for FAST.\n");
#endif
			xmlFreeNode(fastnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (!TEST_FLAG(fastdata->provision_flags, EAP_FAST_PROVISION_ALLOWED)))
	{
		if (!TEST_FLAG(fastdata->provision_flags, EAP_FAST_PROVISION_ALLOWED))
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Allow_Provision", "no") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Allow_Provision> node for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Allow_Provision", "yes") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Allow_Provision> node for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (TEST_FLAG(fastdata->provision_flags, EAP_FAST_PROVISION_ANONYMOUS)))
	{
		if (!TEST_FLAG(fastdata->provision_flags, EAP_FAST_PROVISION_ANONYMOUS))
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Allow_Anonymous_Provision", "no") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Allow_Anonymous_Provision> node for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Allow_Anonymous_Provision", "yes") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Allow_Anonymous_Provision> node for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (!TEST_FLAG(fastdata->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED)))
	{
		if (!TEST_FLAG(fastdata->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED))
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Allow_Authenticated_Provision", "no") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Allow_Authenticated_Provision> node for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Allow_Authenticated_Provision", "yes") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Allow_Authenticated_Provision> node for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (fastdata->chunk_size != 0))
	{
		sprintf((char *)&tempstatic, "%d", fastdata->chunk_size);
		if (xsupconfwrite_common_newSibling(fastnode, "Chunk_Size", tempstatic) == NULL)
		{
#ifdef WRITE_EAP_FAST_DEBUG
			printf("Couldn't create <Chunk_Size> node for FAST!\n");
#endif
			xmlFreeNode(fastnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (fastdata->innerid != NULL))
	{
		xsupconfwrite_convert_amp(fastdata->innerid, &temp);
		if (xsupconfwrite_common_newSibling(fastnode, "Inner_ID", temp) == NULL)
		{
#ifdef WRITE_EAP_FAST_DEBUG
			printf("Couldn't create <Inner_ID> node for FAST!\n");
#endif
			free(temp);
			xmlFreeNode(fastnode);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (fastdata->trusted_server != NULL))
	{
		if (xsupconfwrite_common_newSibling(fastnode, "Trusted_Server", fastdata->trusted_server) == NULL)
		{
#ifdef WRITE_EAP_FAST_DEBUG
			printf("Couldn't create <Trusted_Server> node for FAST!\n");
#endif
			xmlFreeNode(fastnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (fastdata->validate_cert != TRUE))
	{
		if (fastdata->validate_cert != FALSE)
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Validate_Certificate", "yes") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Validate_Certificate> for PEAP!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(fastnode, "Validate_Certificate", "no") == NULL)
			{
#ifdef WRITE_EAP_FAST_DEBUG
				printf("Couldn't create <Validate_Certificate> for FAST!\n");
#endif
				xmlFreeNode(fastnode);
				return NULL;
			}
		}
	}

	p2node = xmlNewNode(NULL, (xmlChar *)"Phase2");
	if (p2node == NULL)
	{
#ifdef WRITE_EAP_FAST_DEBUG
		printf("Couldn't create <Phase2> node for FAST!\n");
#endif
		xmlFreeNode(fastnode);
		return NULL;
	}

	p2node = xmlAddSibling(fastnode, p2node);
	if (p2node == NULL)
	{
#ifdef WRITE_EAP_FAST_DEBUG
		printf("Couldn't add <Phase2> node to FAST!\n");
#endif
		xmlFreeNode(fastnode);
		return NULL;
	}

	eapnode = xsupconfwrite_eap_create_tree(fastdata->phase2, config_type, write_all);
	if (eapnode == NULL)
	{
#ifdef WRITE_EAP_FAST_DEBUG
		printf("Couldn't create phase 2 <EAP> data for FAST!\n");
#endif
		xmlFreeNode(fastnode);
		return NULL;
	}

	if (xmlAddChild(p2node, eapnode) == NULL)
	{
#ifdef WRITE_EAP_FAST_DEBUG
		printf("Couldn't add phase 2 EAP data to FAST!\n");
#endif
		xmlFreeNode(fastnode);
		return NULL;
	}

	return fastnode;
}
