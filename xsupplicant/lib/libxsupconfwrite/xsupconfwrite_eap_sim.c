/**
 * Implementation for converting variables that make up the SIM configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_sim.c
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
#include "libxsupconfig/pwd_crypt.h"
#include "xsupconfwrite_common.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_EAP_SIM_DEBUG 1


/**
 * \brief Create an EAP-SIM block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] simdata  A config_eap_sim structure that contains all of the
 *                     variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \todo Do we need the <Username> tag to be added?
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the SIM configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_sim_create_tree(struct config_eap_sim *simdata, uint8_t config_type,
										     char write_all)
{
	xmlNodePtr simnode = NULL;
	char *temp = NULL;
	uint16_t ressize;
		
	if (simdata == NULL) return NULL;

	simnode = xsupconfwrite_common_newSibling(NULL, "Type", "SIM");
	if (simnode == NULL)
	{
#ifdef WRITE_EAP_SIM_DEBUG
		printf("Couldn't create <Type> node for SIM!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (simdata->password != NULL))
	{
		if ((simdata->password != NULL) && (pwcrypt_funcs_available() == TRUE))
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt(config_type, (uint8_t *)simdata->password, strlen(simdata->password), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				if (xsupconfwrite_common_newSibling(simnode, "Password", simdata->password) == NULL)
				{
#ifdef WRITE_EAP_SIM_DEBUG
					printf("Couldn't create <Password> node for SIM.\n");
#endif
					xmlFreeNode(simnode);
					return NULL;
				}
			}
			else
			{
				if (xsupconfwrite_common_newSibling(simnode, "Encrypted_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_SIM_DEBUG
					printf("Couldn't create <Encrypted_Password> node.\n");
#endif
					xmlFreeNode(simnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(simnode, "Password", simdata->password) == NULL)
			{
#ifdef WRITE_EAP_SIM_DEBUG
				printf("Couldn't create <Password> node for SIM.\n");
#endif
				xmlFreeNode(simnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (simdata->reader != NULL))
	{
		if (xsupconfwrite_common_newSibling(simnode, "Reader", simdata->reader) == NULL)
		{
#ifdef WRITE_EAP_SIM_DEBUG
			printf("Couldn't create <Reader> node for SIM!\n");
#endif
			return NULL;
		}
	}

	if ((write_all == TRUE) || (simdata->auto_realm == TRUE))
	{
		if (simdata->auto_realm == TRUE)
		{
			if (xsupconfwrite_common_newSibling(simnode, "Auto_Realm", "yes") == NULL)
			{
#ifdef WRITE_EAP_SIM_DEBUG
				printf("Couldn't create <Auto_Realm> node for SIM!\n");
#endif
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(simnode, "Auto_Realm", "no") == NULL)
			{
#ifdef WRITE_EAP_SIM_DEBUG
				printf("Couldn't create <Auto_Realm> node for SIM!\n");
#endif
				return NULL;
			}
		}
	}

	return simnode;
}
