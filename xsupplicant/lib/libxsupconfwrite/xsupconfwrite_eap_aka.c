/**
 * Implementation for converting variables that make up the AKA configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_aka.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfwrite_eap_aka.c,v 1.5 2007/10/22 03:29:06 galimorerpg Exp $
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

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "libxsupconfig/pwd_crypt.h"
#include "xsupconfwrite_common.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_EAP_AKA_DEBUG 1


/**
 * \brief Create an EAP-AKA block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] akadata  A config_eap_aka structure that contains all of the
 *                     variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \todo Do we need the <Username> tag to be added?
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the AKA configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_aka_create_tree(struct config_eap_aka *akadata, 
										     char write_all)
{
	xmlNodePtr akanode = NULL;
	char *temp = NULL;
	uint16_t ressize;
		
	if (akadata == NULL) return NULL;

	akanode = xsupconfwrite_common_newSibling(NULL, "Type", "AKA");
	if (akanode == NULL)
	{
#ifdef WRITE_EAP_AKA_DEBUG
		printf("Couldn't create <Type> node for AKA!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (akadata->password != NULL))
	{
		if ((akadata->password != NULL) && (pwcrypt_funcs_available() == TRUE))
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt((uint8_t *)akadata->password, strlen(akadata->password), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				if (xmlNewChild(akanode, NULL, (xmlChar *)"Encrypted_Password", (xmlChar *)akadata->password) == NULL)
				{
#ifdef WRITE_EAP_AKA_DEBUG
					printf("Couldn't create <Encrypted_Password> node.\n");
#endif
					xmlFreeNode(akanode);
					return NULL;
				}
			}
			else
			{
				// For AKA, the "password" is a PIN, so we shouldn't need to worry about the existance of an & in it.
				if (xsupconfwrite_common_newSibling(akanode, "Password", akadata->password) == NULL)
				{
#ifdef WRITE_EAP_AKA_DEBUG
					printf("Couldn't create <Password> node for AKA.\n");
#endif
					return NULL;
				}
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(akanode, "Password", akadata->password) == NULL)
			{
#ifdef WRITE_EAP_AKA_DEBUG
				printf("Couldn't create <Password> node for AKA.\n");
#endif
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (akadata->auto_realm == TRUE))
	{
		if (akadata->auto_realm == TRUE)
		{
			if (xsupconfwrite_common_newSibling(akanode, "Auto_Realm", "yes") == NULL)
			{
#ifdef WRITE_EAP_AKA_DEBUG
				printf("Couldn't create <Auto_Realm> node for AKA!\n");
#endif
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(akanode, "Auto_Realm", "no") == NULL)
			{
#ifdef WRITE_EAP_AKA_DEBUG
				printf("Couldn't create <Auto_Realm> node for AKA!\n");
#endif
				return NULL;
			}
		}
	}

	return akanode;
}
