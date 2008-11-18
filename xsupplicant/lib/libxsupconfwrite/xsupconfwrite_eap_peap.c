/**
 * Implementation for converting variables that make up the PEAP configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_peap.c
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
#include "xsupconfwrite_eap.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_EAP_PEAP_DEBUG 1


/**
 * \brief Create a EAP-PEAP block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] peapdata  A config_eap_tls structure that contains all of the
 *                      variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the PEAP configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_peap_create_tree(struct config_eap_peap *peapdata, uint8_t config_type,
								 		      char write_all)
{
	xmlNodePtr peapnode = NULL;
	xmlNodePtr p2node = NULL;
	xmlNodePtr eapnode = NULL;
	char *temp = NULL;
	char tempstatic[10];
	uint16_t ressize;

		
	if (peapdata == NULL) return NULL;

	peapnode = xsupconfwrite_common_newSibling(NULL, "Type", "PEAP");
	if (peapnode == NULL)
	{
#ifdef WRITE_EAP_PEAP_DEBUG
		printf("Couldn't create <Type> node for PEAP!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (peapdata->user_cert != NULL))
	{
		if (xsupconfwrite_common_newSibling(peapnode, "User_Certificate", peapdata->user_cert) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <User_Certificate> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->trusted_server != NULL))
	{
		if (xsupconfwrite_common_newSibling(peapnode, "Trusted_Server", peapdata->trusted_server) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <Trusted_Server> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->crl_dir != NULL))
	{
		if (xsupconfwrite_common_newSibling(peapnode, "CRL_Directory", peapdata->crl_dir) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <CRL_Directory> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->user_key != NULL))
	{
		if (xsupconfwrite_common_newSibling(peapnode, "User_Key_File", peapdata->user_key) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <User_Key_File> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->user_key_pass != NULL))
	{
		if ((peapdata->user_key_pass != NULL) && (pwcrypt_funcs_available() == TRUE))
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt(config_type, (uint8_t *)peapdata->user_key_pass, strlen(peapdata->user_key_pass), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				xsupconfwrite_convert_amp(peapdata->user_key_pass, &temp);
				if (xsupconfwrite_common_newSibling(peapnode, "User_Key_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_PEAP_DEBUG
					printf("Couldn't create <User_Key_Password> node for PEAP!\n");
#endif
					xmlFreeNode(peapnode);
					return NULL;
				}
			}
			else
			{
				if (xsupconfwrite_common_newSibling(peapnode, "Encrypted_User_Key_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_PEAP_DEBUG
					printf("Couldn't create <Encrypted_User_Key_Password> node.\n");
#endif
					xmlFreeNode(peapnode);
					return NULL;
				}
			}
		}
		else
		{
			xsupconfwrite_convert_amp(peapdata->user_key_pass, &temp);
			if (xsupconfwrite_common_newSibling(peapnode, "User_Key_Password", temp) == NULL)
			{
#ifdef WRITE_EAP_PEAP_DEBUG
				printf("Couldn't create <User_Key_Password> node for PEAP!\n");
#endif
				xmlFreeNode(peapnode);
				free(temp);
				return NULL;
			}

			free(temp);
		}
	}

	if ((write_all == TRUE) || (peapdata->session_resume != RES_UNSET))
	{
		switch (peapdata->session_resume)
		{
		default:
		case RES_NO:
		case RES_UNSET:
			temp = _strdup("no");  // Default setting.
			break;

		case RES_YES:
			temp = _strdup("yes");
			break;
		}

		if (xsupconfwrite_common_newSibling(peapnode, "Session_Resume", temp) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <Session_Resume> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (peapdata->chunk_size != 0))
	{
		sprintf((char *)&tempstatic, "%d", peapdata->chunk_size);

		if (xsupconfwrite_common_newSibling(peapnode, "Chunk_Size", tempstatic) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <Chunk_Size> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->random_file != NULL))
	{
		if (xsupconfwrite_common_newSibling(peapnode, "Random_File", peapdata->random_file) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <Random_File> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->validate_cert != TRUE))
	{
		if (peapdata->validate_cert != FALSE)
		{
			if (xsupconfwrite_common_newSibling(peapnode, "Validate_Certificate", "yes") == NULL)
			{
#ifdef WRITE_EAP_PEAP_DEBUG
				printf("Couldn't create <Validate_Certificate> for PEAP!\n");
#endif
				xmlFreeNode(peapnode);
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(peapnode, "Validate_Certificate", "no") == NULL)
			{
#ifdef WRITE_EAP_PEAP_DEBUG
				printf("Couldn't create <Validate_Certificate> for PEAP!\n");
#endif
				xmlFreeNode(peapnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (peapdata->proper_peapv1 != FALSE))
	{
		if (peapdata->proper_peapv1 != FALSE)
		{
			if (xsupconfwrite_common_newSibling(peapnode, "Proper_PEAP_V1_Keying", "yes") == NULL)
			{
#ifdef WRITE_EAP_PEAP_DEBUG
				printf("Couldn't create <Proper_PEAP_V1_Keying> for PEAP!\n");
#endif
				xmlFreeNode(peapnode);
				return NULL;
			}
		}
		else
		{
			if (xsupconfwrite_common_newSibling(peapnode, "Proper_PEAP_V1_Keying", "no") == NULL)
			{
#ifdef WRITE_EAP_PEAP_DEBUG
				printf("Couldn't create <Proper_PEAP_V1_Keying> for PEAP!\n");
#endif
				xmlFreeNode(peapnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (peapdata->force_peap_version != 0xff))
	{
		sprintf((char *)&tempstatic, "%d", peapdata->force_peap_version);
		if (xsupconfwrite_common_newSibling(peapnode, "Force_PEAP_Version", tempstatic) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <Force_PEAP_Version> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (peapdata->identity != NULL))
	{
		xsupconfwrite_convert_amp(peapdata->identity, &temp);
		if (xsupconfwrite_common_newSibling(peapnode, "Inner_ID", temp) == NULL)
		{
#ifdef WRITE_EAP_PEAP_DEBUG
			printf("Couldn't create <Inner_ID> node for PEAP!\n");
#endif
			xmlFreeNode(peapnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	p2node = xmlNewNode(NULL, (xmlChar *)"Phase2");
	if (p2node == NULL)
	{
#ifdef WRITE_EAP_PEAP_DEBUG
		printf("Couldn't create <Phase2> node for PEAP!\n");
#endif
		xmlFreeNode(peapnode);
		return NULL;
	}

	p2node = xmlAddSibling(peapnode, p2node);
	if (p2node == NULL)
	{
#ifdef WRITE_EAP_PEAP_DEBUG
		printf("Couldn't add <Phase2> node to PEAP!\n");
#endif
		xmlFreeNode(peapnode);
		return NULL;
	}

	eapnode = xsupconfwrite_eap_create_tree(peapdata->phase2, config_type, write_all);
	if (eapnode == NULL)
	{
#ifdef WRITE_EAP_PEAP_DEBUG
		printf("Couldn't create phase 2 <EAP> data for PEAP!\n");
#endif
		xmlFreeNode(peapnode);
		return NULL;
	}

	if (xmlAddChild(p2node, eapnode) == NULL)
	{
#ifdef WRITE_EAP_PEAP_DEBUG
		printf("Couldn't add phase 2 EAP data to PEAP!\n");
#endif
		xmlFreeNode(peapnode);
		return NULL;
	}

	return peapnode;
}
