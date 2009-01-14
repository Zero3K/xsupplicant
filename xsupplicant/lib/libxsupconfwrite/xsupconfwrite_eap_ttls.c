/**
 * Implementation for converting variables that make up the TTLS configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_ttls.c
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
// #define WRITE_EAP_TTLS_DEBUG 1


/**
 * \brief Create a EAP-TTLS block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] tlsdata  A config_eap_ttls structure that contains all of the
 *                     variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the TTLS configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_ttls_create_tree(struct config_eap_ttls *ttlsdata, uint8_t config_type, 
										      char write_all)
{
	xmlNodePtr ttlsnode = NULL;
	xmlNodePtr p2node = NULL;
	xmlNodePtr eapnode = NULL;
	char *temp = NULL;
	char tempstatic[10];
	uint16_t ressize = 0;
		
	if (ttlsdata == NULL) return NULL;

	ttlsnode = xsupconfwrite_common_newSibling(NULL, "Type", "TTLS");
	if (ttlsnode == NULL)
	{
#ifdef WRITE_EAP_TTLS_DEBUG
		printf("Couldn't create <Type> node for TTLS!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (ttlsdata->user_cert != NULL))
	{
		if (xsupconfwrite_common_newSibling(ttlsnode, "User_Certificate", ttlsdata->user_cert) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <User_Certificate> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ttlsdata->trusted_server != NULL))
	{
		if (xsupconfwrite_common_newSibling(ttlsnode, "Trusted_Server", ttlsdata->trusted_server) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <Trusted_Server> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (ttlsdata->crl_dir != NULL))
	{
		if (xsupconfwrite_common_newSibling(ttlsnode, "CRL_Directory", ttlsdata->crl_dir) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <CRL_Directory> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ttlsdata->user_key != NULL))
	{
		if (xsupconfwrite_common_newSibling(ttlsnode, "User_Key_File", ttlsdata->user_key) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <User_Key_File> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ttlsdata->user_key_pass != NULL))
	{
		if ((ttlsdata->user_key_pass != NULL) && (pwcrypt_funcs_available() == TRUE))
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt(config_type, (uint8_t *)ttlsdata->user_key_pass, strlen(ttlsdata->user_key_pass), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				xsupconfwrite_convert_amp(ttlsdata->user_key_pass, &temp);
				if (xsupconfwrite_common_newSibling(ttlsnode, "User_Key_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_TTLS_DEBUG
					printf("Couldn't create <User_Key_Password> node for TTLS!\n");
#endif
					xmlFreeNode(ttlsnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
			else
			{
				if (xsupconfwrite_common_newSibling(ttlsnode, "Encrypted_User_Key_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_TTLS_DEBUG
					printf("Couldn't create <Encrypted_User_Key_Password> node.\n");
#endif
					xmlFreeNode(ttlsnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
		}
		else
		{
			xsupconfwrite_convert_amp(ttlsdata->user_key_pass, &temp);
			if (xsupconfwrite_common_newSibling(ttlsnode, "User_Key_Password", temp) == NULL)
			{
#ifdef WRITE_EAP_TTLS_DEBUG
				printf("Couldn't create <User_Key_Password> node for TTLS!\n");
#endif
				xmlFreeNode(ttlsnode);
				free(temp);
				return NULL;
			}

			free(temp);
		}
	}

	if ((write_all == TRUE) || (ttlsdata->session_resume != RES_UNSET))
	{
		switch (ttlsdata->session_resume)
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

		if (xsupconfwrite_common_newSibling(ttlsnode, "Session_Resume", temp) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <Session_Resume> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if (xsupconfwrite_common_write_bool(ttlsnode, "Use_Logon_Credentials", 
		TEST_FLAG(ttlsdata->flags, TTLS_FLAGS_USE_LOGON_CREDS), FALSE, write_all, TRUE) == NULL)
	{
		xmlFreeNode(ttlsnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(ttlsnode, "Validate_Certificate",
		ttlsdata->validate_cert, TRUE, write_all, TRUE) == NULL)
	{
		xmlFreeNode(ttlsnode);
		return NULL;
	}

	if ((write_all == TRUE) || (ttlsdata->chunk_size != 0))
	{
		sprintf((char *)&tempstatic, "%d", ttlsdata->chunk_size);

		if (xsupconfwrite_common_newSibling(ttlsnode, "Chunk_Size", tempstatic) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <Chunk_Size> node for TLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ttlsdata->random_file != NULL))
	{
		if (xsupconfwrite_common_newSibling(ttlsnode, "Random_File", ttlsdata->random_file) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <Random_File> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ttlsdata->inner_id != NULL))
	{
		xsupconfwrite_convert_amp(ttlsdata->inner_id, &temp);
		if (xsupconfwrite_common_newSibling(ttlsnode, "Inner_ID", temp) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create <Inner_ID> node for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	switch (ttlsdata->phase2_type)
	{
	case TTLS_PHASE2_PAP:
		temp = _strdup("PAP");
		break;

	case TTLS_PHASE2_CHAP:
		temp = _strdup("CHAP");
		break;

	case TTLS_PHASE2_MSCHAP:
		temp = _strdup("MSCHAP");
		break;

	case TTLS_PHASE2_MSCHAPV2:
		temp = _strdup("MSCHAPv2");
		break;

	case TTLS_PHASE2_EAP:
		temp = _strdup("EAP");
		break;
	case TTLS_PHASE2_UNDEFINED:
	        temp = _strdup("UNDEFINED");
		break;
	// This should never happen, but we're better safe than sorry.
        default:
	        temp = _strdup("UNKNOWN");
		break;
	}

	if (xsupconfwrite_common_newSibling(ttlsnode, "Inner_Method", temp) == NULL)
	{
#ifdef WRITE_EAP_TTLS_DEBUG
		printf("Couldn't create <Inner_Method> node for TTLS!\n");
#endif
		xmlFreeNode(ttlsnode);
		return NULL;
	}

	free(temp);
	temp = NULL;

	p2node = xmlNewNode(NULL, (xmlChar *)"Phase2");
	if (p2node == NULL)
	{
#ifdef WRITE_EAP_TTLS_DEBUG
		printf("Couldn't create <Phase2> node for TTLS!\n");
#endif
		xmlFreeNode(ttlsnode);
		return NULL;
	}

	p2node = xmlAddSibling(ttlsnode, p2node);
	if (p2node == NULL)
	{
#ifdef WRITE_EAP_TTLS_DEBUG
		printf("Couldn't add <Phase2> node to TTLS!\n");
#endif
		xmlFreeNode(ttlsnode);
		return NULL;
	}
	
	switch (ttlsdata->phase2_type)
	{
	case TTLS_PHASE2_PAP:
	case TTLS_PHASE2_CHAP:
	case TTLS_PHASE2_MSCHAP:
	case TTLS_PHASE2_MSCHAPV2:
		if (((struct config_pwd_only *)(ttlsdata->phase2_data)) != NULL)
		{
			if (pwcrypt_funcs_available() == TRUE)
			{
				if ((ttlsdata->phase2_data != NULL) && (((struct config_pwd_only *)(ttlsdata->phase2_data))->password != NULL))
				{
					// Write the encrypted version.
					if (pwcrypt_encrypt(config_type, (uint8_t *)(((struct config_pwd_only *)(ttlsdata->phase2_data))->password), strlen(((struct config_pwd_only *)(ttlsdata->phase2_data))->password), (uint8_t **)&temp, &ressize) != 0)
					{
						// Couldn't encrypt the data.  So write the cleartext version.
						xsupconfwrite_convert_amp(((struct config_pwd_only *)(ttlsdata->phase2_data))->password, &temp);
						if (xmlNewChild(p2node, NULL, (xmlChar *)"Password", (xmlChar *)temp) == NULL)
						{
#ifdef WRITE_EAP_TTLS_DEBUG
							printf("Couldn't create <Password> node for phase 2 TTLS!\n");
#endif
							xmlFreeNode(ttlsnode);
							free(temp);
							return NULL;
						}

						free(temp);
					}
					else
					{
						if (xmlNewChild(p2node, NULL, (xmlChar *)"Encrypted_Password", (xmlChar *)temp) == NULL)
						{
#ifdef WRITE_EAP_TTLS_DEBUG
							printf("Couldn't create <Password> node for phase 2 TTLS!\n");
#endif
							free(temp);
							xmlFreeNode(ttlsnode);
							return NULL;
						}
						free(temp);
					}
				}
			}
			else
			{
				xsupconfwrite_convert_amp(((struct config_pwd_only *)(ttlsdata->phase2_data))->password, &temp);
				if (xmlNewChild(p2node, NULL, (xmlChar *)"Password", (xmlChar *)temp) == NULL)
				{
#ifdef WRITE_EAP_TTLS_DEBUG
					printf("Couldn't create <Password> node for phase 2 TTLS!\n");
#endif
					xmlFreeNode(ttlsnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
		}
		break;

	case TTLS_PHASE2_EAP:
		eapnode = xsupconfwrite_eap_create_tree(ttlsdata->phase2_data, config_type, write_all);
		if (eapnode == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't create phase 2 <EAP> data for TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}

		if (xmlAddChild(p2node, eapnode) == NULL)
		{
#ifdef WRITE_EAP_TTLS_DEBUG
			printf("Couldn't add phase 2 EAP data to TTLS!\n");
#endif
			xmlFreeNode(ttlsnode);
			return NULL;
		}
		break;
	case TTLS_PHASE2_UNDEFINED:
	  printf("Error: Unexpected phase 2 type TTLS_PHASE2_UNDEFINED\n");
	  break;
	default:
	  printf("Error: Unexpectedly reached default case at %s:%d\n", __FUNCTION__, __LINE__);
	  break;								     
	}

	return ttlsnode;
}
