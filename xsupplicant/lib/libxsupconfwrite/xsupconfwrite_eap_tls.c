/**
 * Implementation for converting variables that make up the TLS configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_tls.c
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
// #define WRITE_EAP_TLS_DEBUG 1


/**
 * \brief Create a EAP-TLS block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] tlsdata  A config_eap_tls structure that contains all of the
 *                     variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the TLS configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_tls_create_tree(struct config_eap_tls *tlsdata, uint8_t config_type,
										      char write_all)
{
	xmlNodePtr tlsnode = NULL;
	char *temp = NULL;
	char tempstatic[10];
	uint16_t ressize = 0;
		
	if (tlsdata == NULL) return NULL;

	tlsnode = xsupconfwrite_common_newSibling(NULL, "Type", "TLS");
	if (tlsnode == NULL)
	{
#ifdef WRITE_EAP_TLS_DEBUG
		printf("Couldn't create <Type> node for TLS!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (tlsdata->user_cert != NULL))
	{
		if (xsupconfwrite_common_newSibling(tlsnode, "User_Certificate", tlsdata->user_cert) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <User_Certificate> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (tlsdata->trusted_server != NULL))
	{
		xsupconfwrite_convert_amp(tlsdata->trusted_server, &temp);
		if (xsupconfwrite_common_newSibling(tlsnode, "Trusted_Server", temp) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <Trusted_Server> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (tlsdata->crl_dir != NULL))
	{
		if (xsupconfwrite_common_newSibling(tlsnode, "CRL_Directory", tlsdata->crl_dir) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <CRL_Directory> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (tlsdata->user_key != NULL))
	{
		if (xsupconfwrite_common_newSibling(tlsnode, "User_Key_File", tlsdata->user_key) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <User_Key_File> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (tlsdata->user_key_pass != NULL))
	{
		if ((tlsdata->user_key_pass != NULL) && (pwcrypt_funcs_available() == TRUE))
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt(config_type, (uint8_t *)tlsdata->user_key_pass, strlen(tlsdata->user_key_pass), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				xsupconfwrite_convert_amp(tlsdata->user_key_pass, &temp);
				if (xsupconfwrite_common_newSibling(tlsnode, "User_Key_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_TLS_DEBUG
					printf("Couldn't create <User_Key_Password> node for TLS!\n");
#endif
					xmlFreeNode(tlsnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
			else
			{
				if (xsupconfwrite_common_newSibling(tlsnode, "Encrypted_User_Key_Password", temp) == NULL)
				{
#ifdef WRITE_EAP_TLS_DEBUG
					printf("Couldn't create <Encrypted_User_Key_Password> node.\n");
#endif
					xmlFreeNode(tlsnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
		}
		else
		{
			xsupconfwrite_convert_amp(tlsdata->user_key_pass, &temp);
			if (xsupconfwrite_common_newSibling(tlsnode, "User_Key_Password", temp) == NULL)
			{
#ifdef WRITE_EAP_TLS_DEBUG
				printf("Couldn't create <User_Key_Password> node for TLS!\n");
#endif
				xmlFreeNode(tlsnode);
				free(temp);
				return NULL;
			}

			free(temp);
		}
	}

	if (xsupconfwrite_common_write_bool(tlsnode, "Session_Resume", 
		TEST_FLAG(tlsdata->flags, EAP_TLS_FLAGS_SESSION_RESUME), FALSE, write_all, TRUE) == NULL)
	{
		xmlFreeNode(tlsnode);
		return NULL;
	}

	if ((write_all == TRUE) || (tlsdata->chunk_size != 0))
	{
		sprintf((char *)&tempstatic, "%d", tlsdata->chunk_size);

		if (xsupconfwrite_common_newSibling(tlsnode, "Chunk_Size", tempstatic) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <Chunk_Size> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (tlsdata->random_file != NULL))
	{
		if (xsupconfwrite_common_newSibling(tlsnode, "Random_File", tlsdata->random_file) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <Random_File> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (tlsdata->store_type != NULL))
	{
		if (xsupconfwrite_common_newSibling(tlsnode, "Store_Type", tlsdata->store_type) == NULL)
		{
#ifdef WRITE_EAP_TLS_DEBUG
			printf("Couldn't create <Store_Type> node for TLS!\n");
#endif
			xmlFreeNode(tlsnode);
			return NULL;
		}
	}

	// XXX The OpenSC stuff isn't implemented for now because it will probably
	// change.
	return tlsnode;
}
