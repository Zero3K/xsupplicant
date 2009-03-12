/**
 * Implementation for converting variables that make up the EAP-MSCHAPv2 configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_mschapv2.c
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
// #define WRITE_EAP_MSCHAPV2_DEBUG 1

/**
 * \brief Create an EAP-MSCHAPv2 block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] chap2data  A config_eap_mschapv2 structure that contains all of the
 *                       variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the EAP-MSCHAPv2 configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_mschapv2_create_tree(struct config_eap_mschapv2 *
						  chap2data,
						  uint8_t config_type,
						  char write_all)
{
	xmlNodePtr chap2node = NULL;
	char *temp = NULL;
	uint16_t ressize;

	if (chap2data == NULL)
		return NULL;

	chap2node = xsupconfwrite_common_newSibling(NULL, "Type", "MSCHAPv2");
	if (chap2node == NULL) {
#ifdef WRITE_EAP_MSCHAPV2_DEBUG
		printf("Couldn't create <Type> node for MSCHAPv2!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (chap2data->password != NULL)) {
		if ((chap2data->password != NULL)
		    && (pwcrypt_funcs_available() == TRUE)) {
			// Write the encrypted version.
			if (pwcrypt_encrypt
			    (config_type, (uint8_t *) chap2data->password,
			     strlen(chap2data->password), (uint8_t **) & temp,
			     &ressize) != 0) {
				// Couldn't encrypt the data.  So write the cleartext version.
				xsupconfwrite_convert_amp(chap2data->password,
							  &temp);
				if (xsupconfwrite_common_newSibling
				    (chap2node, "Password", temp) == NULL) {
#ifdef WRITE_EAP_MSCHAPV2_DEBUG
					printf
					    ("Couldn't create <Password> node for MSCHAPv2.\n");
#endif
					xmlFreeNode(chap2node);
					free(temp);
					return NULL;
				}

				free(temp);
			} else {
				if (xsupconfwrite_common_newSibling
				    (chap2node, "Encrypted_Password",
				     temp) == NULL) {
#ifdef WRITE_EAP_MSCHAPV2_DEBUG
					printf
					    ("Couldn't create <Encrypted_Password> node.\n");
#endif
					xmlFreeNode(chap2node);
					free(temp);
					return NULL;
				}
				free(temp);
			}
		} else {
			xsupconfwrite_convert_amp(chap2data->password, &temp);
			if (xsupconfwrite_common_newSibling
			    (chap2node, "Password", temp) == NULL) {
#ifdef WRITE_EAP_MSCHAPV2_DEBUG
				printf
				    ("Couldn't create <Password> node for MSCHAPv2.\n");
#endif
				xmlFreeNode(chap2node);
				free(temp);
				return NULL;
			}

			free(temp);
		}
	}

	if ((write_all == TRUE) || (chap2data->nthash != NULL)) {
		if (xsupconfwrite_common_newSibling
		    (chap2node, "NT_Password_Hash",
		     chap2data->nthash) == NULL) {
#ifdef WRITE_EAP_MSCHAPV2_DEBUG
			printf
			    ("Couldn't create <NT_Password_Hash> node for MSCHAPv2!\n");
#endif
			xmlFreeNode(chap2node);
			return NULL;
		}
	}

	if (xsupconfwrite_common_write_bool(chap2node, "IAS_Quirk",
					    TEST_FLAG(chap2data->flags,
						      FLAGS_EAP_MSCHAPV2_IAS_QUIRK),
					    FALSE, write_all, TRUE) == NULL) {
		xmlFreeNode(chap2node);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool
	    (chap2node, "Machine_Authentication_Mode",
	     TEST_FLAG(chap2data->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH),
	     FALSE, write_all, TRUE) == NULL) {
		xmlFreeNode(chap2node);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(chap2node, "Use_Logon_Credentials",
					    TEST_FLAG(chap2data->flags,
						      FLAGS_EAP_MSCHAPV2_USE_LOGON_CREDS),
					    FALSE, write_all, TRUE) == NULL) {
		xmlFreeNode(chap2node);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(chap2node, "Volatile",
					    TEST_FLAG(chap2data->flags,
						      FLAGS_EAP_MSCHAPV2_VOLATILE),
					    FALSE, write_all, TRUE) == NULL) {
		xmlFreeNode(chap2node);
		return NULL;
	}

	return chap2node;
}
