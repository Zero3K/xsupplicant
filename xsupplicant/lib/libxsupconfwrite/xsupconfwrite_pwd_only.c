/**
 * Implementation for converting variables that make up the <EAP> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_pwd_only.c
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

#include "src/xsup_common.h"

#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "libxsupconfig/pwd_crypt.h"
#include "xsupconfwrite_common.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_PWD_ONLY_DEBUG 1


/**
 * \brief Create a password only block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] pwdonly  A config_pwd_only structure that contains all of the
 *                     variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the password only tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_pwd_only_create_tree(char *tagname, 
											  struct config_pwd_only *pwdonly, uint8_t config_type,
										      char write_all)
{
	xmlNodePtr pwdnode = NULL;
	char *temp = NULL;
	uint16_t ressize = 0;

		
	if ((tagname == NULL) || (pwdonly == NULL)) return NULL;

	pwdnode = xsupconfwrite_common_newSibling(NULL, "Type", tagname);
	if (pwdnode == NULL)
	{
#ifdef WRITE_PWD_ONLY_CONFIG
		printf("Couldn't allocate memory to store <%s> block!\n", tagname);
#endif
		return NULL;
	}
	
	if (pwdonly->password != NULL)
	{
		if (pwcrypt_funcs_available() == TRUE)
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt(config_type, (uint8_t *)pwdonly->password, strlen(pwdonly->password), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				xsupconfwrite_convert_amp(pwdonly->password, &temp);
				if (xsupconfwrite_common_newSibling(pwdnode, "Password", temp) == NULL)
				{
#ifdef WRITE_PWD_ONLY_CONFIG
					printf("Couldn't allocate memory to store <Password> node!\n");
#endif
					xmlFreeNode(pwdnode);
					free(temp);
					return NULL;
				}

				free(temp);
			}
			else
			{
				if (xsupconfwrite_common_newSibling(pwdnode, "Encrypted_Password", temp) == NULL)
				{
#ifdef WRITE_PWD_ONLY_CONFIG
					printf("Couldn't create <Encrypted_Password> node.\n");
#endif
					xmlFreeNode(pwdnode);
					free(temp);
					return NULL;
				}
				free(temp);
			}
		}
		else
		{
			xsupconfwrite_convert_amp(pwdonly->password, &temp);
			if (xsupconfwrite_common_newSibling(pwdnode, "Password", temp) == NULL)
			{
#ifdef WRITE_PWD_ONLY_CONFIG
				printf("Couldn't allocate memory to store <Password> node!\n");
#endif
				xmlFreeNode(pwdnode);
				free(temp);
				return NULL;
			}

			free(temp);
		}
	}

	return pwdnode;
}
