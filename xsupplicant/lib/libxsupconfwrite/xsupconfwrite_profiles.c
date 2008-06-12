/**
 * Implementation for converting variables that make up the <Connections> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_profiles.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfwrite_profiles.c,v 1.5 2007/10/22 03:29:06 galimorerpg Exp $
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
#include "xsupconfwrite.h"
#include "xsupconfwrite_common.h"
#include "xsupconfwrite_eap.h"
#include "src/eap_types/tnc/tnc_compliance_options.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_PROFILES_CONFIG 1

/**
 * \brief Create the <Compliance> block that can be part of the <Profile> block for the
 *        configuration file, in a format that libxml2 can understand.
 *
 * @param[in] profs   A config_profiles structure that contains all of the variables
 *                    that we want to convert to XML.
 * @param[in] parent   The xmlNodePtr structure that contains the parent <Profile>.
 * @param[in] write_all   A T/F value that indicates if we should write the data event
 *                        if it is set to it's default value.
 *
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Profile> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_profile_compliance_create_tree(struct config_profiles *profs, 
														xmlNodePtr parent, char write_all)
{
	xmlNodePtr compliance = NULL;
	char *temp = NULL;

	compliance = xmlNewChild(parent, NULL, (xmlChar *)"Compliance", NULL);
	if (compliance == NULL) return NULL;   //ACK!

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ENABLE)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ENABLE))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Enable", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_PERSONALITY_CHECK)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_PERSONALITY_CHECK))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Personality_Check", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_FIREWALL_CHECK)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_FIREWALL_CHECK))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Firewall_Check", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}
		
		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ANTI_SPYWARE_CHECK)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ANTI_SPYWARE_CHECK))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Anti_Spyware_Check", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ANTI_VIRUS_CHECK)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ANTI_VIRUS_CHECK))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Anti_Virus_Check", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ANTI_PHISHING_CHECK)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ANTI_PHISHING_CHECK))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Anti_Phishing_Check", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ALLOW_FULL_SCAN)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ALLOW_FULL_SCAN))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Allow_Full_Scan", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (!TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ALLOW_AUTO_UPDATE)))
	{
		if (TEST_FLAG(profs->compliance, TNC_COMPLIANCE_ALLOW_AUTO_UPDATE))
		{
			temp = _strdup("yes");
		}
		else
		{
			temp = _strdup("no");
		}

		if (xmlNewChild(compliance, NULL, (xmlChar *)"Allow_Auto_Update", (xmlChar *)temp) == NULL)
		{
			xmlFreeNode(compliance);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	return compliance;
}

/**
 * \brief Create the <Profile> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] profs  A config_profiles structure that contains all of the
 *                   variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Profile> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_profile_create_tree(struct config_profiles *profs, 
											 char write_all)
{
	xmlNodePtr profnode = NULL;
	xmlNodePtr eapnode = NULL;
	char *temp = NULL;
	char temp_str[10];
	
	if (profs == NULL) return NULL;

	// Create the root node for the <Profiles> block.
	profnode = xmlNewNode(NULL, (xmlChar *)"Profile");
	if (profnode == NULL)
	{
#ifdef WRITE_PROFILES_CONFIG
		printf("Couldn't allocate memory to store <Profile> block!\n");
#endif
		return NULL;
	}

	if (profs->ou != NULL)
	{
		xmlSetProp(profnode, (xmlChar *)"OU", (xmlChar *)profs->ou);
	}

	if ((write_all == TRUE) || (profs->name != NULL))
	{
		xsupconfwrite_convert_amp(profs->name, &temp);
		if (xmlNewChild(profnode, NULL, (xmlChar *)"Name", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_PROFILES_CONFIG
			printf("Couldn't allocate memory to store <Name> node!\n");
#endif
			xmlFreeNode(profnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (profs->identity != NULL))
	{
		xsupconfwrite_convert_amp(profs->identity, &temp);
		if (xmlNewChild(profnode, NULL, (xmlChar *)"Identity", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_PROFILES_CONFIG
			printf("Couldn't allocate memory to store <Identity> node!\n");
#endif
			xmlFreeNode(profnode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (TEST_FLAG(profs->flags, CONFIG_VOLATILE_PROFILE)))
	{
		if (TEST_FLAG(profs->flags, CONFIG_VOLATILE_PROFILE))
		{
			if (xmlNewChild(profnode, NULL, (xmlChar *)"Volatile", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_PROFILES_CONFIG
				printf("Couldn't allocate memory to store <Volatile> node!\n");
#endif
				xmlFreeNode(profnode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(profnode, NULL, (xmlChar *)"Volatile", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_PROFILES_CONFIG
				printf("Couldn't allocate memory to store <Volatile> node!\n");
#endif
				xmlFreeNode(profnode);
				return NULL;
			}
		}
	}

	eapnode = xsupconfwrite_eap_create_tree(profs->method, write_all);
	if (eapnode == NULL)
	{
#ifdef WRITE_PROFILES_CONFIG
		printf("Couldn't allocate memory to store <EAP> node(s)!\n");
#endif
		xmlFreeNode(profnode);
		return NULL;
	}

	if (xmlAddChild(profnode, eapnode) == NULL)
	{
#ifdef WRITE_PROFILES_CONFIG
		printf("Couldn't add <EAP> node as a child to <Profile> node!\n");
#endif
		xmlFreeNode(profnode);
		return NULL;
	}

	if (xsupconfwrite_profile_compliance_create_tree(profs, profnode, write_all) == NULL)
	{
#ifdef WRITE_PROFILES_CONFIG
		printf("Couldn't add <Compliance> node as a child to <Profiles> node!\n");
#endif
		xmlFreeNode(profnode);
		return NULL;
	}

	return profnode;
}

/**
 * \brief Create the <Profiles> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] profs  A config_profiles structure that contains all of the
 *                   variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Profiles> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_profiles_create_tree(struct config_profiles *profs, 
													 char write_all, char write_to_disk)
{
	xmlNodePtr profsnode = NULL;
	xmlNodePtr profnode = NULL;
	struct config_profiles *cur = NULL;
	
	if (profs == NULL) return NULL;

	// Create the root node for the <Profiles> block.
	profsnode = xmlNewNode(NULL, (xmlChar *)"Profiles");
	if (profsnode == NULL)
	{
#ifdef WRITE_PROFILES_CONFIG
		printf("Couldn't allocate memory to store <Profiles> block!\n");
#endif
		return NULL;
	}

	cur = profs;

	while (cur != NULL)
	{
		if ((!TEST_FLAG(cur->flags, CONFIG_VOLATILE_PROFILE)) || (write_to_disk == FALSE))
		{
			profnode = xsupconfwrite_profile_create_tree(cur, write_all);
			if (profnode == NULL)
			{
#ifdef WRITE_PROFILES_CONFIG
				printf("Couldn't create <Profile> block!\n");
#endif
				xmlFreeNode(profsnode);
				return NULL;
			}

			if (xmlAddChild(profsnode, profnode) == NULL)
			{
#ifdef WRITE_PROFILES_CONFIG
				printf("Couldn't add <Profile> child node!\n");
#endif
				xmlFreeNode(profsnode);
				xmlFreeNode(profnode);
				return NULL;
			}
		}

		cur = cur->next;
	}

	return profsnode;
}
