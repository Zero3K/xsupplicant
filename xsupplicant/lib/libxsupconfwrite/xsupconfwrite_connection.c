/**
 * Implementation for converting variables that make up the <Connection> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_connection.c
 *
 * \author chris@open1x.org
 *
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
#include "xsupconfwrite.h"
#include "xsupconfwrite_common.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_CONNECTION_CONFIG 1

/**
 * \brief Create the <IPv4_Configuration> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] ipdata  A config_ip_data structure that contains all of the
 *                    variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <IPv4_Configuration> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_connection_ipdata(struct config_ip_data *ipdata, 
												char write_all)
{
	xmlNodePtr ipNode = NULL;
	char *temp = NULL;
	
	if (ipdata == NULL) return NULL;

	// Create the root node for the <IPv4_Configuration> block.
	ipNode = xmlNewNode(NULL, (xmlChar *)"IPv4_Configuration");
	if (ipNode == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't allocate memory to store <IPv4_Configuration> block!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (ipdata->type != 0))
	{
		switch (ipdata->type)
		{
		default:
		case 0:
			temp = _strdup("DHCP");
			break;

		case 1:
			temp = _strdup("STATIC");
			break;

		case 2:
			temp = _strdup("NONE");
			break;
		}

		if (xmlNewChild(ipNode, NULL, (xmlChar *)"Type", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Type> node!\n");
#endif
			xmlFreeNode(ipNode);
			free(temp);
			return NULL;
		}

		free(temp);
		temp = NULL;
	}

	if ((write_all == TRUE) || (ipdata->ipaddr != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"IP_Address", (xmlChar *)ipdata->ipaddr) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <IP_Address> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ipdata->netmask != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"Netmask", (xmlChar *)ipdata->netmask) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Netmask> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ipdata->gateway != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"Gateway", (xmlChar *)ipdata->gateway) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Gateway> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ipdata->dns1 != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"DNS1", (xmlChar *)ipdata->dns1) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <DNS1> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ipdata->dns2 != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"DNS2", (xmlChar *)ipdata->dns2) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <DNS2> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ipdata->dns3 != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"DNS3", (xmlChar *)ipdata->dns3) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <DNS3> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (ipdata->renew_on_reauth == TRUE))
	{
		if (ipdata->renew_on_reauth == TRUE)
		{
			if (xmlNewChild(ipNode, NULL, (xmlChar *)"Renew_DHCP_on_Reauthentication", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Renew_DHCP_on_Reauthentication> node!\n");
#endif
				xmlFreeNode(ipNode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(ipNode, NULL, (xmlChar *)"Renew_DHCP_on_Reauthentication", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Renew_DHCP_on_Reauthentication> node!\n");
#endif
				xmlFreeNode(ipNode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (ipdata->search_domain != NULL))
	{
		if (xmlNewChild(ipNode, NULL, (xmlChar *)"Search_Domain", (xmlChar *)ipdata->search_domain) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Search_Domain> node!\n");
#endif
			xmlFreeNode(ipNode);
			return NULL;
		}
	}

	return ipNode;
}


/**
 * \brief Create the <Association> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] assoc  A config_association structure that contains all of the
 *                   variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Association> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_connection_association(struct config_association *assoc, uint8_t config_type,
												char write_all)
{
	xmlNodePtr assocNode = NULL;
	char static_temp[50];
	char *temp = NULL;
	uint16_t ressize;
	int i;
	
	if (assoc == NULL) return NULL;

	// Create the root node for the <Association> block.
	assocNode = xmlNewNode(NULL, (xmlChar *)"Association");
	if (assocNode == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't allocate memory to store <Association> block!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (assoc->association_type != ASSOC_AUTO))
	{
		switch (assoc->association_type)
		{
		default:
		case ASSOC_AUTO:
			temp = _strdup("auto");
			break;

		case ASSOC_OPEN:
			temp = _strdup("open");
			break;

		case ASSOC_SHARED:
			temp = _strdup("shared");
			break;

		case ASSOC_LEAP:
			temp = _strdup("leap");
			break;

		case ASSOC_WPA:
			temp = _strdup("wpa");
			break;

		case ASSOC_WPA2:
			temp = _strdup("wpa2");
			break;
		}

		if (xmlNewChild(assocNode, NULL, (xmlChar *)"Type", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Type> node!\n");
#endif
			xmlFreeNode(assocNode);
			free(temp);
			return NULL;
		}

		free(temp);
		temp = NULL;
	}

	if ((write_all == TRUE) || ((assoc->auth_type != AUTH_EAP) && (assoc->auth_type != AUTH_UNKNOWN)))
	{
		switch (assoc->auth_type)
		{
		case AUTH_NONE:
			temp = _strdup("NONE");
			break;

		case AUTH_PSK:
			temp = _strdup("PSK");
			break;

		default:
		case AUTH_EAP:
			temp = _strdup("EAP");
			break;
		}

		if (xmlNewChild(assocNode, NULL, (xmlChar *)"Authentication", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Authentication> node!\n");
#endif
			free(temp);
			xmlFreeNode(assocNode);
			return NULL;
		}

		free(temp);
		temp = NULL;
	}

	// Don't check write_all here.  The absence of this tag means that it should
	// be automagically figured out.
	if (assoc->pairwise_keys != 0)
	{
		if (assoc->pairwise_keys & CRYPT_FLAGS_WEP40)
		{
			if (xmlNewChild(assocNode, NULL, (xmlChar *)"Pairwise_Key_Type", (xmlChar *)"wep40") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Pairwise_Key_Type> node!\n");
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}

		if (assoc->pairwise_keys & CRYPT_FLAGS_TKIP)
		{
			if (xmlNewChild(assocNode, NULL, (xmlChar *)"Pairwise_Key_Type", (xmlChar *)"tkip") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Pairwise_Key_Type> node!\n");
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}

		if (assoc->pairwise_keys & CRYPT_FLAGS_WRAP)
		{
			if (xmlNewChild(assocNode, NULL, (xmlChar *)"Pairwise_Key_Type", (xmlChar *)"wrap") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Pairwise_Key_Type> node!\n");
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}

		if (assoc->pairwise_keys & CRYPT_FLAGS_CCMP)
		{
			if (xmlNewChild(assocNode, NULL, (xmlChar *)"Pairwise_Key_Type", (xmlChar *)"ccmp") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Pairwise_Key_Type> node!\n");
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}
		
		if (assoc->pairwise_keys & CRYPT_FLAGS_WEP104)
		{
			if (xmlNewChild(assocNode, NULL, (xmlChar *)"Pairwise_Key_Type", (xmlChar *)"wep104") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <Pairwise_Key_Type> node!\n");
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}
	}

	// Don't check write_all here.  The absence of this tag means that it should
	// be automagically figured out.
	if (assoc->group_keys != 0)
	{
		switch (assoc->group_keys)
		{
		case CRYPT_WEP40:
			temp = _strdup("wep40");
			break;

		case CRYPT_TKIP:
			temp = _strdup("tkip");
			break;

		case CRYPT_WRAP:
			temp = _strdup("wrap");
			break;

		case CRYPT_CCMP:
			temp = _strdup("ccmp");
			break;

		case CRYPT_WEP104:
			temp = _strdup("wep104");
			break;

		default:
			if (temp != NULL) free(temp);
			temp = NULL;
		}

		if (xmlNewChild(assocNode, NULL, (xmlChar *)"Group_Key_Type", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <Group_Key_Type> node!\n");
#endif
			xmlFreeNode(assocNode);
			free(temp);
			temp = NULL;
			return NULL;
		}

		if (temp != NULL)
		{
			free(temp);
			temp = NULL;
		}
	}

	// Don't check write_all here.  If psk isn't set, then we don't
	// really care what the value is.
	if (assoc->psk != NULL)
	{
		if (pwcrypt_funcs_available() == TRUE)
		{
			// Write the encrypted version.
			if (pwcrypt_encrypt(config_type, (uint8_t *)assoc->psk, strlen(assoc->psk), (uint8_t **)&temp, &ressize) != 0)
			{
				// Couldn't encrypt the data.  So write the cleartext version.
				if (xmlNewChild(assocNode, NULL, (xmlChar *)"PSK", (xmlChar *)assoc->psk) == NULL)
				{
#ifdef WRITE_CONNECTION_CONFIG
					printf("Couldn't create <PSK> node.\n");
#endif
					xmlFreeNode(assocNode);
					return NULL;
				}
			}
			else
			{
				if (xmlNewChild(assocNode, NULL, (xmlChar *)"Encrypted_PSK", (xmlChar *)temp) == NULL)
				{
#ifdef WRITE_CONNECTION_CONFIG
					printf("Couldn't create <Encrypted_PSK> node.\n");
#endif
					xmlFreeNode(assocNode);
					free(temp);
					return NULL;
				}
				free(temp);
				temp = NULL;
			}
		}
		else
		{
			if (xmlNewChild(assocNode, NULL, (xmlChar *)"PSK", (xmlChar *)assoc->psk) == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <PSK> node.\n");
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}
	}

	// Don't check write_all here.  If psk_hex isn't set, then we don't
	// really care what the value is.
	if (assoc->psk_hex != NULL)
	{
		if (xmlNewChild(assocNode, NULL, (xmlChar *)"PSK_Hex", (xmlChar *)assoc->psk_hex) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <PSK_Hex> node!\n");
#endif
			xmlFreeNode(assocNode);
			return NULL;
		}
	}

	// Don't check write_all here.  If the TX_key isn't set, then we don't 
	// really care what the key values are.
	if (assoc->txkey != 0)
	{
		sprintf((char *)&static_temp, "%d", assoc->txkey);
		if (xmlNewChild(assocNode, NULL, (xmlChar *)"TX_Key", (xmlChar *)static_temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't create <TX_Key> node!\n");
#endif
			xmlFreeNode(assocNode);
			return NULL;
		}

		for (i=1;i < 5; i++)
		{
			sprintf((char *)&static_temp, "Key_%d", i);
			if (xmlNewChild(assocNode, NULL, (xmlChar *)static_temp, (xmlChar *)assoc->keys[i]) == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't create <%s> node!\n", static_temp);
#endif
				xmlFreeNode(assocNode);
				return NULL;
			}
		}
	}

	return assocNode;
}

/**
 * \brief Create the <Connection> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] con         A config_connection structure that contains all of the
 *                        variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Connection> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_connection_create_tree(struct config_connection *con, uint8_t config_type,
									 char write_all)
{
	xmlNodePtr connode = NULL;
	xmlNodePtr assocNode = NULL;
	xmlNodePtr ipNode = NULL;
	char static_temp[10];
	char *temp = NULL;
	
	if (con == NULL) return NULL;

	// Create the root node for the <Connection> block.
	connode = xmlNewNode(NULL, (xmlChar *)"Connection");
	if (connode == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't allocate memory to store <Connection> block!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (con->name != NULL))
	{
		xsupconfwrite_convert_amp(con->name, &temp);
		if (xmlNewChild(connode, NULL, (xmlChar *)"Name", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't allocate memory to store <Name> node!\n");
#endif
			xmlFreeNode(connode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	if ((write_all == TRUE) || (con->priority != DEFAULT_PRIORITY))
	{
		sprintf((char *)&static_temp, "%d", con->priority);
		if (xmlNewChild(connode, NULL, (xmlChar *)"Priority", (xmlChar *)static_temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't allocate memory to store <Priority> node!\n");
#endif
			xmlFreeNode(connode);
			return NULL;
		}
	}

	//  Don't check write_all here!  Not having this tag means the connection
	//  is wired.
	if (con->ssid != NULL)
	{
		xsupconfwrite_convert_amp(con->ssid, &temp);
		if (xmlNewChild(connode, NULL, (xmlChar *)"SSID", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't allocate memory to store <SSID> node!\n");
#endif
			xmlFreeNode(connode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	// Don't check write_all here!  Not having a profile is allowed if the 
	// connection is WPA(2)-PSK, or Static WEP!
	if (con->profile != NULL)
	{
		xsupconfwrite_convert_amp(con->profile, &temp);
		if (xmlNewChild(connode, NULL, (xmlChar *)"Profile", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't allocate memory to store <Profile> node!\n");
#endif
			xmlFreeNode(connode);
			free(temp);
			return NULL;
		}

		free(temp);
	}

	// Don't check write_all here, because if the MAC address is all 0s, we don't
	// want to write it.
	if (memcmp(con->dest_mac, "\x00\x00\x00\x00\x00\x00", 6) != 0)
	{
		temp = mac2str((char *)con->dest_mac);
		if (xmlNewChild(connode, NULL, (xmlChar *)"Destination_MAC", (xmlChar *)temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't allocate memory to store <Destination_MAC> node!\n");
#endif
			free(temp);
			xmlFreeNode(connode);
			return NULL;
		}

		free(temp);
		temp = NULL;
	}

	if ((write_all == TRUE) || (con->force_eapol_ver != 0))
	{
		sprintf((char *)&static_temp, "%d", con->force_eapol_ver);
		if (xmlNewChild(connode, NULL, (xmlChar *)"Force_EAPoL_Version", (xmlChar *)static_temp) == NULL)
		{
#ifdef WRITE_CONNECTION_CONFIG
			printf("Couldn't allocate memory to store <Force_EAPoL_Version> node!\n");
#endif
			xmlFreeNode(connode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (TEST_FLAG(con->flags, CONFIG_NET_IS_HIDDEN)))
	{
		if (TEST_FLAG(con->flags, CONFIG_NET_IS_HIDDEN))
		{
			if (xmlNewChild(connode, NULL, (xmlChar *)"Hidden_SSID", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't allocate memory to store <Hidden_SSID> node!\n");
#endif
				xmlFreeNode(connode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(connode, NULL, (xmlChar *)"Hidden_SSID", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't allocate memory to store <Hidden_SSID> node!\n");
#endif
				xmlFreeNode(connode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE) || (TEST_FLAG(con->flags, CONFIG_VOLATILE_CONN)))
	{
		if (TEST_FLAG(con->flags, CONFIG_VOLATILE_CONN))
		{
			if (xmlNewChild(connode, NULL, (xmlChar *)"Volatile", (xmlChar *)"yes") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't allocate memory to store <Volatile> node!\n");
#endif
				xmlFreeNode(connode);
				return NULL;
			}
		}
		else
		{
			if (xmlNewChild(connode, NULL, (xmlChar *)"Volatile", (xmlChar *)"no") == NULL)
			{
#ifdef WRITE_CONNECTION_CONFIG
				printf("Couldn't allocate memory to store <Volatile> node!\n");
#endif
				xmlFreeNode(connode);
				return NULL;
			}
		}
	}

	assocNode = xsupconfwrite_connection_association(&con->association, config_type, write_all);
	if (assocNode == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't allocate memory to create <Association> block!\n");
#endif
		xmlFreeNode(connode);
		return NULL;
	}

	if (xmlAddChild(connode, assocNode) == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't add <Association> block as a child block of <Connection>!\n");
#endif
		xmlFreeNode(connode);
		xmlFreeNode(assocNode);
		return NULL;
	}

	ipNode = xsupconfwrite_connection_ipdata(&con->ip, write_all);
	if (ipNode == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't allocate memory to create <IPv4_Configuration> block!\n");
#endif
		xmlFreeNode(connode);
		return NULL;
	}

	if (xmlAddChild(connode, ipNode) == NULL)
	{
#ifdef WRITE_CONNECTION_CONFIG
		printf("Couldn't add <IPv4_Configuration> block as a child block of <Connection>!\n");
#endif
		xmlFreeNode(connode);
		xmlFreeNode(ipNode);
		return NULL;
	}

	return connode;
}
