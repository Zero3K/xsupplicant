/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_connection.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_connections.h"
#include "xsupconfig_parse_eap_fast.h"
#include "xsupconfig_parse_eap_tls.h"
#include "xsupconfig_parse_eap_md5.h"
#include "xsupconfig_parse_leap.h"
#include "xsupconfig_parse_eap_mschapv2.h"
#include "xsupconfig_parse_eap_sim.h"
#include "xsupconfig_parse_eap_aka.h"
#include "xsupconfig_parse_eap_gtc.h"
#include "xsupconfig_parse_eap_otp.h"
#include "xsupconfig_parse_eap_peap.h"
#include "xsupconfig_parse_eap_ttls.h"
#include "xsupconfig_parse_conn_association.h"
#include "xsupconfig_parse_conn_ip.h"
#include "xsupconfig_common.h"
#include "xsupconfig_defaults.h"
#include "xsupconfig.h"
#include "src/xsup_err.h"
#include "liblist/liblist.h"

#define MAX_EAPOL_VER		2

multichoice crypto_choices[] = {
	{1, "WEP40"}
	,
	{1, "wep40"}
	,
	{2, "TKIP"}
	,
	{2, "tkip"}
	,
	{3, "WRAP"}
	,
	{3, "wrap"}
	,
	{4, "CCMP"}
	,
	{4, "ccmp"}
	,
	{5, "wep104"}
	,
	{5, "WEP105"}
};

multichoice assoc_choices[] = {
	{0, "open"}
	,
	{0, "OPEN"}
	,
	{1, "shared"}
	,
	{1, "SHARED"}
	,
	{2, "leap"}
	,
	{2, "LEAP"}
};

/**
 * \brief Create a new connection node when the parser reaches a <Connection>
 *		block in the config file.
 *
 * @param[in] conn   A pointer to the head of the list that we want to add this
 *						node to.
 *
 * \retval void*  a pointer to the newly created node.
 **/
void *xsupconfig_parse_connection_generic(struct config_connection **conn)
{
	struct config_connection *newconn = NULL;

#ifdef PARSE_DEBUG
	printf("Parsing connection.\n");
#endif

	if (xsupconfig_defaults_create_connection(&newconn) != XENONE)
		exit(2);

	liblist_add_to_tail((genlist **) conn, (genlist *) newconn);

	return newconn;
}

/**
 *  This is called when the parser decides it is time to parse connection
 *  information.  It should start at the top of the list of connections,
 *  find the last node in the list, and allocate memory for the new node.
 **/
void *xsupconfig_parse_connection(void **attr, uint8_t config_type,
				  xmlNodePtr node)
{
	return xsupconfig_parse_connection_generic(&conf_connections);
}

/**
 *  This is called when the parser decides it is time to parse connection
 *  information.  It should start at the top of the list of connections,
 *  find the last node in the list, and allocate memory for the new node.
 **/
void *xsupconfig_parse_user_connection(void **attr, uint8_t config_type,
				       xmlNodePtr node)
{
	return xsupconfig_parse_connection_generic(&conf_user_connections);
}

void *xsupconfig_parse_connection_priority(void **attr, uint8_t config_type,
					   xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;

	value = (char *)xmlNodeGetContent(node);

	conn = (struct config_connection *)(*attr);
	if (conn == NULL) {
		fprintf(stderr,
			"Configuration data is invalid!  Cannot continue!  (Line %ld)\n",
			xsupconfig_parse_get_line_num());
		exit(2);
	}
#ifdef PARSE_DEBUG
	printf("Network has a priority value of %s\n", value);
#endif

	if (xsupconfig_common_is_number(value) == 0) {
		xsupconfig_common_log
		    ("Priority value setting at line %ld isn't valid.  Using default.",
		     xsupconfig_parse_get_line_num());
	} else {
		conn->priority = atoi(value);
	}

	xmlFree(value);

	return conn;
}

void *xsupconfig_parse_connection_eapol_ver(void **attr, uint8_t config_type,
					    xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	uint8_t vval = 0;

	value = (char *)xmlNodeGetContent(node);

	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("Network wants EAPoL version value of %s\n", value);
#endif

	if (xsupconfig_common_is_number(value) == 0) {
		xsupconfig_common_log
		    ("Value assigned to Force_EAPoL_Version at line %ld is not a number! "
		     "Using default.", xsupconfig_parse_get_line_num());
		conn->force_eapol_ver = 0;	// Set it to the default.
	} else {
		vval = atoi(value);
		if (vval > MAX_EAPOL_VER) {
			xsupconfig_common_log
			    ("Value assigned to Force_EAPoL_Version at line %ld is invalid! "
			     "Using default.", xsupconfig_parse_get_line_num());

			conn->force_eapol_ver = 0;
		} else {
			conn->force_eapol_ver = atoi(value);
		}
	}

	xmlFree(value);

	return conn;
}

void *xsupconfig_parse_connection_name(void **attr, uint8_t config_type,
				       xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	struct config_connection *check = NULL;
	char *value = NULL;
	char *original = NULL;
	char *newname = NULL;
	int done = 0, len = 0;
	xmlChar *content = NULL;

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("Connection has a name of %s\n", value);
#endif

	if (xsup_common_in_startup() == TRUE) {
		original = _strdup(value);

		while (done == 0) {
			check = conf_connections;
			if (check != NULL) {
				// Make sure we don't already have it.
				while (check != NULL) {
					if (check->name != NULL) {
						if (strcmp(check->name, value)
						    == 0)
							break;
					}

					check = check->next;
				}

				if (check != NULL) {
					if (newname != NULL) {
						free(newname);
						newname = NULL;
					}

					len =
					    strlen(value) + strlen(" (dup)") +
					    1;
					newname =
					    malloc(strlen(value) +
						   strlen(" (dup)") + 1);
					if (newname == NULL) {
						xsupconfig_common_log
						    ("Couldn't allocate memory to store duplicate connection!\n");
					} else {
						memset(newname, 0x00, len);
						strcpy(newname, value);
						strcat(newname, " (dup)");

						// Then, replace value.
						free(value);
						value = newname;
						newname = NULL;
					}
				} else {
					// We have a valid name.
					done = 1;
				}
			} else {
				// There is nothing to check, so it must be legit.
				done = 1;
			}
		}

		if (strcmp(original, value) != 0) {
			xsupconfig_common_log
			    ("There was a duplicate connection named '%s'.  The duplicate has been renamed '%s'.",
			     original, value);
		}

		free(original);
	}

	if ((value == NULL) || (strlen(value) == 0)) {
		free(value);
		conn->name = NULL;
	} else {
		conn->name = value;
	}

	return conn;
}

void *xsupconfig_parse_connection_profile(void **attr, uint8_t config_type,
					  xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("Profile is named %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0)) {
		free(value);
		conn->profile = NULL;
	} else {
		conn->profile = value;
	}

	return conn;
}

void *xsupconfig_parse_connection_ssid(void **attr, uint8_t config_type,
				       xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("SSID is %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0)) {
		free(value);
		conn->ssid = NULL;
	} else {
		conn->ssid = value;
	}

	return conn;
}

void *xsupconfig_parse_connection_mac_addr(void **attr, uint8_t config_type,
					   xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *mystr = NULL;
	char *value = NULL;

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("MAC address is : %s\n", value);
#endif

	conn = (struct config_connection *)(*attr);
	mystr = value;

	if (xsupconfig_common_is_valid_mac(mystr) == FALSE) {
		xsupconfig_common_log
		    ("Invalid MAC address at line %ld.  Ignoring.",
		     xsupconfig_parse_get_line_num());
		free(value);
		return conn;
	}

	xsupconfig_common_convert_mac(mystr, (char *)&conn->dest_mac);

#ifdef PARSE_DEBUG
	printf("Result : %02X:%02X:%02X:%02X:%02X:%02X\n", conn->dest_mac[0],
	       conn->dest_mac[1], conn->dest_mac[2], conn->dest_mac[3],
	       conn->dest_mac[4], conn->dest_mac[5]);
#endif

	SET_FLAG(conn->flags, CONFIG_NET_DEST_MAC);
	xmlFree(value);

	return conn;
}

void *xsupconfig_parse_connection_hidden_ssid(void **attr, uint8_t config_type,
					      xmlNodePtr node)
{
	char *value = NULL;
	struct config_connection *conn = NULL;
	uint8_t result = 0;

	conn = (struct config_connection *)(*attr);

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("Hidden SSID : %s\n", value);
#endif

	result = xsupconfig_common_yesno(value);

	if (result == 1) {
		SET_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN);
	} else if (result == 0) {
		UNSET_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN);
	} else {
		xsupconfig_common_log
		    ("Unknown value for Hidden_SSID at line %ld.  Using default of NO.",
		     xsupconfig_parse_get_line_num());
		UNSET_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN);
	}

	xmlFree(value);

	return conn;
}

void *xsupconfig_parse_connection_volatile(void **attr, uint8_t config_type,
					   xmlNodePtr node)
{
	char *value = NULL;
	struct config_connection *conn = NULL;
	uint8_t result = 0;

	conn = (struct config_connection *)(*attr);

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("Volatile : %s\n", value);
#endif

	result = xsupconfig_common_yesno(value);

	if (result == 1) {
		SET_FLAG(conn->flags, CONFIG_VOLATILE_CONN);
	} else if (result == 0) {
		UNSET_FLAG(conn->flags, CONFIG_VOLATILE_CONN);
	} else {
		xsupconfig_common_log
		    ("Unknown value for Volatile at line %ld.  Using default of NO.",
		     xsupconfig_parse_get_line_num());
		UNSET_FLAG(conn->flags, CONFIG_VOLATILE_CONN);
	}

	xmlFree(value);

	return conn;
}

void *xsupconfig_parse_connection_do_nothing(void **attr, uint8_t config_type,
					     xmlNodePtr node)
{
	// Don't do anything.
	return (*attr);
}

parser connection[] = {
	{"Name", NULL, FALSE, OPTION_ANY_CONFIG,
	 xsupconfig_parse_connection_name}
	,
	{"Priority", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_connection_priority}
	,
	{"Profile", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_connection_profile}
	,
	{"Force_EAPoL_Version", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_connection_eapol_ver}
	,
	{"SSID", NULL, FALSE, OPTION_ANY_CONFIG,
	 xsupconfig_parse_connection_ssid}
	,
	{"Volatile", NULL, FALSE, OPTION_ANY_CONFIG,
	 xsupconfig_parse_connection_volatile}
	,
	{"Association", (struct conf_parse_struct *)&conn_association, TRUE,
	 OPTION_ANY_CONFIG, xsupconfig_parse_conn_association},
	{"Destination_MAC", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_connection_mac_addr},
	{"Hidden_SSID", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_connection_hidden_ssid},
	{"IPv4_Configuration", (struct conf_parse_struct *)&conn_ip, TRUE,
	 OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip},

	// Config items no longer used, but we want to parse to avoid throwing errors.
	{"Interface", NULL, FALSE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_connection_do_nothing},

	{NULL, NULL, FALSE, 0, NULL}
};
