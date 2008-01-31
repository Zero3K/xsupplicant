/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_connection.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_connection.c,v 1.4 2007/10/20 08:10:13 galimorerpg Exp $
 * $Date: 2007/10/20 08:10:13 $
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

multichoice crypto_choices[] = {
  { 1, "WEP40"},
  { 1, "wep40"},
  { 2, "TKIP"},
  { 2, "tkip"},
  { 3, "WRAP"},
  { 3, "wrap"},
  { 4, "CCMP"},
  { 4, "ccmp"},
  { 5, "wep104"},
  { 5, "WEP105"}};

multichoice assoc_choices[] = {
  { 0, "open"},
  { 0, "OPEN"},
  { 1, "shared"},
  { 1, "SHARED"},
  { 2, "leap"},
  { 2, "LEAP"}};

/**
 *  This is called when the parser decides it is time to parse connection
 *  information.  It should start at the top of the list of connections,
 *  find the last node in the list, and allocate memory for the new node.
 **/
void *xsupconfig_parse_connection(void **attr, xmlNodePtr node)
{
	struct config_connection *cur;

#ifdef PARSE_DEBUG
  printf("Parsing connection.\n");
#endif

  if (conf_connections == NULL)
  {
	  if (xsupconfig_defaults_create_connection(&conf_connections) != XENONE)
	  {
		  exit(2);
	  }

	  cur = conf_connections;
  }
  else
  {
	  cur = conf_connections;

	  while (cur->next != NULL) cur = cur->next;

	  if (xsupconfig_defaults_create_connection(&cur->next) != XENONE)
	  {
		  exit(2);
	  }

	  cur = cur->next;
  }

  cur->ou = (char *)xmlGetProp(node, (xmlChar *)"OU");   // Should return NULL if it isn't there.

  return cur;
}

void *xsupconfig_parse_connection_priority(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  conn = (struct config_connection *)(*attr);
  if (conn == NULL)
    {
      fprintf(stderr, "Configuration data is invalid!  Cannot continue!  (Line %ld)\n",
	     xsupconfig_parse_get_line_num());
      exit(2);
    }

#ifdef PARSE_DEBUG
  printf("Network has a priority value of %s\n", value);
#endif

  if (xsupconfig_common_is_number(value) == 0)
    {
		xsupconfig_common_log("Priority value setting at line %ld isn't valid.  Using default.",
			xsupconfig_parse_get_line_num());
    }
  else
    {
      conn->priority = atoi(value);
    }

  FREE(value);

  return conn;
}

void *xsupconfig_parse_connection_eapol_ver(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  conn = (*attr);

#ifdef PARSE_DEBUG
  printf("Network wants EAPoL version value of %s\n", value);
#endif

  if (xsupconfig_common_is_number(value) == 0)
    {
		xsupconfig_common_log("Value assigned to Force_EAPoL_Version at line %ld is not a number! "
				"Using default.", xsupconfig_parse_get_line_num());
    }
  else
    {
      conn->force_eapol_ver = atoi(value);
    }

  FREE(value);

  return conn;
}

void *xsupconfig_parse_connection_name(void **attr, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  struct config_connection *check = NULL;
  char *value = NULL;
  char *original = NULL;
  char *newname = NULL;
  int done = 0, len = 0;

  value = (char *)xmlNodeGetContent(node);

  conn = (*attr);

#ifdef PARSE_DEBUG
  printf("Connection has a name of %s\n", value);
#endif

	if (xsup_common_in_startup() == TRUE)
	{
	  original = _strdup(value);

	  while (done == 0)
	  {
		  check = conf_connections;
		  if (check != NULL)
			{
			  // Make sure we don't already have it.
			  while (check != NULL)
			  {
				  if (check->name != NULL)
				  {
					  if (strcmp(check->name, value) == 0) break;
				  }		

				  check = check->next;
			  }	

			  if (check != NULL)
			  {
				  if (newname != NULL)
				  {
					  free(newname);
					  newname = NULL;
				  }

				  len = strlen(value) + strlen(" (dup)") + 1;
				  newname = malloc(strlen(value) + strlen(" (dup)") + 1);
				  if (newname == NULL)
				  {
					 xsupconfig_common_log("Couldn't allocate memory to store duplicate connection!\n");
				  }
				  else
				  {
					  memset(newname, 0x00, len);
					  strcpy(newname, value);
					  strcat(newname, " (dup)");

					  // Then, replace value.
					  free(value);
					  value = newname;
					  newname = NULL;
				  }
			  }
			  else
			  {
				  // We have a valid name.
				  done = 1;
			  }
		  }
		  else
		  {
			  // There is nothing to check, so it must be legit.
			  done = 1;
		  }
	}

	  if (strcmp(original, value) != 0)
	  {
		  xsupconfig_common_log("There was a duplicate connection named '%s'.  The duplicate has been renamed '%s'.", original, value);
	  }

	  free(original);
	}

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->name = NULL;
	}
	else
	{
		conn->name = value;
	}

  return conn;
}

void *xsupconfig_parse_connection_profile(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  conn = (*attr);

#ifdef PARSE_DEBUG
  printf("Profile is named %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->profile = NULL;
	}
	else
	{
		conn->profile = value;
	}

  return conn;
}

void *xsupconfig_parse_connection_ssid(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  conn = (*attr);

#ifdef PARSE_DEBUG
  printf("SSID is %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ssid = NULL;
	}
	else
	{
		conn->ssid = value;
	}

  return conn;
}

void *xsupconfig_parse_connection_device(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  conn = (*attr);

#ifdef PARSE_DEBUG
  printf("Device is %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->device = NULL;
	}
	else
	{
		conn->device = value;
	}

  return conn;
}

void *xsupconfig_parse_connection_mac_addr(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *mystr;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("MAC address is : %s\n", value);
#endif

  conn = (struct config_connection *)(*attr);
  mystr = value;

  if (xsupconfig_common_is_valid_mac(mystr) == FALSE) 
  {
	  xsupconfig_common_log("Invalid MAC address at line %ld.  Ignoring.",
		  xsupconfig_parse_get_line_num());
	  free(value);
	  return conn;
  }

  xsupconfig_common_convert_mac(mystr, (char *)&conn->dest_mac);

#ifdef PARSE_DEBUG
  printf("Result : %02X:%02X:%02X:%02X:%02X:%02X\n", conn->dest_mac[0], conn->dest_mac[1], conn->dest_mac[2],
	 conn->dest_mac[3], conn->dest_mac[4], conn->dest_mac[5]);
#endif

  SET_FLAG(conn->flags, CONFIG_NET_DEST_MAC);
  free(value);

  return conn;
}

void *xsupconfig_parse_connection_hidden_ssid(void **attr, xmlNodePtr node)
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
 
    if (result == 1)
    {
      SET_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN);
    }
  else if (result == 0)
    {
      UNSET_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN);
    }
  else
    {
		xsupconfig_common_log("Unknown value for Hidden_SSID at line %ld.  Using default of NO.",
			xsupconfig_parse_get_line_num());
      UNSET_FLAG(conn->flags, CONFIG_NET_IS_HIDDEN);
    }

  FREE(value);

  return conn;
}
  
parser connection[] = {
  {"Name", NULL, FALSE, xsupconfig_parse_connection_name},
  {"Priority", NULL, FALSE, &xsupconfig_parse_connection_priority},
  {"Profile", NULL, FALSE, &xsupconfig_parse_connection_profile},
  {"Force_EAPoL_Version", NULL, FALSE, &xsupconfig_parse_connection_eapol_ver},
  {"SSID", NULL, FALSE, xsupconfig_parse_connection_ssid},
  {"Interface", NULL, FALSE, xsupconfig_parse_connection_device},
  {"Association", (struct conf_parse_struct *)&conn_association, TRUE, xsupconfig_parse_conn_association},
  {"Destination_MAC", NULL, FALSE, &xsupconfig_parse_connection_mac_addr},
  {"Hidden_SSID", NULL, FALSE, &xsupconfig_parse_connection_hidden_ssid},
  {"IPv4_Configuration", (struct conf_parse_struct *)&conn_ip, TRUE, xsupconfig_parse_conn_ip},

  {NULL, NULL, FALSE, NULL}};
