/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_conn_ip.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#include <strings.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_conn_association.h"

multichoice ip_type_choices[] = {
  { 0,   "DHCP" },
  { 1,   "STATIC" },
  { 2,   "NONE" },
  { -1, NULL}};

void *xsupconfig_parse_conn_ip(void **attr, uint8_t config_type, xmlNodePtr node)
{
  return (*attr);
}

void *xsupconfig_parse_conn_ip_type(void **attr, uint8_t config_type, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  int result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("IP Allocation Type : %s\n", value);
#endif

  conn = (*attr);

  xsupconfig_common_upcase(value);

  result = xsupconfig_common_select_from_list(ip_type_choices, value);

  if (result == -1)
  {
	  xsupconfig_common_log("Unknown IP address allocation type '%s' in line %ld.  Defaulting to DHCP.",
		  value, xsupconfig_parse_get_line_num());
	  conn->ip.type = 0;
  }
  else
  {
	  conn->ip.type = result;
  }
  
  xmlFree(value);

  return conn;
}

/**
 * \brief Verify that an IP address (or netmask) is valid.
 *
 * @param[in] ipstr   The IP or netmask to check.
 *
 * \retval TRUE if it is valid
 * \retval FALSE if it isn't.
 **/
static int xsupconfig_parse_is_addr_valid(char *ipstr)
{
	int oct1 = 0, oct2 = 0, oct3 = 0, oct4 = 0;

	sscanf(ipstr, "%d.%d.%d.%d", &oct1, &oct2, &oct3, &oct4);

	if ((oct1 < 0) || (oct1 > 0xff)) return FALSE;
	if ((oct2 < 0) || (oct2 > 0xff)) return FALSE;
	if ((oct3 < 0) || (oct3 > 0xff)) return FALSE;
	if ((oct4 < 0) || (oct4 > 0xff)) return FALSE;

	return TRUE;
}

void *xsupconfig_parse_conn_ip_addr(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("IP Address is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.ipaddr = NULL;
	}
	else
	{
		if (xsupconfig_parse_is_addr_valid(value) == TRUE)
		{
			conn->ip.ipaddr = value;
		}
		else
		{
			xsupconfig_common_log("IP address specified at line %ld is invalid.",
				xsupconfig_parse_get_line_num());
			conn->ip.ipaddr = NULL;
		}
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_netmask(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("IP Netmask is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.netmask = NULL;
	}
	else
	{
		if (xsupconfig_parse_is_addr_valid(value) == TRUE)
		{
			conn->ip.netmask = value;
		}
		else
		{
			xsupconfig_common_log("Netmask defined at line %ld is invalid.",
				xsupconfig_parse_get_line_num());
			conn->ip.netmask = NULL;
		}
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_gateway(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("IP Gateway is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.gateway = NULL;
	}
	else
	{
		if (xsupconfig_parse_is_addr_valid(value) == TRUE)
		{
			conn->ip.gateway = value;
		}
		else
		{
			xsupconfig_common_log("IP Gateway defined at line %ld is invalid.",
				xsupconfig_parse_get_line_num());
			conn->ip.gateway = NULL;
		}
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_dns1(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("DNS1 Address is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.dns1 = NULL;
	}
	else
	{
		if (xsupconfig_parse_is_addr_valid(value) == TRUE)
		{
			conn->ip.dns1 = value;
		}
		else
		{
			xsupconfig_common_log("The DNS address specified at line %ld is invalid.",
				xsupconfig_parse_get_line_num());
			conn->ip.dns1 = NULL;
		}
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_dns2(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("DNS2 Address is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.dns2 = NULL;
	}
	else
	{
		if (xsupconfig_parse_is_addr_valid(value) == TRUE)
		{
			conn->ip.dns2 = value;
		}
		else
		{
			xsupconfig_common_log("The DNS address specified at line %ld is invalid.",
				xsupconfig_parse_get_line_num());
			conn->ip.dns2 = NULL;
		}
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_dns3(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("DNS3 Address is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.dns3 = NULL;
	}
	else
	{
		if (xsupconfig_parse_is_addr_valid(value) == TRUE)
		{
			conn->ip.dns3 = value;
		}
		else
		{
			xsupconfig_common_log("The DNS address specified at line %ld is invalid.",
				xsupconfig_parse_get_line_num());
			conn->ip.dns3 = NULL;
		}
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_search_domain(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	xmlChar *content = NULL;
	
	conn = (*attr);

	content = xmlNodeGetContent(node);
	value = _strdup((char *)content);
	xmlFree(content);

#ifdef PARSE_DEBUG
	printf("Search Domain is : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		conn->ip.search_domain = NULL;
	}
	else
	{
		conn->ip.search_domain = value;
	}

	return conn;
}

void *xsupconfig_parse_conn_ip_renew_on_reauth(void **attr, uint8_t config_type, xmlNodePtr node)
{
	struct config_connection *conn = NULL;
	char *value = NULL;
	uint8_t result = 0;
	
	conn = (*attr);

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("Renew on Reauth : %s\n", value);
#endif

  result = xsupconfig_common_yesno(value);

  if (result == 1) 
    {
		conn->ip.renew_on_reauth = TRUE;
    }
  else if (result == 0)
    {
		conn->ip.renew_on_reauth = FALSE;
    }
  else
    {
		xsupconfig_common_log("Unknown reauthentication setting of '%s' at line %ld.  Defaulting to NO.",
			value, xsupconfig_parse_get_line_num());
		conn->ip.renew_on_reauth = FALSE;
    }

  xmlFree(value);

  return conn;
}

parser conn_ip[] = {
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_type},
  {"IP_Address", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_addr},
  {"Netmask", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_netmask},
  {"Gateway", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_gateway},
  {"DNS1", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_dns1},
  {"DNS2", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_dns2},
  {"DNS3", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_dns3},
  {"Search_Domain", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_search_domain},
  {"Renew_DHCP_on_Reauthentication", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_ip_renew_on_reauth},

  {NULL, NULL, FALSE, 0, NULL}};
