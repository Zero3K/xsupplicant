/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_conn_association.c
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
#include "src/error_prequeue.h" 
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_conn_association.h"
#include "src/xsup_debug.h"
#include "pwd_crypt.h"

multichoice net_association_choices[] = {
  { ASSOC_AUTO,   "AUTO" },
  { ASSOC_AUTO,   "auto" },
  { ASSOC_OPEN,   "OPEN" },
  { ASSOC_OPEN,   "open" },
  { ASSOC_SHARED, "SHARED" },
  { ASSOC_SHARED, "shared" },
  { ASSOC_LEAP,   "LEAP" },
  { ASSOC_LEAP,   "leap" },
  { ASSOC_WPA,    "WPA" },
  { ASSOC_WPA,    "wpa" },
  { ASSOC_WPA2,   "WPA2" },
  { ASSOC_WPA2,   "wpa2" },
  { -1, NULL}};

multichoice auth_types[] = {
	{ AUTH_NONE,  "NONE" },
	{ AUTH_NONE,  "none" },
	{ AUTH_PSK,   "PSK" },
	{ AUTH_PSK,   "psk" },
	{ AUTH_EAP,   "EAP" },
	{ AUTH_EAP,   "eap" },
	{ -1, NULL}};

multichoice enc_types[] = {
	{ CRYPT_WEP40,   "WEP40"},
	{ CRYPT_WEP40,   "wep40"},
	{ CRYPT_TKIP,	 "TKIP"},
	{ CRYPT_TKIP,    "tkip"},
	{ CRYPT_WRAP,    "WRAP"},
	{ CRYPT_WRAP,    "wrap"},
	{ CRYPT_CCMP,	 "CCMP"},
	{ CRYPT_CCMP,    "ccmp"},
	{ CRYPT_WEP104,  "WEP104"},
	{ CRYPT_WEP104,  "wep104"},
	{ -1, NULL}};

void *xsupconfig_parse_conn_association(void **attr, xmlNodePtr node)
{
  return (*attr);
}

void *xsupconfig_parse_conn_association_type(void **attr, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  char *value = NULL;
  char *errstr = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Association Type : %s\n", value);
#endif

  conn = (*attr);

  conn->association.association_type = xsupconfig_common_select_from_list(net_association_choices, value);

  if (conn->association.association_type == -1)
  {
	  if (xsup_common_in_startup() == TRUE)
	  {
		  errstr = malloc(strlen(value)+100);
		  if (errstr != NULL)
		  {
			  sprintf(errstr, "Unknown association type '%s' at line %ld.  Defaulting to AUTO.", value, xsupconfig_parse_get_line_num());
			  error_prequeue_add(errstr);
			  free(errstr);
		  }
		  else
		  {
			  debug_printf(DEBUG_NORMAL, "Unknown association type '%s' at line %ld.  Defaulting to AUTO.\n", value, xsupconfig_parse_get_line_num());
		  }
	  }
	  else
	  {
		debug_printf(DEBUG_NORMAL, "Unknown association type '%s' at line %ld!  Defaulting to AUTO.\n", value, xsupconfig_parse_get_line_num());
	  }

	  conn->association.association_type = 0;
  }
  
  FREE(value);

  return conn;
}

void *xsupconfig_parse_conn_authentication_type(void **attr, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  char *value = NULL;
  char *errstr = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Authentication Type : %s\n", value);
#endif

  conn = (*attr);

  conn->association.auth_type = xsupconfig_common_select_from_list(auth_types, value);

  if (conn->association.auth_type == -1)
  {
	  if (xsup_common_in_startup() == TRUE)
	  {
		errstr = malloc(strlen(value) + 100);
		if (errstr != NULL)
		{
			sprintf(errstr, "Unknown authentication type '%s' at line %ld!  Defaulting to NONE.", value, xsupconfig_parse_get_line_num());
			error_prequeue_add(errstr);
			free(errstr);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Unknown authentication type '%s' at line %ld!  Defaulting to NONE.\n", value, xsupconfig_parse_get_line_num());
		}
	  }
	  else
	  {
		debug_printf(DEBUG_NORMAL, "Unknown authentication type '%s' at line %ld!  Defaulting to NONE.\n", value, xsupconfig_parse_get_line_num());
	  }
	  conn->association.auth_type = 0;
  }
  
  FREE(value);

  return conn;
}

void *xsupconfig_parse_conn_group_key_type(void **attr, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  char *value = NULL;
  char *errstr = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Group Key Type : %s\n", value);
#endif

  conn = (*attr);

  conn->association.group_keys = xsupconfig_common_select_from_list(enc_types, value);

  if (conn->association.group_keys == -1)
  {
	  if (xsup_common_in_startup() == TRUE)
	  {
		errstr = malloc(strlen(value) + 100);
		if (errstr != NULL)
		{
			sprintf(errstr, "Unknown group key type '%s' at line %ld!  Defaulting to NONE.", value, xsupconfig_parse_get_line_num());
			error_prequeue_add(errstr);
			free(errstr);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Unknown group key type '%s' at line %ld!  Defaulting to NONE.\n", value, xsupconfig_parse_get_line_num());
		}
	  }
	  else
	  {
		debug_printf(DEBUG_NORMAL, "Unknown group key type '%s' at line %ld!  Defaulting to NONE.\n", value, xsupconfig_parse_get_line_num());
	  }

	  conn->association.group_keys = 0;
  }
  
  FREE(value);

  return conn;
}

void *xsupconfig_parse_conn_pairwise_key_type(void **attr, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  char *value = NULL;
  char *errstr = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf
	  ("Pairwise Key Type : %s\n", value);
#endif

  conn = (*attr);

  switch (xsupconfig_common_select_from_list(enc_types, value))
  {
  case CRYPT_WEP40:
	  conn->association.pairwise_keys |= CRYPT_FLAGS_WEP40;
	  break;

  case CRYPT_TKIP:
	  conn->association.pairwise_keys |= CRYPT_FLAGS_TKIP;
	  break;

  case CRYPT_WRAP:
	  conn->association.pairwise_keys |= CRYPT_FLAGS_WRAP;
	  break;

  case CRYPT_CCMP:
	  conn->association.pairwise_keys |= CRYPT_FLAGS_CCMP;
	  break;

  case CRYPT_WEP104:
	  conn->association.pairwise_keys |= CRYPT_FLAGS_WEP104;
	  break;

  default:
	  if (xsup_common_in_startup() == TRUE)
	  {
		errstr = malloc(100);
		if (errstr != NULL)
		{
			sprintf(errstr, "Invalid pairwise encryption method requested at line %ld!  Ignoring!", xsupconfig_parse_get_line_num());
			error_prequeue_add(errstr);
			free(errstr);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Invalid pairwise encryption method requested at line %ld!  Ignoring!\n", xsupconfig_parse_get_line_num());
		}
	  }
	  else
	  {
		debug_printf(DEBUG_NORMAL, "Invalid pairwise encryption method requested at line %ld!  Ignoring!\n", xsupconfig_parse_get_line_num());
	  }
	  break;
  }
  
  FREE(value);

  return conn;
}

void *xsupconfig_parse_conn_tx_key(void **attr, xmlNodePtr node)
{
  struct config_connection *conn = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  conn = (struct config_connection *)(*attr);
  if (conn == NULL)
    {
		fprintf(stderr, "Configuration data is invalid!  Cannot continue!  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

#ifdef PARSE_DEBUG
  printf("Static WEP TX key is %s\n", value);
#endif

  if (xsupconfig_common_is_number(value) == 0)
    {
		xsupconfig_common_log("Value assigned to WEP TX key is not a number!  Using default!  (Line %ld)",
			xsupconfig_parse_get_line_num());
    }
  else
    {
		conn->association.txkey = atoi(value);
    }

  FREE(value);

  return conn;
}

int string_is_hex(char *instr)
{
	int i;

	for (i=0; i<strlen(instr); i++)
	{
		if (is_hex(instr[i]) == FALSE) return FALSE;
	}

	return TRUE;
}

void *xsupconfig_parse_conn_key1(void **attr, xmlNodePtr node)
{
	char *value;
	struct config_connection *conn;

	value = (char *)xmlNodeGetContent(node);
	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("Key 1 : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		conn->association.keys[1] = NULL;

		if (strlen(value) == 0) free(value);		
	}
	else
	{
		conn->association.keys[1] = value;
	}

	return (*attr);
}

void *xsupconfig_parse_conn_key2(void **attr, xmlNodePtr node)
{
	char *value;
	struct config_connection *conn;

	value = (char *)xmlNodeGetContent(node);
	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("Key 2 : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		conn->association.keys[2] = NULL;

		if (strlen(value) == 0) free(value);
	}
	else
	{
		conn->association.keys[2] = value;
	}

	return (*attr);
}

void *xsupconfig_parse_conn_key3(void **attr, xmlNodePtr node)
{
	char *value;
	struct config_connection *conn;

	value = (char *)xmlNodeGetContent(node);
	conn = (*attr);

#ifdef PARSE_DEBUG
	printf("Key 3 : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		conn->association.keys[3] = NULL;

		if (strlen(value) == 0) free(value);
	}
	else
	{
		conn->association.keys[3] = value;
	}

	return (*attr);
}

void *xsupconfig_parse_conn_key4(void **attr, xmlNodePtr node)
{
	char *value;
	struct config_connection *conn;

	value = (char *)xmlNodeGetContent(node);
	conn = (*attr);	

#ifdef PARSE_DEBUG
	printf("Key 4 : %s\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		conn->association.keys[4] = NULL;

		if (strlen(value) == 0) free(value);
	}
	else
	{
		conn->association.keys[4] = value;
	}

	return (*attr);
}

void *xsupconfig_parse_conn_psk(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  conn = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("WPA Preshared Key is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		conn->association.psk = NULL;

		if (strlen(value) == 0) free(value);
	}
	else
	{
		conn->association.psk = value;
	}

  return conn;
}

void *xsupconfig_parse_conn_enc_psk(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;
  uint16_t size;

  conn = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("WPA (Encrypted) Preshared Key is '%s'!\n", value);
#endif

  if ((value == NULL) || (strlen(value) == 0))
  {
	  free(value);
	  return conn;
  }

  if (pwcrypt_decrypt((uint8_t *)value, strlen(value), (uint8_t **)&conn->association.psk, &size) != 0)
  {
	  free(value);
	  conn->association.psk = NULL;
	  return conn;
  }

  if ((conn->association.psk != NULL) && (strlen(conn->association.psk) == 0))
  {
	  FREE(conn->association.psk);
  }

  free(value);

  return conn;
}

void *xsupconfig_parse_conn_psk_hex(void **attr, xmlNodePtr node)
{
  struct config_connection *conn;
  char *value;

  conn = (*attr);

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("WPA Hex Key is '%s'!\n", value);
#endif

  if ((value == NULL) || (strlen(value) == 0))
  {
	  free(value);
	  conn->association.psk_hex = NULL;
  }
  else
  {
	conn->association.psk_hex = value;
  }

  return conn;
}

parser conn_association[] = {
  {"Type", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_association_type},
  {"Pairwise_Key_Type", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_pairwise_key_type},
  {"Group_Key_Type", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_group_key_type},
  {"Authentication", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_authentication_type},

  {"TX_Key", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_tx_key},
  {"Key_1", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_key1},
  {"Key_2", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_key2},
  {"Key_3", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_key3},
  {"Key_4", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_key4},

  {"PSK", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_psk},
  {"Encrypted_PSK", NULL, FALSE, OPTION_ANY_CONFIG, xsupconfig_parse_conn_enc_psk},
  {"PSK_Hex", NULL, FALSE, OPTION_ANY_CONFIG,
  xsupconfig_parse_conn_psk_hex},

  {NULL, NULL, FALSE, 0, NULL}};
