/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_interface.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_interface.c,v 1.6 2008/01/26 01:19:59 chessing Exp $
 * $Date: 2008/01/26 01:19:59 $
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "xsupconfig_vars.h"
#include "src/xsup_common.h"
#include "src/xsup_debug.h"
#include "xsupconfig_parse.h"
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_defaults.h"
#include "xsupconfig_devices.h"
#include "src/xsup_err.h"

void *xsupconfig_parse_interface(void **attr, xmlNodePtr node)
{
  struct xsup_devices *mydevs;
  struct xsup_interfaces *ints;

  mydevs = (*attr);

#ifdef PARSE_DEBUG
  printf("Building interfaces config.\n");
#endif

  if (mydevs->interf == NULL)
    {
		if (xsupconfig_defaults_create_interface(&mydevs->interf) != XENONE)
		{
			printf("Couldn't allocate memory to store interface setting configuration!"
					"  (Line %ld)\n", xsupconfig_parse_get_line_num());
			exit(1);
		}

      ints = mydevs->interf;
    }
  else
    {
      ints = mydevs->interf;

      while (ints->next != NULL) ints = ints->next;

	  if (xsupconfig_defaults_create_interface(&ints->next) != XENONE)
	  {
		printf("Couldn't allocate memory to store new interface data!\n");
		return NULL;
	  }

      ints = ints->next;
    }

  return ints;
}

void *xsupconfig_parse_interface_description(void **attr, xmlNodePtr node)
{
  struct xsup_interfaces *myints = NULL;
  struct xsup_interfaces *check = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

  myints = (*attr);

#ifdef PARSE_DEBUG
  printf("Interface description is '%s'!\n", value);
#endif

	if (xsup_common_in_startup() == TRUE)
	{
	  check = NULL;

	  if (conf_devices != NULL)
	  {
		  check = conf_devices->interf;
	  }

	  while (check != NULL)
	  {
		  if (check->description != NULL)
		  {
			  if (strcmp(check->description, value) == 0)
			  {
				  xsupconfig_common_log("There is more than one interface with the description of '%s'.  This should have only happened if you manually modified the configuration file.  If you have, you should manually remove (or rename) the duplicate interface that you don't want to use.\n", value);
			  }
		  }

		  check = check->next;
	  }
	}

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myints->description = NULL;
	}
	else
	{
		myints->description = value;
	}

  return myints;
}

void *xsupconfig_parse_interface_type(void **attr, xmlNodePtr node)
{
  struct xsup_interfaces *myints;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  myints = (*attr);

#ifdef PARSE_DEBUG
  printf("Interface type is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myints->driver_type = NULL;
	}
	else
	{
		myints->driver_type = value;
	}

  return myints;
}

void *xsupconfig_parse_interface_mac(void **attr, xmlNodePtr node)
{
  struct xsup_interfaces *myints = NULL;
  struct xsup_interfaces *check = NULL;
  char *mystr = NULL;
  char *value = NULL;
  uint8_t mac[6];
  uint8_t zerosmac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("MAC address is : %s\n", value);
#endif

  myints = (struct xsup_interfaces *)(*attr);

  mystr = value;

  if (xsupconfig_common_is_valid_mac(mystr) == FALSE) 
  {
	  printf("Invalid MAC address at line %ld.  Ignoring!\n", 
			xsupconfig_parse_get_line_num());
	  return myints;
  }

  xsupconfig_common_convert_mac(mystr, (char *)&mac);

	if (xsup_common_in_startup() == TRUE)
	{
	  check = NULL;

	  if (conf_devices != NULL)
	  {
		check = conf_devices->interf;
	  }

	  // There are some "interfaces" that will have a MAC address of all 0s.  
	  // These aren't interfaces that we should be using, but if they get entered
	  // in to our config file, then we throw up an error.  We don't want to do that
	  // so don't run our checks if the MAC is all 0s.
	  if (memcmp(mac, zerosmac, 6) != 0)
	  {
		while (check != NULL)
		{
		  if (check->description != NULL)
		  {
			  if (memcmp(check->mac, mac, 6) == 0)
			  {
				  xsupconfig_common_log("There is more than one interface with the MAC address of %02X:%02X:%02X:%02X:%02X:%02X.  This should have only happened if you manually modified the configuration file.  If you have, you should manually remove (or rename) the duplicate interface that you don't want to use.\n",
					  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			  }
		  }

		  check = check->next;
		}
	  }
	}

  memcpy(&myints->mac, &mac, 6);

#ifdef PARSE_DEBUG
  printf("Result : %02X:%02X:%02X:%02X:%02X:%02X\n", myints->mac[0], myints->mac[1], myints->mac[2],
	 myints->mac[3], myints->mac[4], myints->mac[5]);
#endif

  FREE(value);

  return myints;
}

/**
 * \brief Get the name of the default connection for this interface.
 *
 * @param[in,out] attr   A pointer to an xsup_interfaces struct that we want to operate on.
 * @param[in] node   The node that the parser is currently on.
 *
 * \retval ptr to the modified xsup_interfaces struct.
 **/
void *xsupconfig_parse_default_connection(void **attr, xmlNodePtr node)
{
  struct xsup_interfaces *myints;
  char *value;

  value = (char *)xmlNodeGetContent(node);

  myints = (*attr);

#ifdef PARSE_DEBUG
  printf("Default connection is '%s'!\n", value);
#endif

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myints->default_connection = NULL;
	}
	else
	{
		myints->default_connection = value;
	}

  return myints;
}

/**
 * \brief Check the value that is set in the "<Wireless>" tag of an interface.
 *
 * @param[in,out] attr   A pointer to an xsup_interfaces struct that we want to operate on.
 * @param[in] node   The node that the parser is currently on.
 *
 * \retval ptr to the modified xsup_interfaces struct.
 **/
void *xsupconfig_parse_interface_is_wireless(void **attr, xmlNodePtr node)
{
  struct xsup_interfaces *myints = NULL;
  char *value = NULL;
  uint8_t result = 0;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Interface is wireless : %s\n", value);
#endif

  myints = (struct xsup_interfaces *)(*attr);

  result = xsupconfig_common_yesno(value);
 
  if (result == 1)
    {
      SET_FLAG(myints->flags, CONFIG_INTERFACE_IS_WIRELESS);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myints->flags, CONFIG_INTERFACE_IS_WIRELESS);
    }
  else
    {
      printf("Unknown value for Wireless.  (Line %ld)\n    Using "
	     "default of 'NO'.\n", xsupconfig_parse_get_line_num());
      UNSET_FLAG(myints->flags, CONFIG_INTERFACE_IS_WIRELESS);
    }

  FREE(value);

  return myints;
}

/**
 * \brief Check the value that is set in the "<Wireless>" tag of an interface.
 *
 * @param[in,out] attr   A pointer to an xsup_interfaces struct that we want to operate on.
 * @param[in] node   The node that the parser is currently on.
 *
 * \retval ptr to the modified xsup_interfaces struct.
 **/
void *xsupconfig_parse_manage_interface(void **attr, xmlNodePtr node)
{
  struct xsup_interfaces *myints = NULL;
  char *value = NULL;
  uint8_t result = 0;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Interface should be managed : %s\n", value);
#endif

  myints = (struct xsup_interfaces *)(*attr);

  result = xsupconfig_common_yesno(value);
 
  if (result == 1)
    {
      UNSET_FLAG(myints->flags, CONFIG_INTERFACE_DONT_MANAGE);
    }
  else if (result == 0)
    {
      SET_FLAG(myints->flags, CONFIG_INTERFACE_DONT_MANAGE);
    }
  else
    {
      printf("Unknown value for Manage.  (Line %ld)\n    Using "
	     "default of 'YES'.\n", xsupconfig_parse_get_line_num());
      UNSET_FLAG(myints->flags, CONFIG_INTERFACE_DONT_MANAGE);
    }

  FREE(value);

  return myints;
}


parser interf[] = {
  {"Description", NULL, FALSE, &xsupconfig_parse_interface_description},
  {"MAC", NULL, FALSE, &xsupconfig_parse_interface_mac},
  {"Type", NULL, FALSE, &xsupconfig_parse_interface_type},
  {"Wireless", NULL, FALSE, &xsupconfig_parse_interface_is_wireless},
  {"Default_Connection", NULL, FALSE, &xsupconfig_parse_default_connection},
  {"Manage", NULL, FALSE, xsupconfig_parse_manage_interface},
  
  {NULL, NULL, FALSE, NULL}};
