/**
 * Implementation for writing a config from memory to the disk.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite.c
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
#include <time.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "xsupconfwrite_globals.h"
#include "xsupconfwrite_devices.h"
#include "xsupconfwrite_trusted_servers.h"
#include "xsupconfwrite_connections.h"
#include "xsupconfwrite_profiles.h"
#include "xsupconfwrite.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifdef WINDOWS
#include <windows.h>
#endif

// Enable this for textual debug output.
//#define DEBUG  1

char *mac2str(char *mac)
{
	char *retval = NULL;

	retval = malloc(50);  // More than enough space.
	if (retval == NULL) return NULL;

	sprintf(retval, "%02X:%02X:%02X:%02X:%02X:%02X", (uint8_t)mac[0], (uint8_t)mac[1], 
		(uint8_t)mac[2], (uint8_t)mac[3], (uint8_t)mac[4], (uint8_t)mac[5]);

	return retval;
}

/**
 * \brief Make the calls needed to create an XML node set that contains the global 
 *        variable information.
 *
 * @param[in] conf_globals
 * 
 * \retval NULL on failure
 * \retval xmlNodePtr pointing to a tree of nodes that contains the <Globals> piece
 *                    of a configuration file.
 **/
xmlNodePtr xsupconfwrite_create_globals(struct config_globals *conf_globals)
{
	return xsupconfwrite_globals_create_tree(conf_globals, FALSE);
}

/**
 * \brief Make the calls needed to create an XML node set that contains the <Devices> 
 *        variable information.
 *
 * @param[in] conf_devices
 * 
 * \retval NULL on failure
 * \retval xmlNodePtr pointing to a tree of nodes that contains the <Devices> piece
 *                    of a configuration file.
 **/
xmlNodePtr xsupconfwrite_create_devices(struct xsup_devices *conf_devices)
{
	return xsupconfwrite_devices_create_tree(conf_devices, FALSE);
}

/**
 * \brief Make the calls needed to create an XML node set that contains the <Plugins> 
 *        variable information.
 *
 * @param[in] conf_plugins
 * 
 * \retval NULL on failure
 * \retval xmlNodePtr pointing to a tree of nodes that contains the <Plugins> piece
 *                    of a configuration file.
 **/
xmlNodePtr xsupconfwrite_create_plugins(struct conf_plugins *conf_plugins)
{
	return xsupconfwrite_plugins_create_tree(conf_plugins, FALSE);
}

/**
 * \brief Make the calls needed to create an XML node set that contains the <Trusted_Servers> 
 *        variable information.
 *
 * @param[in] conf_trusted_servers
 * 
 * \retval NULL on failure
 * \retval xmlNodePtr pointing to a tree of nodes that contains the <Trusted_Servers> piece
 *                    of a configuration file.
 **/
xmlNodePtr xsupconfwrite_create_trusted_servers(struct config_trusted_servers *conf_trusted_servers, char write_to_disk)
{
	return xsupconfwrite_trusted_servers_create_tree(conf_trusted_servers, FALSE, write_to_disk);
}

/**
 * \brief Make the calls needed to create an XML node set that contains the <Connections> 
 *        variable information.
 *
 * @param[in] conf_connections
 * 
 * \retval NULL on failure
 * \retval xmlNodePtr pointing to a tree of nodes that contains the <Connections> piece
 *                    of a configuration file.
 **/
xmlNodePtr xsupconfwrite_create_connections(struct config_connection *conf_connections, uint8_t config_type, char write_to_disk)
{
	return xsupconfwrite_connections_create_tree(conf_connections, config_type, FALSE, write_to_disk);
}

/**
 * \brief Make the calls needed to create an XML node set that contains the <Profiles> 
 *        variable information.
 *
 * @param[in] conf_profiles
 * 
 * \retval NULL on failure
 * \retval xmlNodePtr pointing to a tree of nodes that contains the <Profiles> piece
 *                    of a configuration file.
 **/
xmlNodePtr xsupconfwrite_create_profiles(struct config_profiles *conf_profiles, uint8_t config_type, char write_to_disk)
{
	return xsupconfwrite_profiles_create_tree(conf_profiles, config_type, FALSE, write_to_disk);
}


/**
 * \brief This function writes the config information out to the system level config file.
 *
 * If destfile is set to NULL, then we will use the value that is stored
 * in the config_fname variable.  (Which should be the path to the config that we 
 * originally parsed to get the structure.)
 *
 * \retval 0 on success
 * \retval -1 on error.
 **/
int xsupconfwrite_write_config(char *destfile)
{
  xmlNodePtr globals = NULL;
  xmlNodePtr devices = NULL;
  xmlNodePtr trusted_servers = NULL;
  xmlNodePtr connections = NULL;
  xmlNodePtr profiles = NULL;
  xmlNodePtr plugins = NULL;
  xmlNodePtr rootnode = NULL;
  xmlDocPtr doc = NULL;
  char tempstatic[26];

#ifdef WINDOWS
  SYSTEMTIME systime;
#else
  time_t systime;
#endif // WINDOWS

  xmlKeepBlanksDefault(0);

  doc = xmlNewDoc(BAD_CAST "1.0");
  if (doc == NULL)
  {
	  return XSUPCONFWRITE_FAILED;
  }

  rootnode = xmlNewNode(NULL, BAD_CAST "XsupplicantConfig");
  if (rootnode == NULL)
  {
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
  }

  xmlNewProp(rootnode, (xmlChar *)"version", (xmlChar *)"1.0");

  memset(&tempstatic, 0x00, sizeof(tempstatic));

#ifdef WINDOWS
  GetLocalTime(&systime);

  sprintf((char *)&tempstatic, "%d/%d/%d", systime.wMonth, systime.wDay, systime.wYear);
#else
  time(&systime);
  
  // ctime returns a 26-character string.  Size includes \0 char.
  ctime_r(&systime, tempstatic);

  // Cut off the \n added by ctime.
  tempstatic[strlen(tempstatic) - 1] = '\0';
#endif

  xmlNewProp(rootnode, (xmlChar *)"generated_date", (xmlChar *)tempstatic);

  xmlDocSetRootElement(doc, rootnode);

  if (conf_globals != NULL)
  {
	globals = xsupconfwrite_create_globals(conf_globals);
	if (globals == NULL)
		{
#ifdef DEBUG
			printf("Error creating <Globals> block!\n");
#endif
			xmlFreeDoc(doc);
			return XSUPCONFWRITE_FAILED;
		}
	xmlAddChild(rootnode, globals);
  }

  if (conf_devices != NULL)
  {
	devices = xsupconfwrite_create_devices(conf_devices);
	if (devices == NULL)
	{
#ifdef DEBUG
	  printf("Error creating <Devices> block!\n");
#endif
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, devices);
  }

  if (conf_plugins != NULL)
  {
	  plugins = xsupconfwrite_create_plugins(conf_plugins);
	  if (plugins == NULL)
	  {
#ifdef DEBUG
		  printf("Error creating <Plugins> block!\n");
#endif
		  xmlFreeDoc(doc);
		  return XSUPCONFWRITE_FAILED;
	  }
	  xmlAddChild(rootnode, plugins);
  }

  if (conf_connections != NULL)
  {
	connections = xsupconfwrite_create_connections(conf_connections, CONFIG_LOAD_GLOBAL, TRUE);
	if (connections == NULL)
	{
#ifdef DEBUG
	  printf("Error creating <Connections> block!\n");
#endif
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, connections);
  }

  if (conf_profiles != NULL)
  {
	profiles = xsupconfwrite_create_profiles(conf_profiles, CONFIG_LOAD_GLOBAL, TRUE);
	if (profiles == NULL)
	{
#ifdef DEBUG
	  printf("Error creating <Profiles> block!\n");
#endif
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, profiles);
  }

  if (conf_trusted_servers != NULL)
  {
	trusted_servers = xsupconfwrite_create_trusted_servers(conf_trusted_servers, TRUE);
	if (trusted_servers == NULL)
	{
#ifdef DEBUG
  	  printf("Error creating <Trusted_Servers> block!\n");
#endif
 	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, trusted_servers);
  }

  if ((destfile == NULL) || (strlen(destfile) < 1))
  {
	if (xmlSaveFormatFile(config_fname, doc, 1) < 0) return XSUPCONFWRITE_FAILED;
  }
  else
  {
	if (xmlSaveFormatFile(destfile, doc, 1) < 0) return XSUPCONFWRITE_FAILED;
  }

  xmlFreeDoc(doc);

  return XSUPCONFWRITE_ERRNONE;
}

/**
 * \brief This function writes the config information out to the user level config file.
 *
 * @param[in] destfile   The full path and filename to store the user configuration information.
 *
 * \retval 0 on success
 * \retval -1 on error.
 **/
int xsupconfwrite_write_user_config(char *destfile)
{
  xmlNodePtr globals = NULL;
  xmlNodePtr devices = NULL;
  xmlNodePtr trusted_servers = NULL;
  xmlNodePtr connections = NULL;
  xmlNodePtr profiles = NULL;
  xmlNodePtr rootnode = NULL;
  xmlDocPtr doc = NULL;
  char tempstatic[26];

#ifdef WINDOWS
  SYSTEMTIME systime;
#else
  time_t systime;
#endif // WINDOWS

  if (destfile == NULL) return -1;

  xmlKeepBlanksDefault(0);

  doc = xmlNewDoc(BAD_CAST "1.0");
  if (doc == NULL)
  {
	  return XSUPCONFWRITE_FAILED;
  }

  rootnode = xmlNewNode(NULL, BAD_CAST "XsupplicantConfig");
  if (rootnode == NULL)
  {
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
  }

  xmlNewProp(rootnode, (xmlChar *)"version", (xmlChar *)"1.0");

  memset(&tempstatic, 0x00, sizeof(tempstatic));

#ifdef WINDOWS
  GetLocalTime(&systime);

  sprintf((char *)&tempstatic, "%d/%d/%d", systime.wMonth, systime.wDay, systime.wYear);
#else
  time(&systime);
  
  // ctime returns a 26-character string.  Size includes \0 char.
  ctime_r(&systime, tempstatic);

  // Cut off the \n added by ctime.
  tempstatic[strlen(tempstatic) - 1] = '\0';
#endif

  xmlNewProp(rootnode, (xmlChar *)"generated_date", (xmlChar *)tempstatic);

  xmlDocSetRootElement(doc, rootnode);

  if (conf_user_connections != NULL)
  {
	connections = xsupconfwrite_create_connections(conf_user_connections, CONFIG_LOAD_USER, TRUE);
	if (connections == NULL)
	{
#ifdef DEBUG
	  printf("Error creating <Connections> block!\n");
#endif
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, connections);
  }

  if (conf_user_profiles != NULL)
  {
	profiles = xsupconfwrite_create_profiles(conf_user_profiles, CONFIG_LOAD_USER, TRUE);
	if (profiles == NULL)
	{
#ifdef DEBUG
	  printf("Error creating <Profiles> block!\n");
#endif
	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, profiles);
  }

  if (conf_user_trusted_servers != NULL)
  {
	trusted_servers = xsupconfwrite_create_trusted_servers(conf_user_trusted_servers, TRUE);
	if (trusted_servers == NULL)
	{
#ifdef DEBUG
  	  printf("Error creating <Trusted_Servers> block!\n");
#endif
 	  xmlFreeDoc(doc);
	  return XSUPCONFWRITE_FAILED;
	}
	xmlAddChild(rootnode, trusted_servers);
  }

  if (xmlSaveFormatFile(destfile, doc, 1) < 0) return XSUPCONFWRITE_FAILED;

  xmlFreeDoc(doc);

  return XSUPCONFWRITE_ERRNONE;
}

