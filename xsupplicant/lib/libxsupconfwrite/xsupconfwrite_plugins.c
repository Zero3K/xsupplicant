/**
 * Implementation for converting variables that make up the <Profiles> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_profiles.c
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
#endif	/*  */
    
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "xsupconfwrite.h"
#include "xsupconfwrite_common.h"
#include "xsupconfwrite_eap.h"
#include "src/eap_types/tnc/tnc_compliance_options.h"
    
// Uncomment the #define below to enable textual debug output.
// #define WRITE_PLUGINS_CONFIG 1
    
/**
 * \brief Create the <Plugin> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] plugins  A config_plugins structure that contains all of the
 *						variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Plugin> tree in a format that is used by 
 *         libxml2.
 **/ 
    xmlNodePtr xsupconfwrite_plugin_create_tree(struct config_plugins * plugs,
						uint8_t config_type,
						char write_all)
{
	xmlNodePtr plugnode = NULL;
	char *temp = NULL;
	if (plugs == NULL)
		return NULL;
	
	    // Create the root node for the <Plugin> block.
	    plugnode = xmlNewNode(NULL, (xmlChar *) "Plugin");
	if (plugnode == NULL)
		 {
		
#ifdef WRITE_PLUGINS_CONFIG
		    printf
		    ("Couldn't allocate memory to store <Plugin> block!\n");
		
#endif	/*  */
		    return NULL;
		}
	if ((write_all == TRUE) || (plugs->name != NULL))
		 {
		xsupconfwrite_convert_amp(plugs->name, &temp);
		if (xmlNewChild
		     (plugnode, NULL, (xmlChar *) "Name",
		      (xmlChar *) temp) == NULL)
			 {
			
#ifdef WRITE_PLUGINS_CONFIG
			    printf
			    ("Couldn't allocate memory to store <Name> node!\n");
			
#endif	/*  */
			    xmlFreeNode(plugnode);
			free(temp);
			return NULL;
			}
		free(temp);
		}
	if ((write_all == TRUE) || (plugs->path != NULL))
		 {
		xsupconfwrite_convert_amp(plugs->path, &temp);
		if (xmlNewChild
		     (plugnode, NULL, (xmlChar *) "Path",
		      (xmlChar *) temp) == NULL)
			 {
			
#ifdef WRITE_PLUGINS_CONFIG
			    printf
			    ("Couldn't allocate memory to store <Path> node!\n");
			
#endif	/*  */
			    xmlFreeNode(plugnode);
			free(temp);
			return NULL;
			}
		free(temp);
		}
	if ((write_all == TRUE) || (plugs->description != NULL))
		 {
		xsupconfwrite_convert_amp(plugs->description, &temp);
		if (xmlNewChild
		     (plugnode, NULL, (xmlChar *) "Description",
		      (xmlChar *) temp) == NULL)
			 {
			
#ifdef WRITE_PLUGINS_CONFIG
			    printf
			    ("Couldn't allocate memory to store <Description> node!\n");
			
#endif	/*  */
			    xmlFreeNode(plugnode);
			free(temp);
			return NULL;
			}
		free(temp);
		}
	if (xsupconfwrite_common_write_bool
	      (plugnode, "Enabled", plugs->enabled, TRUE, write_all,
	       FALSE) == NULL)
		 {
		xmlFreeNode(plugnode);
		return NULL;
		}
	return plugnode;
}


/**
 * \brief Create the <Plugins> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] plugs  A config_plugins structure that contains all of the
 *                   variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Plugins> tree in a format that is used by 
 *         libxml2.
 **/ 
    xmlNodePtr xsupconfwrite_plugins_create_tree(struct config_plugins * plugs,
						 uint8_t config_type,
						 char write_all,
						 char write_to_disk)
{
	xmlNodePtr plugsnode = NULL;
	xmlNodePtr plugnode = NULL;
	struct config_plugins *cur = NULL;
	if (plugs == NULL)
		return NULL;
	
	    // Create the root node for the <Plugins> block.
	    plugsnode = xmlNewNode(NULL, (xmlChar *) "Plugins");
	if (plugsnode == NULL)
		 {
		
#ifdef WRITE_PLUGINS_CONFIG
		    printf
		    ("Couldn't allocate memory to store <Plugins> block!\n");
		
#endif	/*  */
		    return NULL;
		}
	cur = plugs;
	while (cur != NULL)
		 {
		plugnode =
		    xsupconfwrite_plugin_create_tree(cur, config_type,
						     write_all);
		if (plugnode == NULL)
			 {
			
#ifdef WRITE_PLUGINS_CONFIG
			    printf("Couldn't create <Plugin> block!\n");
			
#endif	/*  */
			    xmlFreeNode(plugsnode);
			return NULL;
			}
		if (xmlAddChild(plugsnode, plugnode) == NULL)
			 {
			
#ifdef WRITE_PLUGINS_CONFIG
			    printf("Couldn't add <Plugin> child node!\n");
			
#endif	/*  */
			    xmlFreeNode(plugsnode);
			xmlFreeNode(plugnode);
			return NULL;
			}
		cur = cur->next;
		}
	return plugsnode;
}


