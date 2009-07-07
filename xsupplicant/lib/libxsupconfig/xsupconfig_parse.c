/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse.c
 *
 * \author chris@open1x.org
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
#include "src/error_prequeue.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_globals.h"
#include "xsupconfig_parse_profiles.h"
#include "xsupconfig_parse_connections.h"
#include "xsupconfig_parse_devices.h"
#include "xsupconfig_parse_trusted_servers.h"
#include "xsupconfig_parse_plugins.h"
#include "xsupconfig.h"
#include "xsupconfig_common.h"

//extern struct config_data *config_info;
xmlNode *curnode = NULL;	// A pointer that will be used to determine the
		      // line number for a node in case we need it.

/**
 *  \brief Return the line number for the XML node we are working with.
 *
 * \retval long  The line number that contains the error.
 **/
long xsupconfig_parse_get_line_num()
{
	return xmlGetLineNo(curnode);
}

/**
 *  \brief Ask xmlReadFile to load the XML file that we will use for configuration.
 *
 * @param[in] filename   The path and filename that we want to open and parse.
 *
 * \retval NULL on error.
 * \retval xmlDocPtr  A pointer to an xmlDocPtr structure that represents the XML file that was read.
 **/
xmlDocPtr loadConfig(char *filename)
{
	xmlDocPtr doc = NULL;
	FILE *fp = NULL;

	if (filename == NULL) {
		printf("Unable to parse NULL file!\n");
		error_prequeue_add
		    ("Request to load a configuration from a NULL filename.  You won't have a configuration!");
		return NULL;
	}
	if ((fp = fopen(filename, "r")) == NULL) {
		printf("File %s can't be accessed\n", filename);

		return NULL;
	}

	fclose(fp);
	// We should return one error if the file isn't there and another error
	// if the file is the incorrect format - this would be much better - BRC
	doc = xmlParseFile(filename);
	if (doc == NULL) {
		printf("Error parsing config file!\n");
		error_prequeue_add("Unable to parse configuration file.");
		return NULL;
	}

	return doc;
}

/**
 *  \brief Determine if this parser section we are looking at is a 'terminator'
 *  section.  
 *
 *  A 'terminator' section is determined by having a value of NULL in 
 *  all locations except for 'descend', which should be set to FALSE.
 *
 * @param[in] data   A parser structure that contains information about the data node we are checking.
 *
 * \retval TRUE if the data node is a terminating node.
 * \retval FALSE if the data node is not a terminating node.
 **/
char xsupconfig_is_terminator(parser data)
{
	if (data.name != NULL)
		return FALSE;
	if (data.parsedata != NULL)
		return FALSE;
	if (data.descend != FALSE)
		return FALSE;
	if (data.process != NULL)
		return FALSE;

	return TRUE;
}

/**
 *  \brief Recursively parse the XML data, and build our configuration structure 
 *  in memory.
 *
 * @param[in] node  A pointer to the root node that we want to parse from.
 * @param[in] val   An array of parser options that are understood for the current level of the XML data.
 * @param[in] parse_type   A value that indicates if we are parsing global, or user specific data.
 * @param[in] data   The resulting data from the parse.
 **/
void xsupconfig_parse(xmlNode * node, parser val[], uint8_t parse_type,
		      void **data)
{
	xmlNode *cur_node = NULL;
	int i = 0;
	char done = 0;
	void *next_data = NULL;

	for (cur_node = node; cur_node; cur_node = cur_node->next) {
		// Set 'curnode' so that we can get the proper line number if we need
		// to display an error or warning.
		curnode = cur_node;

		if (cur_node->type == XML_ELEMENT_NODE) {
			i = 0;
			done = FALSE;

			while (done == FALSE) {
				if ((val[i].name != NULL)
				    && (strcmp(val[i].name, (char *)cur_node->name) == 0))
					done = TRUE;

				if (xsupconfig_is_terminator(val[i]) == TRUE)
					done = TRUE;

				if (done == FALSE)
					i++;
			}

			if (xsupconfig_is_terminator(val[i]) != TRUE) {
				if ((val[i].process != NULL)
				    && (val[i].config_allowed & parse_type)) {
					if (val[i].descend == TRUE) {
						next_data = (*val[i].process) (data,
								       parse_type,
								       cur_node);
					} else {
						(*val[i].process) (data,
								   parse_type,
								   cur_node);
						next_data = (*data);
					}
				}

				if (val[i].descend == TRUE) {
					if (val[i].config_allowed & parse_type) {
						xsupconfig_parse(cur_node->children,
								 (parser *)val[i].parsedata,
								 parse_type,
								 &next_data);
					}
				}

				if ((val[i].descend == FALSE)
				    && (val[i].parsedata != NULL)
				    && (val[i].config_allowed & parse_type)) {
					xsupconfig_parse(cur_node,
							 (parser *) val[i].parsedata, parse_type,
							 &next_data);
				}

				if ((val[i].process == NULL)
				    && (val[i].descend == FALSE)) {
					printf("Not sure what to do with node '%s'.\n",
					     cur_node->name);
					xsupconfig_common_log("Found node '%s' in the configuration file.  But not sure how to process it.",
					     cur_node->name);
				}
			} else {
				xsupconfig_common_log("Unknown configuration file tag '%s' at line %ld.",
				     cur_node->name, cur_node->line);
			}
		}
	}

	if (data != NULL)
		(*data) = next_data;
}

/**
 * \brief Parse the global and network level data.
 *
 * This is dummy function that only serves as a place holder.
 **/
void *xsupconfig_parse_global_and_network(void **attr, uint8_t config_type,
					  xmlNodePtr node)
{
#ifdef PARSE_DEBUG
	char *version = NULL;
	char *create_date = NULL;

	version = xmlGetProp(node, "version");
	create_date = xmlGetProp(node, "generated_date");

	printf("Found doc base code.  (Version = %s,  Created = %s)\n", version,
	       create_date);

	FREE(version);
	FREE(create_date);
#endif

	return NULL;
}


parser global_and_network[] = {
	{"Globals", (struct conf_parse_struct *)&globals, TRUE,
	 OPTION_GLOBAL_CONFIG_ONLY,
	 &xsupconfig_parse_build_globals},
	{"Profiles", (struct conf_parse_struct *)&profiles, TRUE,
	 OPTION_ANY_CONFIG,
	 &xsupconfig_parse_profiles},
	{"Connections", (struct conf_parse_struct *)&connections, TRUE,
	 OPTION_ANY_CONFIG,
	 xsupconfig_parse_connections},
	{"Devices", (struct conf_parse_struct *)&devices, TRUE,
	 OPTION_GLOBAL_CONFIG_ONLY,
	 &xsupconfig_parse_devices},
	{"Trusted_Servers", (struct conf_parse_struct *)&trusted_servers, TRUE,
	 OPTION_ANY_CONFIG,
	 &xsupconfig_parse_trusted_servers},
	{"Plugins", (struct conf_parse_struct *)&plugins, TRUE,
	 OPTION_GLOBAL_CONFIG_ONLY,
	 &xsupconfig_parse_plugins},

	{NULL, NULL, FALSE, 0, NULL}
};

parser baselevel[] = {
	{"XsupplicantConfig", (struct conf_parse_struct *)&global_and_network,
	 TRUE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_global_and_network},

	{NULL, NULL, FALSE, 0, NULL}
};

parser user_global_and_network[] = {
	{"Profiles", (struct conf_parse_struct *)&user_profiles, TRUE,
	 OPTION_ANY_CONFIG,
	 &xsupconfig_parse_user_profiles},
	{"Connections", (struct conf_parse_struct *)&user_connections, TRUE,
	 OPTION_ANY_CONFIG,
	 xsupconfig_parse_user_connections},
	{"Trusted_Servers", (struct conf_parse_struct *)&user_trusted_servers,
	 TRUE, OPTION_ANY_CONFIG,
	 &xsupconfig_parse_user_trusted_servers},

	{NULL, NULL, FALSE, 0, NULL}
};

parser user_baselevel[] = {
	{"XsupplicantConfig",
	 (struct conf_parse_struct *)&user_global_and_network, TRUE,
	 OPTION_ANY_CONFIG,
	 &xsupconfig_parse_global_and_network},

	{NULL, NULL, FALSE, 0, NULL}
};

#if 0
int main()
{
	xmlDocPtr doc;
	xmlNode *root_element = NULL;

	doc = loadConfig("./xsupconfig_test.xml");
	if (doc == NULL) {
		printf("Couldn't access test config file!\n");
		return -1;
	}

	root_element = xmlDocGetRootElement(doc);

	xsupconfig_parse(root_element, baselevel, (void **)&config_info);
}
#endif
