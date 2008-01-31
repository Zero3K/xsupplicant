/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_plugins.c
 *
 * \author galimorerpg@users.sourceforge.net
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
#include "xsupconfig_parse.h"
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse_plugin.h"

/**
 * Stub to allow the parser to be more logical.
 **/
void *xsupconfig_parse_plugins(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
	printf("Parsing plugins..\n");
#endif

	conf_plugins = NULL;

	return (*attr);
}

parser plugins[] = {
	{"Plugin", (struct conf_parse_struct *)&plugin, TRUE, xsupconfig_parse_plugin},
	{NULL, NULL, FALSE, NULL}};
