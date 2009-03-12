/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_profiles.c
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
#include "xsupconfig_parse.h"
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse_profile.h"

/**
 * Stub to allow the parser to be more logical.
 **/
void *xsupconfig_parse_profiles(void **attr, uint8_t config_type,
				xmlNodePtr node)
{
#ifdef PARSE_DEBUG
	printf("Parsing profiles..\n");
#endif

	conf_profiles = NULL;

	return (*attr);
}

/**
 * Stub to allow the parser to be more logical.
 **/
void *xsupconfig_parse_user_profiles(void **attr, uint8_t config_type,
				     xmlNodePtr node)
{
#ifdef PARSE_DEBUG
	printf("Parsing profiles..\n");
#endif

	conf_user_profiles = NULL;

	return (*attr);
}

parser profiles[] = {
	{"Profile", (struct conf_parse_struct *)&profile, TRUE,
	 OPTION_ANY_CONFIG, xsupconfig_parse_profile},

	{NULL, NULL, FALSE, 0, NULL}
};

parser user_profiles[] = {
	{"Profile", (struct conf_parse_struct *)&profile, TRUE,
	 OPTION_ANY_CONFIG, xsupconfig_parse_user_profile},

	{NULL, NULL, FALSE, 0, NULL}
};
