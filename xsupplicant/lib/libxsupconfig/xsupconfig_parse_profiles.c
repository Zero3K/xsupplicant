/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_profiles.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_profiles.c,v 1.3 2007/10/17 07:00:41 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:41 $
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
void *xsupconfig_parse_profiles(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
	printf("Parsing profiles..\n");
#endif

	conf_profiles = NULL;

	return (*attr);
}

parser profiles[] = {
	{"Profile", (struct conf_parse_struct *)&profile, TRUE, xsupconfig_parse_profile},

	{NULL, NULL, FALSE, NULL}};
