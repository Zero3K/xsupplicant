/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_connections.c
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
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_connections.h"
#include "xsupconfig_parse_connection.h"
#include "xsupconfig_common.h"
#include "xsupconfig.h"

void *xsupconfig_parse_connections(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
  printf("Parsing connections..\n");
#endif

  conf_connections = NULL;

  return NULL;
}
  
parser connections[] = {
  {"Connection", (struct conf_parse_struct *)&connection, TRUE, OPTION_ANY_CONFIG,
  xsupconfig_parse_connection},

  {NULL, NULL, FALSE, 0, NULL}};
