/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_trusted_servers.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_trusted_servers.c,v 1.3 2007/10/17 07:00:41 galimorerpg Exp $
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
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "xsupconfig_structs.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_trusted_servers.h"
#include "xsupconfig_parse_trusted_server.h"
#include "xsupconfig_common.h"
#include "xsupconfig.h"

void *xsupconfig_parse_trusted_servers(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
  printf("Building trusted servers config.\n");
#endif

  conf_trusted_servers = malloc(sizeof(struct config_trusted_servers));
  if (conf_trusted_servers == NULL)
    {
      printf("Couldn't allocate memory to store trusted servers configuration!"
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(1);
    }

  memset(conf_trusted_servers, 0x00, sizeof(struct config_trusted_servers));

  return conf_trusted_servers;
}


parser trusted_servers[] = {
  {"Trusted_Server", (struct conf_parse_struct *)&trusted_server, TRUE, 
	xsupconfig_parse_trusted_server},
  
  {NULL, NULL, FALSE, NULL}};
