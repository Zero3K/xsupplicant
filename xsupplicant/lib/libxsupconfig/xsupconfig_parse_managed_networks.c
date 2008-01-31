/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_managed_networks.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_managed_networks.c,v 1.3 2007/10/17 07:00:41 galimorerpg Exp $
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
#include "xsupconfig_parse_managed_networks.h"
#include "xsupconfig_parse_managed_network.h"
#include "xsupconfig_common.h"
#include "xsupconfig.h"

void *xsupconfig_parse_managed_networks(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
  printf("Building managed networks config.\n");
#endif

  conf_managed_networks = NULL;

  return (*attr);
}


parser managed_networks[] = {
  {"Managed_Network", (struct conf_parse_struct *)&managed_network, TRUE, 
	xsupconfig_parse_managed_network},
  
  {NULL, NULL, FALSE, NULL}};
