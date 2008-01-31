/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_devices.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_devices.c,v 1.3 2007/10/17 07:00:40 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:40 $
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
#include "xsupconfig_parse_interface.h"
#include "xsupconfig_parse_devices.h"
#include "xsupconfig_devices.h"
#include "src/xsup_debug.h"

void *xsupconfig_parse_devices(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
  printf("Building devices config.\n");
#endif

  conf_devices = malloc(sizeof(struct xsup_devices));
  if (conf_devices == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store device configuration!"
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(1);
    }

  memset(conf_devices, 0x00, sizeof(struct xsup_devices));

  return conf_devices;
}


parser devices[] = {
  {"Interface", (struct conf_parse_struct *)&interf, TRUE, 
	xsupconfig_parse_interface},
  
  {NULL, NULL, FALSE, NULL}};
