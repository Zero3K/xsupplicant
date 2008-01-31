/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_otp.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_eap_otp.c,v 1.3 2007/10/17 07:00:40 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:40 $
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#include <strings.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig.h"
#include "xsupconfig_common.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_parse_eap_otp.h"

void *xsupconfig_parse_eap_otp(void **attr, xmlNodePtr node)
{
  struct config_eap_method *meth;

  meth = (*attr);

  if (meth == NULL)
  {
	meth = xsupconfig_alloc_method(meth, "EAP-OTP");
	(*attr) = meth;
  }
  else
  {
	  meth = xsupconfig_alloc_method(meth, "EAP-OTP");
  }

  if (meth == NULL) return NULL;

#ifdef PARSE_DEBUG
  printf("Parsing method 'EAP-OTP'.\n");
#endif

  meth->method_num = EAP_TYPE_OTP;
  meth->method_data = malloc(sizeof(struct config_pwd_only));
  if (meth->method_data == NULL)
    {
      printf("Couldn't allocate memory to store EAP-OTP data!"
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth->method_data, 0x00, sizeof(struct config_pwd_only));

  return meth->method_data;
}

parser eap_otp[] = {
  {"Type", NULL, FALSE, xsupcommon_do_nothing},

  {NULL, NULL, FALSE, NULL}};
