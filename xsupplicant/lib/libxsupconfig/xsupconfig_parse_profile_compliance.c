/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_profile.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_profile_compliance.c,v 1.4 2007/10/20 08:10:13 galimorerpg Exp $
 * $Date: 2007/10/20 08:10:13 $
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
#include "src/eap_types/tnc/tnc_compliance_options.h"

void *xsupconfig_parse_profile_compliance(void **attr, xmlNodePtr node)
{
	return (*attr);
}

void *xsupconfig_parse_profile_compliance_enable(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Compliance Enable : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ENABLE);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ENABLE);
    }
  else
    {
      printf("Unknown value for compliance Enable. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ENABLE);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_personality_check(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Personality Check : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_PERSONALITY_CHECK);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_PERSONALITY_CHECK);
    }
  else
    {
      printf("Unknown value for personality compliance. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_PERSONALITY_CHECK);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_firewall_check(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Firewall Check : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_FIREWALL_CHECK);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_FIREWALL_CHECK);
    }
  else
    {
      printf("Unknown value for firewall compliance. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_FIREWALL_CHECK);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_anti_spyware_check(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Anti-Spyware Check : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_SPYWARE_CHECK);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_SPYWARE_CHECK);
    }
  else
    {
      printf("Unknown value for anti-spyware compliance. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_SPYWARE_CHECK);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_anti_virus_check(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Anti-Virus Check : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_VIRUS_CHECK);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_VIRUS_CHECK);
    }
  else
    {
      printf("Unknown value for anti-virus compliance. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_VIRUS_CHECK);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_anti_phishing_check(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Anti-Phishing Check : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_PHISHING_CHECK);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_PHISHING_CHECK);
    }
  else
    {
      printf("Unknown value for anti-phishing compliance. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ANTI_PHISHING_CHECK);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_allow_full_system_scan(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Allow full system scan : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ALLOW_FULL_SCAN);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ALLOW_FULL_SCAN);
    }
  else
    {
      printf("Unknown value for allow full system scan. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ALLOW_FULL_SCAN);
    }

  FREE(value);

  return (*attr);
}

void *xsupconfig_parse_profile_compliance_allow_auto_update(void **attr, xmlNodePtr node)
{
  struct config_profiles *myprofile;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Allow auto update : %s\n", value);
#endif

  myprofile = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ALLOW_AUTO_UPDATE);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ALLOW_AUTO_UPDATE);
    }
  else
    {
      printf("Unknown value for allow full system scan. (Line %ld)\n   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myprofile->compliance, TNC_COMPLIANCE_ALLOW_AUTO_UPDATE);
    }

  FREE(value);

  return (*attr);
}

parser compliance[] = {
	{"Enable", NULL, FALSE, xsupconfig_parse_profile_compliance_enable},
	{"Personality_Check", NULL, FALSE, xsupconfig_parse_profile_compliance_personality_check},
	{"Firewall_Check", NULL, FALSE, xsupconfig_parse_profile_compliance_firewall_check},	
	{"Anti_Spyware_Check", NULL, FALSE, xsupconfig_parse_profile_compliance_anti_spyware_check},
	{"Anti_Virus_Check", NULL, FALSE, xsupconfig_parse_profile_compliance_anti_virus_check},
	{"Anti_Phishing_Check", NULL, FALSE, xsupconfig_parse_profile_compliance_anti_phishing_check},
	{"Allow_Full_Scan", NULL, FALSE, xsupconfig_parse_profile_compliance_allow_full_system_scan},
	{"Allow_Auto_Update", NULL, FALSE, xsupconfig_parse_profile_compliance_allow_auto_update},

    {NULL, NULL, FALSE, NULL}};
