/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_globals.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_parse_globals.c,v 1.5 2008/01/26 01:19:59 chessing Exp $
 * $Date: 2008/01/26 01:19:59 $
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
#include "xsupconfig_defaults.h"
#include "src/xsup_debug.h"

multichoice association_choices[] = {
  { 1, "AUTO" },
  { 0, "MANUAL" },
  { -1, NULL}};

multichoice logging_choices[] = {
	{ LOGGING_NONE, "NONE" },
	{ LOGGING_FILE, "FILE" },
	{ LOGGING_SYSLOG, "SYSLOG" }};

multichoice destination_choices[] = {
  { DEST_AUTO, "AUTO" },
  { DEST_AUTO, "auto" },
  { DEST_BSSID, "BSSID" },
  { DEST_BSSID, "bssid" },
  { DEST_MULTICAST, "MULTICAST" },
  { DEST_MULTICAST, "multicast" },
  { DEST_SOURCE, "SOURCE" },
  { DEST_SOURCE, "source" },
  { -1, NULL}};

multichoice roaming_choices[] = {
  { 1, "FIRMWARE" },
  { 0, "XSUPPLICANT" },
  { -1, NULL}};

multichoice debug_choices[] = {
	{DEBUG_NORMAL, "NORMAL"},
	{DEBUG_INT, "INTERFACE"},
	{DEBUG_PHYSICAL_STATE, "PHYSICAL"},
	{DEBUG_DOT1X_STATE, "DOT1X_STATE"},
	{DEBUG_1X_BE_STATE, "DOT1X_BACKEND_STATE"},
	{DEBUG_EAP_STATE, "EAP_STATE"},
	{DEBUG_KEY_STATE, "KEY_STATE"},
	{DEBUG_KEY, "KEY"},
	{DEBUG_AUTHTYPES, "AUTHTYPES"},
	{DEBUG_CONFIG_PARSE, "CONFIG_PARSE"},
	{DEBUG_CONFIG_WRITE, "CONFIG_WRITE"},
	{DEBUG_SMARTCARD, "SMARTCARD"},
	{DEBUG_SNMP, "SNMP"},
	{DEBUG_IPC, "IPC"},
	{DEBUG_INIT, "INIT"},
	{DEBUG_DEINIT, "DEINIT"},
	{DEBUG_CONTEXT, "CONTEXT"},
	{DEBUG_EVENT_CORE, "EVENT_CORE"},
	{DEBUG_TLS_CORE, "TLS_CORE"},
	{DEBUG_TIMERS, "TIMERS"},
	{DEBUG_CERTS, "CERTIFICATES"},
	{DEBUG_TNC, "TNC"},
	{DEBUG_TNC_IMC, "TNC_IMC"},
	{DEBUG_VERBOSE, "VERBOSE"},
	{DEBUG_ALL, "ALL"},
	{-1, NULL}};

void *xsupconfig_parse_build_globals(void **attr, xmlNodePtr node)
{
#ifdef PARSE_DEBUG
  printf("Building globals config.\n");
#endif

  conf_globals = malloc(sizeof(struct config_globals));
  if (conf_globals == NULL)
    {
      printf("Couldn't allocate memory to store global setting configuration!"
	     "  (Line %ld)\n", xsupconfig_parse_get_line_num());
      exit(1);
    }

  memset(conf_globals, 0x00, sizeof(struct config_globals));

  xsupconfig_defaults_set_globals(conf_globals);

  return conf_globals;
}

void *xsupconfig_parse_logpath(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Would write log files to '%s'\n", value);
#endif

  myglobals = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myglobals->logpath = NULL;
	}
	else
	{
		myglobals->logpath = value;
	}

  return myglobals;
}

void *xsupconfig_parse_friendly_warnings(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Should parse friendly warnings = %s\n", value);
#endif

  myglobals = (*attr);
  result = xsupconfig_common_yesno(value);

  if (result == 1) 
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
    }
  else if (result == 0)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
    }
  else
    {
      xsupconfig_common_log("Didn't understand value '%s' in the friendly warning tag. "
	     "(Line %ld)   Defaulting to yes.\n", (char *)value,
	     xsupconfig_parse_get_line_num());

      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_log_facility(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Log facility : %s\n", value);
#endif

  myglobals = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myglobals->log_facility = NULL;
	}
	else
	{
		myglobals->log_facility = value;
	}

  return myglobals;
}

void *xsupconfig_parse_ipc_group(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("IPC Group : %s\n", value);
#endif

  myglobals = (*attr);

	if ((value == NULL) || (strlen(value) == 0))
	{
		free(value);
		myglobals->ipc_group_name = NULL;
	}
	else
	{
		myglobals->ipc_group_name = value;
	}

  return myglobals;
}

void *xsupconfig_parse_auth_period(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Auth Period : %s\n", value);
#endif

  myglobals = (*attr);

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Auth_Period is not a number!  (Line %ld)   "
	     "Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->auth_period = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_held_period(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Held Period : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Held_Period is not a number!  (Line %ld)  "
	     "Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->held_period = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_idle_while(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Idle While : %s\n", value);
#endif

  myglobals = (*attr);

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Idle_While is not a number!  (Line %ld)   "
	     "Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->idleWhile_timeout = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_association(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  int result = 0;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Association : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_select_from_list(association_choices, value);
  
  if (result == 1)
    {
      // Set for auto association.
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_ASSOC_AUTO);
    }

  if (result == 0)
    {
      // Set for manual association.
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_ASSOC_AUTO);
    }

  if (result == -1)
    {
      // Got an error.  Use default.
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_ASSOC_AUTO);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_destination(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  int result = -1;
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Destination : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_select_from_list(destination_choices, value);

  if (result > -1)
    {
      myglobals->destination = result;
    }

  FREE(value);

  return myglobals;
}


void *xsupconfig_parse_stale_key_timeout(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Stale Key Timeout : %s\n", value);
#endif

  myglobals = (*attr);

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Invalid value for Stale_Key_Timeout.  (Line %ld)  Using "
	     "default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->stale_key_timeout = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_max_starts(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Max Starts : %s\n", value);
#endif

  myglobals = (*attr);

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Invalid value for Max_Starts.  (Line %ld)   Using default!\n",
	     xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->max_starts = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_allmulti(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Allmulti : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_ALLMULTI);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_ALLMULTI);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Allmulti. (Line %ld)   Using default of "
	     "'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_ALLMULTI);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_loglevel(void **attr, xmlNodePtr node)
{
	struct config_globals *myglobals;
	char *value;
	int result;

	value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
	printf("Log Level : %s\n", value);
	fflush(stdout); 
#endif

	myglobals = (*attr);

	xsupconfig_common_upcase(value);
	result = xsupconfig_common_select_from_list(debug_choices, value);
	
	if (result < 0)
	{
		myglobals->loglevel = DEBUG_NORMAL;
	}
	else 
	{
		myglobals->loglevel |= result;
	}

	FREE(value);

	return myglobals;
}


void *xsupconfig_parse_roaming(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  int result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Roaming : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_select_from_list(roaming_choices, value);

  if (result == 1)
    {
      // Use FIRMWARE roaming.
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_FIRMWARE_ROAM);
    }
  
  if (result == 0)
    {
      // Use Xsupplicant roaming.
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_FIRMWARE_ROAM);
    }

  if (result == -1)
    {
      // Use default roaming.
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_FIRMWARE_ROAM);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_passive_scanning(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Passive Scanning : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_PASSIVE_SCAN);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_PASSIVE_SCAN);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Passive_Scan.  (Line %ld)   Using default "
	     "of 'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_PASSIVE_SCAN);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_passive_timer(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Passive Timer : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Passive_Timeout is not a number! (Line %ld)"
	     "   Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->passive_timeout = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_assoc_timeout(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Association_Timeout : %s\n", value);
#endif

  myglobals = (*attr);

  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Association_Timeout is not a number!  (Line "
	     "%ld)   Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->assoc_timeout = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_scan_timeout(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Scan_Timeout : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Scan_Timeout is not a number!  (Line %ld)"
		  "   Using default!\n", xsupconfig_parse_get_line_num());
    }
  else
    {
      myglobals->active_timeout = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_logs_to_keep(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Number of Logs To Keep : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Logs_To_Keep is not a number!  (Line %ld)"
		  "   Using default!\n", xsupconfig_parse_get_line_num());
	  myglobals->logs_to_keep = OLD_LOGS_TO_KEEP;
    }
  else
    {
      myglobals->logs_to_keep = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_log_size_to_roll(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Log Size To Roll On : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Logs_To_Keep is not a number!  (Line %ld)"
		  "   Using default!\n", xsupconfig_parse_get_line_num());
	  myglobals->size_to_roll = LOG_SIZE_TO_ROLL;
    }
  else
    {
      myglobals->size_to_roll = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_pmksa_age_out(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("PMKSA Age Out Time : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to PMKSA_Age_Out is not a number!  (Line %ld)"
		  "   Using default!\n", xsupconfig_parse_get_line_num());
	  myglobals->pmksa_age_out = PMKSA_DEFAULT_AGEOUT_TIME;
    }
  else
    {
		myglobals->pmksa_age_out = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_pmksa_refresh_time(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("PMKSA Cache Refresh : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to PMKSA_Refresh_Time is not a number!  (Line %ld)"
		  "   Using default!\n", xsupconfig_parse_get_line_num());
	  myglobals->pmksa_cache_check = PMKSA_CACHE_REFRESH;
    }
  else
    {
		myglobals->pmksa_cache_check = atoi(value);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_use_eap_hints(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals;
  uint8_t result;
  char *value;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Use_EAP_Hints : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_EAP_HINTS);
    }
  else if (result == 0)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_EAP_HINTS);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Use_EAP_Hints.  (Line %ld)   Using "
	     "default of 'YES'.\n", xsupconfig_parse_get_line_num());
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_EAP_HINTS);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_logging(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  int result = LOGGING_FILE;                 // Default is log to a file.
  char *value = NULL;

  value = (char *)xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Logging : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_select_from_list(logging_choices, value);

  if (result > -1)
    {
      myglobals->logtype = result;
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_disconnect_at_logoff(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Disconnect at Logoff : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Disconnect_at_Logoff.  (Line %ld)    Using "
	     "default of 'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_detect_on_startup(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Detect_on_startup : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_DETECT_ON_STARTUP);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_DETECT_ON_STARTUP);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Detect_on_startup.  (Line %ld)    Using "
	     "default of 'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_DETECT_ON_STARTUP);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_roll_logs(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Roll_Logs : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_ROLL_LOGS);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_ROLL_LOGS);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Roll_Logs.  (Line %ld)    Using "
	     "default of 'YES'.\n", xsupconfig_parse_get_line_num());
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_ROLL_LOGS);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_wireless_only(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  uint8_t result;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Wireless_Only : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_WIRELESS_ONLY);
    }
  else if (result == 0)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_WIRELESS_ONLY);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Wireless_Only.  (Line %ld)    Using "
	     "default of 'NO'.\n", xsupconfig_parse_get_line_num());
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_WIRELESS_ONLY);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_control_ints(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  uint8_t result = 0;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Control_Interfaces : %s\n", value);
#endif

  myglobals = (*attr);

  result = xsupconfig_common_yesno(value);

  if (result == 1)
    {
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_INT_CTRL);
    }
  else if (result == 0)
    {
      SET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_INT_CTRL);
    }
  else
    {
      xsupconfig_common_log("Unknown value for Control_Interfaces.  (Line %ld)    Using "
	     "default of 'YES'.\n", xsupconfig_parse_get_line_num());
      UNSET_FLAG(myglobals->flags, CONFIG_GLOBALS_NO_INT_CTRL);
    }

  FREE(value);

  return myglobals;
}

void *xsupconfig_parse_dead_connection_timeout(void **attr, xmlNodePtr node)
{
  struct config_globals *myglobals = NULL;
  char *value = NULL;

  value = xmlNodeGetContent(node);

#ifdef PARSE_DEBUG
  printf("Dead connection timeout : %s\n", value);
#endif

  myglobals = (*attr);
 
  if (xsupconfig_common_is_number(value) == 0)
    {
      xsupconfig_common_log("Value assigned to Dead_Connection_Timeout is not a number!  (Line %ld)"
		  "   Using default!\n", xsupconfig_parse_get_line_num());
	  myglobals->dead_connection_timeout = DEAD_CONN_TIMEOUT;
    }
  else
    {
		myglobals->dead_connection_timeout = atoi(value);
    }

  FREE(value);

  return myglobals;
}

parser globals[] = {
  {"Log_Path", NULL, FALSE, &xsupconfig_parse_logpath},
  {"Log_Level", NULL, FALSE, &xsupconfig_parse_loglevel},
  {"Friendly_Warnings", NULL, FALSE, &xsupconfig_parse_friendly_warnings},
  {"Log_Facility", NULL, FALSE, &xsupconfig_parse_log_facility},
  {"IPC_Group", NULL, FALSE, &xsupconfig_parse_ipc_group},
  {"Auth_Period", NULL, FALSE, &xsupconfig_parse_auth_period},
  {"Held_Period", NULL, FALSE, &xsupconfig_parse_held_period},
  {"Idle_While", NULL, FALSE, &xsupconfig_parse_idle_while},
  {"Association", NULL, FALSE, &xsupconfig_parse_association},
  {"Stale_Key_Timeout", NULL, FALSE, &xsupconfig_parse_stale_key_timeout},
  {"Max_Starts", NULL, FALSE, &xsupconfig_parse_max_starts},
  {"Allmulti", NULL, FALSE, &xsupconfig_parse_allmulti},
  {"Roaming", NULL, FALSE, &xsupconfig_parse_roaming},
  {"Passive_Scanning", NULL, FALSE, &xsupconfig_parse_passive_scanning},
  {"Passive_Timer", NULL, FALSE, &xsupconfig_parse_passive_timer},
  {"Scan_Timeout", NULL, FALSE, &xsupconfig_parse_scan_timeout},
  {"Use_EAP_Hints", NULL, FALSE, &xsupconfig_parse_use_eap_hints},
  {"Destination", NULL, FALSE, &xsupconfig_parse_destination},  ///XXX MOVE THIS!
  {"Association_Timeout", NULL, FALSE, &xsupconfig_parse_assoc_timeout},
  {"Logging", NULL, FALSE, &xsupconfig_parse_logging},
  {"Detect_on_startup", NULL, FALSE, &xsupconfig_parse_detect_on_startup},
  {"Logs_To_Keep", NULL, FALSE, &xsupconfig_parse_logs_to_keep},
  {"Log_Size_To_Roll", NULL, FALSE, &xsupconfig_parse_log_size_to_roll},
  {"Roll_Logs", NULL, FALSE, &xsupconfig_parse_roll_logs},
  {"Disconnect_at_Logoff", NULL, FALSE, &xsupconfig_disconnect_at_logoff},
  {"PMKSA_Age_Out_Time", NULL, FALSE, &xsupconfig_parse_pmksa_age_out},
  {"PMKSA_Refresh_Time", NULL, FALSE, &xsupconfig_parse_pmksa_refresh_time},
  {"Wireless_Only", NULL, FALSE, &xsupconfig_parse_wireless_only},    
  {"Control_Interfaces", NULL, FALSE, &xsupconfig_control_ints},
  {"Dead_Connection_Timeout", NULL, FALSE, &xsupconfig_parse_dead_connection_timeout},
  {NULL, NULL, FALSE, NULL}};
