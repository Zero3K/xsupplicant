/**
 * Implementation for converting variables that make up the <Globals> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_globals.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <libxml/parser.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "src/xsup_debug.h"
#include "xsupconfwrite.h"
#include "xsupconfwrite_common.h"

typedef struct multichoice_struct {
	int value;
	char *text;
} multichoice;

multichoice debug_choices_write[] = {
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
	{-1, NULL}
};

// Uncomment the #define below to enable textual debug output.
// #define WRITE_GLOBALS_DEBUG 1

/**
 * \brief Given a set of debug flags, create the libxml2 format nodes to represent
 *        it in the configuration file.
 *
 * @param[in] parent   The parent node that should contain the newly created debug
 *                     level nodes.
 * @param[in] dbglevel   The bitmap that represents the debug level.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfwrite_globals_build_debug(xmlNodePtr parent, char write_all,
				      uint32_t dbglevel)
{
	int i = 0;

	while (debug_choices_write[i].value != -1) {
		if (dbglevel == DEBUG_ALL) {
			if (xmlNewChild(parent, NULL, (xmlChar *) "Log_Level",
			     (xmlChar *) "ALL") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Couldn't create loglevel node!\n");
#endif
				return -1;
			}

			return 0;
		}

		if (TEST_FLAG(dbglevel, debug_choices_write[i].value)) {
			if ((write_all == TRUE)
			    || (debug_choices_write[i].value != DEBUG_NORMAL)) {
				if (xmlNewChild(parent, NULL, (xmlChar *) "Log_Level",
				     (xmlChar *) debug_choices_write[i].text) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
					printf("Couldn't create loglevel node!\n");
#endif
					return -1;
				}
			}
		}

		i++;
	}

	return 0;
}

/**
 * \brief Take the variables that are part of the config_globals structure, and
 *        convert them to be a tree of XML nodes that libxml2 can work with.
 *
 * @param[in] conf_globals  A config_globals structure that contains all of the
 *                          variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <Globals> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_globals_create_tree(struct config_globals *
					     conf_globals, char write_all)
{
	xmlNodePtr globalnode = NULL;
	char *temp = NULL;
	char static_temp[100];

	if (conf_globals == NULL)
		return NULL;

	// Create the root node for the <Globals> block.
	globalnode = xmlNewNode(NULL, (xmlChar *) "Globals");
	if (globalnode == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
		printf("Couldn't allocate memory to store <Globals> block!\n");
#endif
		return NULL;
	}
	// The "if" statements below should all check two things:
	//
	// 1. If write_all == TRUE, then we should go ahead and build the node no
	//    matter what the value is.
	//
	// 2. If write_all == FALSE, then we should check the value for the global 
	//    variable against the default.  If the value isn't the same as the global
	//    default, we should create the node.

	if ((write_all == TRUE) || (conf_globals->logpath != NULL)) {
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Log_Path",
		     (xmlChar *) conf_globals->logpath) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Logfile> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (conf_globals->log_facility != NULL)) {
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Log_Facility",
		     (xmlChar *) conf_globals->log_facility) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Log_Facility> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || (conf_globals->ipc_group_name != NULL)) {
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "IPC_Group",
		     (xmlChar *) conf_globals->ipc_group_name) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <IPC_Group> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->wiredMachineAuthConnection != NULL)) {
		if (xmlNewChild(globalnode, NULL,
		     (xmlChar *) "Wired_Machine_Authentication_Connection",
		     (xmlChar *) conf_globals->wiredMachineAuthConnection) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Wired_Machine_Authentication_Connection> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->wirelessMachineAuthConnection != NULL)) {
		if (xmlNewChild
		    (globalnode, NULL,
		     (xmlChar *) "Wireless_Machine_Authentication_Connection",
		     (xmlChar *) conf_globals->wirelessMachineAuthConnection) ==
		    NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf
			    ("Failed to create <Wireless_Machine_Authentication_Connection> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Detect_on_startup",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_DETECT_ON_STARTUP),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Allow_Machine_Authentication_to_Remain",
	     TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_ALLOW_MA_REMAIN),
	     FALSE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Wired_Link_Drop_Reprompt",
	     TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_REPROMPT_WIRED),
	     FALSE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Disconnect_at_Logoff",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Friendly_Warnings",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_FRIENDLY_WARNINGS),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if ((write_all == TRUE) || (conf_globals->logtype != LOGGING_FILE)) {
		switch (conf_globals->logtype) {
		case LOGGING_NONE:
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Logging",
			     (xmlChar *) "NONE") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Failed to create <Logging> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
			break;

		case LOGGING_FILE:
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Logging",
			     (xmlChar *) "FILE") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Failed to create <Logging> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
			break;

		case LOGGING_SYSLOG:
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Logging",
			     (xmlChar *) "SYSLOG") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Failed to create <Logging> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
			break;
		}
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Wireless_Only",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY),
					    FALSE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_globals_build_debug(globalnode, write_all, conf_globals->loglevel) != 0) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Allmulti",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_ALLMULTI),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if ((write_all == TRUE)
	    || (!TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_ASSOC_AUTO))) {
		if (!TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_ASSOC_AUTO)) {
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Association",
			     (xmlChar *) "MANUAL") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Failed to create <Association> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
		} else {
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Association",
			     (xmlChar *) "AUTO") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf
				    ("Failed to create <Association> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
		}
	}

	if ((write_all == TRUE)
	    || (!TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_FIRMWARE_ROAM)))
	{
		if (!TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_FIRMWARE_ROAM)) {
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Roaming",
			     (xmlChar *) "FIRMWARE") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Failed to create <Roaming> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
		} else {
			if (xmlNewChild(globalnode, NULL, (xmlChar *) "Roaming",
			     (xmlChar *) "XSUPPLICANT") == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
				printf("Failed to create <Roaming> node!\n");
#endif
				xmlFreeNode(globalnode);
				return NULL;
			}
		}
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Passive_Scanning",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_PASSIVE_SCAN),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Use_EAP_Hints",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_EAP_HINTS),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Roll_Logs",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_ROLL_LOGS),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if (xsupconfwrite_common_write_bool(globalnode, "Control_Interfaces",
					    TEST_FLAG(conf_globals->flags, CONFIG_GLOBALS_INT_CTRL),
					    TRUE, write_all, FALSE) == NULL) {
		xmlFreeNode(globalnode);
		return NULL;
	}

	if ((write_all == TRUE) || (conf_globals->destination != DEST_MULTICAST)) {
		switch (conf_globals->destination) {
		default:
		case DEST_AUTO:
			temp = _strdup("auto");
			break;

		case DEST_MULTICAST:
			temp = _strdup("multicast");
			break;

		case DEST_SOURCE:
			temp = _strdup("source");
			break;
		}

		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Destination",
		     (xmlChar *) temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Destination> node!\n");
#endif
			free(temp);
			xmlFreeNode(globalnode);
			return NULL;
		}

		free(temp);
		temp = NULL;
	}

	if ((write_all == TRUE)
	    || ((conf_globals->auth_period != AUTHENTICATION_TIMEOUT)
		&& (conf_globals->auth_period != 0))) {
		sprintf((char *)&static_temp, "%d", conf_globals->auth_period);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Auth_Period",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Auth_Period> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || ((conf_globals->pmksa_age_out != PMKSA_DEFAULT_AGEOUT_TIME)
		&& (conf_globals->pmksa_age_out != 0))) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->pmksa_age_out);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "PMKSA_Age_Out_Time",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <PMKSA_Age_Out_Time> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || ((conf_globals->dead_connection_timeout != DEAD_CONN_TIMEOUT)
		&& (conf_globals->dead_connection_timeout != 0))) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->dead_connection_timeout);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Dead_Connection_Timeout",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf
			    ("Failed to create <Dead_Connection_Timeout> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || ((conf_globals->pmksa_cache_check != PMKSA_CACHE_REFRESH)
		&& (conf_globals->pmksa_cache_check != 0))) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->pmksa_cache_check);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "PMKSA_Refresh_Time",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <PMKSA_Refresh_Time> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || ((conf_globals->logs_to_keep != 3) &&
				    (conf_globals->logs_to_keep != 0))) {
		sprintf((char *)&static_temp, "%d", conf_globals->logs_to_keep);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Logs_To_Keep",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Logs_To_Keep> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || ((conf_globals->size_to_roll != 3) &&
				    (conf_globals->size_to_roll != 0))) {
		sprintf((char *)&static_temp, "%d", conf_globals->size_to_roll);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Log_Size_To_Roll",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Log_Size_To_Roll> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || ((conf_globals->held_period != 60) && (conf_globals->held_period != 0)))	// XXX held_period should be a #define!
	{
		sprintf((char *)&static_temp, "%d", conf_globals->held_period);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Held_Period",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Held_Period> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE) || ((conf_globals->max_starts != 3) && (conf_globals->max_starts != 0)))	// XXX max_starts should be a #define!
	{
		sprintf((char *)&static_temp, "%d", conf_globals->max_starts);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Max_Starts",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Max_Starts> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->stale_key_timeout != STALE_KEY_WARN_TIMEOUT)) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->stale_key_timeout);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Stale_Key_Timeout",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Stale_Key_Timeout> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->assoc_timeout != ASSOCIATION_TIMEOUT)) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->assoc_timeout);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Association_Timeout",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Association_Timeout> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->passive_timeout != PASSIVE_TIMEOUT)) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->passive_timeout);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Passive_Timer",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Passive_Timer> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->active_timeout != RESCAN_TIMEOUT)) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->active_timeout);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Scan_Timeout",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Scan_Timeout> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	if ((write_all == TRUE)
	    || (conf_globals->idleWhile_timeout != IDLE_WHILE_TIMER)) {
		sprintf((char *)&static_temp, "%d",
			conf_globals->idleWhile_timeout);
		if (xmlNewChild(globalnode, NULL, (xmlChar *) "Idle_While",
		     (xmlChar *) static_temp) == NULL) {
#ifdef WRITE_GLOBALS_CONFIG
			printf("Failed to create <Idle_While> node!\n");
#endif
			xmlFreeNode(globalnode);
			return NULL;
		}
	}

	return globalnode;
}
