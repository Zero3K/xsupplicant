/**
 * Routines for checking the "completeness" of a piece of the configuration.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfcheck.c
 *
 * \author chris@open1x.org
 *
 **/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#include <stdint.h>
#else
#include "src/stdintwin.h"
#endif

#include "src/error_prequeue.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "xsupconfcheck_conn.h"
#include "xsupconfcheck_int.h"
#include "xsupconfcheck_ts.h"
#include "xsupconfcheck_profile.h"
#include "xsupconfcheck.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 * \brief In the config specified by config_type, attempt to locate the 
 *			certificate that we want to use.
 *
 * @param[in] config_type   The configuration that we want to look in for our
 *								certificate.
 *
 * @param[in] tsname   The trusted server name that we are looking for.
 *
 * \retval NULL if the cert isn't found.
 **/
struct config_trusted_server *xsupconfcheck_find_trusted_server(uint8_t
								config_type,
								char *tsname)
{
	struct config_trusted_servers *tss = NULL;
	struct config_trusted_server *ts = NULL;

	tss = config_get_trusted_servers(config_type);
	if (tss == NULL)
		return NULL;

	ts = tss->servers;

	while ((ts != NULL) && (strcmp(ts->name, tsname) != 0))
		ts = ts->next;

	return ts;
}

/**
 * \brief Validate the configuration for a "<Trusted_Server>" in the configuration file.
 *
 * @param[in] tsname   The name of the trusted server that we want to validate.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_trusted_server(char *tsname, int log)
{
	struct config_trusted_server *ts = NULL;

	ts = xsupconfcheck_find_trusted_server(CONFIG_LOAD_USER, tsname);
	if (ts == NULL) {
		ts = xsupconfcheck_find_trusted_server(CONFIG_LOAD_GLOBAL,
						       tsname);
		if (ts == NULL) {
			if (log == TRUE)
				error_prequeue_add
				    ("Couldn't find the trusted server requested.");
			return -1;
		}
	}

	if (xsupconfcheck_ts_check(ts, log) != 0) {
		// Found errors are already in the queue, so we don't need to create any here.
		return -1;
	}

	return 0;
}

/**
 * \brief Validate the configuration for a "<Profile>" in the configuration file.
 *
 * @param[in] profname   The name of the profile that we want to validate.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_check_profile(char *profname, int log)
{
	struct config_profiles *myprof = NULL;
	int retval = 0;

	myprof = config_find_profile(CONFIG_LOAD_GLOBAL, profname);
	if (myprof == NULL) {
		myprof = config_find_profile(CONFIG_LOAD_USER, profname);
		if (myprof == NULL) {
			if (log == TRUE)
				error_prequeue_add
				    ("Couldn't find requested profile!");
			return -1;
		}
	}

	retval = xsupconfcheck_profile_check(myprof, log);
	if (retval != 0) {
		// No need to put a error_prequeue call here since the call above should have already
		// added the needed information.
		return retval;
	}

	return 0;
}

/**
 * \brief Validate the configuration for an "<Interface>" in the configuration file.
 *
 * @param[in] intdesc   The description for the interface that we want to validate.
 *
 * \retval 0 on success
 * \retval -1 on success
 **/
int xsupconfcheck_check_interface(char *intdesc, int log)
{
	struct xsup_interfaces *myints = NULL;

	myints = config_get_config_ints();
	if (myints == NULL) {
		if (log == TRUE)
			error_prequeue_add
			    ("Couldn't find any interfaces in the configuration file!");
		return -1;
	}

	while ((myints != NULL) && (strcmp(myints->description, intdesc) != 0))
		myints = myints->next;

	if (myints == NULL) {
		if (log == TRUE)
			error_prequeue_add
			    ("Couldn't find the interface needed.");
		return -1;
	}

	if (xsupconfcheck_int_check(myints, log) != 0) {
		// No need to log anything here.  The previous call should have filled the queue with errors already.
		return -1;
	}

	return 0;
}

/**
 * \brief Validate the configuration for the "<Connection>" in the configuration file.
 *
 * @param[in] connname   The name of the connection we want to validate.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_check_connection(context * ctx, char *connname, int log)
{
	struct config_connection *conn = NULL;

	if (connname == NULL)
		return -1;

	conn = config_find_connection(CONFIG_LOAD_GLOBAL, connname);
	if (conn == NULL) {
		// Didn't find it in the global configuration, look in the user config.
		conn = config_find_connection(CONFIG_LOAD_USER, connname);
		if (conn == NULL) {
			if (log == TRUE)
				error_prequeue_add
				    ("Couldn't find the connection in the configuration file!  (How did you get here!?)");
			return -1;
		}
	}

	return xsupconfcheck_conn_check(ctx, conn, log);
}
