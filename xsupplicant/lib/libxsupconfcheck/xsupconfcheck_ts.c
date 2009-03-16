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
#ifdef WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>

#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>

#include "src/stdintwin.h"
#include "src/platform/windows/win_cert_handler.h"

extern PCCERT_CONTEXT cert_find_by_long_name(char *certname);

#elif LINUX

void cert_find_by_long_name(char *certname)
{
}

#else
#warning You need to define a certificate handler!
#endif

#include "src/error_prequeue.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsupconfcheck_ts.h"

/**
 * \brief Check to see if a file exists.
 *
 * @param[in] filename   The file name that we want to check for existance.
 *
 * \retval 1 if the file exists.
 * \retval 0 if the file doesn't exist.
 **/
int xsupconfcheck_ts_file_exists(char *filename)
{
	FILE *fp = NULL;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		return 0;
	}

	fclose(fp);
	return 1;
}

/** 
 * \brief Check a trusted server configuration to be sure it has all of the valid 
 *        pieces needed.
 *
 * @param[in] ts   The trusted server structure that we want to check.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupconfcheck_ts_check(struct config_trusted_server *ts, int log)
{
	int retval = 0;
	int i = 0;

#ifdef WINDOWS
	PCCERT_CONTEXT mycert = NULL;
#endif

	if (ts->store_type == NULL) {
		error_prequeue_add
		    ("No store type is set in the configuration file!");
		return -1;
	}

	if (strcmp(ts->store_type, "WINDOWS") == 0) {
#ifndef WINDOWS
		error_prequeue_add
		    ("Trusted server configuration is set to point to Windows, but this OS doesn't seem to be Windows.");
		retval = -1;
#else
		// Now that we have cert chaining, the code below seems broken.
		for (i = 0; i < ts->num_locations; i++) {
			mycert =
			    win_cert_handler_get_from_win_store(ts->store_type,
								ts->
								location[i]);
			if (mycert == NULL) {
				if (log == TRUE)
					error_prequeue_add
					    ("Certificate specified by the trusted server configuration couldn't be found!");
				retval = -1;
			}
		}
#endif
	}

	if (strcmp(ts->store_type, "FILE") == 0) {
		for (i = 0; i < ts->num_locations; i++) {
			if (xsupconfcheck_ts_file_exists(ts->location[i]) != 1) {
				if (log == TRUE)
					error_prequeue_add
					    ("Certificate file specified by the trusted server configuration doesn't exist!");
				retval = -1;
			}
		}
	}

	if (strcmp(ts->store_type, "DIRECTORY") == 0) {
		// XXX Todo.
	}

	return retval;
}
