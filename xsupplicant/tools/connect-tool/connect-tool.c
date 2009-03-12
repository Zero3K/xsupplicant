/**
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file connect-tool.c
 *
 * \author chris@open1x.org
 *
 **/

#ifndef WINDOWS
#include <unistd.h>
#endif

#include <string.h>

#include <libxml/parser.h>

#include "libxsupgui/xsupgui.h"
#include "libxsupgui/xsupgui_xml_common.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupgui/xsupgui_request.h"

#ifdef WINDOWS
#include "src/stdintwin.h"
#else
#define _strdup strdup
#endif

#include "getopts.h"

#define CONNECTION  1
#define INTERFACE 2

#define RET_NO_OPTS       1
#define RET_CANT_CONNECT  2
#define RET_TIMEOUT       3

int main(int argc, char *argv[])
{
	struct options opts[] = {
		{CONNECTION, "connection", "Connect using the named connection",
		 "C", 1},
		{INTERFACE, "interface",
		 "Interface to use with the connection (for verification)", "I",
		 1},
		{0, NULL, NULL, 0}
	};

	int op = 0;
	char *args = NULL;
	char *conn = NULL;
	char *touseint = NULL;
	int result = 0;

	while ((op = getopts(argc, argv, opts, &args)) != 0) {
		switch (op) {
		case CONNECTION:
			printf("Connecting to : %s\n", args);
			conn = args;
			break;

		case INTERFACE:
			printf("Using interface : %s\n", args);
			touseint = args;
			break;
		}
	}

	if (argc < 4) {
		getopts_usage(argv[0], opts);
		return RET_NO_OPTS;
	}

	if (xsupgui_connect() != 0) {
		printf("Error connecting to the XSupplicant daemon.\n");
		return RET_CANT_CONNECT;
	}

	printf("Requesting that the supplicant change connection.\n");
	result = xsupgui_request_set_connection(touseint, conn);

	switch (result) {
	case REQUEST_TIMEOUT:
		printf
		    ("\tThe request to change the connection timed out.  (Is the supplicant running?\n");
		return RET_TIMEOUT;
		break;

	case REQUEST_SUCCESS:
		printf
		    ("\tSuccess..  Your authentication show now be running.\n");
		break;

	default:
		printf("The supplicant returned error code %d.\n", result);
		break;
	}

	xsupgui_disconnect();

	return 0;
}
