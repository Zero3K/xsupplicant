/**
 * The driver function for an application layer EAPOL 
 * implementation
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_driver.c
 *
 * \author chris@open1x.org
 *
 **/

/***
 *** This code implements 802.1X Authentication as a supplicant
 *** and supports multiple Authentication types.  
 ***/

#include <stdlib.h>

#ifndef WINDOWS
#include <unistd.h>
#include <strings.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#else
#include <windows.h>
#include <shlobj.h>
#include <pbt.h>
#endif

#if (WINDOWS || LINUX)
#include <libcrashdump/crash_handler.h>
#include <libcrashdump/crashdump.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

#include "getopts.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig_defaults.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "eap_sm.h"
#include "config_ssid.h"
#include "statemachine.h"
#include "xsup_ipc.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "eapol.h"
#include "snmp.h"
#include "platform/cardif.h"
#include "platform/platform.h"
#include "timer.h"
#include "event_core.h"
#include "interfaces.h"
#include "libsupdetect/supdetect.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "platform/plugin_handler.h"
#include "plugins.h"
#include "pmksa.h"

#include "platform/cert_handler.h"

#include "buildnum.h"

#ifndef BUILDNUM
#define BUILDNUM "BROKEN-FIXME"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

// This is needed to support the use of IW_ENCODE_TEMP keys for Cisco cards
// based on the airo driver.
#ifdef __LINUX__
#include "platform/linux/cardif_linux_wext.h"
#endif
#if  ((HAVE_TNC == 1)  || (HAVE_OSC_TNC == 1))
#include <libtnctncc.h>
#include "eap_types/tnc/tnc_compliance_callbacks.h"
#endif
#define PIDBASE "/var/run/xsupplicant"

context *intiface = NULL;
int dsd = 0;
char *config_path = NULL;
char *pid_filename = NULL;

#ifdef BUILD_SERVICE
#include "win_svc.h"
#endif

// Forward decl.
void global_deinit();

/*********************************************
 *
 * Create a file and store our PID in it
 *
 *********************************************/
int create_pidfile()
{
	FILE *pidfile = NULL;

	if (pid_filename == NULL) {
		return FALSE;
	}

	pidfile = fopen(pid_filename, "w");
	if (pidfile) {
		fprintf(pidfile, "%d", getpid());
		if (fclose(pidfile) != 0) {
			return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}

/*********************************************
 *
 * Delete the pid file
 *
 *********************************************/
int delete_pidfile()
{
	if (pid_filename == NULL) {
		return FALSE;
	}

	if (_unlink(pid_filename) != 0) {
		printf("Unable to delete PID file!\n");
		return FALSE;
	}

	return TRUE;
}

/*********************************************
 *
 * Initialize the configuration data.
 *
 * NOTE : DO NOT debug_printf ANYTHING in this function, because the result
 * of debug_printf is undefined before a valid configuration is loaded.
 *
 *********************************************/
void xsup_driver_init_config(char *config)
{
	struct config_globals *globals = NULL;
#ifdef WINDOWS
	char *default_cfg =
	    "c:\\windows\\system32\\drivers\\etc\\xsupplicant.conf";
	char *global_conf_path = NULL;
#else
	char *default_cfg = "/etc/xsupplicant.conf";
#endif

	if (config == NULL) {
#ifndef WINDOWS
		config = default_cfg;
#else
		global_conf_path = platform_get_machine_data_store_path();
		if (global_conf_path == NULL) {
			printf
			    ("Couldn't allocate memory to store the path to the configuration file!\n");
			global_deinit();
			return;
		}

		config =
		    Malloc(strlen(global_conf_path) +
			   strlen("xsupplicant.conf") + 5);
		if (config == NULL) {
			printf
			    ("Couldn't allocate memory to store the configuration file path string!\n");
			global_deinit();
			return;
		}

		sprintf(config, "%s\\xsupplicant.conf", global_conf_path);
		FREE(global_conf_path);
#endif
	}
#if (WINDOWS || LINUX)
	// Collect the configuration if a troubleticket or crash dump is generated.
	// *DO NOT* delete the configuration file, though. ;)
	crashdump_add_file(config, 0);
#else
#warning Need to implement crash dump file handling for this platform.
#endif				// (WINDOWS || LINUX)

	config_path = _strdup(config);

	// Build up our config information.
	switch (config_system_setup(config)) {
	case XECONFIGFILEFAIL:
	case XECONFIGPARSEFAIL:
		printf("Couldn't read the configuration file.  Building "
		       "defaults.\n");

		conf_globals = Malloc(sizeof(struct config_globals));
		if (conf_globals == NULL) {
			printf
			    ("Couldn't allocate memory to store configuration globals.\n");
			exit(255);
		}
		xsupconfig_defaults_set_globals(conf_globals);
		config_fname = _strdup(config_path);
		break;

	case XECONFIGALREADYLOADED:
		printf("config_system_setup() was called, but a "
		       "configuration is already loaded.\n");
		break;
	}

	FREE(config_path);

	// Also, attempt to load a user config for the case where we come up and a user is already logged in.
	// This call should fail if no user is logged on yet.
	event_core_load_user_config();

#ifdef WINDOWS
	FREE(config);
#endif

	globals = config_get_globals();
	if (globals == NULL) {
		printf("No valid configuration globals available?\n");
		return;
	}

	xsup_debug_set_level(globals->loglevel);
}

/**
 *
 * Initialize the log file that we will save information to.
 *
 **/
int xsup_driver_init_logfile(int xdaemon)
{
	struct config_globals *globals = NULL;

	debug_setdaemon(xdaemon);

	// This line *MUST* always come after the call to xsup_driver_init_config.
	// If config_get_globals() is called before it, then you will always get
	// a NULL value, and probably return an error.
	globals = config_get_globals();

	if (!globals) {
		// Do *NOT* debug_printf this function, or you will have problems!
		// debug_printf may not work until logfile_setup() is called!
		printf("No valid configuration globals in %s!\n", __FUNCTION__);
		return XEMALLOC;
	}

	return logfile_setup(globals->logpath);
}

/*********************************************
 *
 * Initialize all of the pieces that will be needed for our supplicant.
 * We need to initialize in the correct order, in order to make sure
 * that other pieces of the initialization happen with the correct 
 * information available.
 *
 * THIS FUNCTION SHOULD NEVER BE CALLED OUTSIDE OF THIS FILE!
 *
 *********************************************/
int global_init()
{
	// Initialize OpenSSL library
	SSL_library_init();
	SSL_load_error_strings();

	// XXX Temporary (Fix to put in a proper location?)
	load_plugins();

	return XENONE;
}

/***************************************
 *
 * Trap a segfault, and exit cleanly.
 *
 ***************************************/
void global_sigseg()
{
	fprintf(stderr, "[FATAL] SIGSEGV  (Segmentation Fault)!!!\n");
	xsup_ipc_cleanup(intiface);
	fflush(stderr);
	fflush(stdout);
	delete_pidfile();
	exit(-1);
}

/**
 * \brief Update any listeners that need to know we are still in the process of stopping.
 *
 * \note This is mainly used in Windows to notify the SCM that we are still in the process
 *		 of stopping when we have to wait a long time for threads to terminate.
 **/
void stopping_status_update()
{
#ifdef BUILD_SERVICE
	win_svc_status_stopping();
#endif
}

/****************************************
 *
 * Clean up any values that we have set up for use by the supplicant.  This
 * includes calling any clean up routines for other modules such as EAPoL
 * or EAP.
 *
 * THIS FUNCTION SHOULD NEVER BE CALLED OUTSIDE THIS FILE!
 *
 ****************************************/
void global_deinit()
{
	stopping_status_update();
#ifdef BUILD_SERVICE
	win_svc_deinit();
#endif

	stopping_status_update();
	// XXX Temporary (Fix to put in a better location?)
	unload_plugins();

	debug_printf(DEBUG_DEINIT, "Cert handler clean up.\n");
	stopping_status_update();
	cert_handler_deinit();

	debug_printf(DEBUG_DEINIT, "Clean up IPC.\n");
	stopping_status_update();
	xsup_ipc_cleanup(intiface);

#ifdef HAVE_TNC
	// Clean up the TNC library 
	debug_printf(DEBUG_DEINIT, "Clean up any TNC UI callbacks.\n");
	stopping_status_update();
	tnc_compliance_callbacks_cleanup();

	debug_printf(DEBUG_DEINIT, "Clean up TNC.\n");
	stopping_status_update();
	libtnc_tncc_Terminate();
#endif

	debug_printf(DEBUG_DEINIT, "Clean up event core\n");
	stopping_status_update();
	event_core_deinit();

	debug_printf(DEBUG_DEINIT, "Flush interface cache.\n");
	stopping_status_update();
	interfaces_flush_cache();

	debug_printf(DEBUG_DEINIT, "Free up config\n");
	stopping_status_update();
	config_destroy();

	debug_printf(DEBUG_DEINIT, "Clean up OpenSSL error strings\n");
	stopping_status_update();
	ERR_free_strings();

	debug_printf(DEBUG_DEINIT, "Clean up OpenSSL library data\n");
	stopping_status_update();
	EVP_cleanup();		// Clear memory allocated in SSL_library_init()

#ifndef WINDOWS
	debug_printf(DEBUG_DEINIT, "Clean up pid file\n");
	delete_pidfile();
	FREE(pid_filename);
#endif

#if (WINDOWS || LINUX)
	stopping_status_update();
	crashdump_deinit();
#else
#warning Need to implement crash dump file handling for this platform.
#endif				// (WINDOWS || LINUX)

	debug_printf(DEBUG_DEINIT, "Clean up log file\n");
	stopping_status_update();
	logfile_cleanup();

	if (config_path) {
		debug_printf(DEBUG_DEINIT, "Clean up config path.\n");
		FREE(config_path);
	}

	stopping_status_update();
#ifndef BUILD_SERVICE
	exit(0);
#endif
}

/****************************************
 *
 * Clear, and reload our config.
 *
 ****************************************/
void global_config_reload()
{
	struct config_globals *globals = NULL;

	config_destroy();
	config_system_setup(config_path);

	globals = config_get_globals();
	if (globals == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No configuration globals loaded?\n");
		return;
	}

	xsup_debug_set_level(globals->loglevel);

	// XXX Need to change for multi interface.
	context_config_set_globals(intiface);
#ifndef WINDOWS
	signal(SIGHUP, global_config_reload);
#endif

	// XXX need to rebind to all active interfaces.
}

/**
 * \brief Display our usage information.
 *
 * @param[in] prog   The name of the program we are running. (Should always be XSupplicant. ;)
 * @param[in] opts   An array of options that were passed on the command line.
 **/
void usage(char *prog, struct options opts[])
{
	debug_printf(DEBUG_NORMAL, "\n\nXsupplicant %s.%s\n", VERSION,
		     BUILDNUM);

	debug_printf(DEBUG_NORMAL,
		     "(c) Copyright 2002 - 2007 The Open1x Group\n");
	debug_printf(DEBUG_NORMAL,
		     "Dual licensed under the GPL and BSD licenses." "\n\n");
	debug_printf(DEBUG_NORMAL,
		     "This product makes use of the OpenSSL libraries"
		     ". (http://www.openssl.org)\n\n");

	getopts_usage(prog, opts);
	debug_printf(DEBUG_NORMAL, "\n\n <args> for debug can be any of : \n");

	debug_printf(DEBUG_NORMAL, "\tA : Enable ALL debug output.\n");
	debug_printf(DEBUG_NORMAL,
		     "\ta : Enable EAP authentication method debug.\n");
	debug_printf(DEBUG_NORMAL, "\tE : Enable EAP state machine debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tX : Enable 802.1X state machine debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tx : Enable 802.1X backend state machine debug.\n");
	debug_printf(DEBUG_NORMAL, "\tT : Enable TLS core debug.\n");
	debug_printf(DEBUG_NORMAL, "\tK : Enable key state machine debug.\n");
	debug_printf(DEBUG_NORMAL, "\tk : Enable key operations debug.\n");
	debug_printf(DEBUG_NORMAL, "\tt : Enable initialization debug.\n");
	debug_printf(DEBUG_NORMAL, "\td : Enable deinitialization debug.\n");
	debug_printf(DEBUG_NORMAL, "\te : Enable event core debug.\n");
	debug_printf(DEBUG_NORMAL, "\th : Enable plugin (hook) debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\ti : Enable interface level debug output.\n");
	debug_printf(DEBUG_NORMAL, "\tc : Enable interface context debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tp : Enable physical interface state machine debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tP : Enable configuration parseing debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tw : Enable configuration writing debug.\n");
	debug_printf(DEBUG_NORMAL, "\tr : Enable certificate store debug.\n");
	debug_printf(DEBUG_NORMAL, "\ts : Enable smart card debug.\n");
	debug_printf(DEBUG_NORMAL, "\tm : Enable timers debug.\n");
	debug_printf(DEBUG_NORMAL, "\tI : Enable IPC debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tn : Enable SNMP data collection debug output.\n");
	debug_printf(DEBUG_NORMAL, "\tN : Enable TNC debug.\n");
	debug_printf(DEBUG_NORMAL, "\tM : Enable TNC IMC debug.\n");
	debug_printf(DEBUG_NORMAL,
		     "\tv : Enabled verbose debug.  (Same as normal with some of the debugs from above.)\n");
}

int xsup_driver_basic_init(char *config, int xdaemon)
{
	xsup_driver_init_config(config);

	if (xsup_driver_init_logfile(xdaemon) != 0) {
		printf("Couldn't init log file.  Output will be discarded!\n");
	} else {
		debug_printf(DEBUG_NORMAL, "XSupplicant %s.%s started.\n",
			     VERSION, BUILDNUM);
	}

	return 0;
}

/**
 * \brief Initialize the supplicant.
 *
 **/
int xsup_driver_init(uint8_t clear_ipc, char *device, char *drivername,
		     FDEPTH flags)
{
	snmp_init();		// This needs to be moved to support multiple interfaces.

	global_init();

#if ((HAVE_TNC == 1)  ||  (HAVE_OSC_TNC == 1))
	{
		libtnc_tncc_InitializeStd();
	}
#endif

#ifndef WINDOWS
	pid_filename = Malloc(strlen(PIDBASE) + 6);
	if (pid_filename == NULL) {
		/* Skip creating pid file in case of error */
		debug_printf(DEBUG_NORMAL,
			     "Can't allocate memory for the pid filename!\n");
	} else {
		/* Create pid file ... */
		sprintf(pid_filename, "%s.pid", PIDBASE);
		if (!(create_pidfile())) {
			debug_printf(DEBUG_NORMAL,
				     "Failed to create the pid file!\n");
			FREE(pid_filename);
		}
	}
#endif

	// Init the event core.
	event_core_init();

	// Build our interface cache.
	cardif_enum_ints();

	// Init any interfaces passed on the command line.
	if (device != NULL) {
		debug_printf(DEBUG_INIT,
			     "Initing interface passed on the command line.\n");
		if (context_init_interface
		    (&intiface, NULL, device, drivername, flags) != 0) {
			printf
			    ("Couldn't initialize the interface passed on the command line!  Terminating!\n");
			return -1;
		}
	}
	// Init any interfaces in the config file.
	context_init_ints_from_conf(&intiface);

	cert_handler_init();

	// Init IPC
	if (xsup_ipc_init(clear_ipc) != 0) {
		printf("Couldn't initalize daemon socket!\n");
		global_deinit();
		return -2;
	}

	return XENONE;
}

/**
 *
 * The main body of the program.  We should keep this simple!  Process any
 * command line options that were passed in, set any needed variables, and
 * enter the loop to handle sending an receiving frames.
 *
 * \todo Fix things marked "XXX Fix!"
 *
 **/
#ifdef BUILD_SERVICE
// We are building as a service, so this should be our ServiceMain()
int ServiceMain(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	// XXX Revisit these options.  Many of them don't make sense anymore!
	struct options opts[] = {
		{PARAM_CONFIG, "config", "Load a specific config file", "c", 1},
		{PARAM_INTERFACE, "interface", "Use a specific interface", "i",
		 1},
		{PARAM_DEBUG, "debug", "Set debug level", "d", 1},
		{PARAM_FOREGROUND, "foreground", "Run in forground mode", "f",
		 0},

#ifndef WINDOWS
		{PARAM_DRIVER, "driver",
		 "Use special calls for a specific driver", "D", 1},
		{PARAM_ZKEYS, "zero_keys",
		 "Reset WEP keys to 0s on roam. (Needed for some drivers, such as Orinoco_CS on Linux)",
		 "z", 0},
		{PARAM_NOTEMP, "no_temp",
		 "Don't use IW_ENCODE_TEMP in key setting (Linux Only)", "t",
		 0},
#endif
		{PARAM_TERMINATE, "quit",
		 "Terminate when defaulting to authenticated state", "q", 0},
#ifdef LINUX
		{PARAM_ALTERNATE, "alternate",
		 "Watch alternate interface index for wireless events (Linux Only)",
		 "a", 0},
#endif

#ifndef WINDOWS
		{PARAM_CLEAR_CTRL, "socket",
		 "Remove existing control socket, if found", "s", 0},
#endif
		{PARAM_HELP, "help", "Display this help", "h", 0},
		{PARAM_CONNECTION, "connection",
		 "Force the connection to use (not implemented yet)", "C", 1},
		{0, NULL, NULL, NULL, 0}
	};

	int op, pid;
	char *config = NULL, *device = NULL;
	char *args = NULL;
	char *drivername = NULL;

	int xdaemon = 1, new_debug, zeros = 0;
	int retval = 0;
#ifdef WINDOWS
	int numsupps = 0;	// This is only being used by Windows right now.
#endif
	FDEPTH flags = 0;
	uint8_t clear_ipc = FALSE;

#ifdef WINDOWS
	crashdump_init("\\xsupcrashdmp-" BUILDNUM ".zip");
#elsif LINUX
	crashdump_init("/tmp/xsupcrashdmp-" BUILDNUM ".zip");
#else
#warning Need to implement crash dump file handling for this platform.
#endif				// WINDOWS

#ifdef WINDOWS
	// Install the crash handler so that we can generate minidumps if we fail for some reason.
	crash_handler_install("\\xsupengine-" BUILDNUM ".dmp");
	crashdump_add_file("\\xsupengine-" BUILDNUM ".dmp", 1);

	// A second file is implicitly generated by the crash dumper, so we need to add that to the
	// list too.
	crashdump_add_file("\\xsupengine-" BUILDNUM ".dmp.log", 1);
#elif LINUX
	crash_handler_install("/tmp/xsupengine-" BUILDNUM ".txt");
	crashdump_add_file("/tmp/xsupengine-" BUILDNUM ".txt", 1);
#else
#warning You need to implement crash dump handling for your platform.
#endif

#ifdef BUILD_SERVICE
	win_svc_init();
#endif

#ifdef WINDOWS
	retval = 0;
	retval = supdetect_numinstances("xsupplicant.exe");
	if (retval < 0) {
#ifdef BUILD_SERVICE
		win_svc_error_dup();
#endif
	}
	numsupps += retval;

	retval = supdetect_numinstances("xsupplicant_service.exe");

	if (retval < 0) {
#ifdef BUILD_SERVICE
		win_svc_error_dup();
#endif
	}
	numsupps += retval;

	if (retval >= 2) {
		printf("You already have a copy of Xsupplicant running!\n");
#ifdef BUILD_SERVICE
		win_svc_error_dup();
#else
		return 255;
#endif
	}
#else
	if (supdetect_numinstances("xsupplicant") >= 2) {
		printf("You already have a copy of Xsupplicant running!\n");
		return 255;
	}
#endif

	new_debug = 0;
	config = NULL;

	// Process any arguments we were passed in.
	while ((op = getopts(argc, argv, opts, &args)) != 0) {
		switch (op) {
		case -2:
			printf("Unknown option: %s\n", args);
			break;

		case -1:
			printf("Unable to allocate memory from getopts()!\n");
			return -3;
			break;

		case PARAM_CONFIG:
			// Path to config file.
			config = args;
			break;

		case PARAM_INTERFACE:
			// Interface to use.
			device = args;
			break;

		case PARAM_DEBUG:
			// Set the debug level.
			debug_alpha_set_flags(args);
			break;

		case PARAM_FOREGROUND:
			// Force running in the foreground.
			xdaemon = 2;
			break;

		case PARAM_DRIVER:
			// The name of the wireless driver to use.
			drivername = args;
			break;

		case PARAM_ZKEYS:
			// Reset the encryption key to zeros on roam.
			zeros = 1;
			break;

		case PARAM_NOTEMP:
			// Use IW_ENCODE_TEMP for setting keys.
			// XXX FIX!
//                SET_FLAG(flags, DONT_USE_TEMP);
			break;

		case PARAM_TERMINATE:
			// Terminate when we have exhausted the maximum number of starts we
			// want to send.
			SET_FLAG(flags, TERM_ON_FAIL);
			break;

		case PARAM_ALTERNATE:
			// Enable "off by -1 mode" for wireless cards that provide the
			// driver events on an interface that is (interface index)-1.

			// XXX FIX!
//                SET_FLAG(flags, ONEDOWN);
			break;

		case PARAM_CLEAR_CTRL:
			// Clear the IPC socket file, if it still exists.
			clear_ipc = TRUE;
			break;

		case PARAM_HELP:
			usage(argv[0], opts);
			return -2;
			break;

			// added by npetroni, need to do something with bad options.
			// for now, I say exit.
		default:
			usage(argv[0], opts);
			return -2;
			break;
		}
	}

	if (xdaemon == 1) {
		printf("Starting XSupplicant v. %s.%s\n", VERSION, BUILDNUM);

#ifndef WINDOWS
		// We should fork, and let the parent die.
		pid = fork();

		if (pid > 0) {
			// If we are the parent, die.
			exit(0);
		}
#endif				//WINDOWS

		// Otherwise, keep going.
	}

	retval = xsup_driver_basic_init(config, xdaemon);
	if (retval < 0) {
#ifdef BUILD_SERVICE
		win_svc_basic_init_failed();
#endif
		return -1;
	}
#ifdef BUILD_SERVICE
	else {
		win_svc_running();
	}
#endif

	retval = xsup_driver_init(clear_ipc, device, drivername, flags);
	if (retval < 0) {
#ifdef BUILD_SERVICE
		win_svc_init_failed(retval);
#endif
		return -1;
	}
	// When we quit, cleanup.  For Windows, we handle this a different way.  That method is
	// set up in the event_core_init() call for Windows.
#ifndef WINDOWS
	signal(SIGTERM, global_deinit);
	signal(SIGINT, global_deinit);
	signal(SIGQUIT, global_deinit);
	signal(SIGHUP, global_config_reload);
#endif

	xsup_common_startup_complete();

#ifndef BUILD_SERVICE
	while (1) {
		event_core(intiface);
	}
#else				// BUILD_SERVICE
	win_svc_run(intiface);
#endif				// BUILD_SERVICE

	return XENONE;
}
