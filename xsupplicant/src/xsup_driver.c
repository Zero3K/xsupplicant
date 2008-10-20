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
 *** This code implements 802.1X Authentication on a supplicant
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
#include <dbt.h>
#include <devguid.h>

SERVICE_STATUS          ServiceStatus; 
SERVICE_STATUS_HANDLE   hStatus; 
HDEVNOTIFY				hDevStatus;

// Some service specific error codes.
#define SERVICE_ERROR_STOP_REQUESTED       1
#define SERVICE_ERROR_DUPLICATE_INSTANCE   2
#define SERVICE_ERROR_GLOBAL_DEINIT_CALLED 3
#define SERVICE_ERROR_FAILED_TO_INIT       4
#define SERVICE_ERROR_FAILED_TO_START_IPC  5
#define SERVICE_ERROR_BASIC_INIT_FAILED    6

// Used to determine when a network interface is plugged in.
DEFINE_GUID(GUID_NDIS_LAN_CLASS,                    0xad498944, 0x762f, 0x11d0, 0x8d, 0xcb, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c);

DWORD WINAPI ControlHandler( DWORD request,    DWORD dwEventType,
   LPVOID lpEventData, LPVOID lpContext );
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
  FILE *pidfile;
  
  if (pid_filename == NULL)
    {
      return FALSE;
    }

  pidfile = fopen(pid_filename, "w");
  if (pidfile)
    {
      fprintf(pidfile, "%d", getpid());
      if (fclose(pidfile) != 0)
	{
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
  if (pid_filename == NULL)
    {
      return FALSE;
    }
    
  if (_unlink(pid_filename) != 0)
  {
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
	char *default_cfg = "c:\\windows\\system32\\drivers\\etc\\xsupplicant.conf";
	TCHAR szMyPath[MAX_PATH];
#else
  char *default_cfg = "/etc/xsupplicant.conf";
#endif

  if (config == NULL) 
    {
#ifndef WINDOWS
      config = default_cfg;
#else
		// Use CSIDL_SYSTEM for global system config?
	  if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))
	  {
		  printf("Couldn't determine the path to the common app data.\n");
		  global_deinit();
	  }

	  config = Malloc(strlen(szMyPath)+strlen("xsupplicant.conf")+5);
	  if (config == NULL)
	  {
		  printf("Couldn't allocate memory to store the configuration file path string!\n");
		  global_deinit();
	  }

	  sprintf(config, "%s\\xsupplicant.conf", szMyPath);
#endif
    }

#ifdef WINDOWS
  // Collect the configuration if a troubleticket or crash dump is generated.
  // *DO NOT* delete the configuration file, though. ;)
  crashdump_add_file(config, 0);
#else
  #warning Need to implement crash dump file handlingfor this platform.
#endif // WINDOWS

  config_path = _strdup(config);

  // Build up our config information.
  switch(config_setup(config))
    {
    case XECONFIGFILEFAIL:
    case XECONFIGPARSEFAIL:
		printf("Couldn't read the configuration file.  Building "
			"defaults.\n");
		
		conf_globals = Malloc(sizeof(struct config_globals));
		if (conf_globals == NULL)
		{
			printf("Couldn't allocate memory to store configuration globals.\n");
			exit(255);
		}
		xsupconfig_defaults_set_globals(conf_globals);
		config_fname = _strdup(config_path);
		break;

    case XECONFIGALREADYLOADED:
      printf("config_setup() was called, but a "
	     "configuration is already loaded.\n");
      break;
    }

  FREE(config_path);

#ifdef WINDOWS
  FREE(config);
#endif

  globals = config_get_globals();
  if (globals == NULL)
  {
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

 if (!globals)
   {
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

  // XXX Temporary for excalibur_ga
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
    fflush(stderr); fflush(stdout);
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
      ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING; 
	  ServiceStatus.dwWin32ExitCode = NO_ERROR;
	  ServiceStatus.dwCheckPoint++;

      SetServiceStatus(hStatus, &ServiceStatus); 
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
	UnregisterDeviceNotification(hDevStatus);
#endif

	stopping_status_update();
	// XXX Temporary for excalibur_ga
	unload_plugins();

  debug_printf(DEBUG_DEINIT, "Cert handler clean up.\n");
  stopping_status_update();
  cert_handler_deinit();

  debug_printf(DEBUG_DEINIT, "Clean up IPC.\n");
  stopping_status_update();
  xsup_ipc_cleanup(intiface);

#ifdef HAVE_TNC
	// Clean up the TNC library -- (Always do this last to minimize crashes from IMC bugs.)
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
  EVP_cleanup();  // Clear memory allocated in SSL_library_init()

#ifndef WINDOWS
  debug_printf(DEBUG_DEINIT, "Clean up pid file\n");
  delete_pidfile();
  FREE(pid_filename);
#endif

#ifdef WINDOWS
  stopping_status_update();
  crashdump_deinit();
#else
  #warning Need to implement crash dump file handling for this platform.
#endif // WINDOWS

  debug_printf(DEBUG_DEINIT, "Clean up log file\n");
  stopping_status_update();
  logfile_cleanup();

  if (config_path)
    {
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
  config_setup(config_path);

  globals = config_get_globals();
  if (globals == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "No configuration globals loaded?\n");
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
  debug_printf(DEBUG_NORMAL, "\n\nXsupplicant %s.%s\n", VERSION, BUILDNUM);

  debug_printf(DEBUG_NORMAL, "(c) Copyright 2002 - 2007 The Open1x Group\n");
  debug_printf(DEBUG_NORMAL, "Dual licensed under the GPL and BSD licenses."
	       "\n\n");
  debug_printf(DEBUG_NORMAL, "This product makes use of the OpenSSL libraries"
	       ". (http://www.openssl.org)\n\n");

  getopts_usage(prog, opts);
  debug_printf(DEBUG_NORMAL, "\n\n <args> for debug can be any of : \n");
 
  debug_printf(DEBUG_NORMAL, "\tA : Enable ALL debug output.\n");
  debug_printf(DEBUG_NORMAL, "\ta : Enable EAP authentication method debug.\n");
  debug_printf(DEBUG_NORMAL, "\tE : Enable EAP state machine debug.\n");
  debug_printf(DEBUG_NORMAL, "\tX : Enable 802.1X state machine debug.\n");
  debug_printf(DEBUG_NORMAL, "\tx : Enable 802.1X backend state machine debug.\n");
  debug_printf(DEBUG_NORMAL, "\tT : Enable TLS core debug.\n");
  debug_printf(DEBUG_NORMAL, "\tK : Enable key state machine debug.\n");
  debug_printf(DEBUG_NORMAL, "\tk : Enable key operations debug.\n");
  debug_printf(DEBUG_NORMAL, "\tt : Enable initialization debug.\n");
  debug_printf(DEBUG_NORMAL, "\td : Enable deinitialization debug.\n");
  debug_printf(DEBUG_NORMAL, "\te : Enable event core debug.\n");
  debug_printf(DEBUG_NORMAL, "\th : Enable plugin (hook) debug.\n");
  debug_printf(DEBUG_NORMAL, "\ti : Enable interface level debug output.\n");
  debug_printf(DEBUG_NORMAL, "\tc : Enable interface context debug.\n");
  debug_printf(DEBUG_NORMAL, "\tp : Enable physical interface state machine debug.\n");
  debug_printf(DEBUG_NORMAL, "\tP : Enable configuration parseing debug.\n");
  debug_printf(DEBUG_NORMAL, "\tw : Enable configuration writing debug.\n");
  debug_printf(DEBUG_NORMAL, "\tr : Enable certificate store debug.\n");
  debug_printf(DEBUG_NORMAL, "\ts : Enable smart card debug.\n");
  debug_printf(DEBUG_NORMAL, "\tm : Enable timers debug.\n");
  debug_printf(DEBUG_NORMAL, "\tI : Enable IPC debug.\n");
  debug_printf(DEBUG_NORMAL, "\tn : Enable SNMP data collection debug output.\n");
  debug_printf(DEBUG_NORMAL, "\tN : Enable TNC debug.\n");
  debug_printf(DEBUG_NORMAL, "\tM : Enable TNC IMC debug.\n");
  debug_printf(DEBUG_NORMAL, "\tv : Enabled verbose debug.  (Same as normal with some of the debugs from above.)\n");
}

int xsup_driver_basic_init(char *config, int xdaemon)
{
  xsup_driver_init_config(config);

  if (xsup_driver_init_logfile(xdaemon) != 0)
    {
      printf("Couldn't init log file.  Output will be discarded!\n");
    }
  else
  {
	  debug_printf(DEBUG_NORMAL, "XSupplicant %s.%s started.\n", VERSION, BUILDNUM);
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
  snmp_init();       // This needs to be moved to support multiple interfaces.

  global_init();

#if ((HAVE_TNC == 1)  ||  (HAVE_OSC_TNC == 1))
 {
	 libtnc_tncc_InitializeStd();
 }
#endif
  
#ifndef WINDOWS
  pid_filename = Malloc(strlen(PIDBASE) + 6);
  if (pid_filename == NULL)
    {
      /* Skip creating pid file in case of error */
      debug_printf(DEBUG_NORMAL, "Can't allocate memory for the pid filename!\n");
    } else {
      /* Create pid file ... */
      sprintf(pid_filename, "%s.pid", PIDBASE);
      if(!(create_pidfile()))
        {
          debug_printf(DEBUG_NORMAL, "Failed to create the pid file!\n");
		  FREE(pid_filename);
        }
    }
#endif

  // Init the event core.
  event_core_init();

  // Build our interface cache.
  cardif_enum_ints();

  // Init any interfaces passed on the command line.
  if (device != NULL)
  {
	  debug_printf(DEBUG_INIT, "Initing interface passed on the command line.\n");
	  if (context_init_interface(&intiface, NULL, device, drivername, flags) != 0)
	  {
		  printf("Couldn't initialize the interface passed on the command line!  Terminating!\n");
		  return -1;
	  }
  }

  // Init any interfaces in the config file.
  context_init_ints_from_conf(&intiface);

  cert_handler_init();

  // Init IPC
  if (xsup_ipc_init(clear_ipc) != 0)
    {
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
  struct options opts[] =
  {
	  { PARAM_CONFIG, "config",  "Load a specific config file", "c", 1 },
	  { PARAM_INTERFACE, "interface", "Use a specific interface", "i", 1 },
	  { PARAM_DEBUG, "debug", "Set debug level", "d", 1 },
	  { PARAM_FOREGROUND, "foreground", "Run in forground mode", "f", 0 },

#ifndef WINDOWS
	  { PARAM_DRIVER, "driver", "Use special calls for a specific driver", "D", 1 },
	  { PARAM_ZKEYS, "zero_keys", "Reset WEP keys to 0s on roam. (Needed for some drivers, such as Orinoco_CS on Linux)", "z", 0 },
	  { PARAM_NOTEMP, "no_temp", "Don't use IW_ENCODE_TEMP in key setting (Linux Only)", "t", 0 },
#endif
	  { PARAM_TERMINATE, "quit", "Terminate when defaulting to authenticated state", "q", 0 },
#ifdef LINUX
	  { PARAM_ALTERNATE, "alternate", "Watch alternate interface index for wireless events (Linux Only)", "a", 0 },
#endif

#ifndef WINDOWS
	  { PARAM_CLEAR_CTRL, "socket", "Remove existing control socket, if found", "s", 0 },
#endif
	  { PARAM_PROFILE, "profile", "Force the use of a different profile", "p", 1 },
	  { PARAM_HELP, "help", "Display this help", "h", 0},
	  { PARAM_CONNECTION, "connection", "Force the connection to use (not implemented yet)", "C", 1 }, 
	  { 0, NULL, NULL, NULL, 0 }
  };

  int op, pid;
  char *config = NULL, *device = NULL;
  char *args = NULL;
  char *drivername = NULL;

#ifdef BUILD_SERVICE
  DEV_BROADCAST_DEVICEINTERFACE devBcInterface;
#endif

  int xdaemon = 1, new_debug, zeros=0;
  int retval = 0;
  int numsupps = 0;
  FDEPTH flags = 0;
  uint8_t clear_ipc = FALSE;

#ifdef WINDOWS
  crashdump_init("\\xsupcrashdmp-"BUILDNUM".zip");
#else
  #warning Need to implement crash dump file handling for this platform.
#endif // WINDOWS

#ifdef WINDOWS
	// Install the crash handler so that we can generate minidumps if we fail for some reason.
	crash_handler_install("\\xsupengine-"BUILDNUM".dmp");
	crashdump_add_file("\\xsupengine-"BUILDNUM".dmp", 1);

	// A second file is implicitly generated by the crash dumper, so we need to add that to the
	// list too.
	crashdump_add_file("\\xsupengine-"BUILDNUM".dmp.log", 1);
#endif

#ifdef BUILD_SERVICE
   ServiceStatus.dwServiceType = 
      SERVICE_WIN32; 
   ServiceStatus.dwCurrentState = 
      SERVICE_START_PENDING; 
   ServiceStatus.dwControlsAccepted   =  
      SERVICE_ACCEPT_STOP | 
      SERVICE_ACCEPT_SHUTDOWN |
	  SERVICE_ACCEPT_POWEREVENT |
	  SERVICE_ACCEPT_SESSIONCHANGE;
   ServiceStatus.dwWin32ExitCode = 0; 
   ServiceStatus.dwServiceSpecificExitCode = 0; 
   ServiceStatus.dwCheckPoint = 0; 
   ServiceStatus.dwWaitHint = 0; 
 
   hStatus = RegisterServiceCtrlHandlerEx(
      "XSupplicant", 
      (LPHANDLER_FUNCTION_EX)ControlHandler,
	  NULL); 
   if (hStatus == (SERVICE_STATUS_HANDLE)0) 
   { 
      // Registering Control Handler failed
      return -1; 
   }  

   // Register for device insert/remove notifications.
   ZeroMemory(&devBcInterface, sizeof(devBcInterface));
   devBcInterface.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
   devBcInterface.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
   memcpy( &(devBcInterface.dbcc_classguid),
   			&(GUID_NDIS_LAN_CLASS),
   			sizeof(struct _GUID));

   hDevStatus = RegisterDeviceNotification(hStatus, &devBcInterface, DEVICE_NOTIFY_SERVICE_HANDLE); 
#endif

#ifdef WINDOWS
   retval = 0;
   retval = supdetect_numinstances("xsupplicant.exe");
   if (retval < 0) 
   {
#ifdef BUILD_SERVICE
      ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
      ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
	  ServiceStatus.dwServiceSpecificExitCode = SERVICE_ERROR_DUPLICATE_INSTANCE;
      SetServiceStatus(hStatus, &ServiceStatus); 
#endif
   }
	numsupps += retval;

   retval = supdetect_numinstances("xsupplicant_service.exe");

   if (retval < 0) 
   {
#ifdef BUILD_SERVICE
      ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
      ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR; 
	  ServiceStatus.dwServiceSpecificExitCode = SERVICE_ERROR_DUPLICATE_INSTANCE;
      SetServiceStatus(hStatus, &ServiceStatus); 
#endif
   }
	numsupps += retval;

	if (retval >= 2)
	{
		printf("You already have a copy of Xsupplicant running!\n");
#ifdef BUILD_SERVICE
      ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
      ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR; 
	  ServiceStatus.dwServiceSpecificExitCode = SERVICE_ERROR_DUPLICATE_INSTANCE;
      SetServiceStatus(hStatus, &ServiceStatus); 
#else
		return 255;
#endif
	}
#else
   if (supdetect_numinstances("xsupplicant") >= 2)
   {
	   printf("You already have a copy of Xsupplicant running!\n");
	   return 255;
   }
#endif

  new_debug = 0;
  config = NULL;
	
  // Process any arguments we were passed in.
  while ((op = getopts(argc, argv, opts, &args)) != 0) 
    {
      switch (op)
		{
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
//		  SET_FLAG(flags, DONT_USE_TEMP);
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
//		  SET_FLAG(flags, ONEDOWN);
		  break;
	  
		case PARAM_CLEAR_CTRL:
		  // Clear the IPC socket file, if it still exists.
		  clear_ipc = TRUE;
		  break;

  		case PARAM_PROFILE:
		  printf("Forcing the use of profile '%s'!\n", args);
		  config_set_forced_profile(args);
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

  if (xdaemon == 1)
    {
      printf("Starting XSupplicant v. %s.%s\n", VERSION, BUILDNUM);

#ifndef WINDOWS
      // We should fork, and let the parent die.
      pid = fork();
      
      if (pid > 0) 
		{
			// If we are the parent, die.
			exit(0);
		}
#endif //WINDOWS
      
      // Otherwise, keep going.
    }

  retval = xsup_driver_basic_init(config, xdaemon);
  if (retval < 0)
  {
#ifdef BUILD_SERVICE
      ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
      ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR; 
	  ServiceStatus.dwServiceSpecificExitCode = SERVICE_ERROR_BASIC_INIT_FAILED;
      SetServiceStatus(hStatus, &ServiceStatus); 
#endif
	  return -1;
  }
#ifdef BUILD_SERVICE
  else
  {
	  // The next part of the startup could see some lag that can confuse
	  // Windows about the state of the service.  So, we need to report the
	  // state earlier.  Technically we are in a fully running state here, 
	  // even though no interfaces are operational and no IPC channel is 
	  // available.
	ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
	SetServiceStatus (hStatus, &ServiceStatus);
  }
#endif

  retval = xsup_driver_init(clear_ipc, device, drivername, flags);
  if (retval < 0) 
   {
#ifdef BUILD_SERVICE
      ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
      ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR; 

	  if (retval == 2)
	  {
		  ServiceStatus.dwServiceSpecificExitCode = SERVICE_ERROR_FAILED_TO_START_IPC;
	  }
	  else
	  {
		ServiceStatus.dwServiceSpecificExitCode = SERVICE_ERROR_FAILED_TO_INIT;
	  }
      SetServiceStatus(hStatus, &ServiceStatus); 
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
  signal(SIGSEGV, global_sigseg);
#endif

  xsup_common_startup_complete();

#ifndef BUILD_SERVICE
  while (1)
    {
		event_core(intiface);
    }
#else  // BUILD_SERVICE
   while (ServiceStatus.dwCurrentState == 
          SERVICE_RUNNING)
   {
		event_core(intiface);
   }

   ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
   ServiceStatus.dwWin32ExitCode = NO_ERROR;

   SetServiceStatus(hStatus, &ServiceStatus); 

#endif // BUILD_SERVICE

  return XENONE;
}

#ifdef BUILD_SERVICE
/**
 * Extra functions that are needed to build as a Windows service.
 **/

/**
 * \brief Handle device insertion/removal events that are coming in on the service
 *        event handler.
 *
 * \note Because we filter by the class of events we want, we don't need to do any extra
 *       checking in here.  (Unless someone messes with our filter. ;)
 *
 * @param[in] dwEventType   The event type that triggered this call.
 * @param[in] lpEventData   The data blob that came with the event.
 **/
void ProcessDeviceEvent(DWORD dwEventType, LPVOID lpEventData)
{
	PDEV_BROADCAST_DEVICEINTERFACE lpdb = (PDEV_BROADCAST_DEVICEINTERFACE)lpEventData;

	switch (dwEventType)
	{
		case DBT_DEVICEARRIVAL:
			// This check is largely pointless, but leave it here just to make sure nothing weird
			// happens.
			if (lpdb->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
			{
				// The device name we care about will start with something like this :
				//    \\?\Root#MS_PSCHEDMP#0008#
				debug_printf(DEBUG_INT, "Got a device insertion event for '%ws'.\n", lpdb->dbcc_name);

				// If it is the one we want, then process it, otherwise ignore it.
				if (_wcsnicmp(lpdb->dbcc_name, L"\\\\?\\Root#MS_PSCHEDMP#", 21) == 0)
				{
					debug_printf(DEBUG_INT, "Processing interface insertion!\n");
					cardif_windows_events_add_remove_interface(lpdb->dbcc_name, TRUE);
				}
			}
			break;

		case DBT_DEVICEREMOVECOMPLETE:
			// This check is largely pointless, but leave it here just to make sure nothing weird
			// happens.
			if (lpdb->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
			{
				// The device name we care about will start with something like this :
				//    \\?\Root#MS_PSCHEDMP#0008#
				debug_printf(DEBUG_INT, "Got a device removal event for '%ws'.\n", lpdb->dbcc_name);

				// If it is the one we want, then process it, otherwise ignore it.
				if (_wcsnicmp(lpdb->dbcc_name, L"\\\\?\\Root#MS_PSCHEDMP#", 21) == 0)
				{
					debug_printf(DEBUG_INT, "Processing interface removal!\n");
					cardif_windows_events_add_remove_interface(lpdb->dbcc_name, FALSE);
				}
			}
			break;
		
		default:
			debug_printf(DEBUG_INT, "Got event %x on device handler.\n", dwEventType);
			break;
	}
}

DWORD WINAPI ControlHandler( DWORD request, DWORD dwEventType,
   LPVOID lpEventData, LPVOID lpContext )
{ 
   switch(request) 
   { 
      case SERVICE_CONTROL_STOP: 
         ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING; 
         SetServiceStatus (hStatus, &ServiceStatus); 
		  event_core_terminate();
         return NO_ERROR; 
 
      case SERVICE_CONTROL_SHUTDOWN: 
         ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING; 
         SetServiceStatus (hStatus, &ServiceStatus); 
		  event_core_terminate();
         return NO_ERROR; 

	  case SERVICE_CONTROL_DEVICEEVENT:
		  ProcessDeviceEvent(dwEventType, lpEventData);
		  return NO_ERROR;

	  case SERVICE_CONTROL_SESSIONCHANGE:
		  switch (dwEventType)
		  {
		  case WTS_CONSOLE_CONNECT:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Console connect. (Session : %d  Size : %d)\n", 
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			  if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			  {
				  event_core_user_logged_on();
			  }
			  break;

		  case WTS_CONSOLE_DISCONNECT:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Console disconnect.(Session : %d  Size : %d)\n", 
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			  if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			  {
				  event_core_user_logged_off();
			  }
			  break;

		  case WTS_SESSION_LOGON:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>  User logged on!  (Session : %d  Size : %d)\n", 
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			  if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			  {
				  event_core_user_logged_on();
			  }
			  break;

		  case WTS_SESSION_LOGOFF:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>  User logged off! (Session : %d  Size : %d)\n", 
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				  ((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			  if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			  {
				  event_core_user_logged_off();
			  }
			  break;

		  case WTS_REMOTE_CONNECT:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Remote connect.\n");
			  break;

		  case WTS_REMOTE_DISCONNECT:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Remote disconnect.\n");
			  break;

		  case WTS_SESSION_LOCK:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Session Lock\n");
			  break;

		  case WTS_SESSION_UNLOCK:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Session Unlock\n");
			  break;

		  case WTS_SESSION_REMOTE_CONTROL:
			  debug_printf(DEBUG_EVENT_CORE, ">>>>>>>>>>>>>>>>>>>>>>>>>>> Session is under remote control.\n");
			  break;

		  default:
			  debug_printf(DEBUG_EVENT_CORE, "Unknown event type %d.\n", dwEventType);
			  break;
		  }
		  break;

	  case SERVICE_CONTROL_POWEREVENT:
		  // There are a whole bunch of different states that can be signaled.  The ones
		  // below represent the ones that we either care about now, or might care about
		  // in the future.
		  //
		  //  If we don't process an event, we need to be sure to return NO_ERROR, to avoid
		  // running in to a situation where the OS believes that we want to block it from
		  // suspending.
        switch((int) dwEventType)
            {
            case PBT_APMPOWERSTATUSCHANGE:
				// We don't care about this one right now.
               return NO_ERROR;

			case PBT_APMRESUMEAUTOMATIC:
				// This signal should be generated whenever we resume (sleep or hibernate)
				event_core_waking_up_thread_ctrl();
				return NO_ERROR;

			case PBT_APMRESUMESUSPEND:
				// This signal gets triggered right before PBT_APMRESUMEAUTOMATIC.  So, we don't
				// want to deal with it right now.
				return NO_ERROR;

			case PBT_APMQUERYSUSPEND:
				// This is the first indication that we are going in to suspend mode.  Most of the
				// time it means that we are going to complete going in to suspend mode, however, if
				// PBT_APMQUERYSUSPENDFAILD is triggered, then we won't suspend, so we need to kick
				// everything back up.
				event_core_going_to_sleep_thread_ctrl();
				return NO_ERROR;

			case PBT_APMQUERYSUSPENDFAILED:
				// Suspend failed, so turn everything back on.
				event_core_cancel_sleep_thread_ctrl();
				return NO_ERROR;

            case PBT_APMSUSPEND:
				// We get this signal when the system is starting to go in to a suspend state.
				// By the time we get here, it is probably too late to do much of anything.
               return NO_ERROR;

            // case PBT_WhatEver and so on.
            }
		debug_printf(DEBUG_NORMAL, "Power state event : %x\n", ((int) dwEventType));
		return NO_ERROR;
		break;
        
      default:
         break;
    } 
 
    // Report current status
    SetServiceStatus (hStatus, &ServiceStatus);
 
    return NO_ERROR; 
}

void main() 
{ 
   SERVICE_TABLE_ENTRY ServiceTable[2];
   ServiceTable[0].lpServiceName = "Xsupplicant";
   ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

   ServiceTable[1].lpServiceName = NULL;
   ServiceTable[1].lpServiceProc = NULL;

   // Start the control dispatcher thread for our service
   StartServiceCtrlDispatcher(ServiceTable);  
}

#endif // BUILD_SERVICE
