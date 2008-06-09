/**
 * Routines for displaying/logging debug information.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_debug.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef WINDOWS
#include <strings.h>
#include <unistd.h>
#include <netinet/in.h>
#include <syslog.h>
#include <time.h>
#else
#include <winsock2.h>
#include <shlobj.h>

#define stat64 _stat64
#endif  // WINDOWS

#include <string.h>
#include <stdlib.h>
#include <ctype.h>


#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "xsup_err.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "ipc_events.h"
#include "xsup_debug.h"

#ifdef DEBUG_LOG_PLUGINS
#include "plugins.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define LOGCHECK_INTERVAL   60   ///< The default amount of "time" to check if we need to roll logs.

/** By default just show the "normal" stuff. */
uint32_t debug_level = DEBUG_NORMAL;
int isdaemon = 0;                ///< 2 = foreground mode, 1 = background mode, 0 =???
int syslogging = 0;
FILE *logfile = NULL;
char *active_logpath = NULL;     ///< The logfile that is currently being used.  Will be NULL if a file is not being used.
char *active_logfile = NULL;     ///< The full pathname to the log file.
int logroll_timer = FALSE;       ///< By default, don't roll logs.  (Don't ever change this default.  It won't do what you expect!)
int next_logroll_check = LOGCHECK_INTERVAL;  ///<  This will be decremented by a call to xsup_debug_check_log_roll().  It will happen roughly once a second.  (It may happen faster than that, so don't assume it is always once a second!)

#ifdef WINDOWS
#define DEFAULT_LOG_NAME "xsupplicant"
#define DEFAULT_LOG_EXT  "log"
#define DEFAULT_LOG_PATH "c:\\windows\\system32\\logfiles"
#else
#define DEFAULT_LOG_NAME "xsupplicant.log"
#define DEFAULT_LOG_PATH "/var/log"
#endif

#define TEMP_LOG_BUF_SIZE  2048

/**
 * \brief Check the current log file to see if we need to rotate it.
 **/
void xsup_debug_check_log_roll()
{
#ifndef LINUX
	struct config_globals *globals = NULL;
	struct stat64 statdata;
	uint64_t size = 0;

	next_logroll_check--;

	if (next_logroll_check > 0)  return;   // Not time to check yet.

	if (active_logfile == NULL)
	{
//		debug_printf(DEBUG_EVENT_CORE, "There is no log file defined.  Ignoring.\n");
		return;
	}

	globals = config_get_globals();
	if (globals == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No global configuration information was found!  Not touching the log files.\n");
		next_logroll_check = LOGCHECK_INTERVAL;
		return;
	}

	// Stat the log file and see how big it is.
	memset(&statdata, 0x00, sizeof(statdata));

	if (stat64(active_logfile, &statdata) != 0)
	{
//		debug_printf(DEBUG_NORMAL, "Unable to get file status information for file '%s'.  Log will not be rolled.\n", active_logfile);
		next_logroll_check = LOGCHECK_INTERVAL;
		return;
	}

	if (globals->size_to_roll == 0)
	{
		size = LOG_SIZE_TO_ROLL;
	}
	else
	{
		size = globals->size_to_roll;
	}

	size *= (1024*1024);

	if (statdata.st_size >= size)
	{
		if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ROLL_LOGS))
		{
			debug_printf(DEBUG_NORMAL, "Log file is %d byte(s).  Rolling.\n", statdata.st_size);

			// This should cause logs to be rolled.
			logfile_cleanup();
			logfile_setup();
		}
		else
		{
			debug_printf(DEBUG_EVENT_CORE, "Log rolling threashold reached.  Not rolling logs because we are configured not to.\n");
		}
	}

	next_logroll_check = LOGCHECK_INTERVAL;
#endif
}

/**
 * \brief Validate an assertion.
 *
 * Check the value of 'tf'.  If it returns false, print out some debug
 * information and either return FALSE, or terminate.  (Depending on the
 * value of terminal.)  In general, this function should be called via the
 * xsup_assert() macro, so that the filename, line number, and function
 * name are automatically filled in.
 *
 * @param[in] tf   A value that should be set to either TRUE or FALSE.  Usually in the caller code
 *                 this will be something like (ptr != NULL).
 * @param[in] desc   A text description of the assertion.  Usually this is just the truth value
 *                   from tf included in quotes.
 * @param[in] terminal   If this value is set to TRUE, then if the assertion is FALSE we can't
 *                       continue, and the program terminates.
 * @param[in] file   The name of the source file this assertion was in.  This is automagically
 *                   filled in by the xsup_assert() macro.
 * @param[in] line   The line number in the source file that the assertion happened on.  This is
 *                   automagically filled in by the xsup_assert() macro.
 * @param[in] function   The function name that the assertion happened in.  This is
 *                       automagically filled in by the xsup_assert() macro.
 *
 * \retval TRUE if the assertion is valid.
 * \retval FALSE if the assertion is not valid, and not terminal.
 */
int xsup_assert_long(int tf, char *desc, int terminal, char *file, int line,
		     const char *function)
{
  if (!tf)
    {
      debug_printf(DEBUG_NORMAL, "Assertion '%s' failed in file %s, "
		   "function %s(), at line %d.\n", desc, file, function, line);

      if (terminal)
	{
	  debug_printf(DEBUG_NORMAL, "Cannot continue!\n");
	  exit(255);
	}
      return FALSE;
    }
  return TRUE;
}

/**
 * \brief Get the system date/time as a string to be used in a log file.
 *
 * \retval NULL on failure
 * \retval A date time string of the format mm/dd/yyyy  hh:mm:ss.ms
 **/
char *xsup_debug_system_time()
{
  char *tdstring = NULL;

#ifdef WINDOWS
  SYSTEMTIME systime;

  GetLocalTime(&systime);

  tdstring = Malloc(128);  // Should be WAY more than enough!
  if (tdstring == NULL) 
  {
	  // DO NOT debug_print in here!  It will overflow your stack!
	  return NULL;
  }

  sprintf(tdstring, "%d-%.2d-%.2d  %d:%.2d:%.2d.%.3d", systime.wYear, systime.wMonth, systime.wDay, 
	  systime.wHour, systime.wMinute, systime.wSecond, systime.wMilliseconds);

  return tdstring;
#else
  time_t systime;

  time(&systime);

  tdstring = Malloc(128);  // Should be WAY more than enough!
  if (tdstring == NULL) 
  {
	  debug_printf(DEBUG_NORMAL, "Unable to allocate memory to prepend system date/time.  You logs won't have date/time stamps.");
	  return NULL;
  }

  ctime_r(&systime, tdstring);

  // Cut off the \n added by ctime.
  tdstring[strlen(tdstring) - 1] = '\0';

  return tdstring;
#endif
}


/**
 * \brief Convert a string to be all lowercase.
 *
 * @param[in] instr   The string to convert to lowercase.  The conversion will happen IN PLACE!
 */
void lowercase(char *instr)
{
  int i;

  for (i=0;i<strlen(instr);i++)
    {
      instr[i] = tolower(instr[i]);
    }
}

/**
 * \brief Determine a file exists.
 *
 * @param[in] filename   The full path to the file we want to check for existance.
 *
 * \retval FALSE if the file does not exist
 * \retval TRUE if the file exists.
 **/
static int file_exists(char *filename)
{
	FILE *myfile;

	if (filename == NULL) return FALSE;

	myfile = fopen(filename, "r");   // Try to open in read mode.
	if (myfile == NULL)
	{
		// The file doesn't exist.
		return FALSE;
	}

	fclose(myfile);
	return TRUE;
}

/**
 * \brief Rotate all of the log files only keeping a certain number of them.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
static int rotate_log_files()
{
	int num = 0;
	int namesize = 0;
	int i = 0;
	char temp[10];
	char temp2[10];
	char *full_filename = NULL;
	char *new_filename = NULL;
	struct config_globals *globals;

    globals = config_get_globals();

    if (globals == NULL)
	{
	  printf("No valid configuration globals available at %s!\n",
			__FUNCTION__);
	  return -1;
	}

	num = globals->logs_to_keep-1;   // -1 because we want xsupplicant.log through xsupplicant_(logs_to_keep-1).log

	if (globals->logpath == NULL)
	{
		printf("No log path setting is defined in the configuration file.  We won't roll "
				"logs!\n");
		return -1;
	}

	sprintf((char *)&temp, "%d", num);

#ifdef WINDOWS
	namesize = strlen(temp) + strlen(DEFAULT_LOG_NAME) + strlen(DEFAULT_LOG_EXT) + strlen(globals->logpath) + 5;  // 5 gives us extra padding for a . and \ and _ and a NULL, and one for good measure.
#else
	namesize = strlen(temp) + strlen(DEFAULT_LOG_NAME) + strlen(globals->logpath) + 4;  // 4 gives us extra padding for a . and \ and a NULL, and one for good measure.
#endif

	full_filename = Malloc(namesize);
	if (full_filename == NULL)
	{
		fprintf(stderr, "Failed to allocate space to store the name of the log file we want to roll.\n");
		return -1;
	}

#ifdef WINDOWS
	if (globals->logpath[strlen(globals->logpath)-1] == '\\')
	{
		sprintf(full_filename, "%s%s_%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp, DEFAULT_LOG_EXT);
	}
	else
	{
		sprintf(full_filename, "%s\\%s_%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp, DEFAULT_LOG_EXT);
	}
#else
	sprintf(full_filename, "%s/%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp);
#endif

	if (file_exists(full_filename) == TRUE)
	{
		// The last file has rolled off the end.  So delete it.
		if (unlink(full_filename) != 0)
		{
			fprintf(stderr, "Couldn't delete file '%s'!  Can't roll log files!\n", full_filename);
			return -1;
		}
	}

	FREE(full_filename);

	for (i = num; i > 0; i--)
	{
		if ((i-1) > 0)
		{
			sprintf((char *)&temp, "%d", (i-1));
		}
		else
		{
			memset(&temp, 0x00, sizeof(temp));
		}

#ifdef WINDOWS
		namesize = strlen(temp) + strlen(DEFAULT_LOG_NAME) + strlen(DEFAULT_LOG_EXT) + strlen(globals->logpath) + 5;  // 5 gives us extra padding for a . and \ and _ and a NULL, and one for good measure.
#else
		namesize = strlen(temp) + strlen(DEFAULT_LOG_NAME) + strlen(globals->logpath) + 4;  // 4 gives us extra padding for a . and \ and a NULL, and one for good measure.
#endif

		full_filename = Malloc(namesize);
		if (full_filename == NULL)
		{
			fprintf(stderr, "Failed to allocate space to store the name of the log file we want to roll.\n");
			return -1;
		}

#ifdef WINDOWS
		if (strlen(temp) != 0)
		{
			if (globals->logpath[strlen(globals->logpath)-1] == '\\')
			{
				sprintf(full_filename, "%s%s_%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp, DEFAULT_LOG_EXT);
			}
			else
			{
				sprintf(full_filename, "%s\\%s_%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp, DEFAULT_LOG_EXT);
			}
		}
		else
		{
			if (globals->logpath[strlen(globals->logpath)-1] == '\\')
			{
				sprintf(full_filename, "%s%s.%s", globals->logpath, DEFAULT_LOG_NAME, DEFAULT_LOG_EXT);
			}
			else
			{
				sprintf(full_filename, "%s\\%s.%s", globals->logpath, DEFAULT_LOG_NAME, DEFAULT_LOG_EXT);
			}
		}
#else
		sprintf(full_filename, "%s/%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp);
#endif

		if (file_exists(full_filename) == TRUE)
		{
			new_filename = Malloc(namesize);     // The new name should be the same, or shorter than the existing name.
			if (new_filename == NULL)
			{
				fprintf(stderr, "Failed to allocate space to store the name of the log file we want to roll to.\n");
				return -1;
			}

			sprintf((char *)&temp2, "%d", i);

#ifdef WINDOWS
			if (globals->logpath[strlen(globals->logpath)-1] == '\\')
			{	
				sprintf(new_filename, "%s%s_%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp2, DEFAULT_LOG_EXT);
			}
			else
			{
				sprintf(new_filename, "%s\\%s_%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp2, DEFAULT_LOG_EXT);
			}
#else
			sprintf(new_filename, "%s/%s.%s", globals->logpath, DEFAULT_LOG_NAME, temp2);
#endif

			printf("Rolling log file '%s' to '%s'\n", full_filename, new_filename);
			if (rename(full_filename, new_filename) != 0)
			{
				fprintf(stderr, "Failed to roll log file from '%s' to '%s'.   Is there another file already at '%s'?\n",
					full_filename, new_filename, new_filename);
				return -1;
			}
			else
			{
			    #ifdef WINDOWS
				crashdump_add_file(new_filename, 0);
			    #else
                                #warning Need to implement crash dump file handlingfor this platform.
                            #endif // WINDOWS  
			}

			FREE(new_filename);
		}

		FREE(full_filename);
	}

	return 0;
}

/**
 *
 * Return the logging facility the user asked us to use.
 *
 */
int xsup_debug_get_facility(char *facility_str)
{
#ifndef WINDOWS
  int facility_num = LOG_DAEMON;

  if (strcmp("cron", facility_str) == 0) facility_num = LOG_CRON;
  if (strcmp("daemon", facility_str) == 0) facility_num = LOG_DAEMON;
  if (strcmp("ftp", facility_str) == 0) facility_num = LOG_FTP;
  if (strcmp("kern", facility_str) == 0) facility_num = LOG_KERN;
  if (strcmp("local0", facility_str) == 0) facility_num = LOG_LOCAL0;
  if (strcmp("local1", facility_str) == 0) facility_num = LOG_LOCAL1;
  if (strcmp("local2", facility_str) == 0) facility_num = LOG_LOCAL2;
  if (strcmp("local3", facility_str) == 0) facility_num = LOG_LOCAL3;
  if (strcmp("local4", facility_str) == 0) facility_num = LOG_LOCAL4;
  if (strcmp("local5", facility_str) == 0) facility_num = LOG_LOCAL5;
  if (strcmp("local6", facility_str) == 0) facility_num = LOG_LOCAL6;
  if (strcmp("local7", facility_str) == 0) facility_num = LOG_LOCAL7;
  if (strcmp("lpr", facility_str) == 0) facility_num = LOG_LPR;
  if (strcmp("mail", facility_str) == 0) facility_num = LOG_MAIL;
  if (strcmp("news", facility_str) == 0) facility_num = LOG_NEWS;
  if (strcmp("user", facility_str) == 0) facility_num = LOG_USER;
  if (strcmp("uucp", facility_str) == 0) facility_num = LOG_UUCP;

  return facility_num;
#else
	return 0;
#endif
}

/**
 * \brief Determine if we need to syslog, and if so, set it up.
 *
 * \retval 0 if we don't need to syslog
 * \retval 1 if we need to syslog
 * \retval <0 if we got an error trying to syslog.
 **/
static int should_do_syslog()
{
	char *tempstr = NULL;
	struct config_globals *globals = NULL;
	int facility = 0;

#ifdef WINDOWS
	return 0;        // Windows can't syslog.
#else
	// Otherwise, we need to set up to syslog.
    globals = config_get_globals();

    if (globals == NULL)
	{
	  printf("No valid configuration globals available at %s!\n",
		 __FUNCTION__);
	  return XEMALLOC;
	}

	if (globals->logtype != LOGGING_SYSLOG)) return 0;

    tempstr = globals->log_facility;
    lowercase(tempstr);

    facility = xsup_debug_get_facility(tempstr);

    openlog("Xsupplicant", LOG_CONS | LOG_PID | LOG_NDELAY, 
	        facility);
	     
	syslogging = 1;

	return 1;
#endif
}

/**
 * \brief Determine if the logpath has changed.  
 *
 * @param[in] newpath   The newly set path.  (Usually the same as globals->logpath.)
 *
 * \retval TRUE if the logpath has changed.
 * \retval FALSE if the logpath has not changed.
 **/
int logpath_changed(char *newpath)
{
	// If we are logging to the foreground, then don't do anything.
	if (isdaemon == 2) return FALSE;

	// If we aren't running in the foreground, and newpath isn't NULL (but active_logpath is), then it has changed.
	if ((active_logpath == NULL) && (newpath != NULL)) return TRUE;

	if ((newpath == NULL) || (strlen(newpath) == 0)) 
	{
		// Turn off the log file if we are using it.
/*		if (logfile != NULL)
		{
			debug_printf(DEBUG_NORMAL, "Logging to a file has been disabled.\n");
			fclose(logfile);
			FREE(active_logpath);
		}  */

		return TRUE;
	}

	// If we aren't logging to a file right now, then it doesn't matter if the logpath changed.
	if (logfile == NULL) return TRUE;

	if (strcmp(newpath, active_logpath) == 0) return FALSE;

	return TRUE;
}

/**
 * \brief Remove an old logfile, and create a new one.
 */
int logfile_setup()
{
  char *tempstr = NULL;
#ifdef WINDOWS
  TCHAR szMyPath[MAX_PATH];
#endif
  int result;
  struct config_globals *globals = NULL;

  globals = config_get_globals();

  if (globals == NULL)
  {
	  printf("No valid configuration globals available at %s!\n",
			__FUNCTION__);
	  return -1;
  }

  if (isdaemon != 2)  // If we aren't in foreground mode.
	{
		result = should_do_syslog();
		if (result < 0)
		{
			fprintf(stderr, "Can't create log.  Will log to this console.\n");
			isdaemon = 2;
			return XENONE;
		}

		if (result == 1) return XENONE;

		// Make sure we want to log to a file.
		if (globals->logtype != LOGGING_FILE) return 0;

#ifdef WINDOWS
		if (globals->logpath == NULL)
		{
		  if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))
		  {
			  printf("Couldn't determine the path to the common app data.\n");
			  return -1;
		  }

		  globals->logpath = _strdup(szMyPath);

		  tempstr = (char *)Malloc(strlen(szMyPath)+strlen(DEFAULT_LOG_NAME)+strlen(DEFAULT_LOG_EXT)+4);
		}
		else
		{
		    tempstr = (char *)Malloc(strlen(globals->logpath)+strlen(DEFAULT_LOG_NAME)+strlen(DEFAULT_LOG_EXT)+4);
		}
#else
	    tempstr = (char *)Malloc(strlen(globals->logpath)+strlen(DEFAULT_LOG_NAME)+4);
#endif
	    if (tempstr == NULL)
	    {
	      printf("Couldn't allocate memory for temporary string! (%s:%d)\n",
		     __FUNCTION__, __LINE__);
	      return XEMALLOC;
	    }

#ifdef WINDOWS
		if (globals->logpath == NULL)
		{
 		    sprintf(tempstr, "%s\\%s.%s", szMyPath, DEFAULT_LOG_NAME, DEFAULT_LOG_EXT);
		}
		else
		{
		    sprintf(tempstr, "%s\\%s.%s", globals->logpath, DEFAULT_LOG_NAME, DEFAULT_LOG_EXT);
		}
#else
	    sprintf(tempstr, "%s/%s", globals->logpath, DEFAULT_LOG_NAME);
#endif

		if (rotate_log_files() < 0)
		{
			printf("Error rolling log files!\n");
		}

        logfile = fopen(tempstr, "w+");
        if (!logfile)
		{
			printf("Couldn't create log file '%s'!\n", tempstr);
			return XEGENERROR;
		}

	#ifdef WINDOWS
		crashdump_add_file(tempstr, 0);
	#else
            #warning Need to implement crash dump file handlingfor this platform.
        #endif // WINDOWS


		if (active_logfile != NULL) free(active_logfile);
		active_logfile = _strdup(tempstr);

		FREE(tempstr);

		// Activate our log rolling check timer.
		logroll_timer = TRUE;		
  }

  if (active_logpath != NULL)
  {
	  debug_printf(DEBUG_NORMAL, "active_logpath != NULL!  This is an error in the code, and should be fixed!\n");
	  FREE(active_logpath);
  }

  if (globals->logpath != NULL) active_logpath = _strdup(globals->logpath);

  return XENONE;
}

/**
 *
 * Clean up our old logfile.
 *
 */
void logfile_cleanup()
{
  if (logfile != NULL)
    {
      fclose(logfile);
	  logfile = NULL;
	  FREE(active_logpath);
    }

  if (syslogging == 1)
    {
#ifndef WINDOWS
      closelog();
#endif
    }
}

/**
 * \brief Set flags based on an ASCII string that was passed in.
 *
 * @param[in] new_flags   A string that contains some number of ASCII character
 *                        flags that will be used to set debug flags.
 */
void debug_alpha_set_flags(char *new_flags)
{
  int i;

  debug_level = DEBUG_NORMAL;          // ALWAYS start with the normal flag set.

  for (i=0;i<strlen(new_flags);i++)
    {
      switch (new_flags[i])
	{
	  case 'N':
		  debug_level |= DEBUG_TNC;
		  break;

	  case 'M':
		  debug_level |= DEBUG_TNC_IMC;
		  break;

	  case 'r':
		  debug_level |= DEBUG_CERTS;
		  break;

	  case 'T':
			debug_level |= DEBUG_TLS_CORE;
			break;

	  case 'm':
		  debug_level |= DEBUG_TIMERS;
		  break;

	  case 'c':
		  debug_level |= DEBUG_CONTEXT;
		  break;

	  case 'd':
		  debug_level |= DEBUG_DEINIT;
		  break;

	  case 't':
		  debug_level |= DEBUG_INIT;
		  break;

	  case 's':
		  debug_level |= DEBUG_SMARTCARD;
		  break;

	  case 'I':
		  debug_level |= DEBUG_IPC;
		  break;

	  case 'w':
		  debug_level |= DEBUG_CONFIG_WRITE;
		  break;

	  case 'P':
		  debug_level |= DEBUG_CONFIG_PARSE;
		  break;

	  case 'K':
		  debug_level |= DEBUG_KEY_STATE;
		  break;

	  case 'k':
		  debug_level |= DEBUG_KEY;
		  break;

	  case 'e':
		  debug_level |= DEBUG_EVENT_CORE;
		  break;

	  case 'E':
		  debug_level |= DEBUG_EAP_STATE;
		  break;

	  case 'p':
		  debug_level |= DEBUG_PHYSICAL_STATE;
		  break;

	  case 'X':
		  debug_level |= DEBUG_DOT1X_STATE;
		  break;

	  case 'x':
		  debug_level |= DEBUG_1X_BE_STATE;
		  break;

	case 'a':
	  debug_level |= DEBUG_AUTHTYPES;
	  break;

	case 'i':
	  debug_level |= DEBUG_INT;
	  break;

	case 'n':
	  debug_level |= DEBUG_SNMP;
	  break;

	case 'h':
	  debug_level |= DEBUG_PLUGINS;
	  break;

	case 'v':
		debug_level |= DEBUG_VERBOSE;
		break;

	case 'A':
	  debug_level |= 0xffffffff;   // Set all flags.
	  break;
	}
    }
}

void xsup_debug_set_level(uint32_t level)
{
	debug_level |= level;
}

/**
 *
 * Depending on the value of fh, we will either print to the screen, or
 * a log file.
 *
 */
void ufprintf(FILE *fh, char *instr, int level)
{
  #ifdef DEBUG_LOG_PLUGINS
  // Send the log to any registered logging plugins
  log_hook_full_debug(instr);
  #endif

  // No decide where else to log to.
  if (((isdaemon == 2) || (fh == NULL)) && (syslogging != 1))
    {
      printf("%s", instr);
#ifndef WINDOWS
      fflush(stdout);
#endif
    } else if (syslogging ==1) {
      // XXX Consider ways of using other log levels.
#ifndef WINDOWS
      syslog(LOG_ALERT, "%s", instr);
#endif
    } else {
      fprintf(fh, "%s", instr);
      fflush(fh);
    }
}

/**
 *
 * Set the debug level.  This is a global value, and shouldn't be set per
 * interface.
 *
 */
void debug_setdaemon(int xdaemon)
{
  isdaemon = xdaemon;

  if (xdaemon == TRUE)
    {
#ifdef WINDOWS
		// DO NOT enable this code!  It causes weird stuff to happen with Windows!
		/*
		fclose(stdout);
		fclose(stdin);
		*/
#else
      close(0);
      close(1);
      close(2); 
#endif
    }
}

/**
 *
 * Get the debug level for debug situations where we can't use debug_printf
 * easily.
 *
 */
int debug_getlevel()
{
  return debug_level;
}

#ifndef WINDOWS
static inline char to_hex_char(int val)
#else
static char to_hex_char(int val)
#endif
{
   return("0123456789abcdef"[val & 0xf]);
}

/**
 *
 * Dump hex values, without the ascii versions.
 *
 */
void debug_hex_printf(uint32_t level, uint8_t *hextodump, int size)
{
  int i;
  int len = 0;
  char *logstr = NULL;
  
	logstr = Malloc((size * 3) + 2);
	if (logstr == NULL)
	{
		printf("Couldn't allocate memory to store temporary logging string!\n");
		return;
	}

	memset(logstr, 0x00, ((size * 3)+2));

#ifdef DEBUG_LOG_PLUGINS
   // This gives us a bit of a performance increase in the case where we're not doing full debug
   if(registered_debug_loggers <= 0)
   {
     FREE(logstr);
     return;
   }
#endif

  if (hextodump == NULL)
  {
    FREE(logstr);
    return;
  }
  
  for (i = 0; i < size; i++)
    {
      logstr[len++] = to_hex_char(hextodump[i] >> 4);
      logstr[len++] = to_hex_char(hextodump[i]);
      logstr[len++] = ' ';
    }
  
  logstr[len++] = '\n';
  logstr[len] = 0;


  // If DEBUG_NULL was passed in then don't log to the file, but do log to the plugins.
  if ((!(debug_level & level)) && (level != 0))
  {
#ifdef DEBUG_LOG_PLUGINS
      // Send it to the full logging hook anyway
	  log_hook_full_debug(logstr);
#endif
	  FREE(logstr);
	  return;
  }

  ufprintf(logfile, logstr, level);
  FREE(logstr);
}

/**
 *
 * dump some hex values -- also
 * show the ascii version of the dump.
 *
 */
void debug_hex_dump(uint32_t level, uint8_t *hextodump, int size)
{
  int i;
  char buf[80];
  int str_idx = 0;
  int chr_idx = 0;
  int count;
  int total;
  int tmp;
  
#ifdef DEBUG_LOG_PLUGINS
  if(registered_debug_loggers() <= 0)
    return;
#endif // DEBUG_LOG_PLUGINS

  if (hextodump == NULL)
    return;
  
  /* Initialize constant fields */
  memset(buf, ' ', sizeof(buf));
  buf[4]  = '|';
  buf[54] = '|';
  buf[72] = '\n';
  buf[73] = 0;
  
  count = 0;
  total = 0;
  for (i = 0; i < size; i++)
    {
      if (count == 0)
	{
          str_idx = 6;
          chr_idx = 56;
	  
          buf[0] = to_hex_char(total >> 8);
          buf[1] = to_hex_char(total >> 4);
          buf[2] = to_hex_char(total);
	}
      
      /* store the number */
      tmp = hextodump[i];
      buf[str_idx++] = to_hex_char(tmp >> 4);
      buf[str_idx++] = to_hex_char(tmp);
      str_idx++;
      
      /* store the character */
      buf[chr_idx++] = isprint(tmp) ? tmp : '.';
      
      total++;
      count++;
      if (count >= 16)
		{
          count = 0;

	      if (((debug_level & level)) || (level == 0))
		  {
			ufprintf(logfile, buf, level);
		  }
		  else
		  {
		      #ifdef DEBUG_LOG_PLUGINS
			  log_hook_full_debug(buf);
		      #endif // DEBUG_LOG_PLUGINS
		  }
		}
    }
  
  /* Print partial line if any */
  if (count != 0)
    {
      /* Clear out any junk */
      while (count < 16)
	{
          buf[str_idx]   = ' ';   /* MSB hex */
          buf[str_idx+1] = ' ';   /* LSB hex */
          str_idx += 3;
	  
          buf[chr_idx++] = ' ';
	  
          count++;
	}

      if ((!(debug_level & level)) && (level != 0))
	{
      #ifdef DEBUG_LOG_PLUGINS
	  log_hook_full_debug(buf);
      #endif // DEBUG_LOG_PLUGINS
	  return;
	}


      ufprintf(logfile, buf, level);
    }
}

/**
 * \brief Display some information.  But only if we are at a debug level that
 *		  should display it.
 *
 */
void debug_printf(uint32_t level, char *fmt, ...)
{
  char dumpstr[TEMP_LOG_BUF_SIZE+128], temp[TEMP_LOG_BUF_SIZE];
  char fullstr[TEMP_LOG_BUF_SIZE+128];   // Enough to hold the log string, and timestamp.
  char *ipcevent = NULL;
  char *tdstring = NULL;

#ifndef EXTERNAL_USE
  char *temp_desc = NULL;
  context *ctx = NULL;
#endif

#ifdef DEBUG_LOG_PLUGINS
  // No need wasting time processing this one...
  if(((registered_debug_loggers() <= 0) && ((!(debug_level & level)) && (level != 0))))
    return;
#else 
  if(((!(debug_level & level)) && (level != 0)))
	  return;
#endif // DEBUG_LOG_PLUINS

  if (fmt != NULL)
    {
      va_list ap;
      va_start(ap, fmt);

      memset((char *)&dumpstr, 0x00, TEMP_LOG_BUF_SIZE);
      memset((char *)&temp, 0x00, TEMP_LOG_BUF_SIZE);

      // Print out a tag that identifies the type of debug message being used.
	  if (TEST_FLAG(level, DEBUG_NORMAL))
	  {
	  }
	else if (TEST_FLAG(level, DEBUG_PHYSICAL_STATE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[PHYS_STATE ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_DOT1X_STATE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[DOT1X_STATE] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_1X_BE_STATE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[1X_BE_STATE] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_EAP_STATE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[EAP_STATE  ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_KEY_STATE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[KEY_STATE  ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_KEY))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[KEY        ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_CONFIG_PARSE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[CONF_PARSE ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_CONFIG_WRITE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[CONF_WRITE ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_SMARTCARD))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[SMARTCARD  ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_SNMP))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[SNMP       ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_IPC))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[IPC        ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_INIT))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[INIT       ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_DEINIT))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[DEINIT     ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_AUTHTYPES))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[AUTHTYPES  ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_INT))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[INTERFACE  ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_CONTEXT))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[CONTEXT    ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_EVENT_CORE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[EVENT_CORE ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_TLS_CORE))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[TLS_CORE   ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_TIMERS))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[TIMERS     ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_CERTS))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[CERTS      ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_TNC))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[TNC        ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_TNC_IMC))
	{
	  if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[TNC IMC    ] ") != 0)
	  {
		  printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		  return;
	  }
	}
	else if (TEST_FLAG(level, DEBUG_PLUGINS))
	  {
	    if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[PLUGIN HOOK ] ") != 0 )
	      {
		printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		return;
	      }
	  }
    else if (TEST_FLAG(level, DEBUG_NULL))
    {
        if (xsup_common_strcpy((char *)&dumpstr, TEMP_LOG_BUF_SIZE, "[DEBUG NULL ] ") != 0 )
	      {
		printf("Attempt to overflow a buffer in %s() at %d!\n", __FUNCTION__, __LINE__);
		return;
	      }
    }
	else if (TEST_FLAG(level, DEBUG_VERBOSE))
	{
		// Don't do anything, but this will keep us from throwing an error to the screen.
	}
	else
	{
		printf("Unknown debug level %d.\n", level);
	}

      vsnprintf((char *)&temp, TEMP_LOG_BUF_SIZE-1, fmt, ap);

	  tdstring = xsup_debug_system_time();
	  sprintf((char *)&fullstr, "%s - %s", tdstring, temp);
	  FREE(tdstring);

	  // Send temp to the UI without the subsystem tag.
	  if ((!TEST_FLAG(level, DEBUG_IPC)) && ((debug_level & level) != 0))
	  {
		  if ((TEST_FLAG(level, DEBUG_NORMAL)) || (TEST_FLAG(level, DEBUG_VERBOSE)))
		  {
			ipcevent = _strdup(fullstr);
			ipc_events_log_msg(ipcevent);
			FREE(ipcevent);
		  }
	  }

      if (Strcat((char *)&dumpstr, TEMP_LOG_BUF_SIZE, (char *)&fullstr) != 0)
	{
	  fprintf(stderr, "Refusing to overflow the string!\n");
	  return;
	}

      // If we have registered plugins make sure they get this message...
      if ((!(debug_level & level)) && (level != 0))
	{
      #ifdef DEBUG_LOG_PLUGINS
		  log_hook_full_debug(dumpstr);
	  #endif // DEBUG_LOG_PLUGINS
	  va_end(ap);
	  return;
	}

	ufprintf(logfile, dumpstr, level);

      va_end(ap);
    }
}

/**
 *
 * Display some information.  But only if we are at a debug level that
 * should display it.
 *
 */
void debug_printf_nl(uint32_t level, char *fmt, ...)
{
  char temp[2048];

#ifdef DEBUG_LOG_PLUGINS
  // No need wasting time processing this one...
  if(((registered_debug_loggers() <= 0) && ((!(debug_level & level)) && (level != 0))))
    return;
#endif // DEBUG_LOG_PLUGINS

  if (fmt != NULL)
    {
      va_list ap;
      va_start(ap, fmt);

      vsnprintf((char *)&temp, 2048, fmt, ap);

      if ((!(debug_level & level)) && (level != 0))
	{
#ifdef DEBUG_LOG_PLUGINS
	  log_hook_full_debug(temp);
#endif  // DEBUG_LOG_PLUGINS
	  va_end(ap);
	  return;
	}

      ufprintf(logfile, temp, level);
      
      va_end(ap);
    }
}

