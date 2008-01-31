/**
 * Create a trace file that can be used to help debug issues in the GUI library.
 *
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsup_gui_trace.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsup_gui_trace.c,v 1.2 2007/09/24 02:12:22 galimorerpg Exp $
 * $Date: 2007/09/24 02:12:22 $
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "xsup_gui_trace.h"

FILE *tracefile = NULL;   ///< The handle to the trace file we are using.

/**
 * \brief Establish the GUI trace file.
 *
 * @param[in] filename  The filename that we want to store trace data in.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsup_gui_trace_enable(char *filename)
{
	if (tracefile != NULL) return 0;    // If we call enable again, and we already have a file, return no error.

	tracefile = fopen(filename, "w+");
	if (tracefile == NULL) return -1;

	return 0;
}

/**
 * \brief Close the trace file.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsup_gui_trace_disable()
{
	if (tracefile == NULL) return 0;

	fclose(tracefile);

	return 0;
}

/**
 * \brief Send a trace line to our log file.
 *
 * @param[in] fmt   The format of the string to write to the log file.  (In printf() format.)
 * @param[in] ...   The parameters for the string specified by fmt.
 **/
void xsup_gui_trace(char *fmt, ...)
{
	char temp[TEMP_LOG_BUF_SIZE];
    va_list ap;

	if (tracefile == NULL) return;

      va_start(ap, fmt);

      vsnprintf((char *)&temp, TEMP_LOG_BUF_SIZE-1, fmt, ap);

	  fprintf(tracefile, temp);

	  fflush(tracefile);

	  va_end(ap);
}

