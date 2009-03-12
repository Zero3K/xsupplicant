/**
 *  Library to attempt to detect other supplicants that may be running.
 *
 *  \file linux_calls.c
 *
 *  \author chris@open1x.org
 *
 * $Id: linux_calls.c,v 1.3 2007/10/17 07:00:39 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:39 $
 **/
#ifdef LINUX

#include <stdio.h>

#include "src/xsup_debug.h"
#include "supdetect_private.h"

/**
 * \brief Look in the linux process list to see if a process is running.
 *
 * @param[in] search   The fingerprint record to search for.
 *
 * \retval >0 number of times the fingerprint was matched.
 * \retval 0 process not found.
 **/
int supdetect_check_process_list(sup_fingerprints * search)
{
#warning IMPLEMENT!
	return 0;
}

/**
 * \brief This call is provided so that we can run checks against anything
 *        special that the OS does that we might care about.  (i.e. Windows
 *        Zero Config.)
 *
 * \retval >0 the number of OS specific checks that failed.
 * \retval 0 no OS specific checks failed.
 **/
int os_strange_checks()
{
	return 0;
}

#endif				// LINUX
