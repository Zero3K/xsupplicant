/**
 *  Library to attempt to detect other supplicants that may be running.
 *
 *  \file linux_calls.c
 *
 *  \author chris@open1x.org
 *
 **/
#ifdef LINUX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#include "src/xsup_debug.h"
#include "supdetect_private.h"

/**
 * \brief Given a full path to a process (including the process name), strip
 *          everything but the process name so that we can get a good match.
 *
 * \note  This function returns a pointer to the substring that is contained
 *         in the source string.  IT SHOULD NOT BE FREED!  (Or bad stuff will
 *         happen.)
 *
 * @param[in] srcstr  A string containing a full path to a process.  If this
 *                    string is NULL, this function will return NULL.
 *
 * \retval char* pointer to the substring that contains just the process name.
 **/
char *get_pname_only(char *srcstr)
{
  char *last = NULL;
  char *cur = NULL;

  if (srcstr == NULL) return NULL;

  cur = srcstr;
  while (cur)
    {
      cur = strstr(cur, "/");
      if (cur) cur = cur+1;  // Skip the current /.
      if (cur)
	last = cur;  // Point to the character beyond the /.
    }

  return last;
}

// Taken from the thread at :
// http://www.linuxforums.org/forum/linux-programming-scripting/40078-c-printing-linux-process-table.html

/**
 * \brief Get the number of processes by one name are running.
 *
 * @param[in] p_processname   The name of the process we are looking for.
 *
 * \retval 0 if the process wasn't found.
 * \retval uint of the process if it was found.
 **/
unsigned int getNumProcesses(char *p_processname) {
	DIR *dir_p;
	char *pname;
	struct dirent *dir_entry_p;
	char dir_name[40];										// ??? buffer overrun potential
	char target_name[252];									// ??? buffer overrun potential
	int target_result;
	char exe_link[252];
	int errorcount;
	int result;
	unsigned int num_found = 0;

	errorcount=0;
	result=0;
	dir_p = opendir("/proc/"); 																// Open /proc/ directory
	while(NULL != (dir_entry_p = readdir(dir_p))) {											// Reading /proc/ entries
		if (strspn(dir_entry_p->d_name, "0123456789") == strlen(dir_entry_p->d_name)) {		// Checking for numbered directories 
			strcpy(dir_name, "/proc/");
			strcat(dir_name, dir_entry_p->d_name);
			strcat(dir_name, "/"); 															// Obtaining the full-path eg: /proc/24657/ 
			exe_link[0] = 0;
			strcat(exe_link, dir_name);
			strcat(exe_link, "exe");													 	// Getting the full-path of that exe link
			target_result = readlink(exe_link, target_name, sizeof(target_name)-1);			// Getting the target of the exe ie to which binary it points to
			if (target_result > 0) {
				target_name[target_result] = 0;
				pname = get_pname_only(target_name);

				if (strcmp(pname, p_processname) == 0)
				    num_found++;
			}
		}
	}
	closedir(dir_p);

	return num_found;
}

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
  return getNumProcesses(search->match_string);
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
