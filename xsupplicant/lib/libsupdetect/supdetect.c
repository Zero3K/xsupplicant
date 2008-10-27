/**
 *  Library to attempt to detect other supplicants that may be running.
 *
 *  \file supdetect.c
 *
 *  \author chris@open1x.org
 *
 *  \warning  This library expects to be able to use some calls from the main part of the
 *            supplicant.  It is *NOT* suitable for using with other programs!
 **/

#ifdef WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "supdetect_private.h"
#include "src/xsup_common.h"
#include "src/error_prequeue.h"

#ifdef WINDOWS
#include "windows_calls.h"
#elif LINUX
#include "linux_calls.h"

#define _strdup  strdup
#elif DARWIN
#include "darwin_calls.h"

#define _strdup  strdup

#else
#error You need to define checks for this OS!
#endif

#include "supdetect.h"

typedef void (*found_callback)(char *name, int *blocktype, int *severity);

#ifdef WINDOWS
sup_fingerprints supsearch[] = {
	{CHECK_PROCESS, "WPA Supplicant", "wpa_supplicant.exe", NULL, OTHER_SUPPLICANT, BLOCKER},
	{CHECK_SERVICE, "Atheros Configuration Service", "Atheros Configuration Service", NULL, (WIRELESS_MANAGER | OTHER_SUPPLICANT), BLOCKER},
	{CHECK_PROCESS, "NetGear WG111v2 Manager", "WG111v2.exe", NULL, WIRELESS_MANAGER, BLOCKER},
	{CHECK_PROCESS, "NetGear WG511 Manager", "WG511WLU.exe", NULL, WIRELESS_MANAGER, BLOCKER},
	{-1, NULL, NULL, NULL, -1, -1}
};
#elif LINUX
sup_fingerprints supsearch[] = {
  {-1, NULL, NULL, NULL, -1, -1}
};
#elif DARWIN
sup_fingerprints supsearch[] = {
  {-1, NULL, NULL, NULL, -1, -1}
};
#else
#error You need to define fingerprints for this OS!
#endif

void *callback = NULL;

void supdetect_bind_callback(found_callback cb)
{
}

/**
 * \brief Convert a mixed case string to an all upper case string.
 * 
 * \warning This function converts the string IN PLACE!
 *
 * @param[in] instr   The string to convert to all upper case.
 **/
void toupper_str(char *instr)
{
	unsigned int i, t;

	for (i = 0; i<strlen(instr); i++)
	{
		t = toupper(instr[i]);
		instr[i] = t;
	}
}

/**
 * \brief Add a found supplicant or wireless manager to the queue so that we
 *        can pass it to a listening UI when it connects.
 *
 * @param[in] toadd   The record that matched that we want to log.
 **/
void supdetect_add_to_ui_queue(sup_fingerprints *toadd)
{
	char *result = NULL;

	result = Malloc(strlen(toadd->product_name)+256);
	if (result == NULL)
	{
		printf("Couldn't allocate memory to create error/warning for the UI!\n");
		return;
	}

	if (toadd->block_type && OTHER_SUPPLICANT)
	{
		if (toadd->severity == BLOCKER)
		{
			sprintf(result, "<ERROR> The supplicant '%s' was found.  This may prevent this supplicant from working properly.  Please disable the other supplicant.", toadd->product_name);
		}
		else
		{
			sprintf(result, "<Warning> The supplicant '%s' was found.  This may have adverse effects on this supplicant.  You should consider disabling the other supplicant.", toadd->product_name);
		}
	}
	else
	{
		// For now, the only other option is a wireless manager.  If this changes
		// in the future, this needs to be updated.
		if (toadd->severity == BLOCKER)
		{
			sprintf(result, "<ERROR> The wireless manager '%s' was found.  This may prevent this supplicant from working properly.  Please disable the wireless manager.", toadd->product_name);
		}
		else
		{
			sprintf(result, "<Warning> The wireless manager '%s' was found.  This may have adverse effects on this supplicant.  You should consider disabling the wireless manager.", toadd->product_name);
		}
	}

	if (result != NULL)
	{
		if (error_prequeue_add(result) != 0)
		{
			printf("Couldn't add error/warning message to the UI queue.\n");
		}

		free(result);
		result = NULL;
	}
}

/**
 * \brief Check to see if a file exists.
 *
 * @param[in] search   The record used to search and see if this file exists.
 *
 * \retval 1 if the record was matched
 * \retval 0 if it wasn't.
 * \retval -1 on error
 **/
int supdetect_file_exists(sup_fingerprints *search)
{
	int len = 0;
	char *filename = NULL;
	FILE *fp = NULL;

	if (search->location != NULL)
		len = (int)strlen(search->location);
	
	if (search->product_name != NULL)
		len += (int)strlen(search->product_name);

	len += 3;  // A few bytes for padding.

	filename = malloc(len);
	if (filename == NULL) return -1;

	memset(filename, 0x00, len);

	sprintf(filename, "%s%s", search->location, search->match_string);

	fp = fopen(filename, "r");
	if (fp == NULL) 
	{
		free(filename);
		return 0;
	}

	free(filename);
	fclose(fp);

	return 1;
}

/**
 * \brief Search through all of the known fingerprints to see if any match.
 *
 * \retval >=1 the number of matches found.
 * \retval 0 if no match is found.
 **/
int supdetect_check_for_other_supplicants()
{
	int i = 0;
	int found = 0;

#ifdef WINDOWS
	if (windows_calls_wmi_init() != 0) return -1;
	if (windows_calls_wmi_connect() != 0) return -1;
#endif

	found += os_strange_checks();           // Look for anything weird with this OS.

	while (supsearch[i].check_type != -1)
	{
		switch (supsearch[i].check_type)
		{
		case CHECK_FILE:
			if (supdetect_file_exists(&supsearch[i]) > 0)
			{
				found++;
				
				supdetect_add_to_ui_queue(&supsearch[i]);
			}
			break;

		case CHECK_PROCESS:
			if (supdetect_check_process_list(&supsearch[i]) > 0)
			{
				found++;

				supdetect_add_to_ui_queue(&supsearch[i]);
			}
			break;

#ifdef WINDOWS         // Windows specific checks.
		case CHECK_REGISTRY:
			break;

		case CHECK_SERVICE:
			if (supdetect_check_service_list(&supsearch[i]) > 0)
			{
				found++;

				supdetect_add_to_ui_queue(&supsearch[i]);
			}
			break;
#endif  // WINDOWS

		default:
			printf("Requested check for unknown type %d!\n", supsearch[i].check_type);
			break;
		}

		i++;
	}

#ifdef WINDOWS
	windows_calls_wmi_deinit();
#endif

	return found;
}

/**
 * \brief  Look to see if a specific program is already running.
 *
 * @param[in] matchstr   The name of the program to look for.  This should only be the name of the
 *                       executable, and not the full path.  So, if I wanted to see how many instances
 *                       of Xsupplicant are running, I would put in "xsupplicant.exe" instead of
 *                       "c:\blah\xsupplicant.exe".
 *
 * \retval >=0   The number of instances of the named program that are running.  If you are checking
 *               to see if another instance of the same program is running, you want to check if this
 *               value is >=2.  (One for the previous instance, one for the current.)
 * \retval <0    On error
 **/
int supdetect_numinstances(char *matchstr)
{
	sup_fingerprints mymatch;
	int numinstances = 0;

#ifdef WINDOWS
	if (windows_calls_wmi_init() != 0)
		return -1;

	if (windows_calls_wmi_connect() != 0)
		return -1;
#endif

	memset(&mymatch, 0x00, sizeof(mymatch));

	mymatch.match_string = _strdup(matchstr);

	numinstances = supdetect_check_process_list(&mymatch);

	free(mymatch.match_string);

#ifdef WINDOWS
	windows_calls_wmi_deinit();
#endif

	return numinstances;
}
