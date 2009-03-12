/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file supdetect_private.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __SUPDETECT_PRIVATE_H__
#define __SUPDETECT_PRIVATE_H__

// Ways to check for this issue.  (Generic OS support.)
#define CHECK_FILE      1
#define CHECK_PROCESS   2

// Windows specific checks.
#define CHECK_REGISTRY  10
#define CHECK_SERVICE   11

// Types of things we want to detect  (i.e.  Things that can get in the way.)
#define OTHER_SUPPLICANT  0x01
#define WIRELESS_MANAGER  0x02

// Severity levels that can be used to notify the UI.
#define WARNING           1	///< There are droppings from another supplicant or manager that, if activated, can cause problems.
#define BLOCKER           2	///< The supplicant won't be able to run unless this is fixed.

typedef struct _sup_fingerprints_struct {
	int check_type;		///< File, process, or registry key.
	char *product_name;	///< The name of the product that this maps to.
	char *match_string;	///< String to match.
	char *location;		///< The path to the file or registry key.
	int block_type;		///< The type of program that this is that is blocking us.
	int severity;		///< The severity of the problem.  (i.e. Are we sure it will block, or are we warning that we found droppings.)
} sup_fingerprints;

void toupper_str(char *instr);

extern void *callback;

#endif				// __SUPDETECT_PRIVATE_H__
