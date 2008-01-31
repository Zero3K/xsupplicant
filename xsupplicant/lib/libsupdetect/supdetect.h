/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file supdetect.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __SUPDETECT_H__
#define __SUPDETECT_H__

// Types of things we want to detect  (i.e.  Things that can get in the way.)
#define OTHER_SUPPLICANT  0x01
#define WIRELESS_MANAGER  0x02

// Severity levels that can be used to notify the UI.
#define WARNING           1          ///< There are droppings from another supplicant or manager that, if activated, can cause problems.
#define BLOCKER           2          ///< The supplicant won't be able to run unless this is fixed.

int supdetect_check_for_other_supplicants();
int supdetect_numinstances(char *);

#endif // __SUPDETECT_H__


