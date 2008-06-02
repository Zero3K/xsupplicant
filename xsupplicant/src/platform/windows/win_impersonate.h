/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_impersonate.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __WIN_IMPERSONATE_H__
#define __WIN_IMPERSONATE_H__

// Impersonation errors.
#define IMPERSONATE_NO_ERROR		0
#define IMPERSONATE_HANDLE_IN_USE	-1
#define IMPERSONATE_BAD_USER_TOKEN	-2
#define IMPERSONATE_FAILURE			-3

int win_impersonate_desktop_user();
void win_impersonate_back_to_self();

#endif  // __WIN_IMPERSONATE_H__