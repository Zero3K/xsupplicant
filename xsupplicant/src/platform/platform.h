/**
 * Platform specific calls that *ALL* OSes *MUST* expose!
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file platform.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _PLATFORM_H_
#define _PLATFORM_H_

char *platform_get_machine_data_store_path();
char *platform_get_users_data_store_path();
int platform_user_is_admin();

#endif  // _PLATFORM_H_
