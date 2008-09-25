/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _XSUPCONFCHECK_H_
#define _XSUPCONFCHECK_H_

#include "../../src/context.h"

#define CONNECTION_NEED_PSK     1
#define CONNECTION_NEED_UPW     2
#define CONNECTION_NEED_PIN		3

#define PROFILE_NEED_UPW		1
#define PROFILE_NEED_PIN		2

int xsupconfcheck_trusted_server(char *, int);
int xsupconfcheck_check_profile(char *, int);
int xsupconfcheck_check_interface(char *, int);
int xsupconfcheck_check_connection(context *, char *, int);

#endif
