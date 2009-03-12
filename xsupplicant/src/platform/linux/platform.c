/**
 * Platform specific calls that *ALL* OSes *MUST* expose!
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file platform.c
 *
 * \author chris@open1x.org
 *
 **/  
    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include "xsup_common.h"
char *platform_get_machine_data_store_path() 
{
	return strdup("/etc");
}

char *platform_get_users_data_store_path() 
{
	return strdup("/etc");
}

int platform_user_is_admin() 
{
	return TRUE;		// In the future this may change.
}


