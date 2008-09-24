/**
 * \file win_platform_calls.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <Windows.h>
#include "win_impersonate.h"

 BOOL win_platform_calls_IsUserAdmin(HANDLE activeHandle)
/*++ 
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. 

Arguments: None. 
Return Value: 
   TRUE - Caller has Administrators local group. 
   FALSE - Caller does not have Administrators local group. --
*/ 
{
BOOL b;
SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
PSID AdministratorsGroup; 
b = AllocateAndInitializeSid(
    &NtAuthority,
    2,
    SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,
    0, 0, 0, 0, 0, 0,
    &AdministratorsGroup); 
if(b) 
{
    if (!CheckTokenMembership( activeHandle, AdministratorsGroup, &b)) 
    {
         b = FALSE;
    } 
    FreeSid(AdministratorsGroup); 
}

return(b);
}


int win_platform_calls_is_admin()
{
	HANDLE activeHandle = NULL;
	int retval = FALSE;

	if (win_impersonate_desktop_user() == IMPERSONATE_NO_ERROR)
	{
		activeHandle = win_impersonate_get_impersonation_handle();

		if (win_platform_calls_IsUserAdmin(activeHandle) != FALSE)
		{
			retval = TRUE;
		}

		win_impersonate_back_to_self();
	}

	return retval;
}

