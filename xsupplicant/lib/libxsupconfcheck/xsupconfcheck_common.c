/**
 * Routines for checking the "completeness" of a piece of the configuration.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfcheck_int.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfcheck_common.c,v 1.3 2007/10/17 07:00:39 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:39 $
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/error_prequeue.h"
#include "src/interfaces.h"

/**
 * \brief Check to see if the interface listed is actually live on this system right now.
 *
 * @param[in] devdesc   The device description for the interface we want to look for.
 *
 * \retval NULL on error
 * \retval ptr to an interfaces struct on success
 **/
struct interfaces *xsupconfcheck_common_is_live_int(char *devdesc)
{
	struct interfaces *cur = NULL;

	cur = interfaces_get_cache_head();
	if (cur == NULL)
		return NULL;

	while ((cur != NULL) && (strcmp(cur->desc, devdesc) != 0))
		cur = cur->next;

	if (cur == NULL)
		return NULL;

	// Otherwise, it should be a live one.
	return cur;
}
