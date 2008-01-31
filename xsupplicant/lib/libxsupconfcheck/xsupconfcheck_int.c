/**
 * Routines for checking the "completeness" of a piece of the configuration.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfcheck_int.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfcheck_int.c,v 1.3 2007/10/17 07:00:39 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:39 $
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/context.h"
#include "src/error_prequeue.h"
#include "src/interfaces.h"
#include "xsupconfcheck.h"
#include "xsupconfcheck_common.h"
#include "xsupconfcheck_int.h"


/**
 * \brief Check an interface for validity.
 *
 * @param[in] checkint   The structure that contains the information that we want to validate
 *                       about the interface.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int xsupconfcheck_int_check(struct xsup_interfaces *checkint, int log)
{
	struct interfaces *liveint = NULL;
	int retval = 0;
	char *errmsg = NULL;
	int is_wireless = 0;

	liveint = xsupconfcheck_common_is_live_int(checkint->description);

	if (liveint == NULL)
	{
		errmsg = malloc(strlen(checkint->description) + 100);
		if (errmsg != NULL)
		{
			sprintf(errmsg, "Interface '%s' isn't available on this machine.", checkint->description);
			if (log == TRUE) error_prequeue_add(errmsg);
			free(errmsg);
		}

		retval = -1;   // We have an error that should be in the queue.
		return retval;
	}

	if (memcmp(liveint->mac, checkint->mac, 6) != 0)
	{
		if (log == TRUE) error_prequeue_add("Interface configured has a different MAC address that the one in the configuration file!");
		retval = -1;
	}

	// Verify that if the interface is configured as wireless that the OS tells us it is.
	if ((checkint->flags & CONFIG_INTERFACE_IS_WIRELESS) == CONFIG_INTERFACE_IS_WIRELESS)
		is_wireless = 1;

	if (liveint->is_wireless != is_wireless)
	{
		if (log == TRUE) error_prequeue_add("Interface is configured as wireless, but the interface claims that it isn't.");
		retval = -1;
	}

	return retval;
}
