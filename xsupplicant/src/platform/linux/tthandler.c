/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file tthandler.c
 *
 * \author chris@open1x.org
 *
 **/  
    
#include <stdio.h>
    
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../plugin_handler.h"
#include "../../ipc_events.h"
#include "../../xsup_debug.h"
#include "../../ipc_events_index.h"
#include "libcrashdump/crashdump.h"
#include "plugins.h"


/**
 * \brief Spawn the thread that will create the trouble ticket data.
 *
 * @param[in] tempdir   The path to a temporary directory that can be used to create trouble
 *                      ticket data.
 *
 * @param[in] tt_path   The full path to the final trouble ticket.
 **/ 
void tthandler_create_troubleticket(char *tempdir, char *tt_path) 
{
	int failed_plugins = 0;

	if (!xsup_assert((tempdir != NULL), "tempdir != NULL", FALSE))
	  return;

	if (!xsup_assert((tt_path != NULL), "tt_path != NULL", FALSE))
	  return;

	failed_plugins = plugin_hook_trouble_ticket_dump_file(tempdir);

	if (failed_plugins < 0)
	  ipc_events_ui(NULL, IPC_EVENT_UI_TROUBLETICKET_ERROR, NULL);
	
	crashdump_gather_files(tt_path);
	
	ipc_events_ui(NULL, IPC_EVENT_UI_TROUBLETICKET_DONE, NULL);
}

