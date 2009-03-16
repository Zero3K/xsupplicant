/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file tthandler.c
 *
 * \author chris@open1x.org
 *
 **/  
    
#include <windows.h>
#include <stdio.h>
    
#include "../../stdintwin.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../plugin_handler.h"
#include "../../ipc_events.h"
#include "../../xsup_debug.h"
#include "../../ipc_events_index.h"
    typedef struct {
	char *tempdir;
	 char *ttpath;
} ttdata_type;

/**
 * \brief The thread that will handle creation of the trouble ticket file, and
 *        notify the UI when it is complete.
 *
 * @param[in] data  A pointer to a structure that contains the temp file directory, and the
 *                  final location of the trouble ticket data.
 **/ 
void tthandler_troubleticket_thread(void *data) 
{
	int failed_plugins = 0;
	ttdata_type * tempdata = NULL;
	if (!xsup_assert((data != NULL), "data != NULL", FALSE))
		 {
		_endthread();
		return;
		}
	tempdata = (ttdata_type *) data;
	failed_plugins =
	    plugin_hook_trouble_ticket_dump_file(tempdata->tempdir);
	if (failed_plugins < 0)
		 {
		
		    // ACK!  NASTY error!
		    ipc_events_ui(NULL, IPC_EVENT_UI_TROUBLETICKET_ERROR, NULL);
		FREE(tempdata->tempdir);
		FREE(tempdata->ttpath);
		FREE(tempdata);
		}
	
	    crashdump_gather_files(tempdata->ttpath);
	
	    ipc_events_ui(NULL, IPC_EVENT_UI_TROUBLETICKET_DONE, NULL);
	FREE(tempdata->tempdir);
	FREE(tempdata->ttpath);
	FREE(tempdata);
	_endthread();
}


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
	ttdata_type * ttdata = NULL;
	if (!xsup_assert((tempdir != NULL), "tempdir != NULL", FALSE))
		return;
	if (!xsup_assert((tt_path != NULL), "tt_path != NULL", FALSE))
		return;
	ttdata = Malloc(sizeof(ttdata_type));
	if (ttdata == NULL)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to allocate memory to store the trouble ticket request structure.\n");
		return;
		}
	ttdata->tempdir = _strdup(tempdir);
	ttdata->ttpath = _strdup(tt_path);
	_beginthread(tthandler_troubleticket_thread, 0, ttdata);
}


