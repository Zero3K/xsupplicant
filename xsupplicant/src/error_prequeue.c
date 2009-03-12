/**
 * Routines for queueing error messages to be sent to a UI once it connects.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file error_prequeue.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WINDOWS
#include "stdintwin.h"
#endif

#include "xsup_debug.h"
#include "xsup_common.h"
#include "liblist/liblist.h"
#include "error_prequeue.h"

// #define DEBUG_PREQUEUE   1

err_prequeue *queue_head = NULL;

/**
 * \brief Add a new error message to the queue.
 *
 * @param[in] errmsg  The error message itself
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int error_prequeue_add(char *errmsg)
{
	err_prequeue *cur = NULL;

	cur = Malloc(sizeof(cur));
	if (cur == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't queue error to be sent to the UI!\n");
		return -1;
	}

	cur->errstr = _strdup(errmsg);
	cur->next = NULL;

	// Write this message to the log file.
	debug_printf(DEBUG_NORMAL, "%s\n", errmsg);

	liblist_add_to_tail((genlist **) & queue_head, (genlist *) cur);

	return 0;
}

/**
 * \brief The callback that is used to free the memory used by a single node.
 *
 * @param[in] node   The node to free the memory of.
 **/
node_delete_func error_prequeue_delete_node(void **node)
{
	err_prequeue *cur = NULL;

	if ((node == NULL) || ((*node) == NULL))
		return NULL;

	cur = (*node);

	FREE(cur->errstr);

	return NULL;
}

/**
 * \brief Flush the error prequeue, and free all the memory it used.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int error_prequeue_flush()
{
	liblist_delete_list((genlist **) & queue_head,
			    (node_delete_func) & error_prequeue_delete_node);

	return 0;
}

/**
 * \brief Determine if there are error messages in the prequeue that are ready to
 *        be sent to a UI.
 *
 * \retval int The number of events that are currently in the queue.
 **/
int error_prequeue_events_available()
{
	return liblist_num_nodes((genlist *) queue_head);
}

/**
 * \brief Return the pointer to the head of the error prequeue structure.
 *
 * \warning The caller should *NOT* free any of the nodes in the list itself!  Doing so
 *          will result in an inconsistant state in the queued errors, and likely cause a 
 *          crash.
 *
 * \retval ptr If there are queued messages.
 * \retval NULL If there are none.
 **/
err_prequeue *error_prequeue_get_head()
{
	return queue_head;
}
