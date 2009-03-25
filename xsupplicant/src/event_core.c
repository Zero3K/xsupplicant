/**
 * Event core implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file event_core.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "wireless_sm.h"
#include "event_core.h"
#include "eapol.h"
#include "timer.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "statemachine.h"
#include "ipc_events_index.h"
#include "ipc_events.h"
#include "platform/platform.h"
#include "libcrashdump/crashdump.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifdef USE_DIRECT_RADIUS
#include "platform/radius/cardif_radius.h"
#endif

#ifdef MACOSX_FRAMER
// If we run in to another situation where we need a manual event handler, then
// we should remove this, and create a callback.
#include "platform/macosx/cardif_macosx.h"
#endif

#ifdef LINUX
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "platform/linux/cardif_linux_rtnetlink.h"
#endif

typedef struct eventhandler_struct {
	int socket;
	char *name;
	context *ctx;
	int (*func_to_call) (context *, int);
} eventhandler;

eventhandler events[MAX_EVENTS];

int locate;
int terminate = 0;
int num_event_slots = MAX_EVENTS;

time_t last_check = 0;
context *active_ctx = NULL;

void (*imc_ui_connect_callback) () = NULL;
void (*imc_notify_callback) () = NULL;

void global_deinit();		// In xsup_driver.c, there is no header we can include so this prototype keeps the compiler from complaining.

/**
 *  \brief  Return the context that is currently being processed!
 **/
context *event_core_get_active_ctx()
{
	return active_ctx;
}

/**
 * \brief We got a request to terminate ourselves.
 * returns 1 if already in progress otherwise 0
 **/
int event_core_terminate()
{
	if (terminate) {
		debug_printf(DEBUG_DEINIT,
			     "Already going down, so ignoning SHUTDOWN event.\n");
		return 1;
	}
	terminate = 1;
	debug_printf(DEBUG_DEINIT, "Sending SHUTDOWN event to GUI .\n");
	ipc_events_ui(NULL, IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN, NULL);
	return 0;
}

/**
 * \brief Initialize the event core. -- This should make any generic calls needed
 *        to set up the OS to provide us with events.
 **/
void event_core_init()
{
	int i;

	for (i = 0; i < MAX_EVENTS; i++) {
		events[i].socket = -1;
		events[i].name = NULL;
		events[i].ctx = NULL;
		events[i].func_to_call = NULL;
	}

#ifdef LINUX
	cardif_linux_rtnetlink_init();
#endif

	time(&last_check);	// Get our starting clock position.
}

/**
 * \brief Deinit the event core. -- This should call deinit functions for 
 *        anything that was inited in event_core_init()
 **/
void event_core_deinit()
{
	int i;

#ifdef LINUX
	cardif_linux_rtnetlink_cleanup();
#endif

	for (i = 0; i < MAX_EVENTS; i++) {
		if (events[i].name) {
			debug_printf(DEBUG_EVENT_CORE | DEBUG_DEINIT,
				     "Clearing handler '%s'.\n",
				     events[i].name);
			event_core_deregister(events[i].socket);
		}
	}
}

/**
 * \brief Register an event handler.
 *
 *  Register a socket, and a function to call when that socket has something
 * to read.  If "hilo" is set to 0, we will register this socket to the 
 * highest priority handler available.  If it is set to 2, we will register
 * this socket to the lowest priority handler available.  If it is set to 1,
 * we will register it to whatever is available.
 *
 * @param[in] sock   The socket to monitor for events.
 * @param[in] ctx   The context that should be used with this socket.
 * @param[in] call_func   The function to call when an event happens on 'sock'.
 * @param[in] hilo   A setting to define if this is a high priority, or low
 *                   priority socket.
 * @param[in] name   A text string to identify the sock that is being 
 *                   registered.
 *
 * \retval  -1   if there are no more slots available
 * \retval   0   on success
 **/
int event_core_register(int sock, context * ctx,
			int (*call_func) (context *, int), int hilo, char *name)
{
	int i = 0, done = FALSE;

	if (!xsup_assert((call_func != NULL), "call_func != NULL", FALSE))
		return -1;

	if (!xsup_assert((name != NULL), "name != NULL", FALSE))
		return -1;

	if (hilo == 0) {
		while ((i < MAX_EVENTS) && (done != TRUE)) {
			if (events[i].socket < 0) {
				debug_printf(DEBUG_EVENT_CORE,
					     "Registered event handler '%s' in "
					     "slot %d, with socket %d.\n", name,
					     i, sock);

				events[i].socket = sock;
				events[i].name = strdup(name);
				events[i].ctx = ctx;
				events[i].func_to_call = call_func;
				done = TRUE;
			}

			i++;
		}

		if ((i >= MAX_EVENTS) && (done == FALSE)) {
			debug_printf(DEBUG_NORMAL,
				     "Not enough event handler slots "
				     "available!\n");
			return -1;
		}
	} else {
		i = MAX_EVENTS - 1;
		while ((i >= 0) && (done != TRUE)) {
			if (events[i].socket < 0) {
				debug_printf(DEBUG_EVENT_CORE,
					     "Registered event handler '%s' in "
					     "slot %d, with socket %d.\n", name,
					     i, sock);
				events[i].socket = sock;
				events[i].ctx = ctx;
				events[i].name = strdup(name);
				events[i].func_to_call = call_func;
				done = TRUE;
			}

			i--;
		}

		if ((i < 0) && (done == FALSE)) {
			debug_printf(DEBUG_NORMAL,
				     "Not enough event handler slots "
				     "available!\n");
			return -1;
		}
	}

	return 0;
}

/**
 * \brief Deregister an event handler based on the socket id that we have.
 *
 * @param[in] sock   The socket we want to deregister.
 **/
void event_core_deregister(int sock)
{
	int i;

	for (i = 0; i < MAX_EVENTS; i++) {
		if (events[i].socket == sock) {
			debug_printf(DEBUG_EVENT_CORE,
				     "Deregistering event handler '%s' in "
				     "slot %d, with socket %d.\n",
				     events[i].name, i, sock);

			FREE(events[i].name);
			events[i].socket = -1;
			if (events[i].ctx != NULL)
				context_destroy(events[i].ctx);
			events[i].ctx = NULL;
			events[i].func_to_call = NULL;
		}
	}
}

/**
 * \brief Process any events that we may have received.
 *
 * This includes processing frames that may have come in.  There should be 
 * *NOTHING* OS specific in this code!!!  If something OS specific is needed, 
 * you will need to create a new event core for it.
 **/
void event_core()
{
	int i, biggest = 0, result = 0;
	fd_set rfds;
	struct timeval timeout;
	time_t cur_time;
	wireless_ctx *wctx;

	if (terminate == 1) {
		debug_printf(DEBUG_NORMAL,
			     "Got to terminate the event core!\n");
		global_deinit();
		return;
	}

	FD_ZERO(&rfds);

	for (i = 0; i < MAX_EVENTS; i++) {
#ifdef MACOSX_FRAMER
		if (events[i].ctx != NULL) {
			active_ctx = events[i].ctx;

			cardif_macosx_manual_events(events[i].ctx);

			active_ctx = NULL;
		}
#endif
		if (events[i].socket > 0) {
			FD_SET(events[i].socket, &rfds);

			if (events[i].socket > biggest)
				biggest = events[i].socket;
		}
	}

#ifdef USE_DIRECT_RADIUS
	if (cardif_radius_eap_sm(ctx) == TRUE) {
		debug_printf(DEBUG_NORMAL, "Got a fake ID request!\n");
		result = cardif_get_socket(ctx);

		for (i = 0; i < MAX_EVENTS; i++) {
			if (events[i].socket == result) {
				if (events[i].func_to_call) {
					events[i].func_to_call(ctx,
							       events
							       [i].socket);
				}
			}
		}
	}
#endif

	if (biggest == 0) {
		debug_printf(DEBUG_NORMAL, "No handles available to watch.\n");
		_exit(3);
	}

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	result = select(biggest + 1, &rfds, NULL, NULL, &timeout);

	if (result < 0) {
		// If we are sent a HUP, we will get an interrupted system call error.
		// Since this is normal, and nothing to worry about, don't display
		// it to the user. ;)
		if (errno != EINTR) {
			debug_printf(DEBUG_NORMAL, "Error : %s\n",
				     strerror(errno));
		}
	}

	if (result > 0) {
	        // See if logs need to be rolled.
	        xsup_debug_check_log_roll();

		for (i = 0; i < MAX_EVENTS; i++) {
			if (events[i].socket > 0) {
				if (FD_ISSET(events[i].socket, &rfds)) {
					debug_printf(DEBUG_EVENT_CORE,
						     "Socket %d (%s) had an event! "
						     "(Event index %d)\n",
						     events[i].socket,
						     events[i].name, i);

					if (events[i].func_to_call) {
						active_ctx = events[i].ctx;

						if (events[i].ctx != NULL) {
							if (events[i].
							    ctx->recvframe !=
							    NULL) {
								if (events
								    [i].ctx->recv_size
								    != 0) {
									debug_printf
									    (DEBUG_NORMAL,
									     "There was an "
									     "unprocessed frame in the buffer! "
									     "Your authentication will probably "
									     "stall because of this!\n");
									debug_printf
									    (DEBUG_NORMAL,
									     "Please send full "
									     "debug output to the list!\n");
								}
							}

							FREE(events[i].
							     ctx->recvframe);
						}

						events[i].func_to_call(events
								       [i].ctx,
								       events
								       [i].socket);
						active_ctx = NULL;
					}
				}
			}
		}
	}
	// See if a second has elapsed.  (This is useful in the situation where
	// we have an event storm that keeps select from timing out.  It may
	// result is some situations where we don't wait a full second before
	// ticking off a second.  But, it is better than the alternative. ;)
	time(&cur_time);
	if (last_check > cur_time) {
		debug_printf(DEBUG_NORMAL,
			     "Let's do the time warp again.  Your clock"
			     " has gone backward!\n");
		last_check = cur_time;
	}

	if ((result == 0) || (cur_time > last_check)) {
		for (i = 0; i < MAX_EVENTS; i++) {
			if (events[i].ctx != NULL) {
				active_ctx = events[i].ctx;
				events[i].ctx->statemachine->tick = TRUE;
				events[i].ctx->tick = TRUE;
				active_ctx = NULL;

				timer_tick(events[i].ctx);
			}
		}

		last_check = cur_time;
	}

	for (i = 0; i < MAX_EVENTS; i++) {
		if (events[i].ctx != NULL) {
			active_ctx = events[i].ctx;
			if (events[i].ctx->intType != ETH_802_11_INT) {
				if (events[i].ctx->conn != NULL) {
					if (events[i].ctx->conn != NULL) {
						statemachine_run(events[i].ctx);
					}
				}
			} else {
				wctx =
				    (wireless_ctx
				     *) ((events[i].ctx)->intTypeData);
				if (wctx != NULL)
					wireless_sm_do_state(events[i].ctx);
			}
			active_ctx = NULL;
		}
#ifdef USE_DIRECT_RADIUS
		// XXX This is broken!
		statemachine_run(ctx);
#endif
	}
}

/**
 * \brief Find the context that matches the interface name string, and
 *        return it.
 *
 * @param[in] matchstr   The OS specific name of the interface we wish to find
 *                       the context for.
 *
 * \retval ptr   Pointer to a context structure for the interface requested.
 * \retval NULL   Couldn't locate the desired interface.
 **/
context *event_core_locate(char *matchstr)
{
	int i;

	if (!xsup_assert((matchstr != NULL), "matchstr != NULL", FALSE))
		return NULL;

	for (i = 0; i < MAX_EVENTS; i++) {
		if ((events[i].ctx != NULL)
		    && (strcmp(events[i].ctx->intName, matchstr) == 0))
			return events[i].ctx;
	}

	// Otherwise we ran out of options.
	return NULL;
}

/**
 * \brief Reset our locator index to 0.
 **/
void event_core_reset_locator()
{
	/*mindtree */
	debug_printf(DEBUG_NORMAL, "event_core_reset_locator:locate = -1 \n");
	locate = -1;
}

/**
 * \brief  Get the next context in our list.
 *
 * \retval ptr   The next context in the list.
 * \retval NULL   There are no more contexts left, or we got an error.
 **/
context *event_core_get_next_context()
{
	int desired_ctx = 0;

	desired_ctx = ++locate;
	debug_printf(DEBUG_NORMAL,
		     "event_core_get_next_context:desired_ctx = %d,MAX_EVENTS = %d,locate = %d \n",
		     desired_ctx, MAX_EVENTS, locate);

	// locate++;
	debug_printf(DEBUG_NORMAL, "event_core_get_next_context:locate = %d \n",
		     locate);

	if (desired_ctx >= MAX_EVENTS)
		return NULL;

	while ((desired_ctx < MAX_EVENTS) && (events[desired_ctx].ctx == NULL)) {
		desired_ctx++;
	}

	locate = desired_ctx;

	if (desired_ctx >= MAX_EVENTS)
		return NULL;

	if (events[desired_ctx].ctx != NULL) {
		debug_printf(DEBUG_NORMAL,
			     "event_core_reset_locator:{return}[desired_ctx = %d,desired_ctx->intName=%s]\n",
			     desired_ctx, events[desired_ctx].ctx->intName);
	} else {
		debug_printf(DEBUG_NORMAL,
			     "event_core_reset_locator:{return}desired_ctx->intName is NULL\n");

	}
	return events[desired_ctx].ctx;
}

/**
 *  \brief Find the context that matches the interface description string, and \
return it.
*
* @param[in] matchstr   The interface description we are looking for.
*
* \retval ptr  Pointer to a context structure for the interface requested.
* \retval NULL Couldn't locate the desired interface.
**/
context *event_core_locate_by_desc(char *matchstr)
{
	int i;

	if (!xsup_assert((matchstr != NULL), "matchstr != NULL", FALSE))
		return NULL;

	for (i = 0; i < MAX_EVENTS; i++) {
		if ((events[i].ctx != NULL)
		    && (strcmp(events[i].ctx->desc, matchstr)
			== 0))
			return events[i].ctx;
	}

	// Otherwise, we ran out of options.
	return NULL;
}

void event_core_change_wireless(config_globals * newsettings)
{
	// Functionality that we don't want to bother with on Linux.
}

void event_core_load_user_config()
{
	char *conf_path = NULL;
	char *temp = NULL;

	temp = platform_get_users_data_store_path();
	if (temp != NULL) {
		conf_path = Malloc(strlen(temp) + 50);
		if (conf_path != NULL) {
			strcpy(conf_path, temp);
			strcat(conf_path, "/xsupplicant.user.conf");

			if (config_load_user_config(conf_path) != XENONE) {
				debug_printf(DEBUG_NORMAL,
					     "Unable to load the user's configuration.  No user specific configuration settings will be available!\n");
			} else {
				debug_printf(DEBUG_NORMAL,
					     "Loaded new user specific configuration.\n");

				// Save the path so we can grab it for a trouble ticket or crash dump.
#if (WINDOWS || LINUX)
				crashdump_add_curuser_conf(conf_path);
#else
#warning Add this for your OS!
#endif
			}

			FREE(temp);
			FREE(conf_path);
		} else {
			FREE(temp);
		}
	}
}

/**
 *  \brief Find the context that matches the connection name string, and return it.  
 *
 * @param[in] matchstr   The connection name of the interface we wish to find the
 *                       context for.
 *
 * \retval ptr  Pointer to a context structure for the interface requested.
 * \retval NULL Couldn't locate the desired interface.
 **/
context *event_core_locate_by_connection(char *matchstr)
{
	int i;

	if (!xsup_assert((matchstr != NULL), "matchstr != NULL", FALSE))
		return NULL;

	for (i = 0; i < num_event_slots; i++) {
		if ((events[i].ctx != NULL)
		    && (events[i].ctx->conn_name != NULL)
		    && (strcmp(events[i].ctx->conn_name, matchstr) == 0))
			return events[i].ctx;
	}

	// Otherwise, we ran out of options.
	return NULL;
}

void event_core_set_active_ctx(context * ctx)
{
	active_ctx = ctx;
}

/**
 * \brief Determine if the machine is going to sleep.
 *
 * \retval TRUE if we are going to sleep (or already asleep ;)
 **/
int event_core_get_sleep_state()
{
  // XXX Add this for Linux!
  /*
	if ((sleep_state == PWR_STATE_SLEEPING)
	    || (sleep_state == PWR_STATE_HELD))
		return TRUE;
  */
	return FALSE;
}

/**
 * \brief Register a callback to notify an IMC when the UI connects to the supplicant.
 *
 * @param[in] callback   The callback that we want to call when the UI connects to the supplicant
 *
 * \warning Currently we only allow a single IMC to request this callback!  In the future
 *          we may need to extend this!
 *
 * \todo Extend this to allow more than one callback to register.
 *
 * \retval 0 on success
 * \retval 1 if another IMC has already registered.
 **/
uint32_t event_core_register_ui_connect_callback(void *callback)
{
	if (imc_ui_connect_callback != NULL)
		return 1;

	imc_ui_connect_callback = callback;

	return 0;
}

/**
 * \brief Register a callback to notify an IMC when a user logs on to the Windows console.
 *
 * @param[in] callback   The callback that we want to call when a user logs in.
 *
 * \warning Currently we only allow a single IMC to request this callback!  In the future
 *          we may need to extend this!
 *
 * \todo Extend this to allow more than one callback to register.
 *
 * \retval 0 on success
 * \retval 1 if another IMC has already registered.
 **/
uint32_t event_core_register_disconnect_callback(void *callback)
{
	if (imc_disconnect_callback != NULL)
		return 1;

	imc_disconnect_callback = callback;

	return 0;
}

/**
 * \brief Register a callback to notify an IMC when a user logs on to the Windows console.
 *
 * @param[in] callback   The callback that we want to call when a user logs in.
 *
 * \warning Currently we only allow a single IMC to request this callback!  In the future
 *          we may need to extend this!
 *
 * \todo Extend this to allow more than one callback to register.
 *
 * \retval 0 on success
 * \retval 1 if another IMC has already registered.
 **/
uint32_t event_core_register_imc_logon_callback(void *callback)
{
	if (imc_notify_callback != NULL)
		return 1;

	imc_notify_callback = callback;

	return 0;
}
