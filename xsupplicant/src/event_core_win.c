/**
 * Event core implementation for Windows.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file event_core_win.c
 *
 * \author chris@open1x.org
 *
 * $Id: event_core_win.c,v 1.7 2008/01/30 21:07:01 galimorerpg Exp $
 * $Date: 2008/01/30 21:07:01 $
 **/

#ifndef WINDOWS
#error This event core is for Windows only!
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <winsock2.h>

#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "context.h"
#include "wireless_sm.h"
#include "event_core_win.h"
#include "eapol.h"
#include "eap_sm.h"
#include "timer.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "statemachine.h"
#include "frame_structs.h"
#include "platform/windows/cardif_windows_wmi.h"
#include "platform/windows/cardif_windows.h"
#include "platform/windows/wzc_ctrl.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "eap_sm.h"
#include "pmksa.h"
#include "platform/windows/wlanapi_interface.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifdef USE_DIRECT_RADIUS
#error Direct RADIUS mode is not availble for Windows!
#endif

// Uncomment this to turn on really excessive debugging output!
//#define DEBUG_EVENT_HANDLER 1
//#define LOCK_DEBUG  1

typedef struct eventhandler_struct {
  HANDLE devHandle;
  char *name;
  context *ctx;
  int (*func_to_call)(context *, HANDLE);
  LPOVERLAPPED ovr;
  HANDLE hEvent;
  uint8_t flags;
  uint8_t silent;
} eventhandler;

eventhandler *events = NULL;  
uint16_t num_event_slots = 0;

int locate = 0;

time_t last_check = 0;
int terminate = 0;         // Is there a request to terminate ourselves.
int userlogon = 0;		   // (single shot) User logged on event.
int userlogoff = 0;        // (single shot) User logged off event.
int user_logged_on = FALSE;  // Is there a user currently logged on to windows?
void (*imc_notify_callback)() = NULL;
void (*imc_ui_connect_callback)() = NULL;
context *active_ctx = NULL;
int sleep_state = PWR_STATE_RUNNING;

void global_deinit();      // In xsup_driver.c

HANDLE evtCoreMutex;

/**
 * Return the context that is currently being processed.
 **/
context *event_core_get_active_ctx()
{
	return active_ctx;
}

void event_core_set_active_ctx(context *ctx)
{
	active_ctx = ctx;
}

/**
 * We got a request to terminate ourselves.
 *
 *  *NOTE* : We won't terminate until the next time we call the event loop.  This means
 *           there is a maximum of 1 second latency following the request to terminate.
 **/
void event_core_terminate()
{
	terminate = 1;
	ipc_events_error(NULL, IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN, NULL);
}

int event_core_set_ovr(HANDLE devHandle, uint8_t eventType, LPOVERLAPPED lovr)
{
	int i;
	uint8_t evtType;

	for (i=0; i < num_event_slots; i++)
	{
#ifdef DEBUG_EVENT_HANDLER
		printf("%d == %d?\n", devHandle, events[i].devHandle);
#endif
		evtType = (events[i].flags & 0xf0);
		if ((devHandle == events[i].devHandle) && (evtType == eventType))
		{
			events[i].ovr = lovr;
			events[i].hEvent = lovr->hEvent;
			return TRUE;
		}
	}

#ifdef DEBUG_EVENT_HANDLER
	debug_printf(DEBUG_EVENT_CORE, "Couldn't locate device handle!\n");
#endif
	return FALSE;
}

/**
 *  Get the OVERLAPPED structure that is being used with 'devHandle'.
 **/
LPOVERLAPPED event_core_get_ovr(HANDLE devHandle, uint8_t eventType)
{
	int i;
	uint8_t evtType = 0;

	for (i=0; i < num_event_slots; i++)
	{
#ifdef DEBUG_EVENT_HANDLER
		printf("%d == %d?\n", devHandle, events[i].devHandle);
#endif
		evtType = (events[i].flags & 0xf0);  // Only include the high bits.
		if ((devHandle == events[i].devHandle) && (eventType == evtType))
		{
			return events[i].ovr;
		}
	}

#ifdef DEBUG_EVENT_HANDLER
	debug_printf(DEBUG_EVENT_CORE, "Couldn't locate device handle!\n");
#endif
	return NULL;
}

/**
 * Bind an hEvent to our event structure so that the event_core() will pick it up.
 **/
int event_core_bind_hevent(HANDLE devHandle, HANDLE hEvent, unsigned char evtType)
{
	int i;

	for (i=0; i < num_event_slots; i++)
	{
		if ((devHandle == events[i].devHandle) && ((events[i].flags & evtType) == evtType))
		{
#ifdef DEBUG_EVENT_HANDLER
			debug_printf(DEBUG_NORMAL, "Binding device handle %d to event handle %d.\n",
					devHandle, hEvent);
#endif
			events[i].hEvent = hEvent;
			events[i].ovr->hEvent = hEvent;
	
			return XENONE;
		}
	}

	return -1;
}

// To keep the compiler from complaining that it isn't defined.
void global_deinit();

/**
 *  This function gets called when certain console events happen.
 **/
BOOL WINAPI ConsoleHandler(DWORD CEvent)
{
    char mesg[128];

    switch(CEvent)
    {
    case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		debug_printf(DEBUG_EVENT_CORE, "Caught a BREAK event.\n");
		event_core_terminate();
        break;
    case CTRL_CLOSE_EVENT:
        debug_printf(DEBUG_EVENT_CORE, "Caught a close event.\n");
		event_core_terminate();
        break;
    case CTRL_LOGOFF_EVENT:
		debug_printf(DEBUG_EVENT_CORE, "Caught a logoff event.\n");
        break;
    case CTRL_SHUTDOWN_EVENT:
		debug_printf(DEBUG_EVENT_CORE, "Caught a shutdown event.\n");
		event_core_terminate();
        break;

    }

    return TRUE;
}

/**
 * Set up a handler to catch CTRL-C/CTRL-BREAK and handle it correctly.  (Only useful when
 * running in console mode.)
 **/
void event_core_ctrl_c_handle()
{
	if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler,TRUE) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to install termination handler!\n");
	}
}

/**
 * \brief Set the defaults for a single event instance.
 *
 * @param[in] events   A pointer to the structure that we want to set the defaults on.
 **/
static void event_core_init_single_event(eventhandler *events)
{
      events->devHandle = INVALID_HANDLE_VALUE;
      events->name = NULL;
	  events->ctx = NULL;
	  events->flags = 0x00;
      events->func_to_call = NULL;
	  events->hEvent = INVALID_HANDLE_VALUE;
	  events->ovr = NULL;
}

/***********************************************************************
 *
 * Initialize the event core. -- This should make any generic calls needed
 * to set up the OS to provide us with events.
 *
 ***********************************************************************/
void event_core_init()
{
  int i;

  num_event_slots = STARTING_EVENTS;

  events = Malloc(sizeof(eventhandler) * num_event_slots);
  if (events == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store event slots!\n");
	  global_deinit();
  }

  for (i=0; i < num_event_slots; i++)
    {
		event_core_init_single_event(&events[i]);
    }

  event_core_ctrl_c_handle();
  time(&last_check);   // Get our starting clock position.

  if (cardif_windows_get_os_ver() >= 2)
  {
	  if (cardif_windows_wmi_init() != XENONE)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't establish a connection to WMI!  It is likely that "
				"things will be broken!  (We will try to continue anyway.)\n");
		  ipc_events_error(NULL, IPC_EVENT_ERROR_WMI_ATTACH_FAILED, NULL);
	  }
  }
  else
  {
	  cardif_windows_ip_update();
  }

  if (win_ip_manip_init_iphlpapi() != XENONE)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't load the iphlpapi DLL!  IP address setting functionality will be broken!\n");
  }

  if (wlanapi_interface_connect() != WLANAPI_OK)
  {
	  if (wzc_ctrl_connect() != XENONE)
	  {
		  debug_printf(DEBUG_NORMAL, "Unable to initialize Windows Zero Config handle.  You should "
			  "go in to your network control panel, and click the check box for 'Use Windows to "
			  "configure my wireless settings.'\n");
		  ipc_events_error(NULL, IPC_EVENT_ERROR_WZC_ATTACH_FAILED, NULL);
	  }
  }

  evtCoreMutex = CreateMutex(NULL, FALSE, NULL);   // Nobody owns this mutex to start with.
  if (evtCoreMutex == INVALID_HANDLE_VALUE)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to create a mutex for the event core!\n");
  }
}

/***********************************************************************
 *
 * Deinit the event core. -- This should call deinit functions for anything
 * that was inited in event_core_init()
 *
 ***********************************************************************/
void event_core_deinit()
{
  int i;

  // Only deinit 
  if (cardif_windows_get_os_ver() >= 2)
  {
	cardif_windows_wmi_deinit();
  }

  win_ip_manip_deinit_iphlpapi();

  event_core_lock();    // Even if this fails, we should keep trying to deinit.

  for (i=0;i < num_event_slots; i++)
    {
      if (events[i].name)
	  {
		  event_core_deregister(events[i].devHandle, (events[i].flags & 0xf0));
	  }
    }

  wzc_ctrl_disconnect();

  wlanapi_interface_disconnect();

  event_core_unlock();

  if (evtCoreMutex != INVALID_HANDLE_VALUE) CloseHandle(evtCoreMutex);

  FREE(events);
}

int event_core_lock()
{
	DWORD dwWaitResult;
	DWORD lastError = 0;

	// Wait for our mutex to be available!
	dwWaitResult = WaitForSingleObject(evtCoreMutex, INFINITE);

	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
#ifdef LOCK_DEBUG
		debug_printf(DEBUG_IPC, "Acquired event core lock.  (Thread ID : %d)\n", GetCurrentThreadId());
#endif
		return 0;
		break;

	default:
		lastError = GetLastError();
		if (lastError != 0)
		{
			debug_printf(DEBUG_IPC, "!!!!!!!!!!!! Error acquiring event core lock!  (Error %d -- wait result %d)\n", GetLastError(), dwWaitResult);
		}
		else
		{
			// We can get in to a situation where a thread may have terminated without releasing
			// a lock.  In these cases, Windows may tell us there was an error, but 
			// GetLastError() indicates that the log was obtained correctly.
			debug_printf(DEBUG_NORMAL, "Windows indicated an error obtaining the event core lock.  But, the lock was obtained successfully.  This is usually a bug in the code.  Please report it!\n");
			return 0;
		}
		break;
	}

	return -1;
}

int event_core_unlock()
{
	if (!ReleaseMutex(evtCoreMutex))
	{
		debug_printf(DEBUG_IPC, "!!!!!!!!!!!! Error releasing event core lock!  (Error %d) (Thread id : %d)\n", GetLastError(), GetCurrentThreadId());
		return -1;
	}

#ifdef LOCK_DEBUG
	debug_printf(DEBUG_IPC, "Released event core lock.  (Thread ID : %d)\n", GetCurrentThreadId());
#endif

	return 0;
}

/**
 * \brief Populate a new event handler struct with the data needed.
 *
 * @param[in] events   A pointer to the events struct that we will populate.
 * @param[in] call_func   The function to call when this event is triggered.
 * @param[in] name   A name to give this event.
 *
 **/
static void event_core_fill_reg_struct(eventhandler *events, HANDLE devHandle, int(*call_func)(context *, HANDLE),
										context *ctx, uint8_t flags, char *name)
{
	      events->devHandle = devHandle;
	      events->name = _strdup(name);
		  events->ctx = ctx;
		  events->flags = flags;
	      events->func_to_call = call_func;
		  events->silent = 0;
		  events->ovr = Malloc(sizeof(OVERLAPPED));
		  if (events->ovr == NULL)
		  {
			  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store OVERLAPPED structure!\n");
			  ipc_events_malloc_failed(NULL);
		  }

		  if (flags == EVENT_PRIMARY)
		  {
			  // Set up a receive.
			  cardif_setup_recv(events->ctx);
		  }
}

/*************************************************************************
 *
 *  Register a socket, and a function to call when that socket has something
 * to read.  If "hilo" is set to 0, we will register this socket to the 
 * highest priority handler available.  If it is set to 2, we will register
 * this socket to the lowest priority handler available.  If it is set to 1,
 * we will register it to whatever is available.
 *
 * Returns :
 *   -1 -- if there are no more slots available
 *    0 -- on success
 *
 *************************************************************************/
int event_core_register(HANDLE devHandle, context *ctx, 
		int(*call_func)(context *, HANDLE), uint8_t flags,
		int hilo, char *name)
{
  int i = 0, done = FALSE;
  void *temp = NULL;
  config_globals *globals = NULL;

  if (!xsup_assert((call_func != NULL), "call_func != NULL", FALSE))
    return -1;

  if (!xsup_assert((name != NULL), "name != NULL", FALSE))
    return -1;

  globals = config_get_globals();

  if (hilo == 0)
    {
      while ((i < num_event_slots) && (done != TRUE))
	{
	  if (events[i].devHandle == INVALID_HANDLE_VALUE)
	    {
              debug_printf(DEBUG_EVENT_CORE, "Registered event handler '%s' in "
                           "slot %d.\n", name, i);

			  event_core_fill_reg_struct(&events[i], devHandle, call_func, ctx, flags, name);
			  if ((globals != NULL) && (ctx != NULL) && (ctx->intType != ETH_802_11_INT) && (TEST_FLAG(globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY)))
			  {
				  events[i].flags |= EVENT_IGNORE_INT;
			  }
	      done = TRUE;
	    }
	  
	  i++;
	}
      
      if ((i >= num_event_slots) && (done == FALSE))
	{
	  debug_printf(DEBUG_NORMAL, "Not enough event handler slots "
		       "available!  (Increasing.)\n");

	  num_event_slots += EVENT_GROW;

	  temp = realloc(events, (sizeof(eventhandler) * num_event_slots));
	  if (temp == NULL)
	  {
		  num_event_slots -= EVENT_GROW;
		ipc_events_error(NULL, IPC_EVENT_ERROR_NO_IPC_SLOTS, NULL);
		return -1;
	  }

	  events = temp;

	  for (i = (num_event_slots-EVENT_GROW); i <num_event_slots; i++)
	  {
		  event_core_init_single_event(&events[i]);
	  }

	  // Try to fill the slot again.
	  i = 0;

        while ((i < num_event_slots) && (done != TRUE))
		{
		  if (events[i].devHandle == INVALID_HANDLE_VALUE)
		    {
	           debug_printf(DEBUG_EVENT_CORE, "Registered event handler '%s' in "
	                        "slot %d.\n", name, i);

			  event_core_fill_reg_struct(&events[i], devHandle, call_func, ctx, flags, name);
			  if ((globals != NULL) && (ctx != NULL) && (ctx->intType != ETH_802_11_INT) && (TEST_FLAG(globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY)))
			  {
				  events[i].flags |= EVENT_IGNORE_INT;
			  }

		      done = TRUE;
		    }
	  
		  i++;
		}

	  }
    }
  else
    {
      i = num_event_slots - 1;
      while ((i >= 0) && (done != TRUE))
        {
          if (events[i].devHandle == INVALID_HANDLE_VALUE)
	    {
	      debug_printf(DEBUG_EVENT_CORE, "Registered event handler '%s' in "
			   "slot %d.\n", name, i);
		  event_core_fill_reg_struct(&events[i], devHandle, call_func, ctx, flags, name);
		  if ((globals != NULL) && (ctx != NULL) && (ctx->intType != ETH_802_11_INT) && (TEST_FLAG(globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY)))
		  {
			  events[i].flags |= EVENT_IGNORE_INT;
		  }

              done = TRUE;
            }
	  
	  i--;
        }

      if ((i < 0) && (done == FALSE))
        {
          debug_printf(DEBUG_NORMAL, "Not enough event handler slots "
                        "available!  (Increasing)\n");

	  num_event_slots += EVENT_GROW;

	  temp = realloc(events, (sizeof(eventhandler) * num_event_slots));
	  if (temp == NULL)
	  {
		  num_event_slots -= EVENT_GROW;
		ipc_events_error(NULL, IPC_EVENT_ERROR_NO_IPC_SLOTS, NULL);
		return -1;
	  }

	  events = temp;

	  for (i = (num_event_slots-1); i >= (num_event_slots - EVENT_GROW); i--)
	  {
		  event_core_init_single_event(&events[i]);
	  }

	  i = num_event_slots -1;

        while ((i >= 0) && (done != TRUE))
        {
          if (events[i].devHandle == INVALID_HANDLE_VALUE)
			{
				debug_printf(DEBUG_EVENT_CORE, "Registered event handler '%s' in "
					"slot %d.\n", name, i);
				event_core_fill_reg_struct(&events[i], devHandle, call_func, ctx, flags, name);
			  if ((globals != NULL) && (ctx != NULL) && (ctx->intType != ETH_802_11_INT) && (TEST_FLAG(globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY)))
			  {
				  events[i].flags |= EVENT_IGNORE_INT;
			  }

				done = TRUE;
            }
	  
			i--;
        }

	  return -1;
        }
    }

  return 0;
}

/***********************************************************************
 *
 * Deregister an event handler based on the socket id that we have.  When
 * an interface is deregistered, we need to destroy the context for that
 * interface.  (Assuming there is one.  In the case of an IPC interface,
 * there probably won't be.)
 *
 ***********************************************************************/
void event_core_deregister(HANDLE devHandle, uint8_t flags)
{
  int i;

  for (i=0;i < num_event_slots;i++)
    {
      if ((events[i].devHandle == devHandle) && ((events[i].flags & 0xf0) == flags))
	{
	  debug_printf(DEBUG_EVENT_CORE, "Deregistering event handler '%s' in "
		       "slot %d.\n", events[i].name, i);

	  if ((events[i].ctx != NULL) && ((events[i].flags & 0xf0) != EVENT_SECONDARY)) context_destroy(events[i].ctx);
	  events[i].ctx = NULL;

	  FREE(events[i].name);
	  events[i].devHandle = INVALID_HANDLE_VALUE;
	  events[i].hEvent = INVALID_HANDLE_VALUE;
	  events[i].func_to_call = NULL;
	  FREE(events[i].ovr);
	}
    }
}

/**
 * \brief Recieve a frame, and put it in the right place to be processed.
 *
 * @param[in] ctx   The context that we are recieving the frame on.
 * @param[in] size   The size of the frame we recieved.
 **/
void event_core_recv_frame(context *ctx, ULONG size)
{
	if (ctx->intType == ETH_802_11_INT)
	{
		if (ctx->intTypeData != NULL)
		{
			if (((wireless_ctx *)(ctx->intTypeData))->state != ASSOCIATED)
			{
				cardif_windows_wmi_check_events();
				wireless_sm_do_state(ctx);
			}
		}
	}

	if (ctx->recvframe != NULL)
	{
		if (ctx->recv_size != 0)
		{
			// If we have an unprocessed frame in the buffer, clear it out.
			ctx->recv_size = 0;
		}

		FREE(ctx->recvframe); 
		ctx->recvframe = NULL;
		ctx->eap_state->eapReqData = NULL;
	}

	ctx->recv_size = size;
	ctx->recvframe = ((struct win_sock_data *)(ctx->sockData))->frame;

	((struct win_sock_data *)(ctx->sockData))->frame = NULL;
	((struct win_sock_data *)(ctx->sockData))->size = 0;
					
	// Set up to receive the next frame.
	cardif_setup_recv(ctx);
}

/***********************************************************************
 *
 * Process any events that we may have received.  This includes processing
 * frames that may have come in.
 *
 ***********************************************************************/
void event_core()
{
  HANDLE *handles = NULL;
  int numhandles = 0, i = 0;
  DWORD result = 0;
  LPOVERLAPPED readOvr = 0;
  struct eapol_header *eapol = NULL;
  wireless_ctx *wctx = NULL;
  ULONG bytesrx = 0;
  time_t curtime = 0;
  uint64_t uptime = 0;
  long int err = 0;

  if (terminate == 1)
  {
	  debug_printf(DEBUG_NORMAL, "Got a request to terminate.\n");
	  global_deinit();
  }

  event_core_check_state();

  handles = Malloc(sizeof(HANDLE) * num_event_slots);
  if (handles == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store interface handles.  Terminating.\n");
	  global_deinit();
  }

#if DEBUG_EVENT_HANDLER
  debug_printf(DEBUG_NORMAL, "Watching event handles :\n");
#endif

  cardif_windows_wmi_check_events();

  if (event_core_lock() != 0)
  {
	  debug_printf(DEBUG_NORMAL, "!!!!!!!! Unable to acquire the event core lock!!  Bad things will probably happen!\n");
  }

  for (i = 0; i<num_event_slots; i++)
  {
	  if (events[i].ctx != NULL)
	  {
		  active_ctx = events[i].ctx;
		  cardif_check_events(events[i].ctx);
	  }

	  if ((events[i].hEvent != INVALID_HANDLE_VALUE) && (!TEST_FLAG(events[i].flags, EVENT_IGNORE_INT)) &&
		  ((events[i].ctx == NULL) || (!TEST_FLAG(events[i].ctx->flags, INT_IGNORE))))
	  {
		  // We have a handle, add it to our list of events to watch for, and check for events.
#if DEBUG_EVENT_HANDLER
		  debug_printf(DEBUG_EVENT_CORE, "hEvent = %d  hdl = %d (%s)\n", events[i].hEvent, events[i].devHandle, events[i].name);
#endif
		  handles[numhandles] = events[i].hEvent;
		  numhandles++;
	  }
  }

  if (event_core_unlock() != 0)
  {
	  debug_printf(DEBUG_EVENT_CORE, "Lock failure in %s():%d\n", __FUNCTION__, __LINE__);
  }

  if (numhandles <= 0)
  {
	  debug_printf(DEBUG_NORMAL, "No handles available to watch.  Cannot continue!\n");
	  global_deinit();
  }

  result = WaitForMultipleObjectsEx(numhandles, handles, FALSE, 1000, 1);

  cardif_windows_wmi_check_events();

  if (event_core_lock() != 0)
  {
	  debug_printf(DEBUG_NORMAL, "!!!!!!!! Unable to acquire the event core lock!!  Bad things will probably happen!\n");
  }

	  for (i=(num_event_slots-1); i>=0; i--)
	  {
		  if ((events[i].devHandle != INVALID_HANDLE_VALUE) && (HasOverlappedIoCompleted(events[i].ovr) == TRUE) &&
			  (!TEST_FLAG(events[i].flags, EVENT_IGNORE_INT)) && ((events[i].ctx == NULL) || (!TEST_FLAG(events[i].ctx->flags, INT_IGNORE))))
		  {
			  readOvr = events[i].ovr;

			  if (GetOverlappedResult(events[i].devHandle, readOvr, &bytesrx, FALSE) != 0)
			  {
				  debug_printf(DEBUG_EVENT_CORE, "Got data on handle %d (Size %d).\n", events[i].devHandle,
					  bytesrx);
				  
				  // Only process as a frame handler if we have a context, and
				  // no flags indicating that it isn't a frame handler.
				  if ((events[i].ctx != NULL) && ((events[i].flags & 0xf0) == EVENT_PRIMARY))
  				  {
					  event_core_recv_frame(events[i].ctx, bytesrx);
				  } 

				  if ((events[i].ctx != NULL) && ((events[i].flags & 0xf0) == EVENT_SECONDARY))
				  {
					  cardif_windows_events_set_bytes_rx(events[i].ctx, bytesrx);
				  }

				// Be sure to set active_ctx before calling the function below.  It is
				// used to allow upper layers to determine details of the lower layers.
				active_ctx = events[i].ctx;
				events[i].func_to_call(events[i].ctx, events[i].devHandle);
				events[i].silent = 0;
			  }
			  else
			  {
				  err = GetLastError();
				  if (GetLastError() == ERROR_BROKEN_PIPE)
				  {
					  active_ctx = events[i].ctx;
					  events[i].func_to_call(events[i].ctx, events[i].devHandle);
				  }

				  if ((err == ERROR_OPERATION_ABORTED) && (events[i].ctx != NULL))
				  {
					  active_ctx = events[i].ctx;

					  // If we get an operation aborted event, and it is on an event handler that has a 
					  // context, we want to bounce the I/O handler to see if we can recover.
					  debug_printf(DEBUG_INT, "Operation aborted.  (Hdl : %d  Evt : %d)\n", events[i].devHandle, events[i].hEvent);
					  if ((events[i].flags & 0xf0) == EVENT_PRIMARY)
					  {
		 			    // This is how we restart I/O on a primary event handler.
						cardif_cancel_io(events[i].ctx);
						cardif_restart_io(events[i].ctx);
						events[i].silent++;
					  }

					  if ((events[i].flags & 0xf0) == EVENT_SECONDARY)
					  {
			  			cardif_windows_restart_int_events(events[i].ctx);
					  }

					  // If the interface has been broken for at least 31 seconds, we want to shut it down.
					  if (events[i].silent >= 32)
					  {
						  // We have a network interface that has disappeared, and we
						  // don't know what to do, so dump it's context and log a message.
						  debug_printf(DEBUG_VERBOSE, "The interface '%s' went in to a strange state.  We will terminate it's context.  If you want to "
							  "use this interface, you need to repair it, or unplug it and plug it back in.\n", events[i].ctx->desc);

			  			  ipc_events_ui(events[i].ctx, IPC_EVENT_INTERFACE_REMOVED, events[i].ctx->desc);

						  events[i].ctx->flags |= INT_GONE;
					  
						  // Make sure we deregister both primary and secondary handlers.  (Always deregister the secondary first!)
						  event_core_deregister(events[i].devHandle, EVENT_SECONDARY);
						  event_core_deregister(events[i].devHandle, EVENT_PRIMARY);
					  }
				  }
			  }
		  }
	  }  

  // Clean up our handles array.
  FREE(handles);

  if (userlogoff == TRUE)
  {
	  event_core_win_do_user_logoff();
  }

  if (userlogon == TRUE)
  {
	  // Inform any IMCs that may need to know.
	  debug_printf(DEBUG_EVENT_CORE, ">>* Processed user logged on flag.\n");
	  if (imc_notify_callback != NULL) 
	  {
		  imc_notify_callback();
	  }
	  else
	  {
		  debug_printf(DEBUG_EVENT_CORE, ">>* Notify callback is NULL!\n");
	  }
	  userlogon = FALSE;   // Don't retrigger.
  }

  time(&curtime); 
  if (last_check > curtime)
  {
	  debug_printf(DEBUG_EVENT_CORE, "Let's do the time warp again.  Your clock has gone backward!\n");
	  last_check = curtime;
  }

  // If we got nailed with a bunch of events, make sure we still tick the clock.  This
  // method won't have exactly one second precision, but it should be close enough.
  if (curtime > last_check) 
  {
	  result = WAIT_TIMEOUT;
	  last_check = curtime;
  }

  if (result == WAIT_TIMEOUT)
  {
	  // See if logs need to be rolled.
	  xsup_debug_check_log_roll();

	  for (i=0; i<num_event_slots; i++)
	  {
		  if ((events[i].ctx != NULL) && (!TEST_FLAG(events[i].flags, EVENT_IGNORE_INT)))
		  {
			active_ctx = events[i].ctx;
			events[i].ctx->statemachine->tick = TRUE;
			events[i].ctx->tick = TRUE;
 
			// Tick clock.
			if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY)
			{
				timer_tick(events[i].ctx);
			}
		  }
	  }
  }

  for (i=0; i<num_event_slots; i++)
  {
	if (events[i].ctx != NULL)
	{
		active_ctx = events[i].ctx;
		if (events[i].ctx->intType != ETH_802_11_INT) 
		{
			if (!TEST_FLAG(events[i].flags, EVENT_IGNORE_INT))
			{
				if ((events[i].ctx->conn != NULL) && ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY))
				{
					statemachine_run(events[i].ctx);
				}
				else
				{
					if (events[i].ctx->eap_state != NULL)
					{
						events[i].ctx->eap_state->eap_sm_state = DISCONNECTED;
					}
				}
			}
		}
		else
		{
			if (!TEST_FLAG(events[i].flags, EVENT_IGNORE_INT))
			{
				wireless_sm_do_state(events[i].ctx);

				if (TEST_FLAG(events[i].ctx->flags, WIRELESS_SM_PSK_DONE))
				{
					UNSET_FLAG(events[i].ctx->flags, WIRELESS_SM_PSK_DONE);
					UNSET_FLAG(events[i].ctx->flags, WIRELESS_SM_DOING_PSK);
				}
			}
		}
	}
  }

  if (event_core_unlock() != 0)
  {
	  debug_printf(DEBUG_NORMAL, "!!!!!!!!!!!! Unable to release event core lock!  Bad things will probably happen!!\n");
  }
}

/**
 *  \brief Find the context that matches the interface name string, and return it.  
 *
 * @param[in] matchstr   The OS specific name of the interface we wish to find the
 *                       context for.
 *
 * \retval ptr  Pointer to a context structure for the interface requested.
 * \retval NULL Couldn't locate the desired interface.
 **/
context *event_core_locate(char *matchstr)
{
  int i;

  if (!xsup_assert((matchstr != NULL), "matchstr != NULL", FALSE))
    return NULL;

  for (i = 0; i < num_event_slots; i++)
  {
	  if ((events[i].ctx != NULL) && (strcmp(events[i].ctx->intName, matchstr) == 0))
		  return events[i].ctx;
  }

  // Otherwise, we ran out of options.
  return NULL;
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

  for (i = 0; i < num_event_slots; i++)
  {
	  if ((events[i].ctx != NULL) && (events[i].ctx->conn_name != NULL) && (strcmp(events[i].ctx->conn_name, matchstr) == 0))
		  return events[i].ctx;
  }

  // Otherwise, we ran out of options.
  return NULL;
}

/**
 *  \brief Find the context that matches the interface description string, and return it.  
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

  for (i = 0; i < num_event_slots; i++)
  {
	  if ((events[i].ctx != NULL) && (strcmp(events[i].ctx->desc, matchstr) == 0))
		  return events[i].ctx;
  }

  // Otherwise, we ran out of options.
  return NULL;
}

/**
 *  \brief Find the context that matches the interface description string, and return it.  
 *
 * @param[in] matchstr   The interface description we are looking for.
 *
 * \retval ptr  Pointer to a context structure for the interface requested.
 * \retval NULL Couldn't locate the desired interface.
 **/
context *event_core_locate_by_desc_strstr(char *matchstr)
{
  int i;

  if (!xsup_assert((matchstr != NULL), "matchstr != NULL", FALSE))
    return NULL;

  for (i = 0; i < num_event_slots; i++)
  {
	  if ((events[i].ctx != NULL) && (strstr(events[i].ctx->desc, matchstr) != NULL))
		  return events[i].ctx;
  }

  // Otherwise, we ran out of options.
  return NULL;
}

/**
 *  \brief Find the context that matches the interface caption string, and return it.  
 *
 * @param[in] matchstr   The WMI caption name to search for.
 *
 * \retval ptr  Pointer to a context structure for the interface requested.
 * \retval NULL Couldn't locate the desired interface.
 **/
context *event_core_locate_by_caption(wchar_t *matchstr, int exact)
{
  int i;
  struct win_sock_data *sockData = NULL;
  wchar_t *str = NULL;
  context *ctx = NULL;

  if (!xsup_assert((matchstr != NULL), "matchstr != NULL", FALSE))
    return NULL;

  for (i = 0; i < num_event_slots; i++)
  {
	  if (events[i].ctx != NULL)
	  {
		  sockData = events[i].ctx->sockData;
		  if (sockData != NULL)
		  {
			  // Depending on the type of event it is, Windows may send the full name with the "- Packet Scheduler Miniport"
			  // on the end, or just send the bare name.  In 99% of cases, you want to use an exact match to avoid any
			  // weird stuff..  But, for things like the connect and disconnect events, you need to use a substring
			  // match.   Always try to use an exact match first!!  (It will save you pain in the long run!)
			  if (exact == TRUE)
			  {
				  if (wcscmp(sockData->caption, matchstr) == 0)
					  return events[i].ctx;
			  }
			  else
			  {
				  str = wcsstr(sockData->caption, matchstr);
				  if (str != NULL)
				  {
					  if (wcscmp(str, matchstr) == 0)
						  return events[i].ctx;
				  }
			  }
		  }
	  }
  }

  // Otherwise, we ran out of options.
  return NULL;
}


void event_core_reset_locator()
{
	locate = -1;
}

context *event_core_get_next_context()
{
	int desired_ctx = 0;

	desired_ctx = ++locate;

	if (desired_ctx >= num_event_slots) return NULL;

	while ((desired_ctx < num_event_slots) && (events[desired_ctx].ctx == NULL))
	{
		desired_ctx++;
	}

	locate = desired_ctx;

	if (desired_ctx >= num_event_slots) return NULL;

	return events[desired_ctx].ctx;
}

/**
 * \brief Indicate that we need to take action to enter sleep state.
 *        (Sleep may also indicate hibernate, or other low power
 *        condition where things may happen that we could miss.)
 *
 * \warning This function will *ALWAYS* be called from the service
 *          control thread.  As such, nothing should be done that 
 *          could cause issues with the main thread!
 **/
void event_core_going_to_sleep_thread_ctrl()
{
	sleep_state = PWR_STATE_SLEEPING;
}

/**
 * \brief Another process indicated that going to sleep right now is
 *        unacceptible.   So, we need to turn everything back on again.
 *
 * \warning This function will *ALWAYS* be called from the service
 *          control thread.  As such, nothing should be done that 
 *          could cause issues with the main thread!
 **/
void event_core_cancel_sleep_thread_ctrl()
{
	sleep_state = PWR_STATE_SLEEP_CANCEL;
}

/**
 * \brief We have come out of sleep mode.  We need to take steps to
 *        make sure our configuration is still sane.
 *
 * \warning This function will *ALWAYS* be called from the service
 *          control thread.  As such, nothing should be done that 
 *          could cause issues with the main thread!
 **/
void event_core_waking_up_thread_ctrl()
{
	sleep_state = PWR_STATE_WAKING_UP;
}

/**
 * \brief This function will be called when an indication that we are going 
 *        to sleep is made.  There are certain steps that need to be taken :
 *
 *           1) All pending IO reads need to be canceled.  (This will prevent
 *              extra frames from being read, and screwing us up when we wake up.)
 *
 *           2) A "going to sleep" event needs to be sent to all connected UIs.
 *
 *           3) All contexts need to be flagged so that we don't process them.  (If
 *              we processed them we would undo the steps taken in #1. ;)
 *
 * \note NOTHING should be done that is totally perminent.  There is always a chance that
 *       the sleep request will be canceled.
 **/
void event_core_going_to_sleep()
{
	int i = 0;

	debug_printf(DEBUG_NORMAL, "XSupplicant got a request for the machine to enter a sleep state.\n");

	for (i= 0; i< num_event_slots; i++)
	{
		// Loop through each event slot, cancel the IO, flag the context.
		if (events[i].ctx != NULL)
		{
			cardif_cancel_io(events[i].ctx);
			events[i].flags |= EVENT_IGNORE_INT;
		}
	}

	// Then send a "going to sleep" message.
	ipc_events_ui(NULL, IPC_EVENT_UI_GOING_TO_SLEEP, NULL);

	sleep_state = PWR_STATE_HELD;
}

/**
 * \brief Cancel the sleep request.  We need to turn our frame listeners back on, and continue
 *        as if nothing happened.  There is a small chance that a reauth was taking place
 *        during the time the sleep request was received.  In this case, we will probably fail the
 *        authentication. :-/
 **/
void event_core_cancel_sleep()
{
	int i = 0;

	debug_printf(DEBUG_NORMAL, "Another process canceled the sleep request.\n");

	for (i= 0; i< num_event_slots; i++)
	{
		// Loop through each event slot, cancel the IO, flag the context.
		if (events[i].ctx != NULL)
		{
			if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY)
			{
				cardif_restart_io(events[i].ctx);
			}
			else
			{
				cardif_windows_restart_int_events(events[i].ctx);
			}

			events[i].flags &= (~EVENT_IGNORE_INT);
		}
	}

	// Then send a "sleep cancelled" message.
	ipc_events_ui(NULL, IPC_EVENT_UI_SLEEP_CANCELLED, NULL);

	sleep_state = PWR_STATE_RUNNING;
}

/**
 * \brief We got a wake up event.   We need to sanity check all of our interfaces, reset state
 *        machines, and send notifications that we have come back to life.
 **/
void event_core_waking_up()
{
	int i = 0;
	wireless_ctx *wctx = NULL;

	debug_printf(DEBUG_NORMAL, "XSupplicant is coming out of a sleep state.\n");

	for (i= 0; i< num_event_slots; i++)
	{
		// Loop through each event slot, cancel the IO, flag the context.
		if (events[i].ctx != NULL)
		{
			if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY)
			{
				cardif_restart_io(events[i].ctx);

				// Depending on the order that things are restarted, and the events that 
				// happened before we went to sleep, the UI may believe that some interfaces
				// were removed, and never inserted again.  So, we generated inserted events
				// for each interface we know about so that the UI is in sync with us.
				ipc_events_ui(NULL, IPC_EVENT_INTERFACE_INSERTED, events[i].ctx->intName);

				// Reset our auth count so that we do a new IP release/renew.  Just in case Windows beats us to the punch.
				events[i].ctx->auths = 0;

				// Cause our state machines to reset to a known state.
				events[i].ctx->statemachine->initialize = TRUE;
				events[i].ctx->eap_state->eapRestart = TRUE;

				if (events[i].ctx->intType == ETH_802_11_INT)
				{
					wctx = events[i].ctx->intTypeData;
					memset(wctx->cur_bssid, 0x00, 6);

					if (events[i].ctx->conn != NULL)
					{
						wireless_sm_change_state(ASSOCIATING, events[i].ctx);
					}

					UNSET_FLAG(events[i].ctx->flags, FORCED_CONN);
				}
				else
				{
					// Some interfaces send a link down when the machine is going to
					// sleep.  So, we need to probe to make sure we show proper state
					// when we wake up.
					if (cardif_get_link_state(events[i].ctx) == TRUE)
					{
						events[i].ctx->statemachine->portEnabled = TRUE;
						events[i].ctx->eap_state->portEnabled = TRUE;
						ipc_events_ui(NULL, IPC_EVENT_UI_LINK_UP, events[i].ctx->desc);
					}
					else
					{
						events[i].ctx->statemachine->portEnabled = FALSE;
						events[i].ctx->eap_state->portEnabled = FALSE;
						ipc_events_ui(NULL, IPC_EVENT_UI_LINK_DOWN, events[i].ctx->desc);
					}
				}
			}
			else
			{
				cardif_windows_restart_int_events(events[i].ctx);
			}

			events[i].flags &= (~EVENT_IGNORE_INT);
		}
	}

	// Then send a "waking up" message.
	ipc_events_ui(NULL, IPC_EVENT_UI_WAKING_UP, NULL);

	sleep_state = PWR_STATE_RUNNING;
}

/**
 * \brief Check the state of sleep/wake-up events.  Make any changes that may be
 *        needed for these events.
 **/
void event_core_check_state()
{
	switch (sleep_state)
	{
	default:
	case PWR_STATE_RUNNING:
	case PWR_STATE_HELD:
		break;

	case PWR_STATE_SLEEPING:
		event_core_going_to_sleep();
		break;

	case PWR_STATE_SLEEP_CANCEL:
		event_core_cancel_sleep();
		break;

	case PWR_STATE_WAKING_UP:
		event_core_waking_up();
		break;
	}
}

/**
 * \brief This is called when a user logs on.  It should be expected that this call
 *        may be called from a seperate thread.  So, it should do the minimum amount 
 *        of work possible.
 **/
void event_core_user_logged_on()
{
	if (user_logged_on == FALSE)
	{
		debug_printf(DEBUG_EVENT_CORE, ">>* Set user logged on flag!\n");
		userlogon = TRUE;
	}

	user_logged_on = TRUE;
}

/**
 * \brief This function gets called when a user logs off.  It should do any user specific
 *        cleanup that the engine needs.
 **/
void event_core_user_logged_off()
{
	user_logged_on = FALSE;
	userlogoff = TRUE;
}

void event_core_win_do_user_logoff()
{
	struct config_globals *globals = NULL;
	context *ctx = NULL;
	int i = 0;

	userlogoff = FALSE;  // Don't trigger again.

	globals = config_get_globals();
	if (globals == NULL) 
	{
		debug_printf(DEBUG_NORMAL, "Unable to obtain the global configuration data.\n");
		return;
	}

	if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF))
	{
		debug_printf(DEBUG_NORMAL, "Console user logged off.  Dropping all connections.\n");

		for (i= 0; i< num_event_slots; i++)
		{
			// Loop through each event slot, cancel the IO, flag the context.
			if (events[i].ctx != NULL)
			{
				if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY)
				{
					ctx = events[i].ctx;

					if (ctx->intType == ETH_802_11_INT)
					{
						// Do a wireless disconnect.
						wireless_sm_change_state(INT_STOPPED, ctx);
					}
					else
					{
						// Do a wired disconnect.
						if (statemachine_change_state(ctx, LOGOFF) == 0)
						{
							ctx->conn = NULL;
							FREE(ctx->conn_name);
							eap_sm_deinit(&ctx->eap_state);
							eap_sm_init(&ctx->eap_state);
							ctx->auths = 0;                   // So that we renew DHCP on the next authentication.

							txLogoff(ctx);
						}
					}

					// Unbind any connections.
					ctx->conn = NULL;
					FREE(ctx->conn_name);
					ctx->prof = NULL;
					UNSET_FLAG(ctx->flags, FORCED_CONN);

#ifdef HAVE_TNC
					// If we are using a TNC enabled build, signal the IMC to clean up.
					if(imc_disconnect_callback != NULL)
						imc_disconnect_callback(ctx->tnc_connID);
#endif
				}
			}
		}
	}
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
	if (imc_notify_callback != NULL) return 1;

	imc_notify_callback = callback;

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
	if (imc_disconnect_callback != NULL) return 1;

	imc_disconnect_callback = callback;

	return 0;
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
	if (imc_ui_connect_callback != NULL) return 1;

	imc_ui_connect_callback = callback;

	return 0;
}

/**
 * \brief Drop all active connections.  (But leave them in a state that they should
 *        be able to reconnect.
 **/
void event_core_drop_active_conns()
{
	int i = 0;

	for (i= 0; i< num_event_slots; i++)
	{
		// Loop through each event slot, and disconnect it.
		if ((events[i].ctx != NULL) && (events[i].ctx->conn != NULL))
		{
			if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY)
			{
				if (statemachine_change_state(events[i].ctx, LOGOFF) == 0)
				{
					events[i].ctx->auths = 0;                   // So that we renew DHCP on the next authentication.

					txLogoff(events[i].ctx);
				}

				if (events[i].ctx->intType == ETH_802_11_INT)
				{
					// Send a disassociate.
					cardif_disassociate(events[i].ctx, 0);
				}
			}
		}
	}
}

void event_core_change_wireless(config_globals *newsettings)
{
	config_globals *globals = NULL;
	wireless_ctx *wctx = NULL;
	int i = 0;

	globals = config_get_globals();

	if (globals == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine current state of the Wireless_Only option!\n");
		return;
	}

	// Only do things if something has changed.
	if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_WIRELESS_ONLY) != TEST_FLAG(newsettings->flags, CONFIG_GLOBALS_WIRELESS_ONLY))
	{
		for (i= 0; i< num_event_slots; i++)
		{
			// We only care if this interface is wired.
			if ((events[i].ctx != NULL) && (events[i].ctx->intType != ETH_802_11_INT))
			{
				if (TEST_FLAG(newsettings->flags, CONFIG_GLOBALS_WIRELESS_ONLY))
				{
					// Disable all wired interfaces.  (If it isn't already disabled.)
					if (!TEST_FLAG(events[i].flags, EVENT_IGNORE_INT))
					{
						cardif_cancel_io(events[i].ctx);
						events[i].flags |= EVENT_IGNORE_INT;
					}
				}
				else
				{
					// Enable all wired interfaces.  (If it isn't already enabled.)
					if (TEST_FLAG(events[i].flags, EVENT_IGNORE_INT))
					{
						cardif_restart_io(events[i].ctx);
						events[i].flags &= (~EVENT_IGNORE_INT);

						if (events[i].ctx->intType == ETH_802_11_INT)
						{
							wctx = events[i].ctx->intTypeData;
							memset(wctx->cur_bssid, 0x00, 6);
						}

						// Reset our auth count so that we do a new IP release/renew.  Just in case Windows beats us to the punch.
						events[i].ctx->auths = 0;
					}
				}
			}
		}
	}
}

/**
 * \brief Iterate through all of the interfaces we currently know about, and enable or disable
 *        control of them.
 *
 * @param[in] endis   TRUE if the interfaces should be controlled by XSupplicant.  FALSE if not.
 **/
void event_core_change_os_ctrl_state(void *param)
{
	int i = 0;

	event_core_lock();

	if (param != NULL)
	{
		debug_printf(DEBUG_NORMAL, "XSupplicant is taking control of your interfaces...\n");
	}
	else
	{
		debug_printf(DEBUG_NORMAL, "XSupplicant is giving control of your interfaces to Windows...\n");
	}

	for (i= 0; i< num_event_slots; i++)
	{
		if (param != NULL)
		{
			// XSupplicant should control this interface.
			if (events[i].ctx != NULL)
			{
				if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY) 
				{
					windows_int_ctrl_take_ctrl(events[i].ctx);
					cardif_restart_io(events[i].ctx);
				}
				else
				{
					cardif_windows_restart_int_events(events[i].ctx);
				}

				events[i].flags &= (~EVENT_IGNORE_INT);

				if (TEST_FLAG(events[i].flags, EVENT_PRIMARY))
				{
					// Clear out the connection data so we don't get confused
					// when we come back.
					UNSET_FLAG(events[i].ctx->flags, FORCED_CONN);
					events[i].ctx->conn = NULL;
					events[i].ctx->prof = NULL;
					FREE(events[i].ctx->conn_name);

					if (statemachine_change_state(events[i].ctx, LOGOFF) == 0)
					{
						events[i].ctx->auths = 0;                   // So that we renew DHCP on the next authentication.

						txLogoff(events[i].ctx);
					}

					if (events[i].ctx->intType == ETH_802_11_INT)
					{
						config_ssid_clear(events[i].ctx->intTypeData);
						wireless_sm_change_state(UNASSOCIATED, events[i].ctx);						
					}
				}
			}
		}
		else
		{
			// Windows should control this interface.
			if (events[i].ctx != NULL)
			{
				if ((events[i].flags & EVENT_PRIMARY) == EVENT_PRIMARY) windows_int_ctrl_give_to_windows(events[i].ctx);
				cardif_cancel_io(events[i].ctx);
				events[i].flags |= EVENT_IGNORE_INT;
			}
		}
	}

	event_core_unlock();

	//if (param != NULL) event_core_drop_active_conns();

	ipc_events_ui(NULL, IPC_EVENT_UI_INT_CTRL_CHANGED, NULL);
}

/**
 * \brief Determine if the machine is going to sleep.
 *
 * \retval TRUE if we are going to sleep (or already asleep ;)
 **/
int event_core_get_sleep_state()
{
	if ((sleep_state == PWR_STATE_SLEEPING) || (sleep_state == PWR_STATE_HELD)) return TRUE;

	return FALSE;
}