/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui.c
 *
 * \author chris@open1x.org, Terry.Simons@utah.edu
 *
 **/
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>

#ifndef WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "xsupgui_ud.h"
#else
#include "xsupgui_windows.h"
#endif

#include "xsupgui.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

//#define DEBUG  1

/**
 *  \brief Return the xmlDocPtr that contains the event document.
 *
 *  \retval xmlDocPtr containing the event message. 
 *
 *  \warning  The caller should make sure the return value is not NULL.  It
 *            would be an unusual situation to get here and have NULL returned,
 *            but it is not beyond the realm of possibility.
 **/
xmlDocPtr xsupgui_get_event_doc()
{
#ifdef WINDOWS
	return xsupgui_windows_get_event_doc();
#else
	return xsupgui_ud_get_event_doc();
#endif
}

/**
 * \brief Establish a handler to talk to the supplicant.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupgui_connect()
{
#ifdef WINDOWS
	return xsupgui_windows_connect();
#else
	return xsupgui_ud_connect();
#endif
}

/**
 * \brief Establish a hendler to listen for events.  (This *WILL* block!)
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupgui_connect_event_listener()
{
#ifdef WINDOWS
	return xsupgui_windows_connect_event_listener();
#else
	return xsupgui_ud_connect_event_listener();
#endif
}

/**
 * \brief Disconnect from the daemon.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupgui_disconnect()
{
#ifdef WINDOWS
	return xsupgui_windows_disconnect();
#else
	return xsupgui_ud_disconnect();
#endif
}

/**
 *  \brief Disconnect the socket that is used as an event listener.
 *
 *  \retval 0 on success
 *  \retval -1 on failure
 **/
int xsupgui_disconnect_event_listener()
{
#ifdef WINDOWS
	return xsupgui_windows_disconnect_event_listener();
#else
	return xsupgui_ud_disconnect();
#endif
}

/**
 * \brief Get the socket number we are using, so that it can be used in a select() call.
 *
 * \note This doesn't work on Windows!!!!
 *
 * \retval -1 on error (or unsupported if using Windows)
 * \retval >=0 on success
 **/
int xsupgui_get_selectable_socket()
{
#ifdef WINDOWS
	return -1;
#else
	return xsupgui_ud_selectable_socket();
#endif
}

/**
 * \brief See if we have any data.  The caller should assume this call is blocking
 *        and should use a select() in *nix, or a thread in Windows to avoid having
 *        it block the operation of your program.
 *
 *  \retval >1 there is a new event to process.  
 *  \retval 0 if there is still an event to process
 *  \retval -1 on error.
 **/
int xsupgui_process(int *evttype)
{
#ifdef WINDOWS
	return xsupgui_windows_process(evttype);
#else
	return xsupgui_ud_process(evttype);
#endif
}

/**
 * \brief Send an IPC message via the allocate event socket.
 *
 *  This call is a stub that calls an OS specific version.  
 *
 * @param[in] buffer   The buffer to be sent to down the event socket.
 * @param[in] bufsize   The size of the buffer to be sent.
 *
 * \retval REQUEST_SUCCESS buffer was sent, and acked.
 * \retval REQUEST_FAILURE buffer couldn't be sent, or wasn't acked.
 *
 * \warning This function should *NEVER* be called outside of the
 *           libxsupgui library!
 **/
int xsupgui_send_to_event(unsigned char *buffer, int bufsize)
{
#ifdef WINDOWS
	return xsupgui_windows_send_to_event(buffer, bufsize);
#else
	return xsupgui_ud_send_to_event(buffer, bufsize);
#endif
}

/**
 * \brief Send a packet, and wait for an answer.
 *
 * @param[in] buffer   The buffer to send to the supplicant.
 * @param[in] bufptr   The size of the buffer that needs to be sent.
 * @param[out] retbuf   A buffer that contains the response from the supplicant.
 * @param[out] retsize   The size of the resulting buffer from the supplicant.
 *
 *  \retval REQUEST_SUCCESS for success
 *  \retval REQUEST_FAILURE for error 
 *  \retval REQUEST_TIMEOUT for timeout waiting for a response.
 **/
int xsupgui_send(unsigned char *buffer, int bufptr, unsigned char **retbuf,
		 int *retsize)
{
#ifdef WINDOWS
	return xsupgui_windows_send(buffer, bufptr, retbuf, retsize);
#else
	return xsupgui_ud_send(buffer, bufptr, retbuf, retsize);
#endif
}

/**
 * \brief Free the XML document that held our event.
 **/
void xsupgui_free_event_doc()
{
#ifdef WINDOWS
	xsupgui_windows_free_event_doc();
#else
	xsupgui_ud_free_event_doc();
#endif
}

/**
 * \brief This function needs to be defined so that we can compile xsupconfig.c.  It should *NEVER* be called!
 *
 * @param[in] errmsg  A parameter that is needed by the real call. ;)
 *
 * \retval 0 always
 **/
int error_prequeue_add(char *errmsg)
{
	return 0;
}

/**
 * \brief This function needs to be defined so that we can compile xsupconfig.c.  It should just discard anything
 *        it gets.
 *
 * @param[in] logmsg   The log message.
 *
 **/
int ipc_events_log_msg(char *logmsg)
{
	return 0;
}

#ifndef WINDOWS
// XXX This shouldn't be needed.  Clean it up!
int crashdump_add_file(char *temp, char temp2)
{
	return 0;
}
#endif

