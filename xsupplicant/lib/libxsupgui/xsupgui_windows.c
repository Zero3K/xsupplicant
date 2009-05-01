/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_windows.c
 *
 * \author chris@open1x.org
 **/
#ifdef WINDOWS

#include <windows.h>
#include <libxml/parser.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"
#include "xsup_gui_trace.h"

//#define TRACELOG   1        ///< Comment this out to disable library level tracing.  (Normally you want this commented out!!)

#define MAXBUF   4096		///< 4k is the MTU for our IPC messages.

HANDLE pipehdl = INVALID_HANDLE_VALUE;	///< The read/write handle to our pipe request/response pipe.
HANDLE eventhdl = INVALID_HANDLE_VALUE;	///< The handle to the windows event we bind to our request/response pipe.
HANDLE eventpipe = INVALID_HANDLE_VALUE;	///< Handle to the IPC event generation pipe.
HANDLE eventevent = INVALID_HANDLE_VALUE;	///< The handle to the windows event we bind to our event pipe.
OVERLAPPED ovr;			///< Overlapped structure used for non-blocking access to \ref pipehdl.
OVERLAPPED eovr;		///< Overlapped structure used for non-blocking access to \ref eventpipe.

xmlDocPtr recvmsg = NULL;	///< XML Document that represents an async event that we receiqved.

int ctrl_connected = FALSE;
int evt_connected = FALSE;

LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\open1x_ctrl");	///< Path to Windows pipe used for IPC.

// Uncomment to see printf() debug messages.
#define DEBUG_WINDOWS_GUI  1

/**
 *  \brief Return the xmlDocPtr that contains the event document.
 *
 *  \retval xmlDocPtr containing the event message.  (May be NULL.)
 **/
xmlDocPtr xsupgui_windows_get_event_doc()
{
	return recvmsg;
}

/**
 *  \brief Establish a connection to a request/response IPC Windows pipe.
 *
 *  \retval 0 on success
 *  \retval -1 on error.
 *
 *  \warning A return value of -1 indicates that the supplicant
 *           probably isn't running.  The UI should notify the user of this!
 **/
int xsupgui_windows_connect()
{
	DWORD dwMode;

	// Make sure we aren't already connected.
	if (ctrl_connected == TRUE)
		return IPC_ERROR_CTRL_ALREADY_CONNECTED;

#ifdef TRACELOG
	xsup_gui_trace_enable("c:\\guitrace.log");
#endif

	// Establish an event handle.
	if (eventhdl != INVALID_HANDLE_VALUE)
		return -1;

	eventhdl = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (eventhdl == INVALID_HANDLE_VALUE)
		return -1;

	ovr.hEvent = eventhdl;

	pipehdl = CreateFile(lpszPipename, GENERIC_READ | GENERIC_WRITE,
			     0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
			     NULL);

	if (pipehdl == INVALID_HANDLE_VALUE)
		return -1;

	xsup_gui_trace("Connected control handle %d, event %d\n", pipehdl,
		       eventhdl);

	dwMode = PIPE_READMODE_MESSAGE;
	if (SetNamedPipeHandleState(pipehdl, &dwMode, NULL, NULL) == FALSE)
		return -1;
	xsup_gui_trace("After state change : %d\n", pipehdl);

	ctrl_connected = TRUE;

	return 0;		// We have a valid handle now.
}

/**
 *  \brief Establish a connection to a Windows IPC event listener pipe.
 *
 *  \retval 0 on success
 *  \retval -1 on error
 *
 *  \warning A return value of -1 indicates that the supplicant
 *           probably isn't running.  The UI should notify the user of this!
 **/
int xsupgui_windows_connect_event_listener()
{
	char *result = NULL;
	int ressize = 0;
	DWORD dwMode;

	if (evt_connected == TRUE)
		return IPC_ERROR_EVT_ALREADY_CONNECTED;

	recvmsg = NULL;

	// Establish an event handle.
	eventevent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (eventevent == INVALID_HANDLE_VALUE)
		return -1;

	eovr.hEvent = eventevent;

	eventpipe = CreateFile(lpszPipename, GENERIC_READ | GENERIC_WRITE,
			       0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
			       NULL);

	if (eventpipe == INVALID_HANDLE_VALUE)
		return -1;

	xsup_gui_trace("Connected event handle %d, event %d\n", eventpipe,
		       eventevent);

	dwMode = PIPE_READMODE_MESSAGE;
	if (SetNamedPipeHandleState(eventpipe, &dwMode, NULL, NULL) == FALSE)
		return -1;

	evt_connected = TRUE;

	if (xsupgui_request_set_as_event(&result, &ressize) == REQUEST_FAILURE)
		return -1;

	if (xsupgui_windows_send_to_event(result, ressize) == REQUEST_FAILURE) {
		free(result);
		result = NULL;
		return -1;
	}

	free(result);

	return 0;		// We have a valid handle now.
}

/**
 *  \brief Disconnect the connection to the request/response IPC Windows pipe.
 *
 *  \retval 0 on success
 *  \retval -1 on error
 **/
int xsupgui_windows_disconnect()
{
	xsup_gui_trace("Disconnect control pipe %d, event %d.\n", pipehdl,
		       eventhdl);
	if (eventhdl != INVALID_HANDLE_VALUE)
		CloseHandle(eventhdl);
	if (pipehdl != INVALID_HANDLE_VALUE)
		CloseHandle(pipehdl);
	eventhdl = INVALID_HANDLE_VALUE;
	pipehdl = INVALID_HANDLE_VALUE;

#ifdef TRACELOG
	xsup_gui_trace_disable();
#endif

	ctrl_connected = FALSE;
	return 0;
}

/**
 *  \brief Disconnect the connection to the Windows IPC event pipe.
 *
 *  \retval 0 on success
 *  \retval -1 on error
 **/
int xsupgui_windows_disconnect_event_listener()
{
	xmlFreeDoc(recvmsg);
	recvmsg = NULL;

	xsup_gui_trace("Disconnect control pipe %d, event %d.\n", eventpipe,
		       eventevent);
	if (eventevent != INVALID_HANDLE_VALUE)
		CloseHandle(eventevent);
	if (eventpipe != INVALID_HANDLE_VALUE)
		CloseHandle(eventpipe);
	eventevent = INVALID_HANDLE_VALUE;
	eventpipe = INVALID_HANDLE_VALUE;

	evt_connected = FALSE;
	return 0;
}

/**
 * \brief Flush a named pipe to be sure there isn't any cruft in it.  This should
 *        be used before sending a command to the engine via the named pipe.
 *        On exit from this function, the caller should be fairly sure that the 
 *        pipe is empty, and ready to use.
 **/
void xsupgui_windows_flush_ctrl_pipe()
{
	LPVOID tempbuf;
	char buffer[4096];
	DWORD bread;
	OVERLAPPED ovr;
	HANDLE hevent;

	if (!PeekNamedPipe(pipehdl, NULL, 0, NULL, &bread, NULL))
		return;		// ACK!
	xsup_gui_trace("(%s) Control pipe handle %d\n", __FUNCTION__, pipehdl);

	while (bread > 0) {
		hevent = CreateEvent(NULL, 0, 0, NULL);
		if (hevent == INVALID_HANDLE_VALUE)
			return;	// ACK!  This should't ever happen.

		ovr.hEvent = hevent;

		// There is some data in the buffer.  Read it out and throw it away.
		if (ReadFile
		    (pipehdl, (LPVOID) & buffer, 4096, &bread,
		     (LPOVERLAPPED) & ovr) == FALSE) {
			// It may be an overlapped read (which would be weird, but possible).
			if (GetLastError() != ERROR_IO_PENDING) {
				// ACK!  We are not in a good place.  Bail out.
				return;
			}

			if (WaitForSingleObject(ovr.hEvent, INFINITE) !=
			    WAIT_OBJECT_0) {
				// ACK!  This shouldn't happen!
				return;
			}

			if (!GetOverlappedResult(pipehdl, &ovr, &bread, TRUE))	// TRUE should be safe because we know there is something ready.
			{
				// ACK!  Shouldn't happen!
				return;
			}
		}

		CloseHandle(hevent);

		if (!PeekNamedPipe(pipehdl, NULL, 0, NULL, &bread, NULL))
			return;	// ACK!
		xsup_gui_trace("(In loop) Control pipe handle %d\n", pipehdl);
	}
}

/**
 *  \brief Process events from the supplicant.
 *
 *  Catch unsolicited events that are generated by the supplicant.  
 *
 * @param[out] evttype   The event type that generated the event.
 *

 *  \warning This is a *BLOCKING* call, so it should
 *  be run from a different thread, and signals should be passed
 *  back to the core of the UI.
 *
 *  \retval 1 there is a new event to process.  
 *  \retval 0 if there is nothing to process
 *  \retval >300 on error
 **/
long int xsupgui_windows_process(int *evttype)
{
	int retval = 1;
	char *eventbuf = NULL;
	int eventbufressize = 0;

	if (evttype == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	// If eventbuf points to something, we have a problem.
	if (recvmsg != NULL)
		return IPC_ERROR_STALE_BUFFER_DATA;

	retval = xsupgui_windows_recv_event(&eventbuf, &eventbufressize);

	if (retval != REQUEST_SUCCESS) {
		if (retval == IPC_EVENT_COM_BROKEN) {
			(*evttype) = IPC_EVENT_COM_BROKEN;
			return REQUEST_SUCCESS;
		}

		return retval;
	}

	if ((eventbuf == NULL) || ((eventbufressize - 5) < 0)) {
		recvmsg = NULL;
		if (eventbuf != NULL)
			free(eventbuf);
		return IPC_ERROR_RUNT_RESPONSE;
	}

	recvmsg = xmlReadMemory(&eventbuf[5], (eventbufressize - 5), "ipc_event.xml",
			  NULL, 0);
	if (recvmsg == NULL) {
		retval = GetLastError();

//              xsup_gui_trace("XML Dump :\n");
//              xsup_gui_trace("%s\n", &eventbuf[5]);
//              xsup_gui_trace("------  Windows Error : %d\n", retval);

		free(eventbuf);
		return IPC_ERROR_BAD_RESPONSE;
	}

	if (eventbuf != NULL)
		free(eventbuf);
	eventbuf = NULL;

	(*evttype) = xsupgui_events_get_event_num(recvmsg);

	return REQUEST_SUCCESS;
}

/**
 *  \brief Read data from an already connected Windows pipe.
 *
 *  Get data from a pipe.  This may be used to get data that is a response from
 *  a previously issued request, or get the data for an unsolicited event.
 *
 *  @param[out] result   A buffer to the data that was read.  (This function will allocate it, the
 *                       caller is expected to free it.)
 *  @param[out] resultsize   The amount of data that the buffer contains.
 *
 *  \retval REQUEST_SUCCESS on success
 *  \retval >=300 on error.
 *  \retval REQUEST_TIMEOUT on timeout
 **/
int xsupgui_windows_recv(unsigned char **result, int *resultsize)
{
	unsigned char *resdata = NULL;
	uint8_t *data = NULL;
	int done = FALSE;
	int size = 0;
	int i = 0;
	int offset = 0;
	ipc_header *hdr = NULL;
	uint32_t value32 = 0;
	int retval = 0;

	(*result) = NULL;
	(*resultsize) = 0;

	if (ctrl_connected != TRUE)
		return IPC_ERROR_CTRL_NOT_CONNECTED;

	resdata = malloc(MAXBUF);
	if (resdata == NULL) {
#ifdef DEBUG_WINDOWS_GUI
		printf("Couldn't allocate memory!\n");
#endif
		free(resdata);
		return IPC_ERROR_CANT_MALLOC_LOCAL;
	}

	memset(resdata, 0x00, MAXBUF);

	while (done == FALSE) {
		SetLastError(0);	// Reset the system error code.
		xsup_gui_trace
		    ("(%s) Pipe : %d   Event : %d  Connected : %d   Error : %d\n",
		     __FUNCTION__, pipehdl, ovr.hEvent, ctrl_connected,
		     GetLastError());

		if (HasOverlappedIoCompleted(&ovr) == TRUE) {
			xsup_gui_trace("Error before calling ReadFile : %d\n",
				       GetLastError());
			if (ReadFile(pipehdl, resdata, MAXBUF, &size, &ovr) !=
			    0) {
				retval = GetLastError();

				if ((retval != 0) && (retval != 997)) {
					xsup_gui_trace
					    ("Couldn't read data!  Error : %d\n",
					     retval);
					xsup_gui_trace
					    ("Pipe : %d   Event : %d   Size in : %d    Size out : %d\n",
					     eventpipe, eovr.hEvent, MAXBUF,
					     resultsize);
					free(resdata);
					return IPC_ERROR_UNABLE_TO_READ;
				}
			}
		}

		switch (WaitForSingleObject(eventhdl, 30000)) {
		case WAIT_OBJECT_0:
			if (GetOverlappedResult(pipehdl, &ovr, &size, FALSE) !=
			    0) {
				ResetEvent(eventhdl);

#ifdef TRACELOG
				xsup_gui_trace("Overlapped result code : %d\n",
					       GetLastError());
#endif
				if (size < sizeof(ipc_header)) {
#ifdef TRACELOG
					xsup_gui_trace("Size = %d\n", size);
#endif
					return IPC_ERROR_UNABLE_TO_READ;
				}

				if (resdata[0] == 0x00) {
					size = (size - sizeof(ipc_header));

					if (size <= 0) {
						free(resdata);
						return IPC_ERROR_RECV_IPC_RUNT;
					}

					if (data == NULL) {
						data = malloc(size);
						if (data == NULL) {
							free(resdata);
							return
							    IPC_ERROR_CANT_MALLOC_LOCAL;
						}

						memset(data, 0x00, size);
					}

					memcpy(&data[offset],
					       &resdata[sizeof(ipc_header)],
					       size);
					free(resdata);

					(*resultsize) = offset + size;
					(*result) = data;
					return REQUEST_SUCCESS;
				}

				if ((resdata[0] & IPC_MSG_TOTAL_SIZE) ==
				    IPC_MSG_TOTAL_SIZE) {
					// We need to allocate memory.
					if (data != NULL) {
						return
						    IPC_ERROR_NOT_INITIALIZED;
					}

					hdr = (ipc_header *) & resdata[0];
					value32 = ntohl(hdr->length);

					data = malloc(value32);
					if (data == NULL) {
						free(resdata);
						return
						    IPC_ERROR_CANT_MALLOC_LOCAL;
					}
					memset(data, 0x00, value32);
				}
				// Copy the data.
				memcpy(&data[offset],
				       &resdata[sizeof(ipc_header)],
				       (size - sizeof(ipc_header)));
				offset += (size - sizeof(ipc_header));
			}
			break;

		case WAIT_TIMEOUT:
			// If we don't cancel the pending IO, then the next request gets hosed.
			CancelIo(pipehdl);
			return REQUEST_TIMEOUT;
			break;

		default:
#ifdef DEBUG_WINDOWS_GUI
			printf("Read error!\n");
#endif
			free(resdata);
			return IPC_ERROR_READ_DEFAULT_FAILURE;
			break;
		}
	}

	return REQUEST_TIMEOUT;	// Timeout waiting for response.  (Shouldn't ever get here!)
}

/**
 *  \brief Read data from an already connected Windows pipe acting as an IPC event pipe.
 *
 *  Get an unsolicited event from the pipe.
 *
 *  @param[out] result   A buffer to the data that was read.  (This function will allocate it, the
 *                       caller is expected to free it.)
 *  @param[out] resultsize   The amount of data that the buffer contains.
 *
 *  \retval REQUEST_SUCCESS on success
 *  \retval >=300 on error.
 **/
int xsupgui_windows_recv_event(unsigned char **result, int *resultsize)
{
	char *resdata = NULL;
	int retval = 0;
	int errval = 0;

	(*result) = NULL;
	(*resultsize) = 0;

	if (evt_connected != TRUE)
		return IPC_ERROR_EVT_NOT_CONNECTED;

	resdata = malloc(MAXBUF);
	if (resdata == NULL) {
#ifdef DEBUG_WINDOWS_GUI
		printf("Couldn't allocate memory!\n");
#endif
		return IPC_ERROR_CANT_MALLOC_LOCAL;
	}

	if (HasOverlappedIoCompleted(&eovr) == TRUE) {
		if (ReadFile(eventpipe, resdata, MAXBUF, resultsize, &eovr) !=
		    0) {
			retval = GetLastError();

			if ((retval != ERROR_SUCCESS) && (retval != ERROR_IO_PENDING))	// 997 = Overlapped I/O in progress, means that we already have a read handle going.
			{
#ifdef DEBUG_WINDOWS_GUI
				printf("Read failed!!!!\n");
#endif
				xsup_gui_trace
				    ("Couldn't read data!  Error : %d\n",
				     retval);
				xsup_gui_trace
				    ("Pipe : %d   Event : %d   Size in : %d    Size out : %d\n",
				     eventpipe, eovr.hEvent, MAXBUF,
				     resultsize);
				free(resdata);
				return IPC_ERROR_UNABLE_TO_READ;
			}
		} else {
			errval = GetLastError();
			if (errval == ERROR_BROKEN_PIPE) {
				free(resdata);
				return IPC_EVENT_COM_BROKEN;
			}
		}
	}

	switch (WaitForSingleObject(eventevent, INFINITE)) {
	case WAIT_OBJECT_0:
		retval =
		    GetOverlappedResult(eventpipe, &eovr, resultsize, FALSE);
		if (retval != 0) {
			(*result) = resdata;
			return REQUEST_SUCCESS;
		}
		xsup_gui_trace("GetOverlappedResult returned %d\n", retval);
		break;

	case WAIT_TIMEOUT:
		// If we don't cancel the pending IO, then the next request gets hosed.
		CancelIo(eventpipe);
		ResetEvent(eventevent);
		free(resdata);
		retval = GetLastError();
		xsup_gui_trace("WAIT_TIMEOUT case Windows error : %d\n",
			       retval);
		return REQUEST_TIMEOUT;
		break;

	default:
#ifdef DEBUG_WINDOWS_GUI
		printf("Read error! %d\n", GetLastError());
#endif
		CancelIo(eventpipe);
		ResetEvent(eventevent);
		free(resdata);
		retval = GetLastError();
		xsup_gui_trace("Default case Windows error : %d\n", retval);
		return IPC_ERROR_UNABLE_TO_READ;
		break;
	}

	retval = GetLastError();
	xsup_gui_trace("Bailout case Windows error : %d\n", retval);
	CancelIo(eventpipe);
	ResetEvent(eventevent);
	free(resdata);
	return REQUEST_TIMEOUT;	// Timeout waiting for response.  (Shouldn't ever get here!)
}

/**
 *  \brief Send an IPC request, and wait for a response.
 *
 *  @param[in] tosend   A memory buffer containing the message to be sent to the supplicant.
 *  @param[in] sendsize   The size of the memory buffer that is being sent.  (Note : On Windows,
 *                    this can't be over 4k!!)
 *
 *  @param[out] result   The result message generated by the supplicant.  The library will allocate
 *               the necessary memory to store the result, the caller is expected to free it!
 *  @param[out] resultsize   A pointer to the size of the result generated by the supplicant.
 *
 *  \retval REQUEST_SUCCESS for success
 *  \retval REQUEST_FAILURE for error 
 *  \retval REQUEST_TIMEOUT for timeout waiting for a response.
 **/
int xsupgui_windows_send(unsigned char *tosend, int sendsize,
			 unsigned char **result, int *resultsize)
{
	DWORD totalbytes = 0;
	DWORD error = 0;

	(*result) = NULL;
	(*resultsize) = 0;

	if (ctrl_connected != TRUE)
		return IPC_ERROR_CTRL_NOT_CONNECTED;

	xsupgui_windows_flush_ctrl_pipe();

	xsup_gui_trace("Sending data!  Pipe : %d\n", pipehdl);
	if (WriteFile(pipehdl, tosend, sendsize, &totalbytes, &ovr) == 0) {
#ifdef DEBUG_WINDOWS_GUI
		error = GetLastError();
		printf("Error sending! %d\n", error);
		if (error == 109)
			exit(1);
#endif
		xsup_gui_trace("Error writing data : %d\n", GetLastError());
		return IPC_ERROR_CANT_SEND_IPC_MSG;
	}

	if (totalbytes != sendsize) {
#ifdef DEBUG_WINDOWS_GUI
		printf("Sent size mismatch!\n");
#endif
		return IPC_ERROR_SEND_SIZE_MISMATCH;
	}

	return xsupgui_windows_recv(result, resultsize);
}

/**
 * \brief Send an IPC message via the allocated event socket.
 *
 *  This function will send an IPC request for the \ref eventpipe to be converted to 
 *  something else.  (Usually taking a generic pipe, and converting it to an event
 *  pipe.)
 *
 * @param[in] buffer   The buffer to be sent to down the event socket.
 * @param[in] bufsize   The size of the buffer to be sent.
 *
 * \retval REQUEST_SUCCESS buffer was sent, and acked.
 * \retval REQUEST_FAILURE buffer couldn't be sent, or wasn't acked.
 *
 * \warning This function should *NEVER* be called outside of the
 *           libxsupgui library!  And should *ONLY* be directly called by
 *           \ref xsupgui_send_to_event().
 **/
int xsupgui_windows_send_to_event(char *buffer, int bufsize)
{
	DWORD totalbytes = 0;
	unsigned char *result = NULL;
	DWORD resultsize = 0;
	int retval = 0;
	xmlDocPtr indoc = NULL;

	if (evt_connected != TRUE)
		return IPC_ERROR_EVT_NOT_CONNECTED;

	if (WriteFile(eventpipe, buffer, bufsize, &totalbytes, &eovr) == 0) {
#ifdef DEBUG_WINDOWS_GUI
		printf("Error sending!\n");
#endif
		return IPC_ERROR_CANT_SEND_IPC_MSG;
	}

	if (totalbytes != bufsize) {
#ifdef DEBUG_WINDOWS_GUI
		printf("Sent size mismatch!\n");
#endif
		return IPC_ERROR_SEND_SIZE_MISMATCH;
	}

	retval = xsupgui_windows_recv_event(&result, &resultsize);
	if (retval != 0)
		return retval;

	indoc = xsupgui_xml_common_validate_msg(&result[5], (resultsize - 5));
	if (indoc == NULL)
		return IPC_ERROR_BAD_RESPONSE_DATA;

	free(result);

	// Otherwise, make sure we have an ACK.
	retval = xsupgui_request_is_ack(indoc);

	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Free the XML document that held our event.
 **/
void xsupgui_windows_free_event_doc()
{
	if (recvmsg != NULL) {
		xmlFreeDoc(recvmsg);
		recvmsg = NULL;
	}
}
#endif				/* WINDOWS */
