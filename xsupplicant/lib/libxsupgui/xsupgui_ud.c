/**
 *
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_ud.c
 *
 * \author chris@open1x.org, Terry.Simons@utah.edu
 *
 **/
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <libxml/parser.h>

#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsupgui_request.h"
#include "xsupgui_events.h"
#include "xsupgui_xml_common.h"
#include "xsupgui.h"
#include "xsupgui_ud.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define XSUP_SOCKET "/tmp/xsupplicant.sock"
#define DEBUG  0

#define MAXBUF  4096

int ipc_sock = -1;
int ipc_event_sock = -1;

xmlDocPtr xmlrecvmsg = NULL;	///< XML Document that represents an async event that we received.

/**
 * \brief Establish a request/response handler to talk to the supplicant.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int xsupgui_ud_connect()
{
	int sockErr;
	struct sockaddr_un sa;

	ipc_sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ipc_sock < 0) {
#if DEBUG
		printf("Error getting socket!\n");
#endif
		return -1;
	}

	Strncpy(sa.sun_path, sizeof(sa.sun_path), XSUP_SOCKET,
		sizeof(sa.sun_path));

	sa.sun_family = AF_LOCAL;

	sockErr = connect(ipc_sock, (struct sockaddr *)&sa, sizeof(sa));
	if (sockErr < 0) {
#if DEBUG
		printf("Socket Error : %d -- %s  (%s:%d)\n", errno,
		       strerror(errno), __FUNCTION__, __LINE__);
#endif
		return errno;
	}

	return 0;
}

/**
 * \brief Establish a connection to the supplicant daemon, and create an
 *        event socket.
 *
 * \retval 0 on success
 * \retval -1 on error
 *
 * \warning A return value of -1 indicates that the supplicant probably
 *          isn't running.  The UI should notify the user of this!
 **/
int xsupgui_ud_connect_event_listener()
{
	int sockErr = 0;
	struct sockaddr_un sa;
	char *result = NULL;
	int ressize = 0;

	ipc_event_sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (ipc_event_sock < 0) {
#if DEBUG
		printf("Error getting socket!\n");
#endif
		return -1;
	}

	Strncpy(sa.sun_path, sizeof(sa.sun_path), XSUP_SOCKET,
		sizeof(sa.sun_path));

	sa.sun_family = AF_LOCAL;

	sockErr = connect(ipc_event_sock, (struct sockaddr *)&sa, sizeof(sa));
	if (sockErr < 0) {
#if DEBUG
		printf("Socket Error : %d -- %s  (%s:%d)\n", errno,
		       strerror(errno), __FUNCTION__, __LINE__);
#endif
		return errno;
	}

	if (xsupgui_request_set_as_event(&result, &ressize) == REQUEST_FAILURE)
		return -1;

	if (xsupgui_ud_send_to_event((unsigned char *)result, ressize) ==
	    REQUEST_FAILURE) {
		free(result);
		result = NULL;
		return -1;
	}

	free(result);
	return 0;
}

/**
 * \brief Disconnect from the daemon.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int xsupgui_ud_disconnect()
{
	if (ipc_sock != -1)
		close(ipc_sock);
	return 0;
}

/**
 * \brief Disconnect an event listener socket from the daemon.
 *
 * \retval -1 on failure
 * \retval 0 on success
 **/
int xsupgui_ud_disconnect_event_listener()
{
	if (ipc_event_sock != -1)
		close(ipc_event_sock);

	return 0;
}

/**
 * \brief  Return the xmlDocPtr that contains the event document.
 *
 * \retval xmlDocPtr containing the event message.  (May be NULL.)
 **/
xmlDocPtr xsupgui_ud_get_event_doc()
{
	return xmlrecvmsg;
}

/**
 * \brief Free the XML event document that is currently stored in memory.
 *
 **/
void xsupgui_ud_free_event_doc()
{
	if (xmlrecvmsg == NULL)
		return;		// Nothing to do.
	xmlFreeDoc(xmlrecvmsg);
	xmlrecvmsg = NULL;
}

/**
 * \brief Read data from an already connected Unix domain socket.
 *
 * @param[out] result   A buffer to the data that was read.  (This function
 *                      will allocate the memory, the caller is expected to
 *                      free it.)
 * @param[out] resultsize   The amount of data that the buffer contains.
 *
 * \retval 0 on success
 * \retval -1 on error
 * \retval -2 on connection broken.
 **/
int xsupgui_ud_recv_event(unsigned char **result, int *resultsize)
{
	unsigned char *resdata = NULL;
	ssize_t cread = 0;
	int retval = 0;

	(*result) = NULL;
	(*resultsize) = 0;

	resdata = malloc(MAXBUF);
	if (resdata == NULL) {
		return IPC_ERROR_CANT_MALLOC_LOCAL;
	}

	cread = recv(ipc_event_sock, resdata, MAXBUF, 0);

	if (cread < 0)
		return IPC_ERROR_UNABLE_TO_READ;	// Got an error.

	if (cread == 0) 
		return REQUEST_TIMEOUT;

	(*resultsize) = cread;
	(*result) = resdata;

	return retval;
}

/**
 * \brief Read data from an already connected Unix domain socket.
 *
 * @param[out] result   A buffer to the data that was read.  (This function
 *                      will allocate memory, the caller is expected to free
 *                      it.)
 * @param[out] resultsize   The amount of data that the buffer contains.
 *
 * \retval 0 on success
 * \retval -1 on error
 * \retval 1 on timeout
 **/
int xsupgui_ud_recv(unsigned char **result, int *resultsize)
{
	unsigned char *resdata = NULL;
	uint8_t *data = NULL;
	ssize_t cread = 0;
	fd_set rfds;
	struct timeval tv;
	int done = FALSE;
	int size = 0;
	int offset = 0;
	ipc_header *hdr = NULL;
	uint32_t value32 = 0;

	(*result) = NULL;
	(*resultsize) = 0;

	if (ipc_sock < 0)
		return IPC_ERROR_CTRL_NOT_CONNECTED;

	resdata = malloc(MAXBUF);
	if (resdata == NULL) {
		return IPC_ERROR_CANT_MALLOC_LOCAL;
	}

	memset(resdata, 0x00, MAXBUF);

	while (done == FALSE) {
		FD_ZERO(&rfds);
		FD_SET(ipc_sock, &rfds);

		tv.tv_sec = 2;
		tv.tv_usec = 0;

		switch (select(ipc_sock + 1, &rfds, 0, 0, &tv)) {
		case 0:
			return 1;	// Timeout
			break;

		case -1:
			return -1;	// Got an error.
			break;

		default:
			// Fall through.
			break;
		}

		cread = recv(ipc_sock, resdata, MAXBUF, 0);

		if (cread == 0) {
			free(resdata);
			return IPC_ERROR_RECV_IPC_RUNT;
		}

		if (cread < 0)	// Got an error.
		{
			free(resdata);
			return IPC_ERROR_UNABLE_TO_READ;
		}

		if (cread < sizeof(ipc_header)) {
			return IPC_ERROR_RECV_IPC_RUNT;
		}

		size = cread;

		if (resdata[0] == 0x00) {
			size = (cread - sizeof(ipc_header));

			if (data == NULL) {
				data = malloc(size);
				if (data == NULL) {
					free(resdata);
					return -1;
				}

				memset(data, 0x00, size);
			}

			memcpy(&data[offset], &resdata[sizeof(ipc_header)],
			       size);

			free(resdata);

			(*resultsize) = offset + size;
			(*result) = data;
			return REQUEST_SUCCESS;
		}

		if ((resdata[0] & IPC_MSG_TOTAL_SIZE) == IPC_MSG_TOTAL_SIZE) {
			// We need to allocate memory.
			if (data != NULL) {
				return IPC_ERROR_NOT_INITIALIZED;
			}

			hdr = (ipc_header *) & resdata[0];
			value32 = ntohl(hdr->length);

			data = malloc(value32);
			if (data == NULL) {
				free(resdata);
				return IPC_ERROR_CANT_MALLOC_LOCAL;
			}
			memset(data, 0x00, value32);
		}
		// Copy the data.
		memcpy(&data[offset], &resdata[sizeof(ipc_header)],
		       (size - sizeof(ipc_header)));
		offset += (size - sizeof(ipc_header));
	}

	(*resultsize) = offset;
	(*result) = data;

	return REQUEST_SUCCESS;
}

/**
 * \brief Process events from the supplicant.
 *
 * Catch unsolicited events that are generated by the supplicant.
 *
 * \warning This is a *BLOCKING* call, so it should be run from a different
 *          thread, and signals should be passed back to the core of the UI.
 *          The other alternative is to call xsupgui_selectable_socket() and
 *          use select() to wait for an event.  However, select() doesn't
 *          work with Windows, so if the UI is to be cross platform, it would
 *          be the wrong way to handle it.
 *
 * \retval >1 there is a new event to process.
 * \retval 0 if there is still an event to process
 * \retval -1 on error
 **/
long int xsupgui_ud_process(int *evttype)
{
	int retval = 1;
	unsigned char *eventbuf = NULL;
	int eventbufressize = 0;

	// If eventbuf points to something, we have a problem.
	if (xmlrecvmsg != NULL)
		return 0;

	retval = xsupgui_ud_recv_event(&eventbuf, &eventbufressize);

	if (retval != REQUEST_SUCCESS) {
		return retval;
	}

	if ((eventbuf == NULL) || ((eventbufressize - 5) < 0)) {
		xmlrecvmsg = NULL;
		if (eventbuf != NULL)
			free(eventbuf);
		return IPC_ERROR_BAD_RESPONSE_DATA;
	}

	xmlrecvmsg =
	    xmlReadMemory((char *)&eventbuf[5], (eventbufressize - 5),
			  "ipc.xml", NULL, 0);
	if (xmlrecvmsg == NULL) {
		free(eventbuf);
		return IPC_ERROR_BAD_RESPONSE_DATA;
	}

	if (eventbuf != NULL)
		free(eventbuf);
	eventbuf = NULL;

	(*evttype) = xsupgui_events_get_event_num(xmlrecvmsg);

	return REQUEST_SUCCESS;
}

/**
 * \brief Return the socket that we created to listen for events.
 *
 * \retval -1 on error
 * \retval >=0 the socket number that can be used with select.
 **/
int xsupgui_ud_selectable_socket()
{
	return ipc_event_sock;
}

/**
 * \brief Send an IPC message via the allocated event socket.
 *
 * This function will send an IPC request to ask that the supplicant treat
 * this socket in a specific way.  (Usually converting it from a 
 * request/response socket to an event socket.)
 *
 * @param[in] buffer   The buffer to be sent down to the event socket.
 * @param[in] bufsize   The size of the buffer to be sent.
 *
 * \retval REQUEST_SUCCESS buffer was sent, and acked
 * \retval REQUEST_FAILURE buffer couldn't be sent, or wasn't acked.
 *
 * \warning This function should *NEVER* be called outside of the libxsupgui
 *          library!  And should *ONLY* be directly called by
 *          \ref xsupgui_send_to_event().
 **/
int xsupgui_ud_send_to_event(unsigned char *buffer, int bufsize)
{
	int totalbytes = 0;
	unsigned char *result = NULL;
	int resultsize = 0;
	int retval = 0;
	xmlDocPtr indoc = NULL;

	totalbytes = send(ipc_event_sock, buffer, bufsize, 0);
	if (totalbytes < 0)
		return REQUEST_FAILURE;

	if (totalbytes != bufsize)
		return REQUEST_FAILURE;

	retval = xsupgui_ud_recv_event(&result, &resultsize);
	if (retval != 0)
		return REQUEST_FAILURE;

	indoc = xsupgui_xml_common_validate_msg(&result[5], (resultsize - 5));
	if (indoc == NULL)
		return REQUEST_FAILURE;

	return xsupgui_request_is_ack(indoc);
}

/**
 * \brief Send an IPC request, and wait for a response.
 *
 * @param[in] tosend   A memory buffer containing the message to be sent to the
 *                     supplicant.
 *
 * @param[in] sendsize   The size of the memory buffer that is being sent.
 *                       (Note : This can't be over 4k!)
 *
 * @param[out] result   The result message generated by the supplicant.  The
 *                      library will allocate the necessary memory to store
 *                      the result, the caller is expected to free it!
 *
 * @param[out] resultsize   A pointer to the size of the result generated by
 *                          the supplicant.
 *
 * \retval REQUEST_SUCCESS for success
 * \retval REQUEST_FAILURE for error
 * \retval REQUEST_TIMEOUT for timeout waiting for a response.
 **/
int xsupgui_ud_send(unsigned char *tosend, int sendsize, unsigned char **result,
		    int *resultsize)
{
	int totalbytes = 0;

	(*result) = NULL;
	(*resultsize) = 0;

	totalbytes = send(ipc_sock, tosend, sendsize, 0);
	if (totalbytes < 0)
		return REQUEST_FAILURE;

	if (totalbytes != sendsize)
		return REQUEST_FAILURE;

	return xsupgui_ud_recv(result, resultsize);
}
