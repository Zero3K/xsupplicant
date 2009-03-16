/**
 *
 * \file xsup_ipc.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org, Terry.Simons@utah.edu
 *
 **/

#ifndef WINDOWS

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#endif				// __APPLE__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
#include <grp.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "ipc_callout.h"
#include "event_core.h"
#include "xsup_ipc.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define XSUP_SOCKET "/tmp/xsupplicant.sock"

#define INSTANCES  5		///< Maximum # of IPC sockets we will allow connected.
#define BUFSIZE 4096

typedef struct {
	int sock;
	uint8_t flags;
} ipcstruct;

ipcstruct ipcs[INSTANCES];

static int ipc_sock = -1;

#define IPC_CONNECTED    BIT(0)
#define IPC_EVENTS_ONLY  BIT(1)

char socknamestr[256];

/**
 * \brief Determine the GID for a group name.  Used to determine what file 
 *        permissions should be enabled on our IPC socket.
 *
 * @param[in] grp_name   The name of the group that we want to have ownership
 *                       of the IPC socket.
 *
 * \retval -1 on error
 * \retval >=0 on success
 **/
int xsup_ipc_get_group_num(char *grp_name)
{
	struct group grp;
	struct group *grdata = &grp;
	struct group *tmpGrp;
	char *buffer = NULL;
	long buflen = 0;
	int retval;

#ifdef __APPLE__
	// We need to find something to replace the below sysconf call with
#if MAC_OS_X_VERSION_MIN_REQUIRED <= MAC_OS_X_VERSION_10_4
#warning Mac OS X 10.3 and earlier do not define _SC_GETGR_R_SIZE_MAX.
#else
	buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
#endif
#else
	buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
#endif

	if (buflen < 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't determine the maximum buffer "
			     "size needed from getgrnam_r()\n");
		return -1;
	}

	buffer = (char *)Malloc(buflen);
	if (buffer == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory needed to "
			     "obtain IPC group information!\n");
		return -1;
	}

	if (getgrnam_r(grp_name, grdata, buffer, buflen, &tmpGrp) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Unable to obtain the group index needed"
			     " to enable IPC functionality.  IPC will not be "
			     "available.\n");
		FREE(buffer);
		return -1;
	}

	retval = grp.gr_gid;

	if (buffer != NULL) {
		FREE(buffer);
	}

	return retval;
}

/**
 * \brief Initalize the socket that we will use to communicate with a 
 *        client/clients. Also, set up any structures that may be needed.
 *
 * \retval XENONE on success
 * \retval <0 on failure
 **/
int xsup_ipc_init(uint8_t clear)
{
	int sockErr = 0, ipc_gid = 0;
	char *error = NULL;
	struct sockaddr_un sa;
	struct config_globals *globals;
	int i;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return XEGENERROR;

	sa.sun_family = AF_LOCAL;
	memset(socknamestr, 0x00, 256);
	Strncpy(socknamestr, sizeof(socknamestr), XSUP_SOCKET, 256);
	Strncpy(sa.sun_path, sizeof(socknamestr), socknamestr,
		sizeof(sa.sun_path));

	if (clear == TRUE) {
		// We need to clear the socket file if it exists.

		debug_printf(DEBUG_INT, "Clearing control socket %s.\n",
			     socknamestr);
		remove(socknamestr);
	}
	// Socket we will be using to communicate.
	ipc_sock = socket(PF_UNIX, SOCK_STREAM, 0);

	if (ipc_sock == -1) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't establish handler to daemon "
			     "socket!\n");
		return XENOSOCK;
	}

	debug_printf(DEBUG_INT,
		     "Opened socket descriptor #%d for IPC listener.\n",
		     ipc_sock);

	sockErr = bind(ipc_sock, (struct sockaddr *)&sa, sizeof(sa));
	if (sockErr == -1) {
		error = strerror(errno);
		debug_printf(DEBUG_NORMAL,
			     "An error occured binding to socket.  "
			     "(Error : %s)\n", error);
		close(ipc_sock);
		return XENOSOCK;
	}

	sockErr = listen(ipc_sock, 10);
	if (sockErr < 0) {
		error = strerror(errno);
		debug_printf(DEBUG_NORMAL,
			     "An error occured listening on the socket! "
			     "(Error : %s)\n", error);
		close(ipc_sock);
		return XENOSOCK;
	}
	// Set the rights on the file.
	if (chmod
	    (socknamestr,
	     S_IREAD | S_IWRITE | S_IEXEC | S_IRGRP | S_IWGRP | S_IXGRP |
	     S_IROTH | S_IXOTH) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Can't set rights on socket file %s! (Error"
			     " : %s)\n", socknamestr, strerror(errno));
	}
	// Set the correct group ownership. 
	if (globals->ipc_group_name != NULL) {
		ipc_gid = xsup_ipc_get_group_num(globals->ipc_group_name);

		if (ipc_gid < 0) {
			/* If we didn't get a valid response, then set the group to root. */
			ipc_gid = 0;
		}
	} else {
		ipc_gid = xsup_ipc_get_group_num("users");
		if (ipc_gid < 0)
			ipc_gid = 0;	// If it isn't found, use root.
	}

	if (ipc_gid >= 0) {
		if (chown(socknamestr, -1, ipc_gid) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "Can't set group ownership on socket "
				     "file %s! (Error : %s)\n", socknamestr,
				     strerror(errno));
		}
	}
	// And register our connection handler.
	event_core_register(ipc_sock, NULL, xsup_ipc_new_socket, LOW_PRIORITY,
			    "IPC master socket");

	for (i = 0; i < INSTANCES; i++) {
		ipcs[i].sock = 0;
		ipcs[i].flags = 0;
	}

	return XENONE;
}

/**
 * \brief Send a message to a client.
 *
 * In some cases, the messages we send will be too large for a single packet.  
 * In these cases, we will fragment the messages, and send them on their way.  
 * Because the communications channel is local, we shouldn't need any form of
 * ACKing to the packets, so we will just blast away. ;)
 *
 * Packets sent across the channel will ALWAYS begin with a 5 byte header.  The
 * first byte in the header will indicate the how the packet is fragmented (or
 * IF the packet is fragmented).
 *
 * Bit flags in the first byte will indicate what data will be in the remaining
 * four bytes, and if the other end should be looking for additional fragments.
 * If all bits are set to 0, then the following 4 bytes should be ignored.  
 * (However, if a developer wants to be anal-retentive, it could include the 
 * length of the packet as described below.)
 *
 * All bits clear - (Hex 0x00) - The packet is self contained, or the final fragment
 *                               in the series.
 * Bit 0 set      - (Hex 0x01) - The next four bytes contain the total size of
 *                               the message that needs to be communicated.  (This does
 *                               not include 5 bytes at the beginning of each message!)
 * Bit 1 set      - (Hex 0x02) - There are more fragments to come.
 * Bit 2 set      - (Hex 0x04) - The next four bytes contain the length of this packet.
 *                               This does not include the 5 bytes at the beginning of
 *                               each message.  So, a sanity check on the other end should
 *                               look for the value of the four bytes, plus 5 to see if
 *                               all of the message made it through.
 *
 * \note For obvious reasons, bits 0 and 2 should *NEVER* be set at the same time!
 *
 * @param[in] skfd   The socket to send the message on.
 * @param[in] tosend   The message to send.
 * @param[in] tolen   The length of the message to send.
 *
 **/
void xsup_ipc_send_message(int skfd, char *tosend, int tolen)
{
	uint8_t *frag = NULL;
	ipc_header *hdr = NULL;
	uint32_t offset = 0;
	uint32_t frag_size = 0;

	if ((!tosend) || (tolen <= 0)) {
		debug_printf(DEBUG_NORMAL, "(IPC) Invalid data passed into "
			     "xsup_ipc_send_message()!\n");
		return;
	}

	debug_printf(DEBUG_IPC, "(IPC) Sending %d byte(s) total.\n", tolen);

	if (tolen < BUFSIZE) {
		// We can send thiss in a single message.
		frag = Malloc(tolen + sizeof(ipc_header));
		if (frag == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory to store "
				     "an IPC fragment to be sent!\n");
			return;
		}

		hdr = (ipc_header *) & frag[0];

		hdr->flag_byte = IPC_MSG_COMPLETE;
		hdr->length = (uint32_t) htonl(tolen);

		debug_printf(DEBUG_IPC,
			     "Sending complete packet of %d byte(s).\n",
			     (tolen + sizeof(ipc_header)));
		memcpy(&frag[sizeof(ipc_header)], tosend, tolen);

		debug_hex_dump(DEBUG_IPC, (uint8_t *) frag,
			       (tolen + sizeof(ipc_header)));

		if (send(skfd, frag, (tolen + sizeof(ipc_header)), 0) < 0) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't send response document to the "
				     "IPC client!\n");
			FREE(frag);
			return;
		}

		FREE(frag);
	} else {
		// We need to send multiple fragments.
		frag = Malloc(BUFSIZE);
		if (frag == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate the buffer needed to "
				     "send IPC fragments!\n");
			return;
		}

		while (offset < tolen) {
			hdr = (ipc_header *) & frag[0];

			if (offset == 0)	// This is the first packet in a fragment chain.
			{
				// This is our first fragment, so include the length.
				hdr->flag_byte =
				    (IPC_MSG_TOTAL_SIZE | IPC_MSG_MORE_FRAGS);
				frag_size = (BUFSIZE - sizeof(ipc_header));
				hdr->length = htonl(tolen);
			} else if ((tolen - offset) >
				   (BUFSIZE - sizeof(ipc_header))) {
				// We have more fragments.
				hdr->flag_byte =
				    (IPC_MSG_MORE_FRAGS | IPC_MSG_FRAG_SIZE);
				frag_size = (BUFSIZE - sizeof(ipc_header));
				hdr->length = htonl(frag_size);
			} else {
				// This is the last fragment.
				hdr->flag_byte = IPC_MSG_COMPLETE;
				hdr->length = 0;
				frag_size = (tolen - offset);
			}

			debug_printf(DEBUG_IPC,
				     "Sending fragment of %d byte(s).\n",
				     (frag_size + sizeof(ipc_header)));

			memcpy(&frag[sizeof(ipc_header)], &tosend[offset],
			       frag_size);

			debug_hex_dump(DEBUG_IPC, frag,
				       (frag_size + sizeof(ipc_header)));

			if (send
			    (skfd, frag, (frag_size + sizeof(ipc_header)),
			     0) <= 0) {
				debug_printf(DEBUG_NORMAL,
					     "Couldn't send response document "
					     "to the IPC client!\n");
				FREE(frag);
				return;
			}

			offset += frag_size;
		}
		FREE(frag);
	}
}

/**
 * \brief Send a message to all registered clients.
 *
 * @param[in] message   The message you want to send to all connected clients.
 * @param[in] msglen   The length of the message you want to send.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int xsup_ipc_send_all(char *message, int msglen)
{
	int i = 0;

	if (!xsup_assert((msglen > 0), "msglen > 0", FALSE))
		return -1;
	if (!xsup_assert((message != NULL), "message != NULL", FALSE))
		return -1;

	for (i = 0; i < INSTANCES; i++) {
		if ((TEST_FLAG(ipcs[i].flags, IPC_CONNECTED)) &&
		    (TEST_FLAG(ipcs[i].flags, IPC_EVENTS_ONLY))) {
			xsup_ipc_send_message(ipcs[i].sock, message, msglen);
		}
	}

	return 0;
}

/***********************************************************
 *
 * Push an EAP notification to any connected clients.
 *
 ***********************************************************/
void xsup_ipc_send_eap_notify(char *notify)
{
}

/**************************************************************************
 *
 *  This callback is used when a GUI client asks us for some information.
 *  The functionality should be simple.  Gather the information, and answer
 *  as quickly as possible, so we can get on to other interesting things. ;)
 *
 **************************************************************************/
int xsup_ipc_event(context * ctx, int sock)
{
	int i = 0;
	uint8_t *buf = NULL;
	uint8_t *resbuf = NULL;
	int resbufsize = 0;
	ssize_t result = 0;
	int retval = 0;

	debug_printf(DEBUG_INT, "(IPC) Processing an event for socket %d!\n",
		     sock);

	for (i = 0; i < INSTANCES; i++) {
		if (ipcs[i].sock == sock)
			break;
	}

	if (i >= INSTANCES) {
		debug_printf(DEBUG_NORMAL,
			     "Event was triggered on a handle we know "
			     "nothing about!?  (This shouldn't happen!)\n");
		exit(1);
	}

	buf = Malloc(BUFSIZE);
	if (buf == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Insufficient memory to create temporary IPC "
			     "buffer!\n");
		return -1;
	}

	result = recvfrom(ipcs[i].sock, buf, BUFSIZE, 0, 0, 0);
	if ((result <= 0) || (errno == EPIPE)) {
		debug_printf(DEBUG_INT, "Connection broken.\n");
		close(ipcs[i].sock);
		event_core_deregister(ipcs[i].sock);
		ipcs[i].sock = 0;
		ipcs[i].flags = 0;
		FREE(buf);
		return -1;
	}

	retval = ipc_callout_process(buf, result, &resbuf, &resbufsize);

	switch (retval) {
	case IPC_CHANGE_TO_EVENT_ONLY:
		// Change this handle to only send out events.
		SET_FLAG(ipcs[i].flags, IPC_EVENTS_ONLY);
		debug_printf(DEBUG_INT,
			     "Changed IPC pipe %d to be events only!\n",
			     ipcs[i].sock);
		break;

	case IPC_CHANGE_TO_SYNC_ONLY:
		// Need to change this handle to only do request/response.
		UNSET_FLAG(ipcs[i].flags, IPC_EVENTS_ONLY);
		debug_printf(DEBUG_INT,
			     "Changed IPC pipe %d to be request/response "
			     "only.\n", ipcs[i].sock);
		break;

	default:
		// Do nothing.
		break;
	}

	// Make sure we have something to send.
	if ((resbuf != NULL) && (resbufsize > 0)) {
		xsup_ipc_send_message(ipcs[i].sock, (char *)resbuf, resbufsize);
	}

	FREE(resbuf);
	FREE(buf);

	return XENONE;
}

/**********************************************************************
 *
 *  This handler is called when the parent IPC socket gets a connection
 *  event.  All it should do is accept the connection, and register a new
 *  handler to handle communication with the client.
 *
 **********************************************************************/
int xsup_ipc_new_socket(context * ctx, int sock)
{
	int newsock, len, i;
	struct sockaddr sa;

	// We got a request for a new IPC client connection.
	debug_printf(DEBUG_INT, "(IPC) Got a request to connect a new "
		     "client.\n");

	// See if we have an open slot.
	i = 0;
	while (i < INSTANCES) {
		if (ipcs[i].sock == 0)
			break;
		i++;
	}

	if (i >= INSTANCES) {
		debug_printf(DEBUG_NORMAL, "No available IPC sockets!\n");
		return -1;
	}

	memset(&sa, 0x00, sizeof(sa));
	len = sizeof(sa);
	newsock =
	    accept(ipc_sock, (struct sockaddr *)&sa, (unsigned int *)&len);
	if (newsock <= 0) {
		debug_printf(DEBUG_NORMAL, "Got a request for a new IPC "
			     "client connection.  But, accept() returned"
			     " an error!\n");
		debug_printf(DEBUG_NORMAL, "Error was (%d) : %s\n", errno,
			     strerror(errno));
	} else {
		debug_printf(DEBUG_INT, "Registering a new socket handler.\n");

		// Record the socket number we want to listen to.
		ipcs[i].sock = newsock;
		ipcs[i].flags = IPC_CONNECTED;

		if (event_core_register(newsock, NULL, xsup_ipc_event,
					LOW_PRIORITY, "client msg socket") < 0)
		{
			debug_printf(DEBUG_NORMAL,
				     "No available socket handlers!\n");
			close(newsock);
		}

		debug_printf(DEBUG_NORMAL,
			     "Xsupplicant %s has connected a new client." "\n",
			     VERSION);
	}

	return XENONE;
}

/**
 * \brief Clean up any structures used, and close out any communication sockets
 *        that may be open.
 **/
void xsup_ipc_cleanup()
{
	char *error;

	debug_printf(DEBUG_DEINIT | DEBUG_IPC, "Shutting down IPC socket!\n");
	debug_printf(DEBUG_INT, "Closing socket descriptor #%d\n", ipc_sock);

	if (ipc_sock < 0)
		return;		// Nothing to do.

	if (close(ipc_sock) < 0) {
		error = strerror(errno);
		debug_printf(DEBUG_NORMAL,
			     "Error closing socket!  (Error : %s)\n", error);
	}

	unlink(socknamestr);
}
