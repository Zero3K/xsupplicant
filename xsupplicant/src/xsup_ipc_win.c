/**
 *
 * \file xsup_ipc_win.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org, Terry.Simons@utah.edu
 **/

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <sddl.h>

#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "context.h"
#include "xsup_ipc.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "ipc_callout.h"
#include "event_core_win.h"
#include "platform/windows/cardif_windows.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define INSTANCES  10   // Maximum # of UIs we will allow to be connected
					    // at once.

#define BUFSIZE 4096
#define PIPE_TIMEOUT 5000

#define IPC_CONNECTED     BIT(0)
#define IPC_EVENTS_ONLY	  BIT(1)

// For Windows, we need to keep track of a fair bit of information 
// about each UI connection.
typedef struct
{
	HANDLE hevent;
	HANDLE hdl;
	uint8_t flags;
	uint8_t buffer[BUFSIZE];
	DWORD inbuf;
} pipestruct;

pipestruct pipes[INSTANCES];

LPTSTR pipename = TEXT("\\\\.\\pipe\\open1x_ctrl");

// XXX Clean this up ;)
extern void (*imc_ui_connect_callback)();

// Forward decls.
int xsup_ipc_win_event(context *ctx, HANDLE hevent);
void xsup_ipc_send_message(HANDLE pipehdl, char *tosend, int tolen);

int xsup_ipc_win_create_pipe(int i)
{
	DWORD err = 0;
	char handle_str[128];
	LPOVERLAPPED ovr = NULL;
	LPVOID lpMsgBuf = NULL;
	SECURITY_ATTRIBUTES *pSA = NULL;
     TCHAR * szSD = TEXT("D:")       // Discretionary ACL
        TEXT("(D;OICI;GA;;;BG)")     // Deny access to 
                                     // built-in guests
        TEXT("(D;OICI;GA;;;AN)")     // Deny access to 
                                     // anonymous logon
        TEXT("(A;OICI;GRGWGX;;;AU)") // Allow 
                                     // read/write/execute 
                                     // to authenticated 
                                     // users
        TEXT("(A;OICI;GA;;;BA)");    // Allow full control 
                                     // to administrators

		pipes[i].hevent = CreateEvent(NULL, TRUE, FALSE, NULL);

		if (pipes[i].hevent == NULL)
		{
			err = GetLastError();
			lpMsgBuf = GetLastErrorStr(err);
			debug_printf(DEBUG_NORMAL, "Couldn't create event handler for IPC! (Error %d : %s)\n",
				err, lpMsgBuf);
			LocalFree(lpMsgBuf);
			return -1;
		}

		pSA = malloc(sizeof(SECURITY_ATTRIBUTES));
		if (pSA != NULL)
		{
			if (ConvertStringSecurityDescriptorToSecurityDescriptor(
		            szSD,
			      SDDL_REVISION_1,
			     &(pSA->lpSecurityDescriptor),
			     NULL) == 0)
			{
				debug_printf(DEBUG_NORMAL, "Unable to set rights on the named pipe!  Only administrative users will be able to control the supplicant.\n");
				FREE(pSA);
			}
		}

		pipes[i].flags = 0;
		pipes[i].inbuf = 0;
		memset(&pipes[i].buffer, 0x00, sizeof(pipes[i].buffer));

		pipes[i].hdl = CreateNamedPipe(pipename, 
					PIPE_ACCESS_DUPLEX |
					FILE_FLAG_OVERLAPPED,
					PIPE_TYPE_MESSAGE |
					PIPE_READMODE_MESSAGE,
					INSTANCES,
					BUFSIZE*sizeof(TCHAR),
					BUFSIZE*sizeof(TCHAR),
					PIPE_TIMEOUT,
					pSA);

		LocalFree(pSA->lpSecurityDescriptor);
		FREE(pSA);

		if (pipes[i].hdl == INVALID_HANDLE_VALUE)
		{
			err = GetLastError();
			lpMsgBuf = GetLastErrorStr(err);
			debug_printf(DEBUG_NORMAL, "Couldn't create named pipes for IPC control!  (Error %d : %s)\n",
				err, lpMsgBuf);
			LocalFree(lpMsgBuf);
			return -1;
		}

		memset(&handle_str, 0x00, sizeof(handle_str));
		sprintf((char *)&handle_str, "pipe handle #%d", i);

		event_core_register(pipes[i].hdl, NULL, xsup_ipc_win_event, 0, HIGH_PRIORITY, handle_str);
		event_core_bind_hevent(pipes[i].hdl, pipes[i].hevent, 0);
		ovr = event_core_get_ovr(pipes[i].hdl, 0);
		if (ovr == NULL)
		{
			debug_printf(DEBUG_NORMAL, "OVERLAPPED structure is NULL!\n");
			return -1;
		}

		if (ConnectNamedPipe(pipes[i].hdl, ovr) != 0)
		{
			err = GetLastError();
			lpMsgBuf = GetLastErrorStr(err);
			debug_printf(DEBUG_NORMAL, "Couldn't establish listener for named pipe! (Error %d : %s)\n",
				err, lpMsgBuf);
			LocalFree(lpMsgBuf);
			return -1;
		}

	return XENONE;
}

int xsup_ipc_win_event(context *ctx, HANDLE hdl)
{
	int i;
	LPOVERLAPPED lovr;
	uint8_t *result;
	uint8_t retval;
	int ressize;
	int eventPipeConnectOccurred = FALSE;
	DWORD bxfer, resulterr;

	for (i=0; i<INSTANCES; i++)
	{
		if (pipes[i].hdl == hdl) break;
	}

	if (i == INSTANCES)
	{
		debug_printf(DEBUG_NORMAL, "Event was triggered on an handle we know nothing about?  (hdl = %d)\n", hdl);
		ResetEvent(hdl);  // To keep it from calling us over and over. ;)
		return -1;
	}

	if (!TEST_FLAG(pipes[i].flags, IPC_CONNECTED))
	{
		ResetEvent(pipes[i].hevent);

		debug_printf(DEBUG_IPC, "Connected pipe %d.\n", pipes[i].hdl);

		event_core_user_logged_on();                // This will trigger the user logged on actions in the event that we didn't get a user logon even from Windows.

		SET_FLAG(pipes[i].flags, IPC_CONNECTED);
		lovr = event_core_get_ovr(pipes[i].hdl, 0);
		if (lovr == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't locate bound OVERLAPPED structure!\n");
			return -1;
		}

		if (HasOverlappedIoCompleted(lovr) == TRUE)
		{
			// And set up a read handler.
			if (ReadFile(pipes[i].hdl, &pipes[i].buffer, BUFSIZE, (LPDWORD)&pipes[i].inbuf, lovr) == 0)
			{
				resulterr = GetLastError();

				if (resulterr == ERROR_BROKEN_PIPE)
				{
					debug_printf(DEBUG_IPC, "Disconnected PIPE on handle %d.\n", pipes[i].hdl);
					pipes[i].flags = 0;
					event_core_deregister(pipes[i].hdl, 0);
					CloseHandle(pipes[i].hevent);
					CloseHandle(pipes[i].hdl);
					pipes[i].hevent = INVALID_HANDLE_VALUE;
					pipes[i].hdl = INVALID_HANDLE_VALUE;

					return xsup_ipc_win_create_pipe(i);
				}

				if (resulterr != ERROR_IO_PENDING)
				{
					debug_printf(DEBUG_NORMAL, "Error setting PIPE read handler!\n");
					debug_printf(DEBUG_NORMAL, "Error was : %d\n", resulterr);
				}
			}	 
			else
			{
				resulterr = GetLastError();

				if (resulterr == ERROR_BROKEN_PIPE)
				{
					debug_printf(DEBUG_IPC, "Disconnected PIPE on handle %d.\n", pipes[i].hdl);
					pipes[i].flags = 0;
					event_core_deregister(pipes[i].hdl, 0);
					CloseHandle(pipes[i].hevent);
					CloseHandle(pipes[i].hdl);
					pipes[i].hevent = INVALID_HANDLE_VALUE;
					pipes[i].hdl = INVALID_HANDLE_VALUE;

					return xsup_ipc_win_create_pipe(i);
				}
			}
		}

		return XENONE;
	}
	else
	{
		lovr = event_core_get_ovr(pipes[i].hdl, 0);
		if (lovr == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't locate bound OVERLAPPED structure!\n");
			return -1;
		}

		ResetEvent(pipes[i].hevent);

		if (GetOverlappedResult(pipes[i].hdl, lovr, &bxfer, FALSE) == 0)
		{
			// Got an error.
			resulterr = GetLastError();

			if (resulterr == ERROR_BROKEN_PIPE)
			{
				debug_printf(DEBUG_IPC, "Disconnected PIPE on handle %d.\n", pipes[i].hdl);
				pipes[i].flags = 0;
				event_core_deregister(pipes[i].hdl, 0);
				CloseHandle(pipes[i].hevent);
				CloseHandle(pipes[i].hdl);
				pipes[i].hevent = INVALID_HANDLE_VALUE;
				pipes[i].hdl = INVALID_HANDLE_VALUE;

				return xsup_ipc_win_create_pipe(i);
			}

			printf("Error : %d\n", resulterr);
		}
		else
		{
			pipes[i].inbuf = bxfer;

			debug_printf(DEBUG_IPC, "Got data on pipe %d.  (hevent = %d   hdl = %d)\n", i,
				pipes[i].hevent, pipes[i].hdl);

#ifdef UNSAFE_DUMPS
			debug_hex_dump(DEBUG_IPC, pipes[i].buffer, pipes[i].inbuf);
#endif

			// Process it.
			retval = ipc_callout_process(pipes[i].buffer, pipes[i].inbuf, &result, &ressize);
			switch (retval)
			{
			case IPC_CHANGE_TO_EVENT_ONLY:
				// Need to change this handle to only send out events.
				SET_FLAG(pipes[i].flags, IPC_EVENTS_ONLY);
				debug_printf(DEBUG_IPC, "Changed IPC pipe %d to be events only.\n", pipes[i].hdl);
				eventPipeConnectOccurred = TRUE;
				break;

			case IPC_CHANGE_TO_SYNC_ONLY:
				// Need to change this handle to only do request/response.
				UNSET_FLAG(pipes[i].flags, IPC_EVENTS_ONLY);
				debug_printf(DEBUG_IPC, "Changed IPC pipe %d to be request/response only.\n", pipes[i].hdl);
				break;

			default:
				// Do nothing.
				break;
			}

			// Make sure we have something to send.
			if ((result != NULL) && (ressize > 0))
			{
				xsup_ipc_send_message(pipes[i].hdl, result, ressize);

				FREE(result);
			}

			FREE(result);

			pipes[i].inbuf = 0;
			memset(&pipes[i].buffer, 0x00, sizeof(pipes[i].buffer));

			lovr = event_core_get_ovr(pipes[i].hdl, 0);
			if (lovr == NULL)
			{
				debug_printf(DEBUG_NORMAL, "Invalid OVERLAPPED structure!\n");
				return -1;
			}

			// And set up a read handler.
			if (HasOverlappedIoCompleted(lovr) == TRUE)
			{
				if (ReadFile(pipes[i].hdl, &pipes[i].buffer, BUFSIZE, (LPDWORD)&pipes[i].inbuf, lovr) == 0)
				{
					resulterr = GetLastError();

					if (resulterr == ERROR_BROKEN_PIPE)
					{
						debug_printf(DEBUG_IPC, "Disconnected PIPE on handle %d.\n", pipes[i].hdl);
						pipes[i].flags = 0;
						event_core_deregister(pipes[i].hdl, 0);
						CloseHandle(pipes[i].hevent);
						CloseHandle(pipes[i].hdl);
						pipes[i].hevent = INVALID_HANDLE_VALUE;
						pipes[i].hdl = INVALID_HANDLE_VALUE;

						return xsup_ipc_win_create_pipe(i);
					}

					if (resulterr != ERROR_IO_PENDING)
					{
						debug_printf(DEBUG_NORMAL, "Error setting PIPE read handler!\n");
						debug_printf(DEBUG_NORMAL, "Error : %d\n", resulterr);
					}
				}
			}
		}
	}

	if(eventPipeConnectOccurred == TRUE) 
	{
#ifdef HAVE_TNC
				// Notify IMC that the UI has connected.
				if(imc_ui_connect_callback != NULL)
				{
					(*imc_ui_connect_callback)();
				}
#endif // HAVE_TNC
	}
	return XENONE;
}

/**
 * \brief Initalize the socket that we will use to communicate with a 
 *        client/clients. Also, set up any structures that may be needed.
 *
 * @param[in] clear   Should we clear out the older sockets that might be
 *                    hanging around.  (This is not used on Windows!)
 * 
 * \retval XENONE on success
 * \retval -1 on error
 **/
int xsup_ipc_init(uint8_t clear)
{
	int i, valid = FALSE;
	

	// Loop through the number of instances we have, and create an
	// event handle, and a socket handle for each one.
	for (i=0; i<INSTANCES; i++)
	{
		if (xsup_ipc_win_create_pipe(i) == XENONE)
		{
			valid = TRUE;
		}
	}

	// If we don't have any valid pipe handles, return an error.
	if (valid != TRUE) return -1;

	ipc_events_init();

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
 * @param[in] pipehdl   The handle to the pipe that we want to send the message
 *                      on.
 * @param[in] tosend   The message we want to send.
 * @param[in] tolen   The length of the message to be sent.
 **/
void xsup_ipc_send_message(HANDLE pipehdl, char *tosend, int tolen)
{
  DWORD totalbytes = 0;
  int offset = 0;
  uint8_t *frag = NULL;
  ipc_header *hdr = NULL;
  uint32_t frag_size = 0;
  uint32_t value32 = 0;

  if ((!tosend) || (tolen <= 0))
    {
      debug_printf(DEBUG_NORMAL, "(IPC) Invalid data passed into "
		      "xsup_ipc_send_message()!\n");
      return;
    }

  debug_printf(DEBUG_IPC, "(IPC) Sending %d bytes total.\n", tolen);

  if ((tolen + sizeof(ipc_header)) < BUFSIZE)
  {
	  // We can send this in a single message.
	  frag = Malloc(tolen + sizeof(ipc_header));
	  if (frag == NULL)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store an IPC fragment "
				"to be sent!\n");
		  return;
	  }

	  hdr = (ipc_header *)&frag[0];

	  hdr->flag_byte = IPC_MSG_COMPLETE;
	  hdr->length = (uint32_t)htonl(tolen);

	  memcpy(&frag[sizeof(ipc_header)], tosend, tolen);

#ifdef UNSAFE_DUMPS   // This could leave passwords in the log file, so only have it in debug builds!
	  debug_printf(DEBUG_IPC, "Sending complete packet of %d byte(s).\n", (tolen + sizeof(ipc_header)));
	  debug_hex_dump(DEBUG_IPC, (uint8_t *) frag, (tolen + sizeof(ipc_header)));
#endif

	  if (WriteFile(pipehdl, frag, (tolen + sizeof(ipc_header)), &totalbytes, NULL) == 0)
		{
			debug_printf(DEBUG_NORMAL | DEBUG_IPC, "Couldn't send response document to IPC client!\n");
			FREE(frag);
			return;
		}

	  FREE(frag);
  }
  else
  {
	  // We need to send multiple fragments.
	  frag = Malloc(BUFSIZE);
	  if (frag == NULL)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate the buffer needed to send IPC fragments!\n");
		  return;
	  }

	  while (offset < tolen)
	  {
		  hdr = (ipc_header *)&frag[0];

		  if (offset == 0)         // This is the first packet in a fragment chain.
		  {
			  // This is our first fragment, so include the length.
			  hdr->flag_byte = (IPC_MSG_TOTAL_SIZE | IPC_MSG_MORE_FRAGS);
			  frag_size = (BUFSIZE - sizeof(ipc_header));
			  hdr->length = htonl(tolen);
		  }
		  else if ((tolen - offset) > (BUFSIZE - sizeof(ipc_header)))
		  {
			  // We have more fragments.
			  hdr->flag_byte = (IPC_MSG_MORE_FRAGS | IPC_MSG_FRAG_SIZE);
			  frag_size = (BUFSIZE - sizeof(ipc_header));
			  hdr->length = htonl(frag_size);
		  }
		  else
		  {
			  // This is the last fragment.
			  hdr->flag_byte = IPC_MSG_COMPLETE;
			  hdr->length = 0;
			  frag_size = (tolen - offset);
		  }

		  debug_printf(DEBUG_IPC, "Sending fragment of %d byte(s).\n", (frag_size + sizeof(ipc_header)));

		  memcpy(&frag[sizeof(ipc_header)], &tosend[offset], frag_size);

		  debug_hex_dump(DEBUG_IPC, frag, (frag_size + sizeof(ipc_header)));

		  if (WriteFile(pipehdl, frag, (frag_size + sizeof(ipc_header)), &totalbytes, NULL) == 0)
			{
				debug_printf(DEBUG_NORMAL, "Couldn't send response document to IPC client!\n");
				FREE(frag);
				return;
			}

		  if (totalbytes != (frag_size + sizeof(ipc_header)))
		  {
			  debug_printf(DEBUG_NORMAL, "Runt packet sent!  IPC data will be corrupt.\n");
			  debug_printf(DEBUG_NORMAL, "Total Bytes Sent = %d    Fragment Size = %d\n", totalbytes,
				  (frag_size + sizeof(ipc_header)));
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
 * \retval XENONE on success
 * \retval -1 on error
 **/
int xsup_ipc_send_all(char *message, int msglen)
{
  int i;

  if (!xsup_assert((msglen > 0), "msglen > 0", FALSE)) return -1;
  if (!xsup_assert((message != NULL), "message != NULL", FALSE)) return -1;

  for (i=0; i < INSTANCES; i++)
  {
	  if ((TEST_FLAG(pipes[i].flags, IPC_CONNECTED)) && 
		  (TEST_FLAG(pipes[i].flags, IPC_EVENTS_ONLY)))
	  {
		  xsup_ipc_send_message(pipes[i].hdl, message, msglen);
	  }
  }

  return XENONE;
}

/******************************************************************
 *
 * Send a normal log message out to all attached clients.
 *
 ******************************************************************/
void xsup_ipc_send_log(int level, char *msg)
{
#if 0
  char buffer[1500];
  int bufptr;
  struct ipc_cmd *cmd;

  if (ipc_sock < 0) return;   // We can't do anything.
  if (msg == NULL) return;    // Don't send empty messages.

  bufptr = 0;
  cmd = (struct ipc_cmd *)buffer;
  cmd->version = IPC_VERSION_NUM;
  cmd->attribute = LOG_MSG;
  cmd->getset = IPC_SET;       // An unrequested push.
  cmd->len = strlen(msg)+2;    // We want to send a NULL, and add one for
                               // the log level.
  bufptr+=sizeof(struct ipc_cmd);
  buffer[bufptr] = level;
  bufptr++;
  Strncpy(&buffer[bufptr], msg, (1500 - (sizeof(struct ipc_cmd)+1)));
  bufptr += (strlen(msg)+1);

  xsup_ipc_send_all(buffer, bufptr);
#endif
}

/***********************************************************
 *
 * Push an EAP notification to any connected clients.
 *
 ***********************************************************/
void xsup_ipc_send_eap_notify(char *notify)
{
#if 0
  char *buffer;
  int bufptr;
  struct ipc_cmd *cmd;

  buffer = Malloc(strlen(notify)+1 + sizeof(struct ipc_cmd));
  if (buffer == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't send IPC EAP notify message!\n");
      return;
    }

  bufptr = 0;
  cmd = (struct ipc_cmd *)buffer;
  cmd->version = IPC_VERSION_NUM;
  cmd->attribute = NOTIFY;
  cmd->getset = IPC_SET;          // This is an unrequested push.
  cmd->len = strlen(notify);
  bufptr += sizeof(struct ipc_cmd);
  Strncpy((char *)&buffer[bufptr], notify, strlen(notify) + 1);
  bufptr += strlen(notify);

  xsup_ipc_send_all(buffer, bufptr);
  bufptr =0;
  FREE(buffer);
#endif
}


/***********************************************************
 *
 * Clean up any structures used, and close out the communication socket.
 *
 ***********************************************************/
void xsup_ipc_cleanup()
{
  int i;

  debug_printf(DEBUG_DEINIT | DEBUG_IPC, "Shutting down IPC socket!\n");

  ipc_events_deinit();

  for (i=0; i<INSTANCES; i++)
  {
	  debug_printf(DEBUG_DEINIT | DEBUG_IPC, "Closing pipe #%d\n", i);
	  CloseHandle(pipes[i].hdl);
	  CloseHandle(pipes[i].hevent);
  }
}



