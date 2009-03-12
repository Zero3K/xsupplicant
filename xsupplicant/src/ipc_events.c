/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_events.c
 *
 * \author chris@open1x.org
 *
 * \note  There is no reason to generate error events on anything in this file.  If 
 *        a call in this file fails it is an indication that  we won't be able to 
 *        send it out anyway. ;)
 **/
#include <libxml/parser.h>

#ifndef WINDOWS
#include <unistd.h>
#endif

#include <string.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "eap_types/tnc/tnc_compliance_funcs.h"
#include "context.h"
#include "ipc_callout.h"
#include "xsup_debug.h"
#include "xsup_ipc.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "xsup_err.h"
#include "liblist/liblist.h"

#ifdef WINDOWS
#include <windows.h>
#include "event_core_win.h"
#else
#include "event_core.h"
#endif

#ifndef WINDOWS
int ipc_events_in_use = FALSE;	// This is our dirty hack for a platform agnostic mutex. ;)
#warning You should consider implementing proper mutex locking for your platform!
#else
HANDLE ipcLock = INVALID_HANDLE_VALUE;
#endif

#ifndef WINDOWS
/**
 * \brief Lock the IPC event channel so that nobody else can use it.  (In theory. ;)
 *        This will allow us to be thread safe(ish).
 **/
int ipc_events_lock()
{
	while (ipc_events_in_use == TRUE) {
#ifdef WINDOWS
		Sleep(0);	// On windows, this should cause this thread to give up it's remaining time slice.  (Assuming something else is ready to run.)
#else
		usleep(500);	// Sleep a half second.
#endif
	}

#ifdef WINDOWS
//      Sleep(0);  // Give up the remainder of our time slice, so we don't hit a race condition on the lock below.
#endif

	// Lock the channel.
	ipc_events_in_use = TRUE;

	return 0;
}

/**
 * \brief Unlock the IPC event channel.
 **/
int ipc_events_unlock()
{
	ipc_events_in_use = FALSE;

	return 0;
}

void ipc_events_init()
{
}

void ipc_events_deinit()
{
}
#else
void ipc_events_init()
{
	ipcLock = CreateMutex(NULL, FALSE, NULL);	// New mutex that isn't owned by anyone.
	if (ipcLock == INVALID_HANDLE_VALUE) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't init IPC event system locking mutex!\n");
		return;
	}
}

void ipc_events_deinit()
{
	if (ipcLock != INVALID_HANDLE_VALUE) {
		CloseHandle(ipcLock);
		ipcLock = INVALID_HANDLE_VALUE;
	}
}

/**
 * \brief Get a lock on our Mutex.
 *
 * \warning DO NOT debug_printf() in here with anything other than DEBUG_IPC or you *WILL* deadlock!
 **/
int ipc_events_lock()
{
	DWORD dwWaitResult;

	if (ipcLock == INVALID_HANDLE_VALUE)
		return -1;	// We aren't inited yet (or have already deinited).

	// Wait for our mutex to be available!
	dwWaitResult = WaitForSingleObject(ipcLock, INFINITE);

	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
#ifdef LOCK_DEBUG
		debug_printf(DEBUG_IPC, "Acquired IPC event lock.\n");
#endif	/* LOCK_DEBUG */
		return 0;
		break;

	default:
		debug_printf(DEBUG_IPC,
			     "!!!!!!!!!!!! Error acquiring IPC event lock!  (Error %d)\n",
			     GetLastError());
		break;
	}

	return -1;
}

/**
 * \brief Release the mutex for IPC events.
 *
 * \warning DO NOT debug_printf() in here with anything except DEBUG_IPC or you *WILL* deadlock!
 **/
int ipc_events_unlock()
{
	if (!ReleaseMutex(ipcLock)) {
		debug_printf(DEBUG_IPC,
			     "!!!!!!!!!!!! Error releasing IPC event lock!  (Error %d)\n",
			     GetLastError());
		return -1;
	}
#ifdef LOCK_DEBUG
	debug_printf(DEBUG_IPC, "Released IPC event lock.\n");
#endif

	return 0;
}
#endif

/**
 * \brief Remove a \n from the log line.
 *
 * @param[in] logmsg   The log message to remove the \n from.
 *
 **/
void ipc_events_chomp(char *logmsg)
{
	if (logmsg[strlen(logmsg) - 1] == '\n')
		logmsg[strlen(logmsg) - 1] = 0x00;
}

/**
 * \brief Build the XML structure that defines this as a log message.
 *
 * @param[in] ctx   The context for the interface this log message is for.
 * @param[in] logmsg   A 32bit value indicating a log message from the \ref ipc_events_catalog.h
 *
 * \retval NULL on failure
 * \retval xmlNodePtr A pointer to the node the message should go under.
 **/
int ipc_events_log_msg(char *logmsg)
{
	xmlNodePtr t = NULL;
	xmlDocPtr indoc = NULL;
	int retval = IPC_SUCCESS;
	context *ctx = NULL;

	// DO NOT xsup_assert here!  It will cause an infinite loop that will lead to a stack overflow!
	if (logmsg == NULL)
		return IPC_FAILURE;

#ifdef WINDOWS
	// If we don't have a valid IPC handle, don't bother trying to send this data.
	if (ipcLock == INVALID_HANDLE_VALUE)
		return IPC_SUCCESS;
#endif

	ctx = event_core_get_active_ctx();
	if (ctx == NULL)
		return IPC_FAILURE;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return IPC_FAILURE;

	t = xmlDocGetRootElement(indoc);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	t = xmlNewChild(t, NULL, (xmlChar *) "Log", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	if ((ctx != NULL) && (ctx->intName != NULL)) {
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface",
		     (xmlChar *) ctx->intName) == NULL) {
			retval = IPC_FAILURE;
			goto done;
		}
	} else {
		if (xmlNewChild(t, NULL, (xmlChar *) "Interface", NULL) == NULL) {
			retval = IPC_FAILURE;
			goto done;
		}
	}

	ipc_events_chomp(logmsg);	// Remove a \n from the line, if it is there.

	t = xmlNewChild(t, NULL, (xmlChar *) "Message", (xmlChar *) logmsg);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		retval = IPC_FAILURE;
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Take an xmlDocPtr, convert it to ASCII, and send it to the other
 *        end of the IPC event pipe(s).
 *
 * @param[in] indoc   A pointer to the XML document that we need to convert and send.
 *
 * \retval XENONE on success
 * \retval -1 on failure
 **/
int ipc_events_send(xmlDocPtr indoc)
{
	char *retbuf = NULL;
	int retsize = 0;
	int retval = XENONE;

	if (!xsup_assert((indoc != NULL), "indoc != NULL", FALSE))
		return -1;

	if (ipc_events_lock() != 0)
		return -1;	// We got an error acquiring the lock for the mutex, so bail out!

	// Then, put the document back in to a format to be sent.
	xmlDocDumpFormatMemory(indoc, (xmlChar **) & retbuf, &retsize, 0);

	retval = xsup_ipc_send_all(retbuf, retsize);

	if (ipc_events_unlock() != 0) {
		FREE(retbuf);
		return -1;	// We got an error releasing the mutex.  THIS IS REALLY BAD!
	}

	FREE(retbuf);

	return retval;
}

/**
 * \brief Create an XML document indicating a log message to be sent.
 *
 * @param ctx       The context for the interface that generated the event.
 * @param loglevel  A text string indicating the log level of this log message.  
 *                  (See \ref ipc_events.h for the #defines that indicate levels.)
 * @param logtype   A long int that is a #define from \ref ipc_events_index.h 
 *                  (Or other message catalog.)  This will be converted to the proper
 *                  language on the UI side of the connection.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
#if 0
int ipc_event_str_only(context * ctx, char *loglevel, long int logtype)
{
	xmlDocPtr indoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert((loglevel != NULL), "loglevel != NULL", FALSE))
		return -1;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return -1;

	n = xmlDocGetRootElement(indoc);
	if (n == NULL) {
		retval = IPC_FAILURE;
		goto str_only_done;
	}

	t = ipc_events_build_log_msg(ctx, loglevel, logtype, n);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto str_only_done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		retval = IPC_FAILURE;
		goto str_only_done;
	}

 str_only_done:
	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Create an XML document indicating a log message to be sent.
 *
 * @param ctx       The context for the interface that generated the event.
 * @param loglevel  A text string indicating the log level of this log message.  
 *                  (See \ref ipc_events.h for the #defines that indicate levels.)
 * @param logtype   A long int that is a #define from \ref ipc_events_index.h 
 *                  (Or other message catalog.)  This will be converted to the proper
 *                  language on the UI side of the connection.
 * @param tag       The XML tag that the message parameter should be encoded in.
 * @param value     The parameter that will be used in the translated string by the UI.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_tag_msg(context * ctx, char *loglevel, long int logtype,
		       char *tag, char *value)
{
	xmlDocPtr indoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((loglevel != NULL), "loglevel != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((tag != NULL), "tag != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((value != NULL), "value != NULL", FALSE))
		return IPC_FAILURE;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return -1;

	n = xmlDocGetRootElement(indoc);
	if (n == NULL) {
		retval = IPC_FAILURE;
		goto tag_msg_done;
	}

	t = ipc_events_build_log_msg(ctx, loglevel, logtype, n);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto tag_msg_done;
	}

	if (xmlNewChild(t, NULL, tag, value) == NULL) {
		retval = IPC_FAILURE;
		goto tag_msg_done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		retval = IPC_FAILURE;
		goto tag_msg_done;
	}

 tag_msg_done:
	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Send an "Attempting to associate" log message.
 *
 * @param[in] ctx  The context for the interface that generated this event.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_attempting_to_associate(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	return ipc_events_tag_msg(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_ATTEMPTING_TO_ASSOCIATE, "SSID",
				  ((wireless_ctx *) (ctx->intTypeData))->
				  cur_essid);
}

/**
 * \brief Send a "Can't get interface capabilities" log message.
 *
 * @param[in] ctx The context for the interface that generated this event.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_cant_get_interface_capabilities(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	return ipc_events_tag_msg(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_CANT_GET_CAPABILITIES,
				  "Interface", ctx->intName);
}

/**
 * \brief Send a "Scanning for Wireless Networks.." log message.
 *
 * @param[in] ctx The context for the interface that generated this event.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_scanning(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	return ipc_event_str_only(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_SCANNING);
}

/**
 * \brief Send a "Authenticated" log message.
 *
 * @param[in] ctx    The context for the interface that generated the event.
 * @param[in] phase  The phase that we were in when we switch to authenticated state.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_authenticated(context * ctx, int phase)
{
	char txtphase[10];

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	sprintf((char *)&txtphase, "%d", phase);

	return ipc_events_tag_msg(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_AUTHENTICATED, "Phase",
				  txtphase);
}

/**
 * \brief Send a "Authentication Failed" log message.
 *
 * @param[in] ctx    The context for the interface that generated the event.
 * @param[in] phase  The authentication phase we were in when the event happened.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_authentication_failed(context * ctx, int phase)
{
	char txtphase[10];

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	sprintf((char *)&txtphase, "%d", phase);

	return ipc_events_tag_msg(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_AUTHENTICATION_FAILED, "Phase",
				  txtphase);
}

/**
 * \brief Send an "associated" log message.
 *
 * @param[in] ctx  The context for the interface that generated this event.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_associated(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	return ipc_events_tag_msg(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_ASSOCIATED, "SSID",
				  ((wireless_ctx *) (ctx->intTypeData))->
				  cur_essid);
}

/**
 * \brief Send a "starting authentication" log message.
 *
 * @param[in] ctx  The context for the interface that generated this event.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_starting_authentication(context * ctx, int phase)
{
	char txtphase[10];

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	sprintf((char *)&txtphase, "%d", phase);

	return ipc_events_tag_msg(ctx, LOG_LEVEL_NORMAL,
				  IPC_EVENT_LOG_STARTING_AUTH, "Phase",
				  txtphase);
}
#endif				// 0

/**
 * \brief Notify all attached UIs that a state machine has transitioned to a new
 *        state.
 *
 * @param[in] ctx   The context for the interface that is transitioning.
 * @param[in] statemachine   An integer that identifies the state machine that is
 *                           transitioning.  (See ipc_events_index.h for definitions.)
 * @param[in] oldstate   The state that this state machine was in.
 * @param[in] newstate   The state that this state machine has transitioned to.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_statemachine_transition(context * ctx, int statemachine,
				       int oldstate, int newstate)
{
	xmlDocPtr indoc;
	xmlNodePtr t = NULL, root = NULL;
	char temp[10];
	int retval = IPC_SUCCESS;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return IPC_FAILURE;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "State_Transition", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}

	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Interface",
	     (xmlChar *) ctx->intName) == NULL) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}

	sprintf((char *)&temp, "%d", statemachine);
	if (xmlNewChild(t, NULL, (xmlChar *) "Statemachine", (xmlChar *) temp)
	    == NULL) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}

	sprintf((char *)&temp, "%d", oldstate);
	if (xmlNewChild(t, NULL, (xmlChar *) "Old_State", (xmlChar *) temp) ==
	    NULL) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}

	sprintf((char *)&temp, "%d", newstate);
	if (xmlNewChild(t, NULL, (xmlChar *) "New_State", (xmlChar *) temp) ==
	    NULL) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}
#ifdef HAVE_TNC
	if (ctx->tnc_data != NULL) {
		sprintf((char *)&temp, "%d", ctx->tnc_data->connectionID);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "TNC_Connection_ID",
		     (xmlChar *) temp) == NULL) {
			retval = IPC_FAILURE;
			goto statemachine_transition_ipc_done;
		}
	}
#endif				// HAVE_TNC

	if (ipc_events_send(indoc) != XENONE) {
		retval = IPC_FAILURE;
		goto statemachine_transition_ipc_done;
	}

 statemachine_transition_ipc_done:
	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Notify all attached UIs that an error has occurred.
 *
 * @param[in] ctx   The context for the interface that got the error.
 * @param[in] erridx   The index for the error that we are sending.
 * @param[in] param   A parameter to be used with the string that is
 *                    identified by erridx.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
void ipc_events_error(context * ctx, unsigned int erridx, char *param)
{
	context *myctx = NULL;
	char temp[100];
	int retval = IPC_SUCCESS;
	xmlNodePtr t = NULL, root = NULL, n = NULL;
	xmlDocPtr indoc = NULL;

	if (ctx == NULL) {
		myctx = event_core_get_active_ctx();
	} else {
		myctx = ctx;
	}

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		goto done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "Error_Event", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	sprintf((char *)&temp, "%d", erridx);
	n = xmlNewChild(t, NULL, (xmlChar *) "Error_Code", (xmlChar *) temp);
	if (n == NULL) {
		goto done;
	}

	if (xmlNewChild(t, NULL, (xmlChar *) "Argument", (xmlChar *) param) ==
	    NULL) {
		goto done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return;
}

/**
 * \brief Notify all attached UIs that a scan has completed on an interface.
 *
 * @param[in] ctx   The context for the interface that has completed the scan.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
int ipc_events_scan_complete(context * ctx)
{
	xmlDocPtr indoc;
	xmlNodePtr t = NULL, root = NULL;
	int retval = IPC_SUCCESS;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return IPC_FAILURE;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		retval = IPC_FAILURE;
		goto scan_complete_done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "Wireless_Scan_Complete", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto scan_complete_done;
	}

	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Interface",
	     (xmlChar *) ctx->intName) == NULL) {
		retval = IPC_FAILURE;
		goto scan_complete_done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		retval = IPC_FAILURE;
		goto scan_complete_done;
	}

 scan_complete_done:
	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Request that the UI give us a password for the EAP type used
 *        in the interface's current profile.
 *
 * @param[in] eapmethod   A string that indicates the EAP method we want to get 
 *                        the password for.
 * @param[in] chalstr   If the EAP method provides a challenge string, it should
 *                      be passed in here.  If not, this value should be NULL.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_events_request_eap_upwd(char *eapmethod, char *chalstr)
{
	xmlDocPtr indoc = NULL;
	xmlNodePtr t = NULL, root = NULL;
	int retval = IPC_SUCCESS;
	context *ctx = NULL;

	ctx = event_core_get_active_ctx();
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return IPC_FAILURE;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return IPC_FAILURE;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "EAP_Password_Request", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Connection_Name",
	     (xmlChar *) ctx->conn_name) == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	if (xmlNewChild
	    (t, NULL, (xmlChar *) "EAP_Method",
	     (xmlChar *) eapmethod) == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Challenge_String",
	     (xmlChar *) chalstr) == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		retval = IPC_FAILURE;
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return retval;
}

/**
 * \brief Notify all attached UIs that an event they should look at has occurred.
 *
 * @param[in] ctx   The context for the interface that is generating the event.
 * @param[in] erridx   The index for the event that we are sending.
 * @param[in] param   A parameter to be used with the event.  (Should be passed to the event
 *                    handler.)
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
void ipc_events_ui(context * ctx, unsigned int uiidx, char *param)
{
	context *myctx = NULL;
	char temp[100];
	int retval = IPC_SUCCESS;
	xmlNodePtr t = NULL, root = NULL, n = NULL;
	xmlDocPtr indoc = NULL;

	if (ctx == NULL) {
		myctx = event_core_get_active_ctx();
	} else {
		myctx = ctx;
	}

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		goto done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "UI_Event", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	sprintf((char *)&temp, "%d", uiidx);
	n = xmlNewChild(t, NULL, (xmlChar *) "Event_Code", (xmlChar *) & temp);
	if (n == NULL) {
		goto done;
	}

	if (ctx != NULL) {
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface",
		     (xmlChar *) ctx->intName) == NULL) {
			goto done;
		}
	}

	if (xmlNewChild(t, NULL, (xmlChar *) "Parameter", (xmlChar *) param) ==
	    NULL) {
		goto done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return;
}

/**
 * \brief Notify all attached UIs that an external TNC event they should look at has 
 *        occurred.
 *       
 * \note This event will be triggered only when a TNC IMC has something to tell the user
 *       of the UI.  However, since every IMC will have different messages, this assumes
 *       that the UI is aware of the message catalogs that the IMC is looking in.  This is
 *       why the IANA OUI is sent as part of the message.
 * 
 * @param[in] oid   The IANA OUI that generated this message.
 * @param[in] notification   An index in to the message catalog that indicates how this
 *                           message should be displayed.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
void ipc_events_imc_event(uint32_t oid, uint32_t notification)
{
	char temp[100];
	int retval = IPC_SUCCESS;
	xmlNodePtr t = NULL, root = NULL, n = NULL;
	xmlDocPtr indoc = NULL;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		goto done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "TNC_Event", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	sprintf((char *)&temp, "%d", oid);
	n = xmlNewChild(t, NULL, (xmlChar *) "OUI", (xmlChar *) temp);
	if (n == NULL) {
		goto done;
	}

	sprintf((char *)&temp, "%d", notification);
	if (xmlNewChild(t, NULL, (xmlChar *) "Notification", (xmlChar *) temp)
	    == NULL) {
		goto done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return;
}

/**
 * \brief Notify all attached UIs that an external TNC event that requires action
 *        has occurred.
 *       
 * \note This event will be triggered only when a TNC IMC has something to ask the user
 *       of the UI.  However, since every IMC will have different messages, this assumes
 *       that the UI is aware of the message catalogs that the IMC is looking in.  This is
 *       why the IANA OUI is sent as part of the message.
 * 
 * @param[in] imcID   The IMC ID that the IMC uses to track connections.
 * @param[in] connID   The connection ID that the IMC uses to track connections.
 * @param[in] oid   The IANA OUI that generated this message.
 * @param[in] request   The request that the UI should display.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on error
 * \retval IPC_TIMEOUT on timeout
 **/
void ipc_events_imc_request_event(uint32_t imcID, uint32_t connID, uint32_t oid,
				  uint32_t request)
{
	char temp[100];
	int retval = IPC_SUCCESS;
	xmlNodePtr t = NULL, root = NULL, n = NULL;
	xmlDocPtr indoc = NULL;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		goto done;
	}

	t = xmlNewChild(root, NULL, (xmlChar *) "TNC_Request_Event", NULL);
	if (t == NULL) {
		retval = IPC_FAILURE;
		goto done;
	}

	sprintf((char *)&temp, "%d", imcID);
	if (xmlNewChild(t, NULL, (xmlChar *) "imcID", (xmlChar *) temp) == NULL) {
		goto done;
	}

	sprintf((char *)&temp, "%d", connID);
	if (xmlNewChild(t, NULL, (xmlChar *) "connID", (xmlChar *) temp) ==
	    NULL) {
		goto done;
	}

	sprintf((char *)&temp, "%d", oid);
	n = xmlNewChild(t, NULL, (xmlChar *) "OUI", (xmlChar *) temp);
	if (n == NULL) {
		goto done;
	}

	sprintf((char *)&temp, "%d", request);
	if (xmlNewChild(t, NULL, (xmlChar *) "Request", (xmlChar *) temp) ==
	    NULL) {
		goto done;
	}

	if (ipc_events_send(indoc) != XENONE) {
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return;
}

/**
 * \brief  Send a TNC UI batch.
 *
 * @param[in] batchlist   A linked list containing the batch that we want to send to the UI.
 **/
void ipc_events_send_tnc_batch(void *batchlist, uint32_t imcID, uint32_t connID,
			       uint32_t oui, uint32_t msg)
{
#ifdef HAVE_TNC
	xmlNodePtr t = NULL, root = NULL, n = NULL, b = NULL;
	xmlDocPtr indoc = NULL;
	char temp[100];
	int numitems = 0;
	tnc_msg_batch *cur = NULL;
#endif

#ifndef HAVE_TNC
	debug_printf(DEBUG_NORMAL,
		     "Attempt to call %s() when TNC support is not built!?\n",
		     __FUNCTION__);
	return;
#else

	numitems = liblist_num_nodes((genlist *) batchlist);

	cur = (tnc_msg_batch *) batchlist;

	indoc = ipc_callout_build_doc();
	if (indoc == NULL)
		return;

	root = xmlDocGetRootElement(indoc);
	if (root == NULL) {
		goto done;
	}

	t = xmlNewChild(root, NULL, "TNC_Request_Batch_Event", NULL);
	if (t == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create TNC_Request_Batch_Event node!\n");
		goto done;
	}

	sprintf((char *)&temp, "%d", imcID);
	if (xmlNewChild(t, NULL, "imcID", temp) == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create <imcID> node!\n");
		goto done;
	}

	sprintf((char *)&temp, "%d", connID);
	if (xmlNewChild(t, NULL, "connID", temp) == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create <connID> node!\n");
		goto done;
	}

	sprintf((char *)&temp, "%d", oui);
	if (xmlNewChild(t, NULL, "OUI", temp) == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create OUI node!\n");
		goto done;
	}

	sprintf((char *)&temp, "%d", msg);
	if (xmlNewChild(t, NULL, "MsgID", temp) == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create MsgID node!\n");
		goto done;
	}

	sprintf((char *)&temp, "%d", numitems);
	if (xmlNewChild(t, NULL, "Items", temp) == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create <Items> node!\n");
		goto done;
	}

	n = xmlNewChild(t, NULL, "Batch", NULL);
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create <Batch> tag!\n");
		goto done;
	}
	// Iterate through the list, and build all of the nodes.
	while (cur != NULL) {
		b = xmlNewChild(n, NULL, "Item", NULL);
		if (b == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create <Item> tag!\n");
			goto done;
		}

		sprintf((char *)&temp, "%d", cur->imcID);
		if (xmlNewChild(b, NULL, "imcID", temp) == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create <imcID> tag!\n");
			goto done;
		}

		sprintf((char *)&temp, "%d", cur->connectionID);
		if (xmlNewChild(b, NULL, "connectionID", temp) == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create <connectionID> tag!\n");
			goto done;
		}

		sprintf((char *)&temp, "%d", cur->oui);
		if (xmlNewChild(b, NULL, "OUI", temp) == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create <OUI> tag!\n");
			goto done;
		}

		sprintf((char *)&temp, "%d", cur->msgid);
		if (xmlNewChild(b, NULL, "MsgID", temp) == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create <MsgID> tag!\n");
			goto done;
		}

		if (xmlNewChild(b, NULL, "Parameter", cur->parameter) == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create <Parameter> tag!\n");
			goto done;
		}

		cur = cur->next;
	}

	if (ipc_events_send(indoc) != XENONE) {
		goto done;
	}

 done:
	xmlFreeDoc(indoc);

	return;
#endif
}
