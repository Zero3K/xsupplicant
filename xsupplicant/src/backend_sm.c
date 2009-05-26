/**
 * \file backend_sm.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <unistd.h>
#else
#include <winsock2.h>
#endif

#include <string.h>
#include <stdlib.h>

#include <libxsupconfig/xsupconfig_structs.h>
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "statemachine.h"
#include "backend_sm.h"
#include "eapol.h"
#include "snmp.h"
#include "platform/cardif.h"
#include "eap_sm.h"
#include "frame_structs.h"
#include "ipc_events.h"
#include "ipc_callout.h"
#include "ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifdef DARWIN_WIRELESS
#include "platform/macosx/cardif_macosx_wireless.h"
#endif

#define DOT1X_BACKEND_SM_EVENTS 0	///< Set this to 1 if you want to generate IPC events for BACKEND state machine change events.

/**
 * \brief Init any variables that need to be set up, and do anything else 
 *        that the backend state machine needs.
 *
 * @param[in] ctx   The context that contains the backend state machine
 *                  that we are going to init.
 **/
void backend_sm_init(context * ctx)
{
	// If ctx is NULL, we have a showstopper!
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	eap_sm_init(&ctx->eap_state);

	ctx->statemachine->beCurState = UNKNOWN;
}

/**
 * \brief Free any resources that were in use before telling the main 
 *        state machine that we have aborted this authentication.
 *
 * @param[in] ctx   The context for the interface that we are aborting
 *                  the connection on.
 **/
void abortSupp(context * ctx)
{
	// If ctx is NULL, we have a showstopper!
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	ctx->statemachine->suppStart = FALSE;
	ctx->eap_state->eapSuccess = FALSE;
}

/**
 * \brief Sync the EAP state machine variables that have lower layer \
 *        equivs.
 *
 * @param[in] ctx  The context that we need to sync the two state machines
 *                 between.
 **/
void backend_sm_sync_ll_to_p(context * ctx)
{
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (ctx->intType == ETH_802_11_INT) {
		wctx = (wireless_ctx *) ctx->intTypeData;

		if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
			return;
	}

	ctx->eap_state->eapReq = ctx->statemachine->eapReq;
	ctx->eap_state->portEnabled = ctx->statemachine->portEnabled;
	ctx->eap_state->idleWhile = config_get_idleWhile();
	ctx->eap_state->eapRestart = ctx->statemachine->eapRestart;

	if (ctx->prof != NULL) {
		ctx->eap_state->curMethods = ctx->prof->method;
	} else {
		if (ctx->intType == ETH_802_11_INT) {
			if (wctx->cur_essid != NULL) {
				debug_printf(DEBUG_NORMAL,
					     "There is no configuration defined for "
					     "network '%s'.\n",
					     wctx->cur_essid);
			} else {
				debug_printf(DEBUG_NORMAL,
					     "This network does not have a configuration"
					     " defined for it!\n");
			}
			ctx->eap_state->curMethods = NULL;
		}
	}
}

/**
 * \brief Sync the .1X state machine variables that have higher layer 
 *        equivs.
 *
 * @param[in] ctx   The context that needs to have it's data synced.
 **/
void backend_sm_sync_p_to_ll(context * ctx)
{
	ctx->statemachine->eapResp = ctx->eap_state->eapResp;
	ctx->statemachine->eapNoResp = ctx->eap_state->eapNoResp;
	ctx->statemachine->eapSuccess = ctx->eap_state->eapSuccess;
	ctx->statemachine->eapFail = ctx->eap_state->eapFail;

	if ((ctx->statemachine->keyAvailable == FALSE)
	    && (ctx->eap_state->eapKeyAvailable == TRUE)) {
		if (ctx->statemachine->PMK != NULL) {
			FREE(ctx->statemachine->PMK);
		}

		if (ctx->eap_state->eapKeyAvailable == TRUE) {
			ctx->statemachine->PMK =
			    Malloc(ctx->eap_state->eapKeyLen);
			if (ctx->statemachine->PMK != NULL) {
				memcpy(ctx->statemachine->PMK,
				       ctx->eap_state->eapKeyData,
				       ctx->eap_state->eapKeyLen);
			}
		}
	}

	ctx->statemachine->keyAvailable = ctx->eap_state->eapKeyAvailable;
	ctx->statemachine->eapRestart = ctx->eap_state->eapRestart;
}

/**
 * \brief Wait until the layers above have something to send.  (This is 
 *        where we get username/passwords.)
 *
 * @param[in] ctx   The context for the interface that we need to send a
 *                  response on.
 **/
void getSuppRsp(context * ctx)
{
	// If ctx is NULL, we have a showstopper!
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

	// Point to our request data.
	if (ctx->recvframe != NULL) {
		ctx->eap_state->eapReqData = &ctx->recvframe[OFFSET_TO_EAP];
	}
	backend_sm_sync_ll_to_p(ctx);
	eap_sm_run(ctx->eap_state);
	backend_sm_sync_p_to_ll(ctx);
}

/**
 * \brief Transmit the response that should be in the queue.
 *
 * @param[in] ctx   The context for the interface that we need to send
 *                  a response on.
 **/
void txSuppRsp(context * ctx)
{
	uint8_t *frame_ptr = NULL;
	struct eap_header *eapdata = NULL;
	uint16_t eapsize = 0;

	// If ctx is NULL, we have a showstopper!
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);
	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	// Make sure we know that we have sent the frame.
	ctx->eap_state->eapResp = FALSE;
	ctx->statemachine->eapolEap = FALSE;

	if (ctx->sendframe == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Our 'to send' frame buffer is NULL!\n");
		return;
	}

	frame_ptr = &ctx->sendframe[OFFSET_TO_EAP];

	eapdata = (struct eap_header *)ctx->eap_state->eapRespData;

	if (eapdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "The upper layers didn't generate anything to send on '%s'.\n",
			     ctx->desc);
		return;
	}

	eapsize = ntohs(eapdata->eap_length);

	eapdata = (struct eap_header *)frame_ptr;

	if (eapsize > 1520) {
		// We probably have an invalid EAP message.
		debug_printf(DEBUG_NORMAL,
			     "The EAP message size appears to be invalid. "
			     "Ignoring!\n");
		return;
	}

	if (ctx->eap_state->eapRespData == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Got a NULL response from the EAP layer! "
			     "Ignoring!\n");
		return;
	}

	if (frame_ptr == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Our destination frame pointer is NULL!\n");
		return;
	}

	memcpy(frame_ptr, ctx->eap_state->eapRespData, eapsize);
	ctx->send_size = OFFSET_TO_EAP + eapsize;

	eapol_build_header(ctx, EAP_PACKET, (ctx->send_size - OFFSET_TO_EAP),
			   (char *)ctx->sendframe);

	cardif_sendframe(ctx);
}

/**
 * \brief Display information when the backend state machine times out.
 *
 * For some reason, the backend state machine timed out.  Depending on the
 * last packet we recieved, we may be able to provide the user with 
 * information about what went wrong.  For now, we are only going to report
 * on things that may be wrong when a Response ID message goes unanswered,
 * but in the future, we should expand to provide information on specific
 * EAP types where possible.
 *
 * @param[in] ctx   The context for the interface that the state machine
 *                  timed out on.
 *
 * \retval XEGENERROR on a general error
 * \retval XENONE on success
 **/
int backend_sm_timeout_display(context * ctx)
{
	struct config_globals *globals;

	// If ctx is NULL, we have a showstopper!
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	globals = config_get_globals();
	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return XEGENERROR;

	switch (ctx->statemachine->lastEapType) {
	case EAP_TYPE_IDENTITY:
		// The last EAP message we saw was an Identity request.  We assume that
		// we attempted to send a response to that request.  (If not, it should
		// be reported elsewhere.)  If we get here, then there was a timeout
		// waiting for the authenticator to send us a packet containing the
		// beginning of the actual EAP conversation.

		if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
			debug_printf(DEBUG_NORMAL,
				     "[WARNING]  Timeout waiting for the "
				     "authenticator to begin the EAP conversation.  This "
				     "usually happens when the RADIUS server is "
				     "misconfigured, the authenticator can't talk to the "
				     "RADIUS server, or the username provided is "
				     "invalid.\n");
		}
		ipc_events_error(ctx, IPC_EVENT_ERROR_TIMEOUT_WAITING_FOR_ID,
				 NULL);
		ipc_events_ui(ctx, IPC_EVENT_UI_AUTH_TIMEOUT, ctx->desc);
		break;

	default:
		if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
			debug_printf(DEBUG_NORMAL,
				     "[WARNING] Timeout during the EAP "
				     "conversation!  Please verify that the settings in "
				     "your config file are correct and that the "
				     "authenticator and RADIUS servers are properly "
				     "configured.  If this error persists, please run "
				     "Xsupplicant in debug mode, and e-mail the output, "
				     "along with the config file, and RADIUS config file "
				     "(where possible) to open1x-xsupplicant@"
				     "lists.sourceforge.net.\n");
		}
		ctx->statemachine->suppTimeout = TRUE;	// Signal that we got a timeout.
		break;
	}

	return XENONE;
}

/**
 * \brief Display the text string for the backend state we are provided.
 *
 * @param[in] debuglevel   The lowest debug level that should actually
 *                         display this information.  (Levels are
 *                         specified in \ref xsup_debug.h.)
 *
 * @param[in] state   The state that we want to display information for.
 **/
void backend_sm_disp_state(int debuglevel, int state)
{
	switch (state) {
	case REQUEST:
		debug_printf_nl(debuglevel, "REQUEST");
		break;

	case RESPONSE:
		debug_printf_nl(debuglevel, "RESPONSE");
		break;

	case SUCCESS:
		debug_printf_nl(debuglevel, "SUCCESS");
		break;

	case FAIL:
		debug_printf_nl(debuglevel, "FAIL");
		break;

	case TIMEOUT:
		debug_printf_nl(debuglevel, "TIMEOUT");
		break;

	case IDLE:
		debug_printf_nl(debuglevel, "IDLE");
		break;

	case INITIALIZE:
		debug_printf_nl(debuglevel, "INITIALIZE");
		break;

	case RECEIVE:
		debug_printf_nl(debuglevel, "RECEIVE");
		break;

	default:
		debug_printf_nl(debuglevel, "UNKNOWN");
		break;
	}
}

/**
 * \break Check things that might cause a global state change for the 
 *        backend state machine.
 *
 * @param[in] ctx   The context that we want to check the backend state
 *                  machine for.
 **/
void backend_sm_check_globals(context * ctx)
{
	// If ctx is NULL, we have a showstopper.
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	if (ctx->statemachine->initialize || ctx->statemachine->suppAbort) {
		debug_printf(DEBUG_1X_BE_STATE, "(global) -> INITIALIZE\n");
		backend_sm_change_state(ctx, INITIALIZE);
	}

	if (ctx->statemachine->eapRestart == TRUE) {
		debug_printf(DEBUG_1X_BE_STATE,
			     "Supplicant PAE has issued a restart.\n");
		ctx->statemachine->eapRestart = TRUE;

		backend_sm_change_state(ctx, INITIALIZE);

		backend_sm_sync_ll_to_p(ctx);
		eap_sm_run(ctx->eap_state);
		backend_sm_sync_p_to_ll(ctx);
	}
}

/**
 * \brief Change to initialize state.
 *
 * @param[in] ctx   The context for the interface that is changing to
 *                  initialize state.
 **/
void backend_sm_change_to_initialize(context * ctx)
{
	// If ctx is NULL, we have a showstopper.
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	abortSupp(ctx);

	ctx->statemachine->suppAbort = FALSE;
	ctx->statemachine->beCurState = INITIALIZE;
	ctx->statemachine->initialize = FALSE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     INITIALIZE) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Process initialize state.
 *
 * @param[in] ctx  The context that we want to process initialize state
 *                 for.
 **/
void backend_sm_do_initialize(context * ctx)
{
	// Nothing to do here.
}

/**
 * \brief Change to IDLE state.
 *
 * @param[in] ctx  The context for the interface that we want to change
 *                 to idle state.
 **/
void backend_sm_change_to_idle(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	ctx->statemachine->suppStart = FALSE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     IDLE) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = IDLE;
}

/**
 * \brief Process IDLE state.
 *
 * @param[in] ctx   The context for the interface that is in IDLE state.
 **/
void backend_sm_do_idle(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);
	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

	if (ctx->eap_state->eapFail && ctx->statemachine->suppStart) {
		backend_sm_change_state(ctx, FAIL);
	}

	if (ctx->statemachine->eapolEap && ctx->statemachine->suppStart) {
		backend_sm_change_state(ctx, REQUEST);
	}

	if (ctx->eap_state->eapSuccess && ctx->statemachine->suppStart) {
		backend_sm_change_state(ctx, SUCCESS);
	}
}

/**
 * \brief Change to request state.
 *
 * @param[in] ctx   The context for the interface that is changing to
 *                  request state.
 **/
void backend_sm_change_to_request(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	ctx->statemachine->authWhile = 0;
	ctx->statemachine->eapReq = TRUE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     REQUEST) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = REQUEST;

	getSuppRsp(ctx);
}

/**
 * \brief Process request state.
 *
 * @param[in] ctx   The context that we want to process request state for.
 **/
void backend_sm_do_request(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

	if (ctx->eap_state->eapFail) {
		backend_sm_change_state(ctx, FAIL);
	}

	if (ctx->eap_state->eapNoResp) {
		backend_sm_change_state(ctx, RECEIVE);
	}

	if (ctx->eap_state->eapResp) {
		backend_sm_change_state(ctx, RESPONSE);
	}

	if (ctx->eap_state->eapSuccess) {
		backend_sm_change_state(ctx, SUCCESS);
	}
}

/**
 * \brief Change to response state.
 *
 * @param[in] ctx   The context for the interface that is changing to 
 *                  response state.
 **/
void backend_sm_change_to_response(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);
	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

	txSuppRsp(ctx);
	ctx->eap_state->eapResp = FALSE;
	FREE(ctx->eap_state->eapRespData);

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     RESPONSE) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = RESPONSE;

	backend_sm_change_state(ctx, RECEIVE);
}

/**
 * \brief Do response state.
 *
 * @param[in] ctx   The context for the interface that we want to 
 *                  process response state for.
 **/
void backend_sm_do_response(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	debug_printf(DEBUG_NORMAL,
		     "We should have changed state by now!!  Please "
		     "report this to the developers!\n");
	debug_printf(DEBUG_NORMAL, "Moving to RECEIVE like we should have.\n");
	backend_sm_change_state(ctx, RECEIVE);
}

/**
 * \brief Change to receive state.
 *
 * @param[in] ctx   The context for the interface that we are changing 
 *                  to receive state.
 **/
void backend_sm_change_to_receive(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);
	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

	ctx->statemachine->authWhile = ctx->statemachine->authPeriod;
	ctx->statemachine->eapolEap = FALSE;
	ctx->eap_state->eapNoResp = FALSE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     RECEIVE) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = RECEIVE;
}

/**
 * \brief Do receive state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to process receive state for.
 **/
void backend_sm_do_receive(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);
	xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

	if (ctx->eap_state->eapFail) {
		backend_sm_change_state(ctx, FAIL);
	}

	if (ctx->statemachine->authWhile == 0) {
		backend_sm_change_state(ctx, TIMEOUT);
	}

	if (ctx->eap_state->eapSuccess) {
		backend_sm_change_state(ctx, SUCCESS);
	}

	if (ctx->statemachine->eapolEap) {
		backend_sm_change_state(ctx, REQUEST);
	}
}

/**
 * \brief Change to FAIL state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to change to FAIL state on.
 **/
void backend_sm_change_to_fail(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	ctx->statemachine->suppFail = TRUE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     FAIL) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = FAIL;
	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Process FAIL state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to change to FAIL state on.
 **/
void backend_sm_do_fail(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	debug_printf(DEBUG_NORMAL,
		     "Invalid state.  We should *NEVER* get here!!\n");
	debug_printf(DEBUG_NORMAL, "Please report this to the developers.\n");
	debug_printf(DEBUG_NORMAL,
		     "Changing to IDLE state like we should have!\n");
	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Change to TIMEOUT state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to change to TIMEOUT state on.
 **/
void backend_sm_change_to_timeout(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	backend_sm_timeout_display(ctx);
	ctx->statemachine->suppTimeout = TRUE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     TIMEOUT) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = TIMEOUT;
	snmp_backend_timeout();

	// If we are using Cisco/Airespace gear, we need to drop association here,
	// or we won't attempt a new auth.
	if (ctx->intType == ETH_802_11_INT) {
		cardif_disassociate(ctx, 1);
	}

	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Process TIMEOUT state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to process TIMEOUT state for.
 **/
void backend_sm_do_timeout(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	debug_printf(DEBUG_NORMAL,
		     "Invalid state.  We should *NEVER* get here!!\n");
	debug_printf(DEBUG_NORMAL, "Please report this to the developers.\n");
	debug_printf(DEBUG_NORMAL,
		     "Changing to IDLE state like we should have!\n");
	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Change to SUCCESS state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to change to SUCCESS state.
 **/
void backend_sm_change_to_success(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	ctx->statemachine->keyRun = TRUE;
	ctx->statemachine->suppSuccess = TRUE;

#if DOT1X_BACKEND_SM_EVENTS == 1
	// Let all connected listeners know that we transitioned state.
	if (ipc_events_statemachine_transition
	    (ctx, IPC_STATEMACHINE_8021X_BACKEND, ctx->statemachine->beCurState,
	     SUCCESS) != IPC_SUCCESS) {
		// Display, or log an error message, and move on.
		debug_printf(DEBUG_NORMAL,
			     "Unable to send IPC 802.1X backend state change message!\n");
	}
#endif

	ctx->statemachine->beCurState = SUCCESS;

	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Process SUCCESS state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to process SUCCESS state for.
 **/
void backend_sm_do_success(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	debug_printf(DEBUG_NORMAL,
		     "Invalid state.  We should *NEVER* get here!!\n");
	debug_printf(DEBUG_NORMAL, "Please report this to the developers.\n");
	debug_printf(DEBUG_NORMAL,
		     "Changing to IDLE state like we should have!\n");
	backend_sm_change_state(ctx, IDLE);
}

/**
 * \brief Change the backend state.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to change state on.
 *
 * @param[in] newstate   The state that we want to change to.
 **/
void backend_sm_change_state(context * ctx, int newstate)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	debug_printf(DEBUG_1X_BE_STATE, "[backend_sm] ");
	backend_sm_disp_state(DEBUG_1X_BE_STATE, ctx->statemachine->beCurState);
	debug_printf_nl(DEBUG_1X_BE_STATE, " -> ");
	backend_sm_disp_state(DEBUG_1X_BE_STATE, newstate);
	debug_printf_nl(DEBUG_1X_BE_STATE, "\n");

	switch (newstate) {
	case INITIALIZE:
		backend_sm_change_to_initialize(ctx);
		break;

	case IDLE:
		backend_sm_change_to_idle(ctx);
		break;

	case REQUEST:
		backend_sm_change_to_request(ctx);
		break;

	case RESPONSE:
		backend_sm_change_to_response(ctx);
		break;

	case RECEIVE:
		backend_sm_change_to_receive(ctx);
		break;

	case FAIL:
		backend_sm_change_to_fail(ctx);
		break;

	case TIMEOUT:
		backend_sm_change_to_timeout(ctx);
		break;

	case SUCCESS:
		backend_sm_change_to_success(ctx);
		break;
	}
}

/**
 * \brief Run the backend state machine.
 *
 * @param[in] ctx   The context that we need to run the 802.1X backend
 *                  state machine for.
 *
 * \retval XENONE on success
 **/
int backend_sm_run(context * ctx)
{
	xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	/*
	   debug_printf(DEBUG_1X_BE_STATE, "Backend State : ");
	   backend_sm_disp_state(DEBUG_1X_BE_STATE, ctx->statemachine->beCurState);
	   debug_printf_nl(DEBUG_1X_BE_STATE, "\n");
	 */

	backend_sm_check_globals(ctx);

	switch (ctx->statemachine->beCurState) {
	case INITIALIZE:
		// We should *NEVER* get here!
		backend_sm_do_initialize(ctx);
		break;

	case IDLE:
		backend_sm_do_idle(ctx);
		break;

	case REQUEST:
		backend_sm_do_request(ctx);
		break;

	case RESPONSE:
		backend_sm_do_response(ctx);
		break;

	case RECEIVE:
		backend_sm_do_receive(ctx);
		break;

	case FAIL:
		backend_sm_do_fail(ctx);
		break;

	case TIMEOUT:
		backend_sm_do_timeout(ctx);
		break;

	case SUCCESS:
		backend_sm_do_success(ctx);
		break;

	default:
		debug_printf(DEBUG_NORMAL,
			     "Backend State Machine is in an UNKNOWN "
			     "state!\n");
		break;
	}

	return XENONE;
}

/**
 * \brief Clean up anything that we set up during the use of the state 
 *        machine.
 *
 * @param[in] ctx   The context that contains the backend state machine
 *                  that we need to clean the memory up for.
 **/
void backend_sm_deinit(context * ctx)
{
	eap_sm_deinit(&ctx->eap_state);
}
