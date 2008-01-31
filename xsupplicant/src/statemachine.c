/**
 * Handle state machine related functions.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * \file statemachine.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <stdlib.h>

#ifndef WINDOWS
#include <unistd.h>
#include <netinet/in.h>
#include <strings.h>
#endif

#include <string.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "snmp.h"
#include "statemachine.h"
#include "xsup_debug.h"
#include "frame_structs.h"
#include "eap_sm.h"
#include "eapol.h"
#include "xsup_err.h"
#include "xsup_ipc.h"
#include "wpa.h"
#include "backend_sm.h"
#include "platform/cardif.h"
#include "eap_types/leap/eapleap.h"
#include "timer.h"
#include "wireless_sm.h"
#include "ipc_events.h"
#include "ipc_callout.h"
#include "ipc_events_index.h"

#ifdef DARWIN_WIRELESS
#include "platform/macosx/cardif_macosx_wireless.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define DOT1X_SM_EVENTS 1  ///< Set this to 0 if you don't want the 802.1X state machine to generate events.

// This is needed to keep the compiler from complaining about not knowing where
// global_deinit() is.  We should probably change this to something a little
// more "correct".
extern void global_deinit();

void (*imc_disconnect_callback)(uint32_t connectionID) = NULL;

/**
 * \brief Decrement a value, as long as it is greater than 0.
 *
 * @param[in] decval   A pointer to the value to decrement.
 **/
void dec_if_nz(uint8_t *decval)
{
  if (!decval) return;

  if (*decval > 0) (*decval)--;
}

/**
 * \brief Initalize the 802.1X state machine.
 *
 * @param[in] ctx   The context that we are initializing the 802.1X 
 *                  statemachine on.
 *
 * \retval XEMALLOC couldn't allocate the memory needed to init the 802.1X
 *                  state machine.
 * \retval XENONE   on success
 **/
int statemachine_init(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  ctx->statemachine = (struct dot1x_state *)Malloc(sizeof(struct dot1x_state));
  if (ctx->statemachine == NULL) 
  {
	  ipc_events_malloc_failed(ctx);
	  return XEMALLOC;
  }

  ctx->statemachine->initialize = TRUE;

  backend_sm_init(ctx);
  statemachine_reinit(ctx);

  return XENONE;
}

/**
 * \brief Reinitalize the 802.1X state machine
 *
 * @param[in] ctx   The context that contains the 802.1X state machine
 *                  that we want to reinit.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation error
 *
 * \todo Allow startPeriod to be changed to a user setable value.
 **/
int statemachine_reinit(context *ctx)
{
  struct config_globals *globals;
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (ctx->desc != NULL)
  {
	  // Only display this if we know enough about the interface to show something useful. (i.e. After the interface is running,
	  // and not while it is initing.
	debug_printf((DEBUG_DOT1X_STATE | DEBUG_VERBOSE), "Reinit state machine on interface '%s'.\n", ctx->desc);
  }

  globals = config_get_globals();

  xsup_assert((globals != NULL), "globals != NULL", TRUE);

  // Now, we want to set up a few defaults as per the 802.1x doc, and
  // initalize a few other statemachine variables that we will be needing.
  if (globals->auth_period != 0)
    {
      ctx->statemachine->authPeriod = globals->auth_period;
    }
  else
    {
      ctx->statemachine->authPeriod = 30;
    }

  ctx->statemachine->authWhile = ctx->statemachine->authPeriod;

  if (globals->held_period != 0)
    {
      ctx->statemachine->heldPeriod = globals->held_period;
    }
  else
    {
      ctx->statemachine->heldPeriod = 60;
    }

  ctx->statemachine->heldWhile = ctx->statemachine->heldPeriod;

  // XXX Do we want to allow startPeriod to be changed?
  ctx->statemachine->startPeriod = 30;
  ctx->statemachine->startWhen = 0;     // Trigger sending an EAPOL-Start

  if (globals->max_starts != 0)
    {
      ctx->statemachine->maxStart = globals->max_starts;
    }
  else
    {
      ctx->statemachine->maxStart = 3;
    }

  // Set up our inital state.
  ctx->statemachine->userLogoff = FALSE;
  ctx->statemachine->logoffSent = FALSE;
  ctx->statemachine->startCount = 0;

  ctx->statemachine->tick = FALSE;

  /* Some new variables defined by 802.1X-2004 */
  ctx->statemachine->eapolEap = FALSE;
  ctx->statemachine->keyAvailable = FALSE;
  ctx->statemachine->keyDone = FALSE;
  ctx->statemachine->keyRun = FALSE;
  ctx->statemachine->keyTxEnabled = FALSE;
  ctx->statemachine->portControl = AUTO;
  ctx->statemachine->portEnabled = FALSE;
  ctx->statemachine->portValid = TRUE;
  ctx->statemachine->suppAbort = FALSE;
  ctx->statemachine->suppFail = FALSE;
  ctx->statemachine->suppPortStatus = UNAUTHORIZED;
  ctx->statemachine->suppStart = FALSE;
  ctx->statemachine->suppSuccess = FALSE;
  ctx->statemachine->suppTimeout = FALSE;

  ctx->statemachine->eapRestart = FALSE;
  ctx->statemachine->logoffSent = FALSE;
  ctx->statemachine->sPortMode = AUTO;
  ctx->statemachine->startCount = 0;

  /* Init 802.11i-D3.0 vars. */
  ctx->statemachine->DeauthenticationRequest = FALSE;
  ctx->statemachine->AuthenticationRequest = FALSE;
  ctx->statemachine->AuthenticationFailed = FALSE;
  ctx->statemachine->EAPOLKeyReceived = FALSE;
  ctx->statemachine->IntegrityFailed = FALSE;
  ctx->statemachine->MICVerified = FALSE;
  ctx->statemachine->Counter = 0;

  FREE(ctx->statemachine->SNonce);
  FREE(ctx->statemachine->PTK);
  FREE(ctx->statemachine->TPTK);
  FREE(ctx->statemachine->GTK);

  memcpy(ctx->dest_mac, dot1x_default_dest, 6);

  // No need to free the PMK here, it is a pointer to data in the EAP
  // state machine that will be freed by that deinit function.

  ctx->statemachine->MICfailures = 0;

  memset(ctx->statemachine->replay_counter, 0x00, 6);

  ctx->statemachine->to_authenticated = 0;
  ctx->statemachine->last_reauth = 0;

  ctx->statemachine->curState = DISCONNECTED;

  return XENONE;
}

/**
 * \brief Display the state requested.
 *
 * @param[in] debuglevel   An integer that identifies which debug levels
 *                         the state should be shown at.  (See
 *                         xsup_debug.h for a list of debug levels.)
 *
 * @param[in] state   An integer that identifies the state from the 
 *                    802.1X state machine.
 **/
char *statemachine_disp_state(int state)
{
  switch (state)
    {
    case DISCONNECTED:
      return _strdup("DISCONNECTED");
      break;

    case LOGOFF:
      return _strdup("LOGOFF");
      break;

    case ACQUIRED:   // No longer part of 802.1X in 802.1X-2004.
      return _strdup("ACQUIRED");
      break;

    case AUTHENTICATING:
      return _strdup("AUTHENTICATING");
      break;

    case AUTHENTICATED:
      return _strdup("AUTHENTICATED");
      break;

    case CONNECTING:
      return _strdup("CONNECTING");
      break;

    case HELD:
      return _strdup("HELD");
      break;

    case RESTART:
      return _strdup("RESTART");
      break;

    case S_FORCE_AUTH:
      return _strdup("S_FORCE_AUTH");
      break;

    case S_FORCE_UNAUTH:
      return _strdup("S_FORCE_UNAUTH");
      break;

    default:
      return _strdup("UNKNOWN!");
      break;
    }
}

/**
 * \brief Change state to force authorized state.
 *
 * @param[in] ctx   The context that contains the 802.1X state machine
 *                  that we want to put in force authorized state.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation failure
 **/
int statemachine_change_to_s_force_auth(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // Display the state we are changing to.
  debug_printf(DEBUG_DOT1X_STATE | DEBUG_VERBOSE, "%s -- (global) -> S_FORCE_AUTH\n", ctx->desc);

  // Verify that we have valid parameters.
  if (!ctx)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface context! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, S_FORCE_AUTH) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  // Make the change to the new state, and notify any listening GUIs.
  ctx->statemachine->curState = S_FORCE_AUTH;

#ifdef WINDOWS
  if (cardif_windows_wmi_get_uptime(&ctx->statemachine->last_reauth) != 0)
  {
	debug_printf(DEBUG_NORMAL, "Unable to determine the system uptime.  Your time connected counter will be wrong!\n");
  }

  // Only update the to_authenticated timestamp if this is the first time we authed.
  if (ctx->statemachine->to_authenticated == 0)
	  ctx->statemachine->to_authenticated = ctx->statemachine->last_reauth;
#else
#warning Implement for non-Windows platforms!
#endif

  ctx->statemachine->suppPortStatus = AUTHORIZED;
  ctx->statemachine->sPortMode = FORCE_AUTHORIZED;
  ctx->statemachine->portControl = FORCE_AUTHORIZED;

  // Tell the kernel to move the interface from dormant to "up" state.
  cardif_operstate(ctx, XIF_OPER_UP);

  return XENONE;
}

/**
 * \brief Process S_FORCE_AUTH state.
 *
 * @param[in] ctx   The context that contains the 802.1X state machine 
 *                  that is in S_FORCE_AUTH state.
 **/
void statemachine_do_s_force_auth(context *ctx)
{
	// Nothing to do.
}

/**
 * \brief Change state to force authorized state.
 *
 * @param[in] ctx   The context that contains the 802.1X state machine
 *                  that is in S_FORCE_UNAUTH state.
 *
 * \retval XENONE 
 **/
int statemachine_change_to_s_force_unauth(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // Display the state we are changing to.
  debug_printf((DEBUG_DOT1X_STATE | DEBUG_VERBOSE), "%s -- (global) -> S_FORCE_UNAUTH\n", ctx->desc);

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, S_FORCE_UNAUTH) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  // Make the change to the new state, and notify any listening GUIs.
  ctx->statemachine->curState = S_FORCE_UNAUTH;

  // Clear these timers since we are not authenticated.
  ctx->statemachine->last_reauth = 0;

  ctx->statemachine->suppPortStatus = UNAUTHORIZED;
  ctx->statemachine->sPortMode = FORCE_UNAUTHORIZED;
  ctx->statemachine->portControl = FORCE_UNAUTHORIZED;

  // Send a logoff per 802.1X-2004 8.2.11.10
  txLogoff(ctx);

  return XENONE;
}

/**
 * \brief Processing that needs to happen while in S_FORCE_UNAUTH
 *        state.
 *
 * @param[in] ctx   The context for the interface that is currently in
 *                  S_FORCE_UNAUTH state.
 **/
void statemachine_do_s_force_unauth(context *ctx)
{
  // Nothing to do here.
}

/**
 * \brief Change that 802.1X state machine to LOGOFF state.
 *
 * @param[in] ctx   The context for the interface that is changing to 
 *                  LOGOFF state.
 *
 * \retval XENONE on success
 **/
int statemachine_change_to_logoff(context *ctx)
{
  // Verify that we came from a valid state.

  // Verify our parameters are correct.
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  txLogoff(ctx);
  ctx->statemachine->logoffSent = TRUE;
  ctx->statemachine->suppPortStatus = UNAUTHORIZED;
  ctx->statemachine->curState = LOGOFF;
  ctx->statemachine->to_authenticated = 0;
  ctx->statemachine->last_reauth = 0;

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, LOGOFF) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  eap_sm_force_init(ctx->eap_state);

  if (ctx->intType == ETH_802_11_INT)
  {
	// Clear our keys (since we logged off), and send a disassociate.
	cardif_clear_keys(ctx);
	// There doesn't seem to be a better reason for this disassociation.
	cardif_disassociate(ctx, DISASSOC_UNSPECIFIED);
  }

  return XENONE;
}

/**
 * \brief Process LOGOFF state.
 *
 * @param[in] ctx   The context that contains the 802.1X state machine that
 *                  we are going to transition in to LOGOFF state.
 **/
void statemachine_do_logoff(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if (!ctx->statemachine->userLogoff)
    {
      statemachine_change_state(ctx, DISCONNECTED);
    } 
}

/**
 * \brief Change that 802.1X state machine to disconnected state.
 *
 * @param[in] ctx   The context that contains the 802.1X state machine 
 *                  that will transition to disconnected state.
 * 
 * \retval XENONE on success
 **/
int statemachine_change_to_disconnected(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  ctx->statemachine->sPortMode = AUTO;
  ctx->statemachine->startCount = 0;
  ctx->statemachine->logoffSent = FALSE;
  ctx->statemachine->suppPortStatus = UNAUTHORIZED;
  ctx->statemachine->suppAbort = TRUE;
  ctx->statemachine->last_reauth = 0;

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, DISCONNECTED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  ctx->statemachine->curState = DISCONNECTED;

  return XENONE;
}

/**
 * \brief Process disconnected state.
 *
 * @param[in] ctx   The context for the interface that is in disconnected
 *                  state.
 **/
void statemachine_do_disconnected(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if ((!ctx->statemachine->initialize) &&
      (ctx->statemachine->portEnabled))
    {
      statemachine_change_state(ctx, CONNECTING);
    }
}

/**
 * \brief Change to held state.
 *
 * @param[in] ctx   The context that contains the 802.1X state machine
 *                  that is changing in to HELD state.
 *
 * \retval XENONE on success
 **/
int statemachine_change_to_held(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if ((ctx->statemachine->curState != CONNECTING) &&
      (ctx->statemachine->curState != AUTHENTICATING))
    {
      debug_printf(DEBUG_NORMAL, "Invalid attempt to change to HELD state! "
		   "Going to DISCONNECTED state to attempt to reset the "
		   "state machine!\n");
      return statemachine_change_to_disconnected(ctx);
    }
     
#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, HELD) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  ctx->statemachine->heldWhile = ctx->statemachine->heldPeriod;
  ctx->statemachine->suppPortStatus = UNAUTHORIZED;
  ctx->statemachine->curState = HELD;
  ctx->statemachine->eapolEap = FALSE;
  ctx->statemachine->to_authenticated = 0;
  ctx->statemachine->last_reauth = 0;

  ctx->auths = 0;

  // We failed, so tell the kernel that we have gone dormant.
  cardif_operstate(ctx, XIF_OPER_DORMANT);

  return XENONE;
}

/**
 * \brief Process held state.
 *
 * @param[in] ctx   The context that contains the interface that we need
 *                  to process held state for.
 **/
void statemachine_do_held(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx != NULL", TRUE);

  if (ctx->statemachine->heldWhile == 0)
    {
      statemachine_change_state(ctx, CONNECTING);
      return;
    }
  
  if (ctx->statemachine->eapolEap)
    {
      statemachine_change_state(ctx, RESTART);
      return;
    }
}

/**
 * \brief Change to connecting state.
 *
 * @param[in] ctx   The context for the interface that is changing to
 *                  connecting state.
 *
 * \retval XENONE on success
 **/
int statemachine_change_to_connecting(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  // We should only transition to this state from CONNECTING, HELD, 
  // DISCONNECTED, or AUTHENTICATING.
  if ((ctx->statemachine->curState != CONNECTING) &&
      (ctx->statemachine->curState != HELD) &&
      (ctx->statemachine->curState != DISCONNECTED) &&
      (ctx->statemachine->curState != AUTHENTICATING))
    {
      debug_printf(DEBUG_NORMAL, "Attempt to change to CONNECTING state "
		   "from an invalid state!!  Going to DISCONNECTED state "
		   "to attempt to reset the state machine.\n");
      return statemachine_change_state(ctx, DISCONNECTED);
    }

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, CONNECTING) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  ctx->statemachine->curState = CONNECTING;
  ctx->statemachine->last_reauth = 0;

  if (ctx->statemachine->eapolEap)
    {
      // If we have an EAP message in the buffer, then skip sending a start,
      // and go directly to authenticating.
      statemachine_change_state(ctx, RESTART);
      return XENONE;
    }

  ctx->statemachine->startWhen = ctx->statemachine->startPeriod;
  ctx->statemachine->eapolEap = FALSE;

  if (ctx->conn != NULL)
  {
	  // If we don't have a connection defined, we don't want to bother with starts.
	  // We do want to continue to run the state machine, however, so that we can attempt to
	  // gather EAP hints.
	ctx->statemachine->startCount = ctx->statemachine->startCount + 1;
	txStart(ctx);
  }

  return XENONE;
}

/**
 * \brief Process connecting state.
 *
 * @param[in] ctx   The context for the interface that we want to 
 *                  process connecting state for.
 **/
void statemachine_do_connecting(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);
  xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

  if ((ctx->statemachine->startWhen == 0) &&
      (ctx->statemachine->startCount < ctx->statemachine->maxStart))
    {
      // Change to connecting state again.
      statemachine_change_state(ctx, CONNECTING);
      return;
    }
  
  if (((ctx->statemachine->startWhen == 0) &&
       (ctx->statemachine->startCount >= ctx->statemachine->maxStart)
       && ctx->statemachine->portValid))
    {
      // Here, we have defaulted in to authenticated state.  We should
      // display a message to the user to avoid confusion, and terminate
      // if we were asked to.
      debug_printf(DEBUG_NORMAL, "Xsupplicant has defaulted to "
		   "authenticated state on interface '%s', due to the inability to "
		   "successfully start/complete an EAP conversation.  It "
		   "is likely that this authenticator doesn't support "
		   "802.1X, or that 802.1X isn't configured correctly "
		   "on the authenticator or RADIUS server.\n", ctx->desc);

      statemachine_change_state(ctx, S_FORCE_AUTH);
      
      if (ctx->flags & TERM_ON_FAIL)
	{
	  // We have been instructed to terminate.  So, do it cleanly.
	  global_deinit();
	}
      return;
    }
  
  if (ctx->eap_state->eapSuccess || ctx->eap_state->eapFail)
    {
      statemachine_change_state(ctx, AUTHENTICATING);
      return;
    }
  
  if (ctx->statemachine->eapolEap)
    {
      statemachine_change_state(ctx, RESTART);
      return;
    }
  
  if ((ctx->statemachine->startWhen == 0) &&
      (ctx->statemachine->startCount >= ctx->statemachine->maxStart)
      && !ctx->statemachine->portValid)
    {
      statemachine_change_state(ctx, HELD);
      return;
    }
}

/**
 * \brief Change to restart state.
 *
 * @param[in] ctx   The context for the interface that we are changing
 *                  to restart state.
 *
 * \retval XENONE on success
 **/
int statemachine_change_to_restart(context *ctx)
{
	int recv = 0;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  // We should only get here from AUTHENTICATED, CONNECTING, or HELD states.
  if ((ctx->statemachine->curState != AUTHENTICATED) &&
      (ctx->statemachine->curState != CONNECTING) &&
      (ctx->statemachine->curState != HELD) &&
	  (ctx->statemachine->curState != S_FORCE_AUTH) &&
	  (ctx->statemachine->curState != S_FORCE_UNAUTH))
    {
      debug_printf(DEBUG_NORMAL, "Attempt to change to RESTART state from "
		   "an invalid state!  Changing to DISCONNECTED state to "
		   "attempt to recover the state machine.  (Previous state was %d)\n", ctx->statemachine->curState);
      return statemachine_change_state(ctx, DISCONNECTED);
    }

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, RESTART) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  ctx->statemachine->eapRestart = TRUE;
  ctx->statemachine->curState = RESTART;
  ctx->statemachine->last_reauth = 0;

  recv = ctx->statemachine->eapReq;
  ctx->statemachine->portControl = AUTO;

	// Make sure we don't try to go to received state after initialize.  It would be bad.
	ctx->statemachine->eapReq = FALSE;

  backend_sm_run(ctx);

  // However, from here it would be a good thing!
	ctx->statemachine->eapReq = recv;

  if (ctx->statemachine->eapRestart == FALSE)
	  statemachine_change_state(ctx, AUTHENTICATING);

  return XENONE;
}

/**
 * \brief Process restart state.
 *
 * @param[in] ctx   The context for the interface that is currently in
 *                  restart state.
 **/
void statemachine_do_restart(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if (!ctx->statemachine->eapRestart)
    {
      statemachine_change_state(ctx, AUTHENTICATING);
      return;
    }
}

/**
 * \brief Switch to authenticating state.
 *
 * @param[in] ctx   The context for the interface that is changing to
 *                  authenticating state.
 *
 * \retval XENONE on success
 **/
int statemachine_change_to_authenticating(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  // We can only reach authenticating state from CONNECTING or RESTART
  // states.
  if ((ctx->statemachine->curState != CONNECTING) &&
      (ctx->statemachine->curState != RESTART))
    {
      debug_printf(DEBUG_NORMAL, "Attempt to change to AUTHENTICATING state "
		   "from an invalid state!\n");
      return statemachine_change_state(ctx, DISCONNECTED);
    }

  ctx->statemachine->startCount = 0;
  ctx->statemachine->suppSuccess = FALSE;
  ctx->statemachine->suppFail = FALSE;
  ctx->statemachine->suppTimeout = FALSE;
  ctx->statemachine->keyRun = FALSE;
  ctx->statemachine->keyDone = FALSE;
  ctx->statemachine->suppStart = TRUE;
  ctx->statemachine->last_reauth = 0;

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, AUTHENTICATING) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  ctx->statemachine->curState = AUTHENTICATING;

  return XENONE;
}

/**
 * \brief Process authenticating state.
 *
 * @param[in] ctx   The context for the interface that is in
 *                  authenticating state.
 **/
void statemachine_do_authenticating(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if (ctx->statemachine->suppSuccess &&
      ctx->statemachine->portValid)
    {
      statemachine_change_state(ctx, AUTHENTICATED);
      return;
    }
  
  if (ctx->statemachine->suppFail || (ctx->statemachine->keyDone &&
				      !ctx->statemachine->portValid))
    {
      statemachine_change_state(ctx, HELD);
      return;
    }
  
  if (ctx->statemachine->suppTimeout)
    {
      statemachine_change_state(ctx, CONNECTING);
      return;
    }
}

/**
 * \brief Change to authenticated state.
 *
 * @param[in] ctx   The context for the interface that is changing to 
 *                  authenticated state.
 *
 * \retval XENONE on success
 **/
int statemachine_change_to_authenticated(context *ctx)
{
  struct config_globals *globals;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);
  
  ctx->statemachine->suppPortStatus = AUTHORIZED;

#if DOT1X_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_8021X, ctx->statemachine->curState, AUTHENTICATED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC 802.1X state change message!\n");
  }
#endif

  ctx->statemachine->curState = AUTHENTICATED;
  ctx->statemachine->eapolEap = FALSE;

#ifdef WINDOWS
  if (cardif_windows_wmi_get_uptime(&ctx->statemachine->last_reauth) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't determine the current uptime.  Your time authenticated counter will be wrong.\n");
  }

  // Don't update the to_authenticated timer unless it has not been set yet.  to_authenticated will be used to determine
  // how long we have been in an authenticated state.
  if (ctx->statemachine->to_authenticated == 0)
	  ctx->statemachine->to_authenticated = ctx->statemachine->last_reauth;
#else
#warning Implement on non-Windows OSes.
#endif

#ifdef DARWIN_WIRELESS
  if (cardif_macosx_wireless_set_key_material(ctx) != XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't apply keys to the interface!\n");
    }
#endif

  // Tell the kernel to move the interface from dormant to "up" state.
  cardif_operstate(ctx, XIF_OPER_UP);

  // Since we changed to authenticated state, we want to start the passive
  // scan timer, if the user hasn't disabled it.
  globals = config_get_globals();

  if ((!globals) || (TEST_FLAG(globals->flags, CONFIG_GLOBALS_PASSIVE_SCAN)))
    {
      // Start scan timer.
      if (timer_check_existing(ctx, PASSIVE_SCAN_TIMER) == FALSE)
	{
	  // Set up a new timer, since this is the first time we have set a timer.
	  debug_printf((DEBUG_DOT1X_STATE | DEBUG_VERBOSE), "Starting new passive scan timer.\n");
	  timer_add_timer(ctx, PASSIVE_SCAN_TIMER, globals->passive_timeout, NULL,
			  cardif_passive_scan_timeout);
	} 
      else
	{
	  // Reset the timer so we don't scan sooner than needed.
	  debug_printf((DEBUG_DOT1X_STATE | DEBUG_VERBOSE), "Resetting passive scan timer.\n");
	  timer_reset_timer_count(ctx, PASSIVE_SCAN_TIMER, 
				  globals->passive_timeout);
	}
    }

  snmp_dump_stats(ctx->intName);

  return XENONE;
}

/**
 *  This is a layer violation, but is needed to verify that if we get
 * an inner success followed by an outer success that we don't reset the
 * state machine and cause keying to fail.
 **/
int statemachine_is_success(context *ctx)
{
  struct eap_header *eapdata;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return FALSE;

  if (!xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((ctx->eap_state->eapReqData != NULL), 
		   "ctx->eap_state->eapReqData != NULL", FALSE)) return FALSE;

  eapdata = (struct eap_header *)ctx->eap_state->eapReqData;

  if (eapdata->eap_code == EAP_SUCCESS_PKT) return TRUE;

  return FALSE;
}

/**
 * \brief Process authenticated state.
 *
 * @param[in] ctx   The context that contains the interface that is in
 *                  authenticated state.
 **/
void statemachine_do_authenticated(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if ((ctx->statemachine->eapolEap == TRUE) && (eapol_get_eap_type(ctx) == EAP_SUCCESS_PKT))
  {
	  ctx->statemachine->eapolEap = FALSE;
	  debug_printf(DEBUG_DOT1X_STATE, "Looks like another success...  Discarding.\n");
	  FREE(ctx->recvframe);
	  ctx->recv_size = 0;
  }

  if ((ctx->statemachine->eapolEap == TRUE) && (ctx->statemachine->portValid == TRUE) 
	  && (eapol_get_eap_type(ctx) != EAP_SUCCESS_PKT))
    {
		if (eapol_get_eap_type(ctx) == EAP_SUCCESS_PKT)
		{
			printf("How did I get here!?\n");
		}
	
#ifdef HAVE_TNC
		if(imc_disconnect_callback != NULL)
			imc_disconnect_callback(ctx->tnc_connID);
#endif

	  statemachine_change_state(ctx, RESTART);
      return;
    } 
  
  if (!ctx->statemachine->portValid)
    {
#ifdef HAVE_TNC
		if(imc_disconnect_callback != NULL)
			imc_disconnect_callback(ctx->tnc_connID);
#endif
      statemachine_change_state(ctx, DISCONNECTED);
      return;
    }
}

/**
 * \brief Change from whatever state we are currently in, to a new state.
 *
 * @param[in] ctx   The context for the interface that is changing state.
 * @param[in] newstate   The state that this interface is changing to.
 *
 * \retval XENONE on success
 * \retval !XENONE on failure
 **/
int statemachine_change_state(context *ctx, int newstate)
{
  int retval = XENONE;
  char *fromstate = NULL;
  char *tostate = NULL;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  fromstate = statemachine_disp_state(ctx->statemachine->curState);
  tostate = statemachine_disp_state(newstate);

  debug_printf((DEBUG_DOT1X_STATE | DEBUG_VERBOSE), "%s - Changing from %s to %s.\n", ctx->desc, fromstate, tostate);

  FREE(fromstate);
  FREE(tostate);

  switch (newstate)
    {
    case LOGOFF:
      retval=statemachine_change_to_logoff(ctx);
      break;

    case DISCONNECTED:
      retval=statemachine_change_to_disconnected(ctx);
      break;

    case CONNECTING:
      retval=statemachine_change_to_connecting(ctx);
      break;

    case ACQUIRED:
      debug_printf(DEBUG_NORMAL, "Attempt to change to ACQUIRED state. "
		   "WTF are you doing!?\n");
      retval=statemachine_change_to_disconnected(ctx);
      break;

    case AUTHENTICATING:
      retval=statemachine_change_to_authenticating(ctx);
      break;

    case HELD:
      retval=statemachine_change_to_held(ctx);
      break;

    case AUTHENTICATED:
      retval=statemachine_change_to_authenticated(ctx);
      break;

    case RESTART:
      retval=statemachine_change_to_restart(ctx);
      break;

    case S_FORCE_AUTH:
      retval=statemachine_change_to_s_force_auth(ctx);
      break;

    case S_FORCE_UNAUTH:
      retval=statemachine_change_to_s_force_unauth(ctx);
      break;
    }

  return retval;
}

/**
 * \brief Check for cases where we should change state no matter what 
 *        state we are currently in.
 *
 * @param[in] ctx   The context that we are checking on state changes
 *                  against.
 **/
void statemachine_check_global_transition(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);

  if ((ctx->statemachine->userLogoff && !ctx->statemachine->logoffSent)
      && !(ctx->statemachine->initialize || 
	   !ctx->statemachine->portEnabled))
    {
      statemachine_change_state(ctx, LOGOFF);
    }

  if ((ctx->statemachine->portControl == FORCE_AUTHORIZED) &&
      (ctx->statemachine->sPortMode != ctx->statemachine->portControl)
      && !(ctx->statemachine->initialize || 
	   !ctx->statemachine->portEnabled))
    {
      statemachine_change_state(ctx, S_FORCE_AUTH);
    }

  if ((ctx->statemachine->portControl == FORCE_UNAUTHORIZED) &&
      (ctx->statemachine->sPortMode != ctx->statemachine->portControl)
      && !(ctx->statemachine->initialize ||
	   !ctx->statemachine->portEnabled))
    {
      statemachine_change_state(ctx, S_FORCE_UNAUTH);
    }

  if (((ctx->statemachine->portControl == AUTO) &&
      ((ctx->statemachine->sPortMode != ctx->statemachine->portControl)
      || ctx->statemachine->initialize || 
	  !ctx->statemachine->portEnabled)) && (ctx->statemachine->curState != DISCONNECTED))
    {
      statemachine_change_state(ctx, DISCONNECTED);
    }
}

/**
 * \brief Update all state machine timers.
 *
 * @param[in] ctx   The context that contains the timers that we will be
 *                  updating.
 **/
void statemachine_timer_tick(context *ctx)
{
	char *curstate = NULL;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL", TRUE);
  xsup_assert((ctx->eap_state != NULL), "ctx->eap_state != NULL", TRUE);

  // The clock ticked -- Update all of the needed counters.
  dec_if_nz((uint8_t *)&ctx->statemachine->authWhile);
  dec_if_nz((uint8_t *)&ctx->statemachine->heldWhile);
  dec_if_nz((uint8_t *)&ctx->statemachine->startWhen);
  dec_if_nz((uint8_t *)&ctx->eap_state->idleWhile);
  
  ctx->statemachine->tick = FALSE;
  curstate = statemachine_disp_state(ctx->statemachine->curState);

  debug_printf(DEBUG_DOT1X_STATE, "Clock tick for '%s'! authWhile=%d heldWhile=%d "
	  "startWhen=%d curState=%s\n", ctx->desc,
	       ctx->statemachine->authWhile,
	       ctx->statemachine->heldWhile,
	       ctx->statemachine->startWhen, curstate);
  FREE(curstate);
}

/**
 * \brief Process the state machine, send a frame if we need to.
 * 
 * @param[in] ctx   The context for the interface that we would like to 
 *                  process.
 *
 * \retval >0 if there is a frame to be sent.
 * \retval XENONE if there is nothing to do.
 **/
int statemachine_run(context *ctx)
{
	int resval = 0;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);
  xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
	      TRUE);

  if (ctx->statemachine->tick == TRUE)
    {
      statemachine_timer_tick(ctx);

      statemachine_check_global_transition(ctx);
    }

//  ctx->statemachine->portEnabled = cardif_get_if_state(ctx);
  ctx->statemachine->portEnabled = cardif_get_link_state(ctx);
  
  /*
  if (ctx->statemachine->portEnabled == FALSE)
    {
      // Change our wireless state to port down state.
      wireless_sm_change_state(PORT_DOWN, ctx);

      return XENONE;
    }
	*/

  switch(ctx->statemachine->curState)
    {
    case S_FORCE_AUTH:
      statemachine_do_s_force_auth(ctx);
      break;

    case S_FORCE_UNAUTH:
      statemachine_do_s_force_unauth(ctx);
      break;

    case LOGOFF:
      statemachine_do_logoff(ctx);
      break;

    case DISCONNECTED:
      statemachine_do_disconnected(ctx);
      break;

    case HELD:
      statemachine_do_held(ctx);
      break;

    case CONNECTING:
      statemachine_do_connecting(ctx);
      break;

    case RESTART:
      statemachine_do_restart(ctx);
      break;

    case AUTHENTICATING:
      statemachine_do_authenticating(ctx);
      break;

    case AUTHENTICATED:
      statemachine_do_authenticated(ctx);
      break;
    }

  if ((ctx->statemachine->curState != S_FORCE_AUTH) && (ctx->statemachine->curState != S_FORCE_UNAUTH))
  {
	  resval = backend_sm_run(ctx);
  }
  else
  {
	  resval = XENONE;
  }

  ctx->recv_size = 0;   // Flush the frame that should now be processed.
  return resval;
}

/**
 * \brief Clean up our state machine.
 *
 * @param[in] ctx   The context that contains the state machine that we 
 *                  need to clean up.
 *
 * \retval XEMALLOC if there is a problem with the context.
 * \retval XENONE on success
 **/
int statemachine_cleanup(context *ctx)
{
  debug_printf((DEBUG_DOT1X_STATE | DEBUG_DEINIT | DEBUG_VERBOSE), "Doing statemachine cleanup!\n");

  if (!ctx)
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to statemachine_cleanup()!\n");
      return XEMALLOC;
    }

  backend_sm_deinit(ctx);

  FREE(ctx->statemachine->SNonce);
  FREE(ctx->statemachine->PTK);

  FREE(ctx->statemachine);

  return XENONE;
}



/**
 * \brief Create a logoff frame to be sent out to the network.
 *
 * @param[in] ctx   The context that contains the interface that we
 *                  want to send a LOGOFF for.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory related errors
 **/
int txLogoff(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ctx->sendframe != NULL), "ctx->sendframe != NULL",
		   FALSE))
    return XEMALLOC;

  // Don't try to send data if the interface isn't available to send it. ;)
  if ((TEST_FLAG(ctx->flags, INT_GONE)) || (ctx->statemachine->portEnabled == FALSE))
	  return XENONE;

  if ((ctx->prof == NULL) || (ctx->prof->method == NULL))
    {
      debug_printf(DEBUG_DEINIT, "No network information available for interface '%s'.  Assuming"
		   " we don't need to send a logoff.\n", ctx->desc);
      return XENONE;
    }

  if (ctx->conn == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "No connection information available for interface '%s'.  Not sending LOGOFF!\n",
		  ctx->desc);
	  return XENONE;
  }

  // If we aren't using 802.1X don't send logoffs.
  if ((ctx->conn->association.auth_type == AUTH_NONE) &&
	  ((ctx->conn->association.association_type == ASSOC_AUTO) ||
	  (ctx->conn->association.association_type == ASSOC_OPEN) ||
	  (ctx->conn->association.association_type == ASSOC_SHARED))) return XENONE;

  // If we are using WPA-PSK, don't send logoffs.
  if (ctx->conn->association.auth_type == AUTH_PSK) return XENONE;

  debug_printf(DEBUG_DOT1X_STATE, "Sending EAPOL-Logoff Frame.\n");

  eapol_build_header(ctx, EAPOL_LOGOFF, 0, (char *) ctx->sendframe);
  ctx->send_size = OFFSET_TO_EAP;

  snmp_dot1xSuppEapolLogoffFramesTx();

  cardif_sendframe(ctx);

  return XENONE;
}


/**
 * \brief Build an EAPoL Start frame to be sent out to the network.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to send the start frame out on.
 *
 * \retval XEMALLOC on memory related errors.
 * \retval XENONE on success
 **/
int txStart(context *ctx)
{
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (ctx->conn != NULL)
    {
		if (((ctx->conn->association.association_type == ASSOC_WPA) || 
			(ctx->conn->association.association_type == ASSOC_WPA2)) &&
			(ctx->conn->association.auth_type == AUTH_PSK) )
	{
	  debug_printf(DEBUG_DOT1X_STATE, "Doing WPA-PSK.. Not sending start!\n");
	  return XENONE;
	}
    }

  debug_printf(DEBUG_DOT1X_STATE, "Sending EAPOL-Start Frame.\n");

  if (ctx->sendframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There was no buffer allocated to send the "
		   "frame!\n");
      return XEMALLOC;
    }

	// We should *ALWAYS* send a start to the multicast address.  (If it is wired.)
  if (ctx->intType == ETH_802_11_INT)
  {
	memcpy(ctx->dest_mac, dot1x_default_dest, 6);
  }
  
  eapol_build_header(ctx, EAPOL_START, 0, (char *) ctx->sendframe);
  ctx->send_size = OFFSET_TO_EAP;

  snmp_dot1xSuppEapolStartFramesTx();

  cardif_sendframe(ctx);

  return XENONE; 
}
