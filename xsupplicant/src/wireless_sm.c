/**
 *
 * \file wireless_sm.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <stdlib.h>

#ifndef WINDOWS
#include <unistd.h>
#include <inttypes.h>
#endif

#include <string.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "wireless_sm.h"
#include "eapol.h"
#include "event_core.h"
#include "platform/cardif.h"
#include "config_ssid.h"
#include "timer.h"
#include "statemachine.h"
#include "platform/linux/cardif_linux_wext.h"
#include "eap_sm.h"
#include "ipc_events.h"
#include "ipc_callout.h"
#include "ipc_events_index.h"
#include "wpa_common.h"
#include "config_ssid.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define WIRELESS_SM_EVENTS 1  ///< Change this to 0 to disable sending of state change events via IPC.

#define INT_HELD_TIMEOUT    10 // Seconds.

void set_static_wep_keys(context *, struct config_association *);

// This is in mschapv2.c.  We need it for the static WEP piece.
extern void process_hex(char *, int, char *);

/**
 * \brief Return the current state that we are in.
 *
 * @param[in] ctx   The context for the interface we want to get the
 *                  state of.
 *
 * \retval uint8_t   A numeric representation of the state the physical interface
 *                   specified by "ctx" is in.  (States are listed in wireless_sm.h)
 **/
uint8_t wireless_sm_get_state(context *ctx)
{
	wireless_ctx *wctx;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return UNKNOWN;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return UNKNOWN;

  return wctx->state;
}

/**
 * \brief Initialize our wireless statemachine.  We should always start in
 *        ACTIVE_SCAN mode, since we won't know anything about the SSID we
 *        are attempting to connect to.
 *
 * @param[in] zeros_on_roam   Should we reset all of the WEP keys to 0s when we lose
 *                            the association to an AP.  
 * @param[in] ctx   The context for the interface that we wish to init.
 *
 **/
void wireless_sm_init(int zeros_on_roam, context *ctx)
{
   wireless_ctx *wctx = NULL;

   if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
     return;

   wctx = (wireless_ctx *)ctx->intTypeData;

   if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

   debug_printf(DEBUG_INIT | DEBUG_PHYSICAL_STATE, "Init wireless state machine.\n");
   
   if (cardif_get_if_state(ctx) == FALSE)
     {
       // Our interface is currently down.  So go to PORT_DOWN mode.
       wireless_sm_change_state(PORT_DOWN, ctx);
     } else {
       wireless_sm_change_state(ACTIVE_SCAN, ctx);
     }
   
   if (zeros_on_roam == TRUE) 
     {
       SET_FLAG(wctx->flags, WIRELESS_ZEROS_ON_ROAM);
     } else {
       UNSET_FLAG(wctx->flags, WIRELESS_ZEROS_ON_ROAM);
     }
   
   // Probably don't need to do this here, but do it anyway for good 
   // measure, unless we determine it causes a problem for some cards.
   if ((ctx->conn == NULL) || (ctx->conn->association.txkey == 0))
     {
       cardif_clear_keys(ctx);
     }
   else
     {
		 set_static_wep_keys(ctx, &ctx->conn->association);
     }
}

/**
 * \brief The timeout function for the timer that will notify the UI if the
 *        signal strength has changed.
 *
 * This timeout should get called every 5 seconds while the interface is
 * associated.  (And possibly once after the interface is no longer associated,
 * in which case the timer should cancel itself.)
 *
 * @param[in] ctx   The context of the interface this triggered this 
 *                  timeout.
 **/
void wireless_sm_sig_strength_timeout(context *ctx)
{
	wireless_ctx *wctx = NULL;
	char temp[5];
	uint8_t value;

	TRACE

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
  {
	  // If the context is invalid, clean ourselves up and move on.
	  timer_cancel(ctx, SIG_STRENGTH);
	  return;
  }

  // Verify that we are still associated
  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
  {
	  debug_printf(DEBUG_NORMAL, "A signal strength timer expried on interface '%s'"
		  "that doesn't appear to be wireless!\n", ctx->desc);
	  timer_cancel(ctx, SIG_STRENGTH);
	  return;
  }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (wctx->state != ASSOCIATED)
  {
	  debug_printf(DEBUG_PHYSICAL_STATE, "Interface '%s' is no longer associated.  Turning off "
		  "signal strength update timer.\n", ctx->desc); 
	  timer_cancel(ctx, SIG_STRENGTH);
	  return;
  }

  // XXX At some point, we should provide a configurable way to generate the
  //  signal strength updates, so that if we come across an OS that does it without
  //  polling we can use that.
  value = cardif_get_signal_strength_percent(ctx);

  if (wctx->strength != value)
  {
	sprintf((char *)&temp, "%d", value);

	ipc_events_ui(ctx, IPC_EVENT_SIGNAL_STRENGTH, temp);

	wctx->strength = value;
  }

  // Reset the timer to run again in 5 seconds.
  timer_reset_timer_count(ctx, SIG_STRENGTH, 5);
}

/**
 * \brief Set up the signal strength timer to trigger every 5 seconds.
 *
 * @param[in] ctx   The context that should be passed to the signal strength timer, 
 *                  when the timer expires.
 **/
void wireless_sm_set_sig_strength_timer(context *ctx)
{
	if (timer_check_existing(ctx, SIG_STRENGTH) != TRUE)
	{
		// Set the "update RSSI" timer to happen every 5 seconds.
		timer_add_timer(ctx, SIG_STRENGTH, 5, NULL, wireless_sm_sig_strength_timeout);
	}
	
	// Otherwise, the timer is already going, so ignore this request.
}

/**
 * Sets the WEP keys according to the config_static_wep structure.
 * This is used with the initial_wep setting and with static_wep.
 *
 * @todo It may be a good idea to clear the keys not being set
 *
 * @param[in] ctx     The interface data
 * @param[in] assoc   A pointer to the configuration data that contains the
 *                    state WEP keys that we want to set.
 */
void set_static_wep_keys(context *ctx, struct config_association *assoc)
{
   int keyidx, klen, t;
   char key[26];

   if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
     return;

   if (!xsup_assert((assoc != NULL), "assoc != NULL", FALSE))
     return;

   for (keyidx = 1; keyidx < 5; keyidx++)
   {
	   if (assoc->keys[keyidx] != NULL)
      {
		  if (assoc->keys[keyidx] != NULL)
		  {
			klen = strlen((char *)assoc->keys[keyidx]);
         if (((klen/2) == 5) || ((klen/2) == 13))
         {
            // We have a valid length key.  So, convert it, and set it.
			 process_hex((char *)assoc->keys[keyidx], klen, key);

            // Calculate the proper key index.
            t = keyidx-1;

			if (keyidx == assoc->txkey)
            {
               debug_printf(DEBUG_PHYSICAL_STATE, "%s: Setting TX key! [%d]\n",
				   __FUNCTION__, assoc->txkey);
               t |= 0x80;
               cardif_set_wep_key(ctx, (uint8_t *)key, (klen/2), t);
            }
            else
            {
               cardif_set_wep_key(ctx, (uint8_t *)key, (klen/2), t);
            }
			}
         }
      }
   }
}


/**
 * \brief Deinit our wireless statemachine.  Currently does nothing, but is 
 *        included to maintain the init/active/deinit model.
 *
 * @param[in] wctx   The wireless context to deinit.
 **/
void wireless_sm_deinit(wireless_ctx *wctx)
{
}

/**
 * \brief Print out the text value for the state that we have been passed.
 *
 * \note This will only output to the console, or trace files.
 *
 * @param[in] debug_level   An integer that specifies what debug levels should
 *                          display this message.  (Defined in xsup_debug.h)
 * @param[in] showstate   An integer that specifies the state that we want to 
 *                        print an ASCII version of.  (Defined in wireless_sm.h)
 **/
void wireless_sm_disp_state(int debug_level, int showstate)
{
  switch (showstate)
    {
    case UNASSOCIATED:
      debug_printf_nl(debug_level, "UNASSOCIATED");
      break;

    case ASSOCIATED:
      debug_printf_nl(debug_level, "ASSOCIATED");
      break;

    case ACTIVE_SCAN:
      debug_printf_nl(debug_level, "ACTIVE_SCAN");
      break;

    case ASSOCIATING:
      debug_printf_nl(debug_level, "ASSOCIATING");
      break;

    case ASSOCIATION_TIMEOUT_S:
      debug_printf_nl(debug_level, "ASSOCIATION_TIMEOUT");
      break;

    case PORT_DOWN:
      debug_printf_nl(debug_level, "PORT_DOWN");
      break;

    case NO_ENC_ASSOCIATION:
      debug_printf_nl(debug_level, "NO_ENC_ASSOCIATION");
      break;

    case INT_RESTART:
      debug_printf_nl(debug_level, "INT_RESTART");
      break;

    case INT_STOPPED:
      debug_printf_nl(debug_level, "INT_STOPPED");
      break;

	case INT_HELD:
		debug_printf_nl(debug_level, "INT_HELD");
		break;

    default:
      debug_printf_nl(debug_level, "UNKNOWN");
      break;
    }
}

/**
 * \brief Display information about a wireless state machine state change.
 *
 * \note  This function will only output to the console, or trace file.  It will
 *        *NOT* generate events for async listeners!
 *
 * @param[in] debug_level   An integer that specifies the debug level that this
 *                          should be displayed for.
 * @param[in] ctx   The context for the interface that the state change occurred on.
 * @param[in] newstate   The state that this interface has changed to.
 **/
void wireless_sm_disp_state_change(int debug_level, context *ctx, int newstate)
{
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	wctx = (wireless_ctx *)ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  wireless_sm_disp_state(debug_level, wctx->state);
  debug_printf_nl(debug_level, " -> ");
  wireless_sm_disp_state(debug_level, newstate);
  debug_printf_nl(debug_level, "\n");
}

/**
 * \brief Change to unassociated state.  This function should verify that 
 *        everything is in place to allow us to change state.  If it is, then
 *        it should do any setup for the new state, and update the current state
 *        variable for it's context.
 *
 * @param[in] ctx   The context for the interface that is changing to unassociated
 *                  state.
 **/
void wireless_sm_change_to_unassociated(context *ctx)
{
	wireless_ctx *wctx;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

#ifdef DARWIN
  // Macs don't have an event generation system to let us know when we have
  // associated, or disassociated.  So, we need this code.  Enabling this
  // code on other platforms may have strange results.

  if (cardif_check_associated(ctx) == TRUE)
    {
      // False positive.
      debug_printf(DEBUG_PHYSICAL_STATE, "Switched to disassociated state when we really"
		   " are associated!  This may be due to a late event.\n");
      wireless_sm_change_state(ASSOCIATED, ctx);
      return;
    }
#endif

  if (wctx->state != ASSOCIATED)
    {
      // Only change to unassociated state if we are already in associated
      // state.
		debug_printf(DEBUG_PHYSICAL_STATE, "Not changing to unassociated state because we weren't "
				"associated!  Current state is ");
		wireless_sm_disp_state(DEBUG_PHYSICAL_STATE, wctx->state);
		debug_printf_nl(DEBUG_PHYSICAL_STATE, "\n");
      return;
    }

  debug_printf(DEBUG_NORMAL, "The wireless card is not associated to an AP.\n");
  wctx->assoc_type = ASSOC_TYPE_UNKNOWN;

  // We are allowed to switch from any state to unassociated state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, UNASSOCIATED);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, UNASSOCIATED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  statemachine_reinit(ctx);

  // Update our state variables to indicate what state we are in now.
  wctx->state = UNASSOCIATED;

  // Then, switch to active scan state to see if we can associate again.
  wireless_sm_change_state(ACTIVE_SCAN, ctx);
}

/**
 * \brief Change to ACTIVE_SCAN state.  This function is called once when
 *        the state machine transitions to ACTIVE_SCAN.  It should set up
 *        anything that is needed to operate in ACTIVE_SCAN state, and
 *        make any one time calls/changes that need to be made.
 *
 * @param[in] ctx   The context for the interface that is transitioning
 *                  to ACTIVE_SCAN state.
 **/
void wireless_sm_change_to_active_scan(context *ctx)
{
	wireless_ctx *wctx = NULL;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  // Make sure that last state we were in has a valid transition to this
  // state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, ACTIVE_SCAN);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, ACTIVE_SCAN) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  // Clear our keys.
  cardif_clear_keys(ctx);

  UNSET_FLAG(wctx->flags, WIRELESS_CHECKED);

  debug_printf(DEBUG_NORMAL, "Interface '%s' is scanning for wireless networks.  Please wait."
	  "\n", ctx->desc);

#if 0
  if (ipc_events_scanning(ctx) == IPC_SUCCESS)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't send log event!\n");
  }
#endif

  /*
    // XXX This code is broken!
  if ((wireless_sm->state == ASSOCIATING) ||
      (wireless_sm->state == ASSOCIATED))
    {
      abil = config_ssid_get_ssid_abilities();

      // We only flip the zeros on roam bit if we are doing WEP.
      if ((!(abil & WPA_IE)) && (!(abil & RSN_IE)))
	{
	  // We switched to active scan from associating, so flip the
	  // zeros on roam bit.
	  if (TEST_FLAG(wireless_sm->flags, ZEROSONROAM))
	    {
	      debug_printf(DEBUG_PHYSICAL_STATE, "Next association will attempt to use no"
			   " encryption.\n");
	      UNSET_FLAG(wireless_sm->flags, ZEROSONROAM);
	    } else {
	      debug_printf(DEBUG_PHYSICAL_STATE, "Next association will attempt to use all"
			   " zeros.\n");
	      SET_FLAG(wireless_sm->flags, ZEROSONROAM);
	    }
	}
    }
  */

  // Update our state variables to indicate what state we are in now.
  wctx->state = ACTIVE_SCAN;
  UNSET_FLAG(wctx->flags, WIRELESS_SM_INIT);
  UNSET_FLAG(wctx->flags, WIRELESS_SM_SSID_CHANGE);

  // Do any setup that is needed to enter the new state.
  statemachine_reinit(ctx);
  if (cardif_do_wireless_scan(ctx, FALSE) != XENONE)
  {
	  debug_printf(DEBUG_NORMAL, "There was an error starting a scan.\n");
	  timer_cancel(ctx, SCANCHECK_TIMER);  // Cancel the scan check timer, if it was started.
	  wireless_sm_change_state(INT_HELD, ctx);
  }
}

/********************************************************************
 * 
 *  Callback for when the INT_HELD timer expires.
 *
 ********************************************************************/
uint8_t wireless_sm_int_held_timeout(context *ctx)
{
	wireless_ctx *wctx;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  xsup_assert((wctx != NULL), "wctx != NULL", TRUE);

	timer_cancel(ctx, INT_HELD_TIMER);

	// If we switched states while waiting, we don't want to do anything, the
	// state machine should have already handled it.
	if (wctx->state == INT_HELD) wireless_sm_change_state(ACTIVE_SCAN, ctx);
	return XENONE;
}

/********************************************************************
 *
 *  Do INT_HELD state.
 *
 ********************************************************************/
void wireless_sm_do_int_held(context *ctx)
{
	TRACE
	// Nothing to do here.
}

/**
 * \brief Change to INT_HELD state.  This function is called once when
 *        the physical state machine transitions in to INT_HELD state.
 *        It should set up or change anything that will be needed while
 *        in this state, and update the state context variables.
 *
 * @param[in] ctx   The context for the physical interface that is
 *                  attempting to transition to HELD state.
 **/
void wireless_sm_change_to_int_held(context *ctx)
{
  wireless_ctx *wctx = NULL;

  TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;
  // Make sure that last state we were in has a valid transition to this
  // state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, INT_HELD);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, INT_HELD) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif
  
  UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);
	timer_add_timer(ctx, INT_HELD_TIMER, INT_HELD_TIMEOUT, NULL, wireless_sm_int_held_timeout);
	wctx->state = INT_HELD;
}

/**
 * \brief Change to ASSOCIATED state.  This is called once when the state
 *        machine transitions to ASSOCIATED state.  It should verify that
 *        everything is ready for it to transition, setup or change 
 *        any variables that need to be changed, and update the state
 *        variables for the context.
 *
 * @param[in] ctx   The context for the interface that is transitioning
 *                  to associated state.
 *
 * \todo The replay counter doesn't belong in the state machine, since it is a lower layer
 *       structure.  Move it!
 **/
void wireless_sm_change_to_associated(context *ctx)
{
	wireless_ctx *wctx = NULL;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING)) 
  {
	  if (config_ssid_ssid_known(wctx, wctx->cur_essid) == TRUE)
	  {
		  debug_printf(DEBUG_PHYSICAL_STATE, "We know enough about this SSID to skip the scanning, and "
			  "move on.\n");
		  timer_cancel(ctx, SCANCHECK_TIMER);
	  }
	  else
	  {
		return;   // Don't want to switch to associated while
    		      // we are scanning if we don't know anything about the SSID.  It makes a mess! ;)
	  }
  }

  SET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);  // Keep us from retriggering
														 // this state!

  // Make sure that last state we were in has a valid transition to this
  // state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, ASSOCIATED);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, ASSOCIATED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif
  
  debug_printf(DEBUG_NORMAL, "Interface '%s' is associated.\n", ctx->desc);

#if 0
  if (ipc_events_associated(ctx) != IPC_SUCCESS)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't send 'associated' log message to UI!\n");
  }
#endif

  // We are associated, so clear the timer.
  timer_cancel(ctx, ASSOCIATION_TIMER);

  debug_printf(DEBUG_PHYSICAL_STATE, "Clearing replay counter.\n");
  memset(&wctx->replay_counter, 0x00, 8);

  wireless_sm_set_sig_strength_timer(ctx);

  if (ctx->eap_state != NULL)
  {
	  debug_printf(DEBUG_PHYSICAL_STATE, "Reset the EAP state machine..\n");
	  eap_sm_force_init(ctx->eap_state);
  }

  // Update our state variables to indicate what state we are in now.
  wctx->state = ASSOCIATED;

  if (ctx->prof == NULL)
  {
	  // Tell the kernel to move the interface from dormant to "up" state.
	  statemachine_change_state(ctx, S_FORCE_AUTH);
	  //cardif_operstate(ctx, XIF_OPER_UP);
  }
}

/**
 * \brief Transition to NO_ENC_ASSOCIATION state.  This function is called
 *        once when the interface attempts to transition to 
 *        NO_ENC_ASSOCIATION state.  It should verify that everything is
 *        ready to transition to this state, and update the state 
 *        variables in the context.
 *
 * @param[in] ctx   The context that we want to change to
 *                  NO_ENC_ASSOCIATION state.
 **/
void wireless_sm_change_to_no_enc_association(context *ctx)
{
	wireless_ctx *wctx;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, NO_ENC_ASSOCIATION);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, NO_ENC_ASSOCIATION) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  debug_printf(DEBUG_NORMAL, "No configuration is available for this network."
	       "\n");

  debug_printf(DEBUG_PHYSICAL_STATE, "We have no configuration, clearing encryption.\n");
  if (ctx) cardif_enc_disable(ctx);

  wctx->pairwiseKeyType = CIPHER_NONE;

  wctx->state = NO_ENC_ASSOCIATION;
}

/********************************************************************
 *
 * If we get a timeout trying to associate.
 *
 ********************************************************************/
void wireless_sm_association_timeout(context *ctx)
{
	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // Cancel our timer, so we don't keep running the timeout function.
  timer_cancel(ctx, ASSOCIATION_TIMER);

  // Our association timer expired, so change to ASSOCIATION_TIMEOUT_S
  // state.
  wireless_sm_change_state(ASSOCIATION_TIMEOUT_S, ctx);
}

/**
 * \brief Change state to ASSOCIATING. Attempt to transition to 
 *        ASSOCIATING state.  This function is called once when the
 *        interface attempts to transition to ASSOCIATING state.  It
 *        should verify that everything is ready for the state 
 *        transition, update any variables that need it, and update the
 *        state variables for the context.
 *
 * @param[in] ctx   The context of the interface that we want to change
 *                  to ASSOCIATING.
 **/
void wireless_sm_change_to_associating(context *ctx)
{
  struct config_globals *globals = NULL;
  wireless_ctx *wctx = NULL;

  TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  if (!xsup_assert((ctx->conn != NULL), "ctx->conn != NULL", FALSE))
  {
	  printf("Invalid connection context!  Ignoring!\n");
	  return;
  }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  // Cancel the scan timer that is running.
  timer_cancel(ctx, RESCAN_TIMER);

  // Make sure that last state we were in has a valid transition to this
  // state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, ASSOCIATING);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, ASSOCIATING) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  debug_printf(DEBUG_NORMAL, "Interface '%s' is attempting to associate.\n", ctx->desc);

#if 0
  if (ipc_events_attempting_to_associate(ctx) != IPC_SUCCESS)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't send IPC message to IPC event listeners.\n");
  }
#endif

  // Clear the replay counter.
  memset(wctx->replay_counter, 0x00, 8);

  // Populate our PMKSA cache (if we are using WPA2)
  if (wctx->rsn_ie != NULL)
  {
	pmksa_apply_cache(ctx);

	// We also want to tweak the EAPoL start timer to hang back for a couple of seconds to allow for APs to start the
	// PMK handshake.  We don't want this timer to be too long, because some APs seem to wait for a start before doing it,
	// but it can't be too short either because some APs assume that if a start is seen that a full 802.1X handshake is
	// desired.
	ctx->statemachine->startWhen = 2;  
  }

  /*
  if ((wireless_sm->state != ASSOCIATING) && 
      (wireless_sm->state != ACTIVE_SCAN))
    {
      // We have attempted to switch to associating mode from an invalid
      // state.
      debug_printf(DEBUG_NORMAL, "Attempted to change to associating state "
		   "from an invalid state.  Forcing a reinit of wireless sm "
		   "in an attempt to recover.\n");
      wireless_sm->initialize = TRUE;
      return;
      }*/

  wctx->state = ASSOCIATING;

  globals = config_get_globals();
 
  if (globals)
    {
      if (timer_check_existing(ctx, ASSOCIATION_TIMER))
	{
	  timer_reset_timer_count(ctx, ASSOCIATION_TIMER, globals->assoc_timeout);
	} else {
	  timer_add_timer(ctx, ASSOCIATION_TIMER, globals->assoc_timeout, NULL,
			  &wireless_sm_association_timeout);
	}
    } else {
      debug_printf(DEBUG_NORMAL, "Couldn't read global variable information!"
		   " Association timer will not function correctly!\n");
    }

  statemachine_reinit(ctx);

#ifndef WINDOWS
  // Windows can have fits doing this.  Some drivers get mad if you try to set keys before
  // it has associated.
  if (ctx->conn->association.txkey != 0)
    {
		set_static_wep_keys(ctx, &ctx->conn->association);
    }
#endif  // WINDOWS
				
  if (config_ssid_find_by_name(wctx, wctx->cur_essid) != NULL)
  {
	if (config_ssid_using_wep(wctx))
		{
			// Do any setup that is needed to enter the new state.
			cardif_wep_associate(ctx, (wctx->flags & WIRELESS_ZEROS_ON_ROAM));
			debug_printf(DEBUG_PHYSICAL_STATE, "Listed SSID is %s\n", wctx->cur_essid);
		}  else {
			cardif_reassociate(ctx, 1);
		}
  }
  else
  {
	  // It isn't in our cache, so we need to rely on the configuration to figure
	  // out how to talk to this network.
	  if ((ctx->conn != NULL) && (ctx->conn->association.association_type >= ASSOC_TYPE_WPA1))
	  {
		  // For OSes other than Windows, we will need to do something here to determine
		  // the WPA information to use.  Perhaps it will need to be set in the config,
		  // or we will need to be able to do an active probe.
		  cardif_reassociate(ctx, 1);
	  }
	  else
	  {
		  cardif_wep_associate(ctx, (wctx->flags & WIRELESS_ZEROS_ON_ROAM));
	  }
  }

  /*
  if (cardif_GetSSID(ctx, temp_ssid) != XENONE)
    {
      cardif_reassociate(ctx, 1);
    } else {
      if (strcmp(temp_ssid, ctx->cur_essid) != 0)
	{
	  cardif_reassociate(ctx, 1);
	}
    }
  */
}

/**
 * \brief Attempt to transition to ASSOCIATION_TIMEOUT state.  This
 *        function is called once when the interface attempts to 
 *        transition to ASSOCIATION_TIMEOUT state.  It should verify
 *        that everything is ready for the transition, update any
 *        memory that needs it, and update the state variable in the
 *        context.
 *
 * @param[in] ctx   The context that wants to change to 
 *                  ASSOCIATION_TIMEOUT.
 **/
void wireless_sm_change_to_association_timeout(context *ctx)
{
  uint8_t abilities;
  wireless_ctx *wctx;

  TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  // Make sure that last state we were in has a valid transition to this
  // state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, ASSOCIATION_TIMEOUT_S);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, ASSOCIATION_TIMEOUT_S) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  debug_printf(DEBUG_NORMAL, "The association attempt timed out.\n");

  abilities = config_ssid_get_ssid_abilities(wctx);

  // If we are doing WPA or RSN, then we shouldn't mess with the zeros on
  // roam flag.
  if ((!(abilities & WPA_IE)) && (!(abilities & RSN_IE)))
    {
      if (TEST_FLAG(wctx->flags, WIRELESS_ZEROS_ON_ROAM))
	{
	  UNSET_FLAG(wctx->flags, WIRELESS_ZEROS_ON_ROAM);
	} else {
	  SET_FLAG(wctx->flags, WIRELESS_ZEROS_ON_ROAM);
	}
    }

  wctx->state = ASSOCIATION_TIMEOUT_S;
  wireless_sm_change_state(ACTIVE_SCAN, ctx);
}

/**
 * \brief Attempt to transition to PORT_DOWN state.  This function is
 *        called once when the interface is changed to a down state.
 *        The function should verify that the state change is valid,
 *        update any memory, and update the state variable for the
 *        context.
 *
 * @param[in] ctx   The context for the interface that we want to 
 *                  transition to PORT_DOWN state.
 **/
void wireless_sm_change_to_port_down(context *ctx)
{
	wireless_ctx *wctx;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  debug_printf(DEBUG_NORMAL, "Your interface is down.\n");

  // Make sure that last state we were in has a valid transition to this
  // state.
  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, PORT_DOWN);  

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, PORT_DOWN) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  wctx->state = PORT_DOWN;

#ifndef WINDOWS
  // On windows, by the time we get here, the port is down, and we can't clear the keys.  (The
  // interface may not even be in the machine anymore!)
  cardif_clear_keys(ctx);
#endif
  timer_cancel(ctx, STALE_KEY_WARN_TIMER);
  timer_cancel(ctx, REKEY_PROB_TIMER);
  statemachine_reinit(ctx);
}

// Forward declaration needed for next function.
void wireless_sm_do_associated(context *);

/********************************************************************
 *
 * Send a logoff, wipe keys, clear IEs, and send a disassociate.
 *
 ********************************************************************/
void wireless_sm_clear_interface(context *ctx)
{
	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // Send logoff
  ctx->statemachine->userLogoff = TRUE;
  wireless_sm_do_associated(ctx);        // To get the SM to send the logoff.

  // Send a disassociate
  cardif_disassociate(ctx, DISASSOC_UNSPECIFIED);

  // Clear IEs
  cardif_disable_wpa_state(ctx);

  // Wipe keys  (Windows takes care of this during the association phase.)
#ifndef WINDOWS
  cardif_delete_key(ctx, 0, 1);
  cardif_delete_key(ctx, 0, 0);
  cardif_delete_key(ctx, 1, 0);
  cardif_delete_key(ctx, 2, 0);
  cardif_delete_key(ctx, 3, 0);
#endif

  cardif_enc_disable(ctx);
}

/**
 * \brief Transition to INT_RESTART state.
 *
 * We *ONLY* change to restart state when instructed to by events outside
 * of the main Xsupplicant program.  (i.e. A GUI interface.)
 *
 * In restart state, we send a logoff, and disassociate, clear any keys,
 * and wipe any IEs.  Then, we reinit the state machines, and switch back 
 * to ACTIVE_SCAN state.  This should effectively restart the authentication.
 *
 * @param[in] ctx   The context that we want to change to INT_RESTART
 *                  state.
 **/
void wireless_sm_change_to_int_restart(context *ctx)
{
  wireless_ctx *wctx;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  if (xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
	  return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, INT_RESTART);

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, INT_RESTART) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  wireless_sm_clear_interface(ctx);
  statemachine_change_state(ctx, DISCONNECTED);
}

/**
 * \brief Attempt to transition to INT_STOPPED state.
 *
 * We *ONLY* change to stopped state when instructed to by events outside
 * of the main Xsupplicant program.  (i.e. A GUI interface.)
 *
 * In stopped mode, we send a logoff, and disassociate, clear any keys,
 * and delete any IEs in use.  Then, each pass through the state, we flush
 * any buffers that might contain information that would be queued.  (Basically
 * we ignore everything.)
 *
 * @param[in] ctx   The context for the interface that we want to change
 *                  to INT_STOPPED state.
 **/
void wireless_sm_change_to_int_stopped(context *ctx)
{
	wireless_ctx *wctx = NULL;

	TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
	  return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  wireless_sm_disp_state_change(DEBUG_PHYSICAL_STATE, ctx, INT_STOPPED);  

#if WIRELESS_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(ctx, IPC_STATEMACHINE_PHYSICAL, wctx->state, INT_STOPPED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC physical state change message!\n");
  }
#endif

  wireless_sm_clear_interface(ctx);
  statemachine_change_state(ctx, S_FORCE_UNAUTH);

	wctx = (wireless_ctx *)ctx->intTypeData;
	if (wctx == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No valid wireless context!  Stopping the interface will"
			" not work!\n");
		return;
	}

	wctx->state = INT_STOPPED;
}

/********************************************************************
 *
 * Check for global events that would signal a state change.
 *
 ********************************************************************/
void wireless_sm_check_globals(context *ctx)
{
  wireless_ctx *wctx = NULL;

  TRACE

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if (ctx->conn == NULL)
    {
/*      debug_printf(DEBUG_PHYSICAL_STATE, "No valid connection data!! (%s)\n",
		   __FUNCTION__); */
      return;
    } else {
		if ((ctx->prof != NULL) && (ctx->prof->method == NULL)) 
		{
#ifndef TOTAL_WIRELESS_CONTROL
			ctx->statemachine->portControl = FORCE_AUTHORIZED;
			statemachine_change_state(ctx, S_FORCE_AUTH);
			wireless_sm_change_state(NO_ENC_ASSOCIATION, ctx);
#else
			wireless_sm_change_state(ACTIVE_SCAN, ctx);
#endif
			return;
		}
    }

  if ((TEST_FLAG(wctx->flags, WIRELESS_SM_PORT_ACTIVE)) && (!cardif_get_if_state(ctx)))
    {
      // Our interface is down.
      UNSET_FLAG(wctx->flags, WIRELESS_SM_PORT_ACTIVE);
      wireless_sm_change_state(PORT_DOWN, ctx);
    } else {
	  SET_FLAG(wctx->flags, WIRELESS_SM_PORT_ACTIVE);
    }
  /*
  if ((TEST_FLAG(wctx->flags, WIRELESS_SM_INIT)) || (TEST_FLAG(wctx->flags, WIRELESS_SM_SSID_CHANGE)))
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Initialize : %d    SSID Change : %d\n",
		   TEST_FLAG(wctx->flags, WIRELESS_SM_INIT), TEST_FLAG(wctx->flags, WIRELESS_SM_SSID_CHANGE));

      wireless_sm_change_state(ACTIVE_SCAN, ctx);
    }
  */
  if (TEST_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED) && (!TEST_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION)))
    {
      wireless_sm_change_state(ASSOCIATED, ctx);
    }

  if (!TEST_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED))
    {
      wireless_sm_change_state(UNASSOCIATED, ctx);
    }

}

/********************************************************************
 *
 * Change state from where we are, to a new state.  The individual state
 * change handlers *MUST* make sure they are changing from a valid state
 * in to the new state.
 *
 ********************************************************************/
void wireless_sm_change_state(int newstate, context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // If we aren't wireless, then ignore state change requests.
  if (ctx->intType != ETH_802_11_INT)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to change wireless state on an "
			"interface that isn't wireless!?  Something is broken!\n");
	  return;
  }

  switch (newstate)
    {
    case UNASSOCIATED:
      wireless_sm_change_to_unassociated(ctx);
      break;

    case ASSOCIATED:
      wireless_sm_change_to_associated(ctx);
      break;

    case ACTIVE_SCAN:
      wireless_sm_change_to_active_scan(ctx);
      break;

    case ASSOCIATING:
      wireless_sm_change_to_associating(ctx);
      break;

    case ASSOCIATION_TIMEOUT_S:
      wireless_sm_change_to_association_timeout(ctx);
      break;

    case PORT_DOWN:
      wireless_sm_change_to_port_down(ctx);
      break;

    case NO_ENC_ASSOCIATION:
      wireless_sm_change_to_no_enc_association(ctx);
      break;
      
    case INT_RESTART:
      wireless_sm_change_to_int_restart(ctx);
      break;

    case INT_STOPPED:
      wireless_sm_change_to_int_stopped(ctx);
      break;

	case INT_HELD:
		wireless_sm_change_to_int_held(ctx);
		break;

    default:
      debug_printf(DEBUG_NORMAL, "Attempt to change to invalid state in "
		   "%s(), %s, at line %d.\n", __FUNCTION__, __FILE__,
		   __LINE__);
      debug_printf(DEBUG_NORMAL, "Changing to ACTIVE_SCAN to attempt to "
		   "recover.\n");
      wireless_sm_change_to_active_scan(ctx);
      break;
    }
}

/*********************************************************************
 *
 * Handle an event while in port down state.
 *
 *********************************************************************/
void wireless_sm_do_port_down(context *ctx)
{
	wireless_ctx *wctx;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if (cardif_get_if_state(ctx) == TRUE)
  {
	  SET_FLAG(wctx->flags, WIRELESS_SM_PORT_ACTIVE);
	  wireless_sm_change_state(ACTIVE_SCAN, ctx);
  }
  else
  {
	  UNSET_FLAG(wctx->flags, WIRELESS_SM_PORT_ACTIVE);
  }
}

/*********************************************************************
 *
 * Handle an event while we are in unassociated mode.
 *
 *********************************************************************/
void wireless_sm_do_unassociated(context *ctx)
{
  struct config_globals *globals = NULL;
  wireless_ctx *wctx;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  globals = config_get_globals();

  xsup_assert((globals != NULL), "globals != NULL", TRUE);

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ASSOC_AUTO))
    {
      // We are set to auto associate.  So, switch to active scan mode.
      wireless_sm_change_state(ACTIVE_SCAN, ctx);
    } else {
      // Otherwise, we have nothing to do, so take a short nap.  (To avoid
      // hammering the processor.

      if (TEST_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED))
	  {
		wireless_sm_change_state(ASSOCIATED, ctx);
	  } 
    }
}

/*********************************************************************
 *
 * Handle an event while we are in associated mode.
 *
 *********************************************************************/
void wireless_sm_do_associated(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // If we are associated, then go ahead and run the EAPOL state machine.
  if (ctx->recv_size != 0)
  {
	  eapol_execute(ctx);
  }
  else
  {
    if ((ctx->conn != NULL) && (ctx->conn->association.auth_type != AUTH_NONE))
		statemachine_run(ctx);
  }
}

/**********************************************************************
 *
 * The rescan timer expired.  Clear it, and start another scan.
 *
 **********************************************************************/
void wireless_sm_clear_rescan_timer(context *ctx)
{
  // First, cancel the existing timer.
  timer_cancel(ctx, RESCAN_TIMER);

  // Then, change states to ACTIVE_SCAN.
  wireless_sm_change_state(ACTIVE_SCAN, ctx);
}

/**********************************************************************
 *
 * Initiate a rescan timeout.
 *
 **********************************************************************/
void wireless_sm_set_rescan_timer(context *ctx)
{
  struct config_globals *globals;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  globals = config_get_globals();
  if (globals)
    {
      // This function will get called every second when we don't have scan data.
      //  We should only instate a new timer if there isn't an existing one.
      if (!timer_check_existing(ctx, RESCAN_TIMER))
	{
	  // We need to set up a new rescan timer.
	  timer_add_timer(ctx, RESCAN_TIMER, globals->active_timeout, NULL,
			  &wireless_sm_clear_rescan_timer);
	}
    } 
  else
    {
      debug_printf(DEBUG_NORMAL, "Couldn't set rescan timer!  Xsupplicant "
		   "may have problems associating.\n");
    }
}

/*********************************************************************
 *
 * Handle an event while we are in active scan mode.
 *
 *********************************************************************/
void wireless_sm_do_active_scan(context *ctx)
{
  char *newssid = NULL;
  wireless_ctx *wctx = NULL;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if ((!TEST_FLAG(wctx->flags, WIRELESS_SCANNING)) && (!TEST_FLAG(wctx->flags, WIRELESS_CHECKED)))
    {
      // We aren't scanning, so see if we have a valid SSID we can attach
      // to.
      newssid = config_ssid_get_desired_ssid(ctx);
      if (newssid != NULL)
	{
	  debug_printf(DEBUG_PHYSICAL_STATE, "Switching to Associating mode to"
		       " connect to %s.\n", newssid);

	  // Clear out the SSID we are currently connected to.
	  FREE(wctx->cur_essid);

	  wctx->cur_essid = _strdup(newssid);

	  config_build(ctx, wctx->cur_essid);

	  if (ctx->conn != NULL)
	  {
		  if (TEST_FLAG(ctx->conn->flags, CONFIG_NET_DEST_MAC))
			{
				// We need to search again, by MAC address this time.
				config_ssid_get_by_mac(ctx, ctx->conn->dest_mac);
			}
	  }
	  else
	  {
		  debug_printf(DEBUG_NORMAL, "No network configuration data is available.  Is this network configured in your configuration file?  Or are you using -p when you shouldn't be?\n");
	  }

	  wireless_sm_change_state(ASSOCIATING, ctx);
	  return;
	} else {
	  // If we didn't find anything, sleep for a few seconds before we try
	  // again. 
		SET_FLAG(wctx->flags, WIRELESS_CHECKED);
	  wireless_sm_set_rescan_timer(ctx);
	}
    } 
}

/*********************************************************************
 *
 * Handle an event while we are in associating mode.
 *
 *********************************************************************/
void wireless_sm_do_associating(context *ctx)
{
  // Nothing to do here, but wait. ;)
}

/*********************************************************************
 *
 * Handle events while we are in no encryption association mode.
 *
 *********************************************************************/
void wireless_sm_do_no_enc_association(context *ctx)
{
  // Nothing to do here.
}

/*********************************************************************
 *
 * Handle events while we are in STOPPED state.
 *
 *********************************************************************/
void wireless_sm_do_int_stopped(context *ctx)
{
  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  // We basically do the same thing as when we are associated.  It is
  // just that the EAPOL state machine is jammed in to a force unauthenticated
  // state.
  wireless_sm_do_associated(ctx);
}

/*********************************************************************
 *
 * Handle events while in INT_RESTART state.
 *
 *********************************************************************/
void wireless_sm_do_int_restart(context *ctx)
{
  debug_printf(DEBUG_NORMAL, "You should't get here!!  Fix the code!\n");
  debug_printf(DEBUG_NORMAL, "File : %s   Function : %s  Line : %d\n",
	       __FILE__, __FUNCTION__, __LINE__);
  global_deinit();
}

/*********************************************************************
 *
 * Actually call routines that act on the state that we are currently
 * in.
 *
 * \todo When we hit the situation that we think we have a wireless card, and there
 *       is no wireless state machine, throw an error, and mark the interface invalid.
 *       (Also need to add an invalid interface flag, and honor it.)
 *
 *********************************************************************/
void wireless_sm_do_state(context *ctx)
{
	wireless_ctx *wctx;

  xsup_assert((ctx != NULL), "ctx != NULL", TRUE);

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  if (!wctx)
    {
      debug_printf(DEBUG_NORMAL, "No valid wireless state machine context in %s()!\n", 
		  __FUNCTION__);

	  ipc_events_error(ctx, IPC_EVENT_ERROR_NO_WCTX, ctx->desc);

      // We can't continue!
      global_deinit();
      return;
    }

  wireless_sm_check_globals(ctx);

  switch (wctx->state)
    {
    case UNASSOCIATED:
      wireless_sm_do_unassociated(ctx);
      break;

    case ASSOCIATED:
      wireless_sm_do_associated(ctx);
      break;

    case ACTIVE_SCAN:
      wireless_sm_do_active_scan(ctx);
      break;

    case ASSOCIATING:
      wireless_sm_do_associating(ctx);
      break;

    case ASSOCIATION_TIMEOUT_S:
      // The association timeout state simply changes the configuration
      // needed to attempt to associate, and then changes to ACTIVE_SCAN
      // state.
      break;

    case PORT_DOWN:
      wireless_sm_do_port_down(ctx);
      break;

    case NO_ENC_ASSOCIATION:
      wireless_sm_do_no_enc_association(ctx);
      break;

    case INT_RESTART:
      wireless_sm_do_int_restart(ctx);
      break;

    case INT_STOPPED:
      wireless_sm_do_int_stopped(ctx);
      break;

	case INT_HELD:
		wireless_sm_do_int_held(ctx);
		break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown state %d!\n", wctx->state);
      debug_printf(DEBUG_NORMAL, "Switching to ACTIVE_SCAN state to attempt"
		   " to recover.\n");
      wireless_sm_change_state(ACTIVE_SCAN, ctx);
      break;
    }
}
