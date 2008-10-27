/**
 * EAP layer implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eap_sm.c
 *
 * \author chris@open1x.org
 **/

#include <stdlib.h>
#include <string.h>

#ifdef WINDOWS
#include <winsock2.h>
#endif

#include "xsup_err.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "eap_sm.h"
#include "frame_structs.h"
#include "xsup_ipc.h"
#include "ipc_events.h"
#include "ipc_callout.h"
#include "snmp.h"
#include "eap_types/eap_type_common.h"
#include "xsup_common.h"
#include "ipc_events.h"
#include "ipc_callout.h"
#include "ipc_events_index.h"

#ifdef WINDOWS
#include "event_core_win.h"
#else
#include "event_core.h"
#endif

// Header files for auth types we know about.
#include "eap_types/md5/eapmd5.h"
#include "eap_types/tls/eaptls.h"
#include "eap_types/ttls/eapttls.h"
#include "eap_types/mschapv2/eapmschapv2.h"
#include "eap_types/peap/eappeap.h"
#include "eap_types/leap/eapleap.h"
#include "eap_types/otp/eapotp.h"

#ifdef OPENSSL_HELLO_EXTENSION_SUPPORTED
#include "eap_types/fast/eapfast.h"
#endif

#ifdef HAVE_TNC
#include "eap_types/tnc/eaptnc.h"
#endif

#ifdef EAP_SIM_ENABLE
#include "winscard.h"

#include "eap_types/sim/eapsim.h"
#include "eap_types/aka/eapaka.h"
#endif

#define EAP_SM_EVENTS   0     ///< Set this to 1 to generate EAP state change events.

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define STATE_DEBUG 1

struct rfc4137_eap_handler eaphandlers[] = {
  {EAP_TYPE_MD5, "EAP-MD5", eapmd5_check, eapmd5_process, eapmd5_buildResp,
   eapmd5_isKeyAvailable, eapmd5_getKey, eap_type_common_get_zero_len,
   eapmd5_deinit},

  {EAP_TYPE_MSCHAPV2, "EAP-MSCHAPv2", eapmschapv2_check, eapmschapv2_process,
   eapmschapv2_buildResp, eapmschapv2_isKeyAvailable, eapmschapv2_getKey,
   eap_type_common_get_common_key_len, eapmschapv2_deinit},

  {EAP_TYPE_TLS, "EAP-TLS", eaptls_check, eaptls_process, eaptls_buildResp,
   eaptls_isKeyAvailable, eaptls_getKey, eap_type_common_get_common_key_len,
   eaptls_deinit},

  {EAP_TYPE_TTLS, "EAP-TTLS", eapttls_check, eapttls_process, 
   eapttls_buildResp, eapttls_isKeyAvailable, eapttls_getKey, 
   eap_type_common_get_common_key_len, eapttls_deinit},

  {EAP_TYPE_OTP, "EAP-OTP", eapotp_check, eapotp_process, eapotp_buildResp,
   eapotp_isKeyAvailable, eapotp_getKey, eap_type_common_get_zero_len,
   eapotp_deinit},

  {EAP_TYPE_GTC, "EAP-GTC", eapotp_check, eapotp_process, eapotp_buildResp,
   eapotp_isKeyAvailable, eapotp_getKey, eap_type_common_get_zero_len,
   eapotp_deinit},

  {EAP_TYPE_PEAP, "EAP-PEAP", eappeap_check, eappeap_process, 
   eappeap_buildResp, eappeap_isKeyAvailable, eappeap_getKey, 
   eap_type_common_get_common_key_len, eappeap_deinit},

#ifdef HAVE_TNC
  {EAP_TYPE_TNC, "EAP-TNC", eaptnc_check, eaptnc_process, eaptnc_buildResp,
   eaptnc_isKeyAvailable, eaptnc_getKey, eap_type_common_get_zero_len,
   eaptnc_deinit},
#endif

#ifdef EAP_SIM_ENABLE
  {EAP_TYPE_AKA, "EAP-AKA", eapaka_check, eapaka_process, eapaka_buildResp,
   eapaka_isKeyAvailable, eapaka_getKey, eap_type_common_get_common_key_len,
   eapaka_deinit},

  {EAP_TYPE_SIM, "EAP-SIM", eapsim_check, eapsim_process, eapsim_buildResp,
   eapsim_isKeyAvailable, eapsim_getKey, eap_type_common_get_common_key_len,
   eapsim_deinit},
#endif

  {EAP_TYPE_LEAP, "EAP-LEAP", eapleap_check, eapleap_process, 
   eapleap_buildResp, eapleap_isKeyAvailable, eapleap_getKey, 
   eapleap_getKey_len, eapleap_deinit},

#ifdef OPENSSL_HELLO_EXTENSION_SUPPORTED
  {EAP_TYPE_FAST, "EAP-FAST", eapfast_check, eapfast_process,
   eapfast_buildResp, eapfast_isKeyAvailable, eapfast_getKey, 
   eap_type_common_get_common_key_len, eapfast_deinit},
#endif

  {NO_EAP_AUTH, NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};

// Forward decls.
void eap_sm_change_state(eap_sm *sm, int newstate);

/**
 * \brief Init the state machine by allocating memory for the state 
 *        machine variables.
 *
 * @param[in] sm   The location where the EAP state machine should be
 *                 created in memory.
 *
 * \retval XEMALLOC on memory allocate errors
 * \retval XENONE on success
 **/
int eap_sm_init(eap_sm **sm)
{
   debug_printf(DEBUG_INIT, "Init EAP state machine.\n");

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  (*sm) = (eap_sm *)Malloc(sizeof(eap_sm));
  if ((*sm) == NULL)
    {
		ipc_events_malloc_failed(NULL);
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for EAP state "
		   "machine data.\n");
      return XEMALLOC;
    }

  // Allocate the space for the "active method" portion.
  (*sm)->active = Malloc(sizeof(eap_type_data));
  if ((*sm)->active == NULL)
    {
		ipc_events_malloc_failed(NULL);
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for active EAP "
		   "method data!\n");
      return XEMALLOC;
    }

  (*sm)->phase = 1;

  return XENONE;
}

/**
 * \brief Sync the data in our EAP state machine with the data that will 
 *        be passed in to the EAP method.
 *
 * @param[in] sm   A pointer to the EAP state machine that we want to 
 *                 sync with the lower layer.
 **/
void eap_sm_sync_ll_to_e(eap_sm *sm)
{
  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    return;

  if (!xsup_assert((sm->active != NULL), "sm->active != NULL", FALSE))
    return;

  sm->active->methodState = sm->methodState;
  sm->active->decision = sm->decision;
  sm->active->eapReqData = sm->eapReqData;
  sm->active->altAccept = sm->altAccept;
  sm->active->altReject = sm->altReject;
  sm->active->ident = sm->ident;
  sm->active->credsSent = sm->credsSent;
}

/**
 * \brief Sync the data from our EAP method with the data in the EAP 
 *        state machine.
 *
 * @param[in] sm   A pointer to the state machine that we need to sync
 *                 with the EAP method it is using.
 **/
void eap_sm_sync_e_to_ll(eap_sm *sm)
{
  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    return;

  if (!xsup_assert((sm->active != NULL), "sm->active != NULL", FALSE))
    return;

  sm->methodState = sm->active->methodState;
  sm->decision = sm->active->decision;
  sm->ignore = sm->active->ignore;
  sm->eapKeyAvailable = sm->active->eapKeyAvailable;
  sm->altAccept = sm->active->altAccept;
  sm->altReject = sm->active->altReject;
  sm->credsSent = sm->active->credsSent;
  // eapReqData shouldn't have been modified.  So we don't care.
  // No need to resync ident here.  We don't care.
}

/**
 * \brief Display the state defined by the variable 'showstate'
 *
 * @param[in] debug_level   The lowest debug level that this message
 *                          should be shown during.  (See 
 *                          \ref xsup_debug.h for definitions of the
 *                          debug levels.)
 *
 * @param[in] showstate   The state that will be displayed as ASCII.
 **/
void eap_sm_disp_state(int debug_level, uint8_t showstate)
{
  switch (showstate)
    {
    case EAP_DISABLED:
      debug_printf_nl(debug_level, "DISABLED");
      break;

    case EAP_INITIALIZE:
      debug_printf_nl(debug_level, "INITIALIZE");
      break;

    case EAP_IDLE:
      debug_printf_nl(debug_level, "IDLE");
      break;

    case EAP_RECEIVED:
      debug_printf_nl(debug_level, "RECEIVED");
      break;

    case EAP_GET_METHOD:
      debug_printf_nl(debug_level, "GET_METHOD");
      break;

    case EAP_METHOD:
      debug_printf_nl(debug_level, "METHOD");
      break;

    case EAP_SEND_RESPONSE:
      debug_printf_nl(debug_level, "SEND_RESPONSE");
      break;

    case EAP_DISCARD:
      debug_printf_nl(debug_level, "DISCARD");
      break;

    case EAP_IDENTITY:
      debug_printf_nl(debug_level, "IDENTITY");
      break;

    case EAP_NOTIFICATION:
      debug_printf_nl(debug_level, "NOTIFICATION");
      break;

    case EAP_RETRANSMIT:
      debug_printf_nl(debug_level, "RETRANSMIT");
      break;

    case EAP_SUCCESS:
      debug_printf_nl(debug_level, "SUCCESS");
      break;

    case EAP_FAILURE:
      debug_printf_nl(debug_level, "FAILURE");
      break;

    default:
      debug_printf_nl(debug_level, "UNKNOWN!!!");
      break;
    }
}

/**
 * \brief Display a message about the state we have changed from -> to.
 *
 * @param[in] debug_level   The lowest debug level that will result in
 *                          this message being displayed.
 *
 * @param[in] sm   A pointer to the state machine that contains the 
 *                 current state.
 *
 * @param[in] newstate   The state that the EAP state machine will be
 *                       going in to.
 **/
void eap_sm_disp_state_change(int debug_level, eap_sm *sm, int newstate)
{
  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    return;

  debug_printf(debug_level, "(EAP State Machine -- Phase %d) ", sm->phase);
  eap_sm_disp_state(debug_level, sm->eap_sm_state);
  debug_printf_nl(debug_level, " -> ");
  eap_sm_disp_state(debug_level, newstate);
  debug_printf_nl(debug_level, "\n");
}

/**
 * \brief Change to disabled state.
 *
 * @param[in] sm   The EAP state machine that is changing to disabled
 *                 state.
 **/
void eap_sm_change_to_disabled(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_DISABLED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_DISABLED;

  if (sm->portEnabled)
    eap_sm_change_state(sm, EAP_INITIALIZE);
}

/**
 * \brief Change to idle state.
 *
 * @param[in] sm   A pointer to the EAP state machine that needs to
 *                 change to IDLE state.
 **/
void eap_sm_change_to_idle(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_IDLE) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_IDLE;

  if (sm->eapReq)
    {
      eap_sm_change_state(sm, EAP_RECEIVED);
      return;
    }

  if ((sm->altReject) || ((sm->idleWhile == 0) && 
			  (sm->decision != UNCOND_SUCC))
      || ((sm->altAccept) && (sm->methodState != CONT) &&
	  (sm->decision == EAP_FAIL)))
    {
      eap_sm_change_state(sm, EAP_FAILURE);
      return;
    }

  if (((sm->altAccept) && (sm->decision != EAP_FAIL)) ||
      ((sm->idleWhile == 0) && (sm->decision == UNCOND_SUCC)))
    {
      eap_sm_change_state(sm, EAP_SUCCESS);
      return;
    }
}

/**
 * \brief Change to initialize state.  This will result in all of the 
 *        state machine variables being reset.
 *
 * @param[in] sm   A pointer to the state machine that needs to be
 *                 changed to initialize state.
 **/
void eap_sm_change_to_initialize(eap_sm *sm)
{
	int eapstruct = 0;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_INITIALIZE) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  if ((sm->phase == 2) && (sm->reqMethod == EAP_TYPE_TNC))
  {
	  // We need to deinit TNC here, because it will leave phase 2 in a weird state.
	  eapstruct = eap_sm_find_method(sm->selectedMethod);
	  if (eapstruct != -1)
	    {
	      if (eaphandlers[eapstruct].eap_deinit != NULL)
		{
		  eaphandlers[eapstruct].eap_deinit(sm->active);
		}
	    }
  }

  sm->eap_sm_state = EAP_INITIALIZE;

  sm->selectedMethod = NONE;
  sm->methodState = NONE;
  sm->allowNotifications = TRUE;
  sm->decision = EAP_FAIL;
  sm->credsSent = FALSE;			// We have not sent our creds yet.
  sm->idleWhile = config_get_idleWhile();
  sm->lastId = 0xff;                         // Initialize this to something other than 0, since some 
											 // authenticators like to start the conversation with 0.

  if ((sm->phase == 2) && (sm->reqMethod == EAP_TYPE_TNC))
  {
	// If we are doing TNC, and we start with an ID of 255, bad things can happen.  So make sure
	  // to deal with that case.
	  if (eap_type_common_get_eap_reqid(sm->eapReqData) == 0xff)
	  {
		  sm->lastId--;
	  }
  }

  sm->eapSuccess = FALSE;
  sm->eapFail = FALSE;
  sm->altAccept = FALSE;
  sm->altReject = FALSE;

  FREE(sm->eapKeyData);

  sm->eapKeyAvailable = FALSE;
  sm->eapRestart = FALSE;

  if (sm->eapReqData == NULL) sm->eapReq = FALSE;  // Should fix the weird occasional state machine jam.

  // Then, change directly to idle state.
  eap_sm_change_state(sm, EAP_IDLE);
}

/** 
 * \brief Force the state machine back in to INIT mode.  
 *
 * This should only be used for situations such as phase 2 TTLS or PEAP 
 * where a second EAP method may be run.  (i.e., Using EAP-TNC following 
 * a TTLS-EAP-MD5 authentication.
 *
 * @param[in] sm   A pointer to the state machine that we want to force
 *                 to reinit.
 **/
void eap_sm_force_init(eap_sm *sm)
{
  sm->eapReq = FALSE;
  eap_sm_change_state(sm, EAP_INITIALIZE);
}

/**
 * \brief Locate the method we want to use.  And return it's index.
 *
 * @param[in] reqMethod   The EAP ID of the method we want to use.
 *
 * \retval int the index to the EAP handler that can handle the
 *             requested EAP method.
 * \retval -1 on error
 **/
int eap_sm_find_method(uint8_t reqMethod)
{
  int i = 0;

  // First, see if we even know about the EAP method being asked for.
  while ((eaphandlers[i].eap_type_handler != reqMethod) &&
         (eaphandlers[i].eap_type_handler != NO_EAP_AUTH))
    {
      i++;
    }

  if (eaphandlers[i].eap_type_handler == NO_EAP_AUTH)
    {
      return -1;
    }

  return i;
}

/**
 * \brief Parse the EAP data, and populate rxReq, rxSuccess, rxFailure,
 *  reqId, reqMethod.
 *
 * @param[in] sm   A pointer to the state machine that contains the EAP
 *                 packet we need to parse.
 **/
void parseEapReq(eap_sm *sm)
{
  struct eap_header *eapdata;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  if (!xsup_assert((sm->eapReqData != NULL), "sm->eapReqData != NULL", FALSE))
    return;

  eapdata = (struct eap_header *)sm->eapReqData;

  if (eapdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Attempt to parse EAP data that was NULL!\n");
      return;
    }

  if (eapdata->eap_code == EAP_REQUEST_PKT) 
    {
      debug_printf(DEBUG_EAP_STATE, "Got an EAP request.\n");
      sm->rxReq = TRUE;
    }

  if (eapdata->eap_code == EAP_SUCCESS_PKT)
    {
      debug_printf(DEBUG_EAP_STATE, "Got an EAP success.\n");
      snmp_eapol_success_rx();
      sm->rxSuccess = TRUE;
    }

  if (eapdata->eap_code == EAP_FAILURE_PKT)
    {
      debug_printf(DEBUG_EAP_STATE, "Got an EAP failure.\n");
      snmp_eapol_fail_rx();
      sm->rxFailure = TRUE;
    }

  debug_printf(DEBUG_EAP_STATE, "Requested method %d.\n", eapdata->eap_type);
  sm->reqMethod = eapdata->eap_type;

  debug_printf(DEBUG_EAP_STATE, "EAP ID : %d\n", eapdata->eap_identifier);
  sm->reqId = eapdata->eap_identifier;
}

/**
 * \brief Take an EAP method number, and return a human readable string 
 *        that indicates what it is.
 *
 * @param[in] num   The EAP ID for the method we want to look up the 
 *                  human readable name for.
 *
 * \retval NULL on error
 * \retval ptr containing the ASCII name of the EAP method.
 **/
char *eap_sm_method_num_to_string(uint8_t num)
{
	int i;
	char *reqMethod;

	i = eap_sm_find_method(num);
	if (i < 0)
	{
		switch(num)
		{
		case 0:
			reqMethod = _strdup("None");
			break;

		case EAP_TYPE_IDENTITY:
			reqMethod = _strdup("Identity");
			break;

		case EAP_TYPE_NOTIFY:
			reqMethod = _strdup("Notify");
			break;

		case EAP_TYPE_NAK:
			reqMethod = _strdup("NAK");
			break;

		default:
			reqMethod = _strdup("UNKNOWN!?");
			break;
		}
	}
	else
	{
		reqMethod = _strdup(eaphandlers[i].eapname);
	}

	return reqMethod;
}

/**
 *  \brief Dump the state that the EAP method is in.
 *
 * @param[in] meth   The state that the EAP method is in.
 *
 * \retval NULL on error
 * \retval ptr to the ASCII name of the state that the EAP method is in.
 **/
char *eap_sm_method_state_str(uint8_t meth)
{
	char *result = NULL;

	// EAP method states
	switch (meth)
	{
	case INIT:
		result = _strdup("INIT");
		break;

	case CONT:
		result = _strdup("CONT");
		break;

	case MAY_CONT:
		result = _strdup("MAY_CONT");
		break;

	case DONE:
		result = _strdup("DONE");
		break;

	default:
		result = _strdup("UNKNOWN");
		break;
	}

	return result;
}

/**
 * \brief Dump a string that indicates the decision we are working on.
 *
 * @param[in] decision  An integer that identifies the current decision
 *                      of the EAP method.
 *
 * \retval NULL on error
 * \retval ptr to an ASCII version of the decision
 **/
char *eap_sm_decision_str(uint8_t decision)
{
	char *result = NULL;

	switch (decision)
	{
	case NONE:
		result = _strdup("NONE");
		break;

	case EAP_FAIL:
		result = _strdup("FAIL");
		break;

	case UNCOND_SUCC:
		result = _strdup("UNCOND_SUCC");
		break;

	case COND_SUCC:
		result = _strdup("COND_SUCC");
		break;

	default:
		result = _strdup("UNKNOWN!?");
		break;
	}

	return result;
}

/**
 * \brief Dump the EAP state machine state variables in a format that 
 *        can be read by humans.
 *
 * @param[in] sm   A pointer to the EAP state machine that we want to 
 *                 dump information about.
 **/
void eap_sm_dump_state(eap_sm *sm)
{
#ifdef STATE_DEBUG
	char *rxReq = NULL; 
	char *reqMethod = NULL;
	char *selectedMethod = NULL;
	char *methodState = NULL;
	char *allowNotifications = NULL;
	char *decision = NULL;
	char *success = NULL;
	char *failure = NULL;

	rxReq = xsup_common_is_tf(sm->rxReq);
	reqMethod = eap_sm_method_num_to_string(sm->reqMethod);
	selectedMethod = eap_sm_method_num_to_string(sm->selectedMethod);
	methodState = eap_sm_method_state_str(sm->methodState);
	allowNotifications = xsup_common_is_tf(sm->allowNotifications);
	decision = eap_sm_decision_str(sm->decision);
	success = xsup_common_is_tf(sm->rxSuccess);
	failure = xsup_common_is_tf(sm->rxFailure);

	debug_printf(DEBUG_EAP_STATE, "---- EAP State Dump (Phase %d) ----\n", sm->phase);
	  debug_printf(DEBUG_EAP_STATE, "rxReq = %s  reqId = %d  lastId = %d\n",
		  rxReq, sm->reqId, sm->lastId);

	  debug_printf(DEBUG_EAP_STATE, "reqMethod = %d (%s) selectedMethod = %d (%s)\n",
		  sm->reqMethod, reqMethod, sm->selectedMethod, selectedMethod);

	  debug_printf(DEBUG_EAP_STATE, "methodState = %d (%s) allowNotifications = %s  decision = %s\n",
		  sm->methodState, methodState, allowNotifications, decision);
	  
	  debug_printf(DEBUG_EAP_STATE, "rxSuccess = %s  rxFailure = %s\n", 
		  success, failure);
	debug_printf(DEBUG_EAP_STATE, "---- EAP State Dump Finished ----\n");

	  FREE(rxReq);
	  FREE(reqMethod);
	  FREE(selectedMethod);
	  FREE(methodState);
	  FREE(allowNotifications);
	  FREE(decision);
	  FREE(success);
	  FREE(failure);
#endif
}

/**
 * \brief We received a frame.  So parse it, and populate data accordingly.
 *
 * @param[in] sm   A pointer to the EAP state machine that has received
 *                 a packet.
 **/
void eap_sm_change_to_received(eap_sm *sm)
{
  struct config_globals *globals = NULL;
  int eapstruct = 0;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return;

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_RECEIVED) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_RECEIVED;

  // Need to first clear out the short-term variables to be sure we don't
  // get any false positives.
  sm->rxReq = FALSE;
  sm->rxSuccess = FALSE;
  sm->rxFailure = FALSE;
  sm->reqId = 0;
  sm->reqMethod = 0;
  sm->ignore = FALSE;

  parseEapReq(sm);

  eap_sm_dump_state(sm);

  if ((sm->reqId == sm->lastId) && (sm->phase == 2) && (sm->reqMethod == 26))
  {
	  debug_printf(DEBUG_EAP_STATE, "Work around for non-incrementing EAP ID with EAP-MS-CHAPv2 in phase 2!\n");
	  sm->lastId--;
  }

  // Then, evaluate the current state of variables to decide where to go to 
  // next.
  if ((sm->rxSuccess) && (sm->decision != EAP_FAIL))
    {
      if (sm->reqId != sm->lastId)
	{
		if ((!((sm->lastId == 0xff) && (sm->reqId == 0x00))) ||
			((sm->reqId-1) == sm->lastId))
		{
		  if (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
		    {
		      debug_printf(DEBUG_NORMAL, "Your authenticator sent an incorrect"
				   " ID value for the success response.\n");
		      debug_printf(DEBUG_NORMAL, "We received ID %d, when we should "
				   "have received ID %d.\n", sm->reqId, sm->lastId);
		      debug_printf(DEBUG_NORMAL, "Please ask your vendor to fix "
				   "this!\n");
		    }
		}
	}

      if (sm->selectedMethod == EAP_TYPE_LEAP)
	{
	  debug_printf(DEBUG_EAP_STATE, "Got a LEAP success!\n");
	  sm->rxReq = TRUE;
	  sm->rxSuccess = FALSE;
	  eap_sm_change_state(sm, EAP_METHOD);
	}
      else
	{
	  eap_sm_change_state(sm, EAP_SUCCESS);
	}
      return;
    }

  if ((sm->methodState != CONT) && (((sm->rxFailure == TRUE) && 
				     (sm->decision != UNCOND_SUCC)) ||
				    ((sm->rxSuccess) && 
				     (sm->decision == EAP_FAIL))))
    {
      if (sm->reqId != sm->lastId)
		{
			if (((sm->lastId != 0xff)) ||
				((sm->reqId-1) == sm->lastId))
			{

				  if (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
			        {
				      debug_printf(DEBUG_NORMAL, "Your authenticator sent an incorrect"
						   " ID value for the failure response.\n");
				      debug_printf(DEBUG_NORMAL, "We received ID %d, when we should "
						   "have received ID %d.\n", sm->reqId, sm->lastId);
				      debug_printf(DEBUG_NORMAL, "Please ask your vendor to fix "
						   "this!\n");
				    }
			}
		}

	   eap_sm_change_state(sm, EAP_FAILURE);
	   return;
    }

  if ((sm->rxReq) && (sm->reqId != sm->lastId) && 
      (sm->reqMethod == EAP_TYPE_NOTIFY) && (sm->allowNotifications))
    {
      eap_sm_change_state(sm, EAP_NOTIFICATION);
      return;
    }

   // RFC 4192 shows a different way of transitioning to IDENTITY state, but
  // if we follow what it says, we can land in impossible states.  So, we do this
  // instead, because it works. ;)
  if ((sm->rxReq) && (sm->reqMethod == EAP_TYPE_IDENTITY))
    {
		if (sm->selectedMethod != NONE)
		{
			// Clean up the old method, and process the identity frame.
			eapstruct = eap_sm_find_method(sm->selectedMethod);
			if (eaphandlers[eapstruct].eap_deinit != NULL)
				eaphandlers[eapstruct].eap_deinit(sm->active);
		}

      eap_sm_change_state(sm, EAP_IDENTITY);
      return;
    }

  if (((sm->selectedMethod != EAP_TYPE_TNC) && (sm->selectedMethod != NONE)) 
	  && (sm->reqMethod == EAP_TYPE_TNC))
  {
	  // Reinit the state machine before moving on.
	  debug_printf(DEBUG_EAP_STATE, "Starting TNC, resetting EAP.\n");

	  // Deinit old EAP method
	  eapstruct = eap_sm_find_method(sm->selectedMethod);
	  if (eaphandlers[eapstruct].eap_deinit != NULL)
	    eaphandlers[eapstruct].eap_deinit(sm->active);

	  eap_sm_change_state(sm, EAP_INITIALIZE);
	  return;
  }

  if ((sm->rxReq) && (sm->reqId != sm->lastId) &&
      (sm->selectedMethod == NONE) && (sm->reqMethod != EAP_TYPE_IDENTITY) &&
      (sm->reqMethod != EAP_TYPE_NOTIFY))
    {
      eap_sm_change_state(sm, EAP_GET_METHOD);
      return;
    }

  // XXX The sm->phase == 2 part of this should probably go away when we
  // refactor the state machine components in Sea Ant.
  if ((sm->rxReq) && ((sm->reqId != sm->lastId) || (sm->phase == 2)) &&
      (sm->reqMethod == sm->selectedMethod) &&
      (sm->methodState != DONE))
    {
      eap_sm_change_state(sm, EAP_METHOD);
      return;
    }

    if ((sm->rxReq) &&  (sm->reqId == sm->lastId))
    {
		eap_sm_change_state(sm, EAP_RETRANSMIT);
		return;
    }

  if (sm->selectedMethod == EAP_TYPE_LEAP)
    {
      // This is needed to catch the LEAP response for the second half of
      // the LEAP conversation.
      eap_sm_change_state(sm, EAP_METHOD);
      return;
    }

  // Otherwise, discard the packet.
  debug_printf(DEBUG_NORMAL, "Packet discarded because it didn't trigger "
	       "proper state options.\n");

  eap_sm_change_state(sm, EAP_DISCARD);
}

/**
 * \brief Determine if we will allow this method.
 *
 * @param[in] sm   A pointer to the EAP state machine that contains
 *                 information to allow the function to know which EAP
 *                 method is desired.
 *
 * \retval TRUE if it is supported.
 * \retval FALSE if it isn't supported.
 **/
uint8_t allowMethod(eap_sm *sm)
{
  int i = 0;
  uint8_t reqMethod;
  struct config_eap_method *methods;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  reqMethod = sm->reqMethod;

  // First, see if we even know about the EAP method being asked for.
  while ((eaphandlers[i].eap_type_handler != reqMethod) &&
	 (eaphandlers[i].eap_type_handler != NO_EAP_AUTH))
    {
      i++;
    }
  if (eaphandlers[i].eap_type_handler == NO_EAP_AUTH)
    {
      debug_printf(DEBUG_NORMAL, "Unsupported EAP type request.  Type is "
		   "%d.  (%02X Hex)\n", reqMethod, reqMethod);
      return FALSE;
    }

  debug_printf(DEBUG_EAP_STATE, "EAP type %d is supported, checking if it is "
	       "allowed.\n", reqMethod);

#ifdef HAVE_TNC
  // If we were built with TNC, then go ahead and allow it. (Assuming we
  // are in phase 2.)
  if ((sm->phase == 2) && (reqMethod == 38))
  {
	  return TRUE;
  }
#endif

  // We know how to handle it, so let's see if it is allowed by our
  // configuration.
  if (sm->curMethods == NULL)
    {
      debug_printf(DEBUG_EAP_STATE, "There doesn't appear to be any valid "
		   "EAP methods configured for this network!\n");
      return FALSE;
    }

  methods = sm->curMethods;

  while ((methods != NULL) && (methods->method_num != reqMethod))
    {
      methods = methods->next;
    }

  if ((methods != NULL) && (methods->method_num == reqMethod))
    {
      debug_printf(DEBUG_EAP_STATE, "EAP type %d is allowed.\n", 
		   reqMethod);

      // Set up a pointer to our configuration data.
      xsup_assert((sm->active != NULL), "sm->active != NULL", TRUE);

      sm->active->eap_conf_data = methods->method_data;
      return TRUE;
    }

  debug_printf(DEBUG_EAP_STATE, "EAP type %d is *NOT* allowed.\n",
	       reqMethod);
  return FALSE;
}

/**
 * \brief Build a NAK to request the EAP type we really want.
 *
 * @param[in] sm   A pointer to the state machine that contains 
 *                 information needed to properly build a NAK message.
 *
 * \retval NULL on error
 * \retval ptr to a NAK packet on success
 **/
uint8_t *buildNak(eap_sm *sm)
{
  uint8_t *outpacket;
  struct eap_header *eapdata;

  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    return NULL;

  if (sm->curMethods == NULL)
    {
      debug_printf(DEBUG_EAP_STATE, "No EAP methods are configured for this "
		   "network!  Please configure some and try again.\n");
      return NULL;
    }

  // A NAK consists of an EAP header, and a single data byte containing the
  // type we would prefer to use.
  outpacket = Malloc(sizeof(struct eap_header)+1);
  if (outpacket == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to create NAK "
		   "packet!\n");
      return NULL;
    }

  eapdata = (struct eap_header *)outpacket;

  eapdata->eap_code = EAP_RESPONSE_PKT;
  eapdata->eap_identifier = sm->reqId;
  eapdata->eap_length = htons(6);
  eapdata->eap_type = EAP_TYPE_NAK;
  outpacket[sizeof(struct eap_header)] = sm->curMethods->method_num;
  debug_printf(DEBUG_EAP_STATE, "NAKing for type %d\n",
	       sm->curMethods->method_num);

  return outpacket;
}

/**
 * \brief Switch to determining the EAP method to use.
 *
 * @param[in] sm   A pointer to the state machine that contains enough
 *                 information to allow us to determine which EAP method
 *                 to use.
 **/
void eap_sm_change_to_get_method(eap_sm *sm)
{
  int eapstruct = 0;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_GET_METHOD) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_GET_METHOD;

  if (allowMethod(sm) == TRUE)
    {
      if (sm->lastMethod != sm->reqMethod)
	{

		if (sm->lastMethod != 0)
		{
			// We changed EAP methods.  So clean up after the old one.
			eapstruct = eap_sm_find_method(sm->lastMethod);
			if (eapstruct != -1)
			{
				if ((eaphandlers[eapstruct].eap_deinit != NULL) && (sm->active != NULL))
				{
					eaphandlers[eapstruct].eap_deinit(sm->active);
					if (sm->eapKeyData != NULL) FREE(sm->eapKeyData);
					sm->eapKeyData = NULL;
					sm->eapKeyAvailable = FALSE;
				}
			}
		}

		sm->lastMethod = sm->reqMethod;
	}
      sm->selectedMethod = sm->reqMethod;
      sm->methodState = INIT;
    }
  else
    {
      sm->eapRespData = buildNak(sm);
      if (sm->eapRespData == NULL) 
	{
	  sm->eapReq = FALSE;
	  sm->eapResp = FALSE;
	  
	  if (sm->curMethods != NULL)
	  {
		debug_printf(DEBUG_NORMAL, "Packet discarded because a valid "
			       "EAP NAK could not be created.\n");
	  }

	  eap_sm_change_state(sm, EAP_DISCARD);
	  return;
	}
    }
  
  // Then determine where to go next.
  if (sm->selectedMethod == sm->reqMethod)
    {
      eap_sm_change_state(sm, EAP_METHOD);
      return;
    }

  // Otherwise, we have a NAK, so send it.
  eap_sm_change_state(sm, EAP_SEND_RESPONSE);
}

/**
 * Actually process an EAP method.
 *
 * @param[in] sm   A pointer to the EAP state machine that contains 
 *                 the information needed to process an EAP method.
 **/
void eap_sm_change_to_method(eap_sm *sm)
{
  int eapstruct = 0;
  int keyavail = FALSE;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_METHOD) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_METHOD;

  snmp_dot1xSuppEapolReqFramesRx();
  
  // First, determine where the EAP type we want to use is.
  eapstruct = eap_sm_find_method(sm->selectedMethod);
  if (eapstruct < 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't locate the EAP method that the server requested! (Phase %d)\n", sm->phase);
	  debug_printf(DEBUG_NORMAL, "Server asked for EAP method %d.\n", sm->selectedMethod);

	  debug_printf(DEBUG_NORMAL, "Dump : ");
	  debug_hex_printf(DEBUG_NORMAL, sm->eapReqData, 10);
	  return;
  }

  eap_sm_sync_ll_to_e(sm);
  if (eaphandlers[eapstruct].eap_check == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "No EAP check method available!  eapstruct index is %d!\n",
		  eapstruct);
	  return;
  }
  else
  {
	eaphandlers[eapstruct].eap_check(sm->active);
  }
  eap_sm_sync_e_to_ll(sm);

  if (sm->ignore == FALSE) 
    {
		keyavail = eaphandlers[eapstruct].eap_isKeyAvailable(sm->active);

      // Don't need to sync ll to e here, since it should still be current.
      eaphandlers[eapstruct].eap_process(sm->active);
      eap_sm_sync_e_to_ll(sm);
      
      /* methodState is CONT, MAY_CONT, or DONE */
      /* decision is  FAIL, COND_SUCC or UNCOND_SUCC */
      if (!sm->ignore)
	{
		FREE(sm->eapRespData);   // Make sure we don't leak anything.
	  sm->eapRespData = eaphandlers[eapstruct].eap_buildResp(sm->active);

	  snmp_dot1xSuppEapolRespFramesTx();

	  eap_sm_sync_e_to_ll(sm);

	  // Only do this once after we have transitioned from not having a key, to having one.  Otherwise,
	  // we end up wasting a lot of time regenerating key data over and over in phase 2.
	  if ((eaphandlers[eapstruct].eap_isKeyAvailable(sm->active)) && (keyavail == FALSE))
	    {
			FREE(sm->eapKeyData);  // Make sure we don't leak memory on keys.
	      sm->eapKeyData = eaphandlers[eapstruct].eap_getKey(sm->active);
	      sm->eapKeyLen = eaphandlers[eapstruct].eap_getKeyLen(sm->active);

	      eap_sm_sync_e_to_ll(sm);
	    }
	}
    }

  if (sm->ignore) 
    {
      if ((sm->selectedMethod != EAP_TYPE_LEAP) && (sm->decision != UNCOND_SUCC))
	{
	  debug_printf(DEBUG_NORMAL, "Packet discarded on request of higher "
		       "layer.\n");
	}
      eap_sm_change_state(sm, EAP_DISCARD);
      return;
    }

  if ((sm->methodState == DONE) && 
      (sm->decision == EAP_FAIL))
    {
      eap_sm_change_state(sm, EAP_FAILURE);
      return;
    }

  // Otherwise, send the response.
  eap_sm_change_state(sm, EAP_SEND_RESPONSE);
}

/**
 * \brief Send an EAP response.
 *
 * @param[in] sm   A pointer to an EAP state machine that has a response
 *                 packet ready to be sent.
 **/
void eap_sm_change_to_send_response(eap_sm *sm)
{
  struct eap_header *eapdata;
  uint16_t eapsize;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_SEND_RESPONSE) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_SEND_RESPONSE;

  sm->lastId = sm->reqId;

  if (sm->lastRespData != NULL)
    {
      debug_printf(DEBUG_EAP_STATE, "Clearing last response data.\n");
      FREE(sm->lastRespData);
    }

  if (sm->eapRespData == NULL)
    {
      debug_printf(DEBUG_NORMAL, "EAP type didn't return a valid packet to "
		   "send.  Ignoring.\n");
	  eap_sm_change_state(sm, EAP_DISCARD);
      return;
    }

  eapdata = (struct eap_header *)sm->eapRespData;
  eapsize = ntohs(eapdata->eap_length);
  sm->lastRespData = Malloc(eapsize);
  if (sm->lastRespData == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store a copy "
		   "of the EAP packet!\n");
    }
  else
    {
      debug_printf(DEBUG_EAP_STATE, "Allocated %d byte(s) for retransmit if needed"
		   ".\n", eapsize);
      memcpy(sm->lastRespData, sm->eapRespData, eapsize);
    }

  sm->eapReq = FALSE;
  sm->eapResp = TRUE;
  sm->idleWhile = config_get_idleWhile();

  eap_sm_change_state(sm, EAP_IDLE);
}

/**
 * \brief Discard the EAP data, and move on.
 *
 * @param[in] sm   A pointer to an EAP state machine that contains 
 *                 information we need to discard.
 **/
void eap_sm_change_to_discard(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_DISCARD) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eapReq = FALSE;
  sm->eapNoResp = TRUE;

  sm->eap_sm_state = EAP_DISCARD;

  if (sm->lastRespData != NULL)
  {
	  FREE(sm->lastRespData);
  }

  eap_sm_change_state(sm, EAP_IDLE);
}

/**
 * \brief Process any interesting EAP hints that are included in the
 *        request ID packet.
 *
 * If the length of the EAP request ID packet is longer than the space needed
 * to store the basic EAP request, then we may have some network hints.  These
 * hints may include a network name that we can use to determine which network
 * profile to read from the configuration.
 *
 * @param[in] sm   A pointer to the EAP state machine that contains the
 *                 EAP request ID packet.
 **/
void eap_sm_process_hints(eap_sm *sm)
{
#if 0   // Remove this for now, since no UIs support is.
  struct eap_header     *myeap;
  char                  *inframe;
  char                  *hints;
  char                  *networkid, *nidonly;
  struct config_globals *globals;
  uint16_t              eapsize;

  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    return;

  inframe = (char *)sm->eapReqData;

  myeap = (struct eap_header *)inframe;

  eapsize = ntohs(myeap->eap_length);

  if (eapsize > (OFFSET_TO_EAP + sizeof(struct eap_header) + 1))
    {
      // We may have some data.  The character that trails the end of the
      // EAP packet should be 0x00.  So, skip it and show the results.
      hints = (char *)&inframe[sizeof(struct eap_header)+1];

      globals = config_get_globals();
      if (!globals)
        {
          debug_printf(DEBUG_NORMAL, "Couldn't get global configuration "
                       "options.  Assuming we should use EAP hints.\n");
        }

      if ((!globals) ||
          (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_EAP_HINTS)))
        {

          if (hints[0] != 0x00)
            {
              networkid = strstr(hints, "networkid=");

              if (networkid != NULL)
                {
                  nidonly = strtok(networkid, ",");

                  nidonly += strlen("networkid=");

                  if (nidonly[0] != 0x00)
                    {
						// XXX Remove the below messages for now.  We don't provide the UI a way to take advantage of it anyway.
						/*
                      debug_printf(DEBUG_NORMAL, "Network ID from EAP hint : "
				   "%s\n", nidonly);
                      debug_printf(DEBUG_NORMAL, "If this is a wired network, "
				   "the above ID can be used in the "
				   "configuration file to identify this "
                                   "network.\n");
								   */

                      if (config_build(event_core_get_active_ctx(), nidonly) != TRUE)
                        {
                          debug_printf(DEBUG_NORMAL, "Couldn't build config "
				       "for network %s!\n", nidonly);
                        }
                    }
                }
            }
        }
    }
#endif //0 
}

/**
 * \brief Populate the identity for a profile, if needed.
 *
 * For certain EAP methods, such as SIM and AKA, we can populate the ID
 * based on something other than the config file.  (Such as a smartcard.)
 *
 * This function will also populate the ident field of the state machine
 * structure, so that higher layer EAP methods know what value we used.
 *
 * @param[in] sm   A pointer to the state machine that contains the
 *                 information we need to prepopulate the ID.
 **/
void eap_sm_prepopulate_id(eap_sm *sm)
{
	context *ctx;

  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    return;

  ctx = event_core_get_active_ctx();

  if (ctx == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Invalid context?\n");
	  return;
  }

  if (ctx->conn == NULL)
    {
		if (ctx->intType != ETH_802_11_INT)
		{
			debug_printf(DEBUG_NORMAL, "Attempted to authenticate on interface '%s'"
				" but, the interface doesn't have a connection defined.  Your "
				"authentication cannot continue.\n", ctx->desc);
		}
      return;
    }

  if (!xsup_assert((ctx->prof != NULL),
                   "ctx->prof != NULL", FALSE))
    return;

#ifdef EAP_SIM_ENABLE
  // If we have SIM enabled, there is no username, and the primary EAP method
  // is SIM, then ask the SIM card for it's IMSI to use as the username.
  if ((sm->ident == NULL) &&
	  (sm->curMethods->method_num == EAP_TYPE_SIM))
    {
      sm->ident = (char *)Malloc(50);
      if (sm->ident == NULL)
        {
          debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for identity!"
		       "\n");
          return;
        }
      eapsim_get_username(ctx);
	  if ((ctx->prof != NULL) && (ctx->prof->temp_username != NULL)) sm->ident = strdup(ctx->prof->temp_username);
    }

  // Same is true for AKA.
  if ((sm->ident == NULL) &&
      (sm->curMethods->method_num == EAP_TYPE_AKA))
    {
      sm->ident = (char *)Malloc(50);
      if (sm->ident == NULL)
        {
          debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for identity!"
		       "\n");
          return;
        }
      eapaka_get_username(ctx);
	  if ((ctx->prof != NULL) && (ctx->prof->temp_username != NULL)) sm->ident = strdup(ctx->prof->temp_username);
    }
#endif

  if (sm->ident == NULL)
  {
	  if (ctx->prof->identity != NULL)
	  {
		  sm->ident = ctx->prof->identity;
	  }
	  else
	  {
		  sm->ident = ctx->prof->temp_username;
	  }
  }
}


/**
 * \brief Process an identity message and determine what to do with it.
 *
 * @param[in] sm   A pointer to a state machine that contains a request
 *                 identity packet that needs to be processed.
 **/
void processIdentity(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  snmp_dot1xSuppEapolReqIdFramesRx();

  eap_sm_process_hints(sm);
  eap_sm_prepopulate_id(sm);
}

/**
 * \brief Build a response ID message.
 *
 * @param[in] reqId   The request ID value that was send in the request
 *                    ID message.
 *
 * @param[in] ident   The identity to use in the response.
 *
 * \retval NULL on error
 * \retval ptr to a response ID packet on success
 **/
uint8_t *buildIdentity(uint8_t reqId, char *ident)
{
  uint8_t               *newframe;
  struct eap_header     *myeap;
  uint16_t               eapsize;
  uint8_t               *username_ofs;

  if (ident == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "No identity was defined for this "
		   "network!  Please be sure you have an 'Identity' field "
		   "defined for this network in your configuration file.\n");
      return NULL;
    }
  
  debug_printf(DEBUG_EAP_STATE, "Identity : %s\n", ident);

  newframe = Malloc(sizeof(struct eap_header)+strlen(ident)+1);
  if (newframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to create EAP "
		   "packet!\n");
      return NULL;
    }

  // Otherwise, build the response.
  myeap = (struct eap_header *)newframe;

  myeap->eap_code = EAP_RESPONSE_PKT;
  myeap->eap_identifier = reqId;

  eapsize = (strlen(ident)+sizeof(struct eap_header));
  myeap->eap_length = htons(eapsize);

  myeap->eap_type = EAP_TYPE_IDENTITY;
  
  username_ofs = &newframe[sizeof(struct eap_header)];
  if (Strncpy((char *)username_ofs, 
	  ((sizeof(struct eap_header)+strlen(ident)+1)-sizeof(struct eap_header)), 
	  ident, strlen(ident) + 1) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't copy the user's identity in %s() at %d!\n",
			__FUNCTION__, __LINE__);
	  return NULL;
  }

  snmp_dot1xSuppEapolRespIdFramesTx();

  return newframe;
}

/**
 * \brief Process an identity message, and send an identity response.
 *
 * @param[in] sm   A pointer to the state machine that contains the 
 *                 information needed to process and response to an
 *                 identity request.
 **/
void eap_sm_change_to_identity(eap_sm *sm)
{
	context *ctx;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_IDENTITY) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_IDENTITY;

  sm->credsSent = FALSE;			// We have not sent our creds yet.

  ctx = event_core_get_active_ctx();
  if (ctx == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Somehow we got to IDENTITY state in the EAP state machine, but we don't have a context!?\n");
	  return;
  }

  debug_printf(DEBUG_NORMAL, "Interface : %s --- Starting Authentication (Phase %d) ---\n", ctx->desc, sm->phase);
  
  processIdentity(sm);

  FREE(sm->eapRespData);

  sm->eapRespData = buildIdentity(sm->reqId, sm->ident);

  if (sm->eapRespData != NULL) 
    {
      sm->eapResp = TRUE;
      sm->eapNoResp = FALSE;
    }
  else
  {
		eap_sm_change_state(sm, EAP_DISCARD);
		return;
  }

  sm->methodState = INIT;
  eap_sm_change_state(sm, EAP_SEND_RESPONSE);
}

/**
 * \brief Process a notification message, and determine what to do with it.
 *
 * @param[in] eapReqData   A pointer to an EAP request that contains a 
 *                         notification message.
 **/
void processNotify(uint8_t *eapReqData)
{
  struct eap_header *myeap;
  char *notify_str;
  uint16_t length;

  if (!xsup_assert((eapReqData != NULL), "eapReqData != NULL", FALSE))
    return;

  myeap = (struct eap_header *)eapReqData;

  length = ntohs(myeap->eap_length);

  length -= sizeof(struct eap_header);

  notify_str = Malloc(length + 1);
  if (notify_str == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
		   "notification string.\n");
	  ipc_events_malloc_failed(NULL);
      return;
    }

  if (Strncpy(notify_str, (length + 1), (const char *)&eapReqData[sizeof(struct eap_header)], 
	  length) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to overflow the buffer in %s() at %d!\n",
		  __FUNCTION__, __LINE__);
	  return;
  }

  xsup_ipc_send_eap_notify(notify_str);

  FREE(notify_str);
}

/**
 *  Build a notification response.
 *
 * @param[in] reqId   The request ID value from the notification request
 *                    message.
 *
 * \retval NULL on error, or nothing to send
 * \retval ptr to a notification response packet
 **/
uint8_t *buildNotify(uint8_t reqId)
{
  // For now, we do nothing.  (We shouldn't have a notification to send.)
  return NULL;
}

/**
 * \brief Process a notification message.
 *
 * @param[in] sm   A pointer to the EAP state machine that contains the
 *                 notification message.
 **/
void eap_sm_change_to_notification(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
   // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_NOTIFICATION) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_NOTIFICATION;

  processNotify(sm->eapReqData);
  sm->eapRespData = buildNotify(sm->reqId);

  eap_sm_change_state(sm, EAP_SEND_RESPONSE);
}

/**
 * \brief Retransmit a packet if we need to.
 *
 * @param[in] sm   A pointer to a state machine that contains data that
 *                 needs to be retransmitted.
 **/
void eap_sm_change_to_retransmit(eap_sm *sm)
{
  struct eap_header *eapdata = NULL;
  uint16_t           eapsize = 0;
  context			*ctx = NULL;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_RETRANSMIT) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_RETRANSMIT;

  FREE(sm->eapRespData);

  if (sm->lastRespData == NULL)
    {
		// Check and see if we have a callback hooked up.  If we do, then
		// just discard this frame.
		ctx = event_core_get_active_ctx();
		if (ctx->pwd_callback == NULL)
		{
			debug_printf(DEBUG_EAP_STATE, "There was nothing buffered to "
				"retransmit!?\n");

			sm->eapFail = TRUE;
			return;
		}

		eap_sm_change_state(sm, EAP_DISCARD);
		return;
    }
  
  eapdata = (struct eap_header *)sm->lastRespData;
  eapsize = ntohs(eapdata->eap_length);

  sm->eapRespData = Malloc(eapsize);
  if (sm->eapRespData != NULL)
    {
      memcpy(sm->eapRespData, sm->lastRespData, eapsize);
    }

  sm->eapResp = TRUE;

  eap_sm_change_state(sm, EAP_SEND_RESPONSE);
}

/**
 * \brief We got a success message, so set up our key data.
 *
 * @param[in] sm   A pointer to the EAP state machine that contains the
 *                 EAP method that has succeeded.
 **/
void eap_sm_change_to_success(eap_sm *sm)
{
	context *ctx = NULL;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_SUCCESS) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eap_sm_state = EAP_SUCCESS;

  if (sm->eapKeyData != NULL) 
      sm->eapKeyAvailable = TRUE;

  sm->eapSuccess = TRUE;

  ctx = event_core_get_active_ctx();
  if (ctx == NULL)
	return;            // How did we get here!?

  debug_printf(DEBUG_NORMAL, "Interface : %s --- Authenticated (Phase %d) ---\n", ctx->desc, sm->phase);
#if 0
  if (ipc_events_authenticated(ctx, sm->phase) != IPC_SUCCESS)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't send 'starting authentication' log to UI!\n");
  }
#endif
}

/**
 * \brief We failed the EAP authentication.
 *
 * @param[in] sm  A pointer to the EAP state machine that has failed the
 *                authentication.
 **/
void eap_sm_change_to_failure(eap_sm *sm)
{
  context *ctx = NULL;

  xsup_assert((sm != NULL), "sm != NULL", TRUE);

#if EAP_SM_EVENTS == 1
  // Let all connected listeners know that we transitioned state.
  if (ipc_events_statemachine_transition(event_core_get_active_ctx(), IPC_STATEMACHINE_EAP, sm->eap_sm_state, EAP_FAILURE) != IPC_SUCCESS)
  {
	  // Display, or log an error message, and move on.
	  debug_printf(DEBUG_NORMAL, "Unable to send IPC EAP state change message!\n");
  }
#endif

  sm->eapFail = TRUE;

  ctx = event_core_get_active_ctx();
  if (ctx == NULL)
	  return;		// How did we get here!?

  debug_printf(DEBUG_NORMAL, "Interface : %s --- Authentication Failed (Phase %d) ---\n", ctx->desc, sm->phase);

#if 0
  if (ipc_events_authentication_failed(ctx, sm->phase) != IPC_SUCCESS)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't send 'authentication failed' log to UI!\n");
  }
#endif

  sm->eap_sm_state = EAP_FAILURE;

  if (sm->credsSent == TRUE)
  {
	  // We got a failure after the EAP method indicated it sent it's credentials.
	  // So free the temp credentials (if there are any)
	  if (ctx->prof != NULL)
	  {
		  debug_printf(DEBUG_NORMAL, "Authentication failed on '%s' after credentials were sent.  Flushing in memory credentials and requesting new ones.\n", ctx->desc);
		  FREE(ctx->prof->temp_username);
		  FREE(ctx->prof->temp_password);

		  // Ask the UI to give us new credentials.
		  ipc_events_ui(ctx, IPC_EVENT_8021X_FAILED, ctx->conn_name);
	  }
  }
}

/**
 * \brief Change our state to a new one by executing the one time code
 *        needed for the new state.
 *
 * @param[in] sm   A pointer to the EAP state machine that needs to change
 *                 state.
 *
 * @param[in] newstate   The state that the EAP state machine should
 *                       transition to.
 **/
void eap_sm_change_state(eap_sm *sm, int newstate)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  eap_sm_disp_state_change(DEBUG_EAP_STATE, sm, newstate);

  switch (newstate)
    {
    case EAP_DISABLED:
      eap_sm_change_to_disabled(sm);
      break;

    case EAP_INITIALIZE:
      eap_sm_change_to_initialize(sm);
      break;

    case EAP_IDLE:
      eap_sm_change_to_idle(sm);
      break;

    case EAP_RECEIVED:
      eap_sm_change_to_received(sm);
      break;

    case EAP_GET_METHOD:
      eap_sm_change_to_get_method(sm);
      break;

    case EAP_METHOD:
      eap_sm_change_to_method(sm);
      break;

    case EAP_SEND_RESPONSE:
      eap_sm_change_to_send_response(sm);
      break;

    case EAP_DISCARD:
      eap_sm_change_to_discard(sm);
      break;

    case EAP_IDENTITY:
      eap_sm_change_to_identity(sm);
      break;

    case EAP_NOTIFICATION:
      eap_sm_change_to_notification(sm);
      break;

    case EAP_RETRANSMIT:
      eap_sm_change_to_retransmit(sm);
      break;

    case EAP_SUCCESS:
      eap_sm_change_to_success(sm);
      break;

    case EAP_FAILURE:
      eap_sm_change_to_failure(sm);
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Request to change to state %d, which is "
		   "invalid!\n", newstate);
    }
}

/**
 * \brief Check global transitions in the state machine, and change states
 *        accordingly.
 *
 * @param[in] sm   A pointer to the state machine that needs to be checked
 *                 for global transitions.
 *
 * \retval 1 if a state change was called, and handled.
 * \retval 0 if the caller should handle the state change itself
 **/
int eap_sm_check_globals(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);
  
  if (sm->portEnabled != TRUE)
    {
      eap_sm_change_state(sm, EAP_DISABLED);
      return 1;
    }

  if ((sm->eapRestart) && (sm->portEnabled))
    {
      eap_sm_change_state(sm, EAP_INITIALIZE);
      return 1;
    }

  return 0;
}

/**
 * \brief Run the EAP state machine.
 *
 * @param[in] sm   A pointer to the EAP state machine that we need to run.
 *
 * \retval XENONE on success
 **/
int eap_sm_run(eap_sm *sm)
{
  xsup_assert((sm != NULL), "sm != NULL", TRUE);

  if (sm->portEnabled != FALSE)   // Only run if the port is enabled.
  {
	  if (eap_sm_check_globals(sm) == 0)
	  {
	    eap_sm_change_to_idle(sm);
	  }
  }

  return XENONE;
}

/**
 * \brief Clean up our EAP state machine data.
 *
 * @param[in] sm   The EAP state machine to clean up.
 **/
void eap_sm_deinit(eap_sm **sm)
{
  int eapstruct = 0;

  debug_printf(DEBUG_DEINIT, "Deinit EAP State machine.\n");
  // Clean up the memory that we had left over.
  if (!xsup_assert(((*sm) != NULL), "(*sm) != NULL", FALSE))
    {
      debug_printf(DEBUG_NORMAL, "Nothing to clean up!\n");
      return;
    }

  if ((*sm)->active != NULL)
    {
		if ((*sm)->selectedMethod != (*sm)->lastMethod)
		{
			if ((*sm)->lastMethod != 0)
			{
				debug_printf(DEBUG_EAP_STATE, "Calling deinit for EAP type %d\n",
					   (*sm)->lastMethod);

				eapstruct = eap_sm_find_method((*sm)->lastMethod);
				if (eaphandlers[eapstruct].eap_deinit != NULL)
				{
					eaphandlers[eapstruct].eap_deinit((*sm)->active);
					FREE((*sm)->eapKeyData);
					(*sm)->eapKeyAvailable = FALSE;
				}
			}

			(*sm)->lastMethod = (*sm)->selectedMethod;
		}

      FREE((*sm)->active);
    }

  // Otherwise, clean up the pointers in the structure.

  // No need to free eapReqData, since it will always point to another buffer.

  FREE((*sm)->eapRespData);
  FREE((*sm)->eapKeyData);
  FREE((*sm)->lastRespData);
  FREE((*sm));
}

