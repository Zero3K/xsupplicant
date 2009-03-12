/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_events_state.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupgui_events_state.c,v 1.3 2007/10/17 07:00:46 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:46 $
 **/

#include <stdio.h>
#include <string.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "src/xsup_common.h"
#include "xsupgui_events_state.h"

/**
 * \brief Convert a numeric representation of the state
 *        machine in use to a string and return it.
 *
 * \note The caller is expected to free the returned memory!
 *
 * @param[in] state   A numeric representation of the state machine
 *                    that generated an event.
 *
 * \retval ptr   A pointer to a string that identifies the state machine
 *               in use.
 * \retval NULLL   On error.
 **/
char *xsupgui_events_state_get_statemachine_str(int state)
{
	char *retval = NULL;

	switch (state) {
	case IPC_STATEMACHINE_PHYSICAL:
		retval = _strdup("Physical");
		break;

	case IPC_STATEMACHINE_8021X:
		retval = _strdup("802.1X");
		break;

	case IPC_STATEMACHINE_8021X_BACKEND:
		retval = _strdup("802.1X Backend");
		break;

	case IPC_STATEMACHINE_EAP:
		retval = _strdup("EAP");
		break;

	default:
		retval = NULL;
		break;
	}

	return retval;
}

/**
 * \brief Convert a numeric representation of a state for a wireless
 *        interface to a string.
 *
 * @param[in] state   The numeric representation of the state the 
 *                    wireless interface is in.
 *
 * \note The caller is expected to free the returned memory!
 *
 * \retval NULL on error
 * \retval ptr to a string that identifies the state the wireless state
 *         machine is in.
 **/
char *xsupgui_events_state_get_wireless_state_str(int state)
{
	char *retval = NULL;

	switch (state) {
	case UNKNOWN:
		retval = _strdup("UNKNOWN");
		break;

	case UNASSOCIATED:
		retval = _strdup("UNASSOCIATED");
		break;

	case ASSOCIATED:
		retval = _strdup("ASSOCIATED");
		break;

	case ACTIVE_SCAN:
		retval = _strdup("ACTIVE_SCAN");
		break;

	case ASSOCIATING:
		retval = _strdup("ASSOCIATING");
		break;

	case ASSOCIATION_TIMEOUT_S:
		retval = _strdup("ASSOCIATING_TIMEOUT_S");
		break;

	case PORT_DOWN:
		retval = _strdup("PORT_DOWN");
		break;

	case NO_ENC_ASSOCIATION:
		retval = _strdup("NO_ENC_ASSOCIATION");
		break;

	case INT_RESTART:
		retval = _strdup("INT_RESTART");
		break;

	case INT_STOPPED:
		retval = _strdup("INT_STOPPED");
		break;

	case INT_HELD:
		retval = _strdup("INT_HELD");
		break;

	default:
		retval = NULL;
		break;
	}

	return retval;
}

/**
 * \brief Convert a numeric representation of a state for an 802.1X
 *        state to a string.
 *
 * @param[in] state   The numeric representation of the state the 
 *                    interface is in.
 *
 * \note The caller is expected to free the returned memory!
 *
 * \retval NULL on error
 * \retval ptr to a sting that identifies the state the 802.1X state
 *         machine is in.
 **/
char *xsupgui_events_state_get_8021X_state_str(int state)
{
	char *retval = NULL;

	switch (state) {
	case LOGOFF:
		retval = _strdup("LOGOFF");
		break;

	case DISCONNECTED:
		retval = _strdup("DISCONNECTED");
		break;

	case CONNECTING:
		retval = _strdup("CONNECTING");
		break;

	case ACQUIRED:
		retval = _strdup("ACQUIRED");
		break;

	case AUTHENTICATING:
		retval = _strdup("AUTHENTICATING");
		break;

	case HELD:
		retval = _strdup("HELD");
		break;

	case AUTHENTICATED:
		retval = _strdup("AUTHENTICATED");
		break;

	case RESTART:
		retval = _strdup("RESTART");
		break;

	case S_FORCE_AUTH:
		retval = _strdup("S_FORCE_AUTH");
		break;

	case S_FORCE_UNAUTH:
		retval = _strdup("S_FORCE_UNAUTH");
		break;

	default:
		retval = NULL;
		break;
	}

	return retval;
}

/**
 * \brief Convert a numeric representation of a state for an 802.1X
 *        backend state to a string.
 *
 * @param[in] state   The numeric representation of the state the 
 *                    interface is in.
 *
 * \note The caller is expected to free the returned memory!
 *
 * \retval NULL on error
 * \retval ptr to a string that identifies the state the 802.1X backend
 *         state machine is in.
 **/
char *xsupgui_events_state_get_8021Xbe_state_str(int state)
{
	char *retval = NULL;

	switch (state) {
	case UNKNOWN:
		retval = _strdup("UNKNOWN");
		break;

	case REQUEST:
		retval = _strdup("REQUEST");
		break;

	case RESPONSE:
		retval = _strdup("RESPONSE");
		break;

	case SUCCESS:
		retval = _strdup("SUCCESS");
		break;

	case FAIL:
		retval = _strdup("FAIL");
		break;

	case TIMEOUT:
		retval = _strdup("TIMEOUT");
		break;

	case IDLE:
		retval = _strdup("IDLE");
		break;

	case INITIALIZE:
		retval = _strdup("INITIALIZE");
		break;

	case RECEIVE:
		retval = _strdup("RECEIVE");
		break;

	default:
		retval = NULL;
		break;
	}

	return retval;
}

/**
 * \brief Convert a numeric representation of a state for an EAP
 *        state to a string.
 *
 * @param[in] state   The numeric representation of the state the 
 *                    interface is in.
 *
 * \note The caller is expected to free the returned memory!
 *
 * \retval NULL on error
 * \retval ptr to a string that identifies the state the EAP
 *         state machine is in.
 **/
char *xsupgui_events_state_get_eap_state_str(int state)
{
	char *retval = NULL;

	switch (state) {
	case EAP_UNKNOWN:
		retval = _strdup("UNKNOWN");
		break;

	case EAP_DISABLED:
		retval = _strdup("DISABLED");
		break;

	case EAP_INITIALIZE:
		retval = _strdup("INITIALIZE");
		break;

	case EAP_IDLE:
		retval = _strdup("IDLE");
		break;

	case EAP_RECEIVED:
		retval = _strdup("RECEIVED");
		break;

	case EAP_GET_METHOD:
		retval = _strdup("GET_METHOD");
		break;

	case EAP_METHOD:
		retval = _strdup("METHOD");
		break;

	case EAP_SEND_RESPONSE:
		retval = _strdup("SEND_RESPONSE");
		break;

	case EAP_DISCARD:
		retval = _strdup("DISCARD");
		break;

	case EAP_IDENTITY:
		retval = _strdup("IDENTITY");
		break;

	case EAP_NOTIFICATION:
		retval = _strdup("NOTIFICATION");
		break;

	case EAP_RETRANSMIT:
		retval = _strdup("RETRANSMIT");
		break;

	case EAP_SUCCESS:
		retval = _strdup("SUCCESS");
		break;

	case EAP_FAILURE:
		retval = _strdup("FAILURE");
		break;

	default:
		retval = NULL;
		break;
	}

	return retval;
}
