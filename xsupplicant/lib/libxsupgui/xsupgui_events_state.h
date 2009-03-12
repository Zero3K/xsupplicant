/**
 * Values to define which state machine generated and event, and
 * how the states transitioned.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupgui_events_state.h
 *
 * \author chris@open1x.org
 *
 */
#ifndef _XSUPGUI_EVENTS_STATE_H_
#define _XSUPGUI_EVENTS_STATE_H_

// State machines that we may get state machine events for.  (This *MUST*
// stay in sync with the values of the same name in ipc_events_index.h!)
#define IPC_STATEMACHINE_PHYSICAL                              1	///< Identify the physical state machine
#define IPC_STATEMACHINE_8021X                                 2	///< Identify the 802.1X primary state machine
#define IPC_STATEMACHINE_8021X_BACKEND                         3	///< Identify the 802.1X back end state machine
#define IPC_STATEMACHINE_EAP                                   4	///< Identify the EAP state machine.

// Values for the physical state machine, when the physical interface is
// a wireless interface.  These *MUST* stay in sync with wireless_sm.h.
#define UNKNOWN               0	///< The wireless state machine is in an UNKNOWN state.
#define UNASSOCIATED          1	///< The wireless state machine is in UNASSOCIATED state.
#define ASSOCIATED            2	///< The wireless state machine is in ASSOCIATED state.
#define ACTIVE_SCAN           3	///< The wireless state machine is in ACTIVE_SCAN state.
#define ASSOCIATING           4	///< The wireless state machine is in ASSOCIATING state.
#define ASSOCIATION_TIMEOUT_S 5	///< The wireless state machine is in ASSOCIATION_TIMEOUT_S state.
// State 6 has been removed.
#define PORT_DOWN             7	///< The interface is down state.
#define NO_ENC_ASSOCIATION    8	///< Associated to a network with no encryption.
#define INT_RESTART           9	///< Restart everything (All interface state machines)
#define INT_STOPPED           10	///< Stop answering requests.
#define INT_HELD              11	///< Hold the authentication, waiting for an event.

// This matches the order of states listed in IEEE 802.1X-2001, pg. 59,
// section 8.5.10.
#define LOGOFF           1	///< The 802.1X LOGOFF state
#define DISCONNECTED     2	///< The 802.1X DISCONNECTED state
#define CONNECTING       3	///< The 802.1X CONNECTING state
#define ACQUIRED         4	///< The 802.1X ACQUIRED state
#define AUTHENTICATING   5	///< The 802.1X AUTHENTICATING state
#define HELD             6	///< The 802.1X HELD state
#define AUTHENTICATED    7	///< The 802.1X AUTHENTICATED state
// 802.1X-REV-d11 (2004) specifies a few additional states.  Also, in EAPoL
// v2, the ACQUIRED state no longer exists.
#define RESTART          8	///< The 802.1X RESTART state
#define S_FORCE_AUTH     9	///< The 802.1X S_FORCE_AUTH state
#define S_FORCE_UNAUTH   10	///< The 802.1X S_FORCE_UNAUTH state

// States that the 802.1X backend state machine can be in.
#define UNKNOWN      0		///< The 802.1X backend state machine is in an UNKNOWN state.
#define REQUEST      1		///< The 802.1X backend state machine REQUEST state
#define RESPONSE     2		///< The 802.1X backend state machine RESPONSE state
#define SUCCESS      3		///< The 802.1X backend state machine SUCCESS state
#define FAIL         4		///< The 802.1X backend state machine FAIL state
#define TIMEOUT      5		///< The 802.1X backend state machine TIMEOUT state
#define IDLE         6		///< The 802.1X backend state machine IDLE state
#define INITIALIZE   7		///< The 802.1X backend state machine INITIALIZE state
#define RECEIVE      8		///< The 802.1X backend state machine RECEIVE state

// States for the EAP state machine.
#define EAP_UNKNOWN        0	///< The EAP UNKNOWN state
#define EAP_DISABLED       1	///< The EAP DISABLED state
#define EAP_INITIALIZE     2	///< The EAP INITIALIZE state
#define EAP_IDLE           3	///< The EAP IDLE state
#define EAP_RECEIVED       4	///< The EAP RECEIVED state
#define EAP_GET_METHOD     5	///< The EAP GET_METHOD state
#define EAP_METHOD         6	///< The EAP METHOD state
#define EAP_SEND_RESPONSE  7	///< The EAP SEND_RESPONSE state
#define EAP_DISCARD        8	///< The EAP DISCARD state
#define EAP_IDENTITY       9	///< The EAP IDENTITY state
#define EAP_NOTIFICATION   10	///< The EAP NOTIFICATION state
#define EAP_RETRANSMIT     11	///< The EAP RETRANSMIT state
#define EAP_SUCCESS        12	///< The EAP SUCCESS state
#define EAP_FAILURE        13	///< The EAP FAILURE state

char *xsupgui_events_state_get_statemachine_str(int);
char *xsupgui_events_state_get_wireless_state_str(int);
char *xsupgui_events_state_get_8021X_state_str(int);
char *xsupgui_events_state_get_8021Xbe_state_str(int);
char *xsupgui_events_state_get_eap_state_str(int);
#endif				// _XSUPGUI_EVENTS_STATE_H_
