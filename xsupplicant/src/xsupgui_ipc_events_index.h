/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_events_index.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/
#ifndef __IPC_EVENTS_INDEX_H__
#define __IPC_EVENTS_INDEX_H__

// Logging Events  (Use xsupgui_events_generate_log_string() to process these!)
#define IPC_EVENT_LOG_ATTEMPTING_TO_ASSOCIATE                  1   ///< The supplicant is attempting to associate to SSID %s.
#define IPC_EVENT_LOG_SCANNING                                 2   ///< The supplicant is scanning for wireless networks.
#define IPC_EVENT_LOG_ASSOCIATED                               3   ///< The supplicant has associated to network %s.
#define IPC_EVENT_LOG_STARTING_AUTH                            4   ///< ---- Starting Authentication (Phase %s) ----
#define IPC_EVENT_LOG_AUTHENTICATED                            5   ///< Authenticated
#define IPC_EVENT_LOG_AUTHENTICATION_FAILED                    6   ///< Authentication Failed

#define IPC_EVENT_LOG_MAX                                      6   ///< The highest index that is considered a log event.

// Error Events
#define IPC_EVENT_ERROR_CANT_START_SCAN                        1   ///< The supplicant failed to start a scan.  Error was : %s.


// State machines that we may get state machine events for.
// The values in xsupgui_events_state.h *MUST* stay in sync with these!
// Failure to do so will result in strange results.
#define IPC_STATEMACHINE_PHYSICAL                              1   ///< Identify the physical state machine
#define IPC_STATEMACHINE_8021X                                 2   ///< Identify the 802.1X primary state machine
#define IPC_STATEMACHINE_8021X_BACKEND                         3   ///< Identify the 802.1X back end state machine
#define IPC_STATEMACHINE_EAP                                   4   ///< Identify the EAP state machine.


#endif // __IPC_EVENTS_INDEX_H__