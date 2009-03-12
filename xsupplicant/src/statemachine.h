/**
 * Handle state machine related functions.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file statemachine.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _STATEMACHINE_H_
#define _STATEMACHINE_H_

// This matches the order of states listed in IEEE 802.1X-2001, pg. 59,
// section 8.5.10.
#define LOGOFF           1
#define DISCONNECTED     2
#define CONNECTING       3
#define ACQUIRED         4
#define AUTHENTICATING   5
#define HELD             6
#define AUTHENTICATED    7

// 802.1X-REV-d11 (2004) specifies a few additional states.  Also, in EAPoL
// v2, the ACQUIRED state no longer exists.
#define RESTART          8
#define S_FORCE_AUTH     9
#define S_FORCE_UNAUTH   10

extern void (*imc_disconnect_callback) (uint32_t connectionID);

int statemachine_init(context *);
int statemachine_reinit(context *);
int statemachine_run(context *);
int statemachine_cleanup(context *);
int txLogoff(context *);
int txRspId(context *, char *, int *);
int txRspAuth(context *, char *, int, char *, int *);
int txStart(context *);
int statemachine_change_state(context *, int);
#endif
