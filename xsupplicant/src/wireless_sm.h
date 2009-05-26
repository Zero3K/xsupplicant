/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wireless_sm.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _WIRELESS_SM_H_
#define _WIRELESS_SM_H_

// A simple state machine that switches us between associated, and
// unassociated states.  If you add or change any of these, make sure
// to update wireless_sm_disp_state() or your debug information will
// be messed up.  ;)

#define UNKNOWN               0
#define UNASSOCIATED          1
#define ASSOCIATED            2
#define ACTIVE_SCAN           3	// There may be a passive scan later.
#define ASSOCIATING           4	// Attempting to associate
#define ASSOCIATION_TIMEOUT_S 5
// State 6 has been removed.
#define PORT_DOWN             7	// The interface is down state.
#define NO_ENC_ASSOCIATION    8
#define INT_RESTART           9	// Restart everything.
#define INT_STOPPED           10	// Stop answering requests.
#define INT_HELD              11	// Hold the authentication, waiting for an event.

void wireless_sm_init(int, context *);
void wireless_sm_deinit(wireless_ctx *);
void wireless_sm_change_state(int, context *);
void wireless_sm_dump_state();
uint8_t wireless_sm_get_state(context *);
void wireless_sm_do_state(context *);
void wireless_sm_association_timeout(context *ctx);
#endif
