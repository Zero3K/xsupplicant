/*******************************************************************
 * Control the backend state machine as defined in 802.1X-REV-d11.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file backend_sm.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _BACKEND_SM_
#define _BACKEND_SM_

#define UNKNOWN      0
#define REQUEST      1
#define RESPONSE     2
#define SUCCESS      3
#define FAIL         4
#define TIMEOUT      5
#define IDLE         6
#define INITIALIZE   7
#define RECEIVE      8


void backend_sm_init(context *);
void backend_sm_reinit(context *);
int backend_sm_run(context *);
void backend_sm_deinit(context *);
void backend_sm_change_state(context *, int);

#endif
