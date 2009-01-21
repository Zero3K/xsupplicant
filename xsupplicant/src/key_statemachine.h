/**
 * Handle the keying state machine.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file key_statemachine.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _KEY_STATEMACHINE_H_
#define _KEY_STATEMACHINE_H_

#include "context.h"

#define RC4_KEY_TYPE       1
#define WPA2_KEY_TYPE      2
#define WPA_KEY_TYPE       254

void key_statemachine_run(context *);


#endif

