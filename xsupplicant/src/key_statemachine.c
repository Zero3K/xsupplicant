/**
 * Handle the EAPOL keying state machine.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file key_statemachine.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdlib.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "key_statemachine.h"
#include "eapol_key_type1.h"
#include "eapol_key_type2.h"
#include "eapol_key_type254.h"
#include "xsup_debug.h"
#include "frame_structs.h"
#include "ipc_events.h"
#include "ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/*************************************************
 *
 * Call the processKey() function defined in the 802.1x standard.  Here, we
 * need to determine what type of key it is, and call the correct handler.
 *
 *************************************************/
void processKey(context *thisint)
{
  struct key_packet *keydata;
  uint8_t *inframe;

  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return;

  inframe = thisint->recvframe;

  keydata = (struct key_packet *)&inframe[OFFSET_TO_EAP];

  switch (keydata->key_descr)
    {
    case RC4_KEY_TYPE:
      eapol_key_type1_process(thisint);
      break;

    case WPA2_KEY_TYPE:                    // WPA2/802.11i keying
#ifndef DARWIN_WIRELESS
      eapol_key_type2_process(thisint);
#else
      debug_printf(DEBUG_KEY_STATE, "Ignoring key frame!\n");
      FREE(thisint->recvframe);
      thisint->recv_size = 0;
#endif
      break;
      
    case WPA_KEY_TYPE:
#ifndef DARWIN_WIRELESS
      eapol_key_type254_process(thisint);
#else
      debug_printf(DEBUG_KEY_STATE, "Ignoring key frame!\n");
      FREE(thisint->recvframe);
      thisint->recv_size = 0;
#endif
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown EAPoL Key Descriptor (%d)!\n",
		   keydata->key_descr);
	  ipc_events_error(thisint, IPC_EVENT_ERROR_UNKNOWN_EAPOL_KEY_TYPE, NULL);
      break;
    }

  thisint->recv_size = 0;  // Make sure we don't try to process it again.
}

/*************************************************
 *
 * Run the keying state machine that is defined in the 802.1x standard.  
 * Depending on the state, we may need to process a key.
 *
 *************************************************/
void key_statemachine_run(context *thisint)
{
  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return;

  if (!xsup_assert((thisint->statemachine != NULL), 
		   "thisint->statemachine != NULL", FALSE))
    return;

  if ((thisint->statemachine->initialize == TRUE) ||
      (thisint->statemachine->portEnabled == FALSE))
    {
      // Do the NO_KEY_RECIEVE part of the state machine.
    }

  if (thisint->statemachine->rxKey == TRUE)
    {
      processKey(thisint);
      thisint->statemachine->rxKey = FALSE;
    }
}
