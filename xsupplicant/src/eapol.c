/**
 * \file eapol.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <stdlib.h>
#include <stdio.h>

#ifndef WINDOWS
#include <netinet/in.h>
#include <strings.h>
#else
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "snmp.h"
#include "frame_structs.h"
#include "statemachine.h"
#include "eapol.h"
#include "eap_sm.h"
#include "platform/cardif.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "key_statemachine.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/********************************************
 *
 * Set up anything that we will need for EAPoL.  This includes setting the
 * default values for the state machine.
 *
 ********************************************/
int eapol_init(context * newint)
{
	if (!xsup_assert((newint != NULL), "newint != NULL", FALSE))
		return XEMALLOC;

	statemachine_init(newint);

	return XENONE;
}

/*****************************************
 *
 * Do anything that is needed to clean up, and exit cleanly.
 *
 *****************************************/
int eapol_cleanup(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	statemachine_cleanup(ctx);

	return XENONE;
}

/*****************************************
 *
 * Get the EAPOL version that we should be using.
 *
 *****************************************/
uint8_t eapol_get_eapol_ver(context * ctx)
{
	uint8_t eapolver;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return 2;

	if (ctx->conn == NULL) {
		debug_printf(DEBUG_INT,
			     "No configuration available to determine "
			     "proper EAPoL value!  Using default!\n");
		return 2;
	}

	eapolver = ctx->conn->force_eapol_ver;

	// If we have not hard set the eapol version, then use the last
	// version that the authenticator gave us.  This isn't in line with
	// the 802.1X-REV-2004 standard, but many authenticators are checking
	// version #s, and breaking when it isn't 1. :-/
	if ((eapolver < 1) || (eapolver > MAX_EAPOL_VER)) {
		// XXX  FIX : We need to make the SNMP counters multi interface aware.
		//eapolver = snmp_get_dot1xSuppLastEapolFrameVersion();
		eapolver = ctx->eapol_version;

		if (eapolver == 0) {
			eapolver = MAX_EAPOL_VER;
		}
	}

	return eapolver;
}

/*****************************************
 *
 * Add an EAPOL header to a frame that is in the "frame" buffer.
 *
 *****************************************/
void eapol_build_header(context * ctx, int eapolType, int length, char *frame)
{
	struct eapol_header *eapolheader;

	if (!xsup_assert((frame != NULL), "frame != NULL", FALSE))
		return;

	eapolheader = (struct eapol_header *)&frame[OFFSET_PAST_MAC];

	eapolheader->eapol_length = htons(length);
	eapolheader->frame_type = htons(EAPOL_FRAME);
	eapolheader->eapol_version = eapol_get_eapol_ver(ctx);
	eapolheader->eapol_type = eapolType;
}

/*****************************************
 *
 * Actually check to see if we have a frame, and process it if we do.
 *
 *****************************************/
int eapol_execute(context * workint)
{
	struct eapol_header *temp;
	char *inframe;		// A pointer to our frame data.  (Normally will point
	// to the newframe[] array.)
	uint8_t sm_runs = 0;

	if (!xsup_assert((workint != NULL), "workint != NULL", FALSE))
		return XEMALLOC;

	if (workint->recvframe == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Request to run the EAPoL check code without having "
			     "a frame in the buffer!\n");
		return XEGENERROR;
	}

	if (workint->recv_size > 0) {
		// We want to let getframe be called, even if we don't have any
		// config information.  That will keep the frame queue empty so that
		// when we do have enough config information we can start by processing
		// an EAP request that is valid.  If we don't have any config informtion,
		// we should just bail here, and not return an error.

		inframe = (char *)workint->recvframe;

		temp = (struct eapol_header *)&inframe[OFFSET_PAST_MAC];

		if (ntohs(temp->frame_type) == EAPOL_FRAME) {
			if (ntohs(temp->eapol_length) >
			    (workint->recv_size - OFFSET_TO_EAP)) {
				debug_printf(DEBUG_NORMAL,
					     "Interface '%s' received a runt frame.  This frame has been discarded.  (Expected : %d,  Got : %d)\n",
					     workint->desc,
					     ntohs(temp->eapol_length),
					     (workint->recv_size -
					      OFFSET_TO_EAP));
				snmp_inc_dot1xSuppInvalidEapolFramesRx();
				workint->recv_size = 0;

				return XENONE;
			}

			if (temp->eapol_version > MAX_EAPOL_VER) {
				debug_printf(DEBUG_NORMAL,
					     "EAPoL version too high! (Version "
					     "%d > %d)  Discarding!\n",
					     temp->eapol_version,
					     MAX_EAPOL_VER);
				snmp_inc_dot1xSuppInvalidEapolFramesRx();
				workint->recv_size = 0;
			} else {
				snmp_dot1xSuppLastEapolFrameVersion(temp->
								    eapol_version);
				workint->eapol_version = temp->eapol_version;

				switch (temp->eapol_type) {
				case EAP_PACKET:
					workint->statemachine->eapolEap = TRUE;
					break;

				case EAPOL_START:
					// We may see starts when being used in multi-host configurations.  So don't say 
					// anything so we don't scare the users. ;)
					debug_printf(DEBUG_DOT1X_STATE,
						     "Got EAPoL-Start! Ignoring!\n");
					return XEIGNOREDFRAME;

				case EAPOL_LOGOFF:
					// We may see logoffs when being used in multi-host configurations.  Don't say anything
					// so we don't scare the users.
					debug_printf(DEBUG_DOT1X_STATE,
						     "Got EAPoL-Logoff! Ignoring!\n");
					return XEIGNOREDFRAME;

				case EAPOL_KEY:
					debug_printf(DEBUG_KEY_STATE,
						     "Processing EAPoL-Key!\n");
					workint->statemachine->rxKey = TRUE;
					key_statemachine_run(workint);
					return XGOODKEYFRAME;

				case EAPOL_ASF_ALERT:
					debug_printf(DEBUG_NORMAL,
						     "Got EAPoL-ASF-Alert!\n");
					return XEIGNOREDFRAME;

				default:
					debug_printf(DEBUG_NORMAL,
						     "Unknown EAPoL type! (%02X)\n",
						     temp->eapol_type);
					return XEIGNOREDFRAME;
				}
			}
		} else {
			debug_printf(DEBUG_DOT1X_STATE,
				     "Got a frame, but it isn't an EAPoL "
				     "frame, ignoring.  (Type was %04X)\n",
				     ntohs(temp->frame_type));
		}
	}
	// Process our state machine.  Keep running it if we have an EAPoL message
	// in the queue.
	sm_runs = 0;

	while ((sm_runs < 0xff) && (workint->statemachine->eapolEap == TRUE)
	       && (workint->conn != NULL)) {
		statemachine_run(workint);
		sm_runs++;
	}

	if (sm_runs == 0xff) {
		debug_printf(DEBUG_NORMAL,
			     "The state machine appears to have gotten "
			     "jammed.  Please report this to the list.\n");
	}

	return XENONE;
}

int eapol_withframe(context * ctx, int sock)
{
	if (cardif_getframe(ctx) > 0) {
		return eapol_execute(ctx);
	}
	return XENONE;
}

/**
 * \brief Determine the EAP type that is in the packet.
 *
 * @param ctx   The context that contains the frame we need to look at.
 *
 * \retval eaptype   The EAP type that the packet contains.
 * \retval -1 on error
 **/
int eapol_get_eap_type(context * ctx)
{
	struct eap_header *eaphdr = NULL;

	if (ctx == NULL)
		return -1;

	eaphdr = (struct eap_header *)&ctx->recvframe[OFFSET_TO_EAP];

	return eaphdr->eap_code;
}
