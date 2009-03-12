/**
 * EAP One Time Password (OTP/GTC) implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapotp.c
 *
 * \author chris@open1x.org
 *
 **/

#include <openssl/ssl.h>
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#else
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../eap_sm.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "eapotp.h"
#include "../../xsup_common.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "../../platform/cardif.h"
#include "../../eapol.h"

#ifdef WINDOWS
#include "../../event_core_win.h"
#else
#include "../../event_core.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

static uint8_t new_response = FALSE;

/**
 * \brief Setup to handle GTC/OTP EAP requests
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 * \retval XENONE on success.
 **/
int eapotp_init(eap_type_data * eapdata)
{
	// Do anything special that might be needed for this EAP type to work.
	debug_printf(DEBUG_AUTHTYPES, "Initalized EAP-OTP!\n");

	eap_type_common_init_eap_data(eapdata);

	return XENONE;
}

/**
 * \brief Check to see if we are prepared to do an OTP authentication.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 **/
void eapotp_check(eap_type_data * eapdata)
{
	// For GTC and OTP, there really isn't anything to check.
	eapdata->ignore = FALSE;
}

/**
 * \brief Respond to an OTP or GTC request.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 * \retval PTR to a packet to return.  (NULL on failure.)
 **/
uint8_t *eapotp_buildResp(eap_type_data * eapdata)
{
	struct eap_header *eaphdr = NULL;
	struct config_pwd_only *otpconf = NULL;
	uint8_t *retdata = NULL;
	uint16_t datasize, respofs = 0;
	uint8_t reqId = 0;
	uint8_t eapType = 0;
	context *ctx = NULL;
	char *pwd = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return NULL;

	if (!xsup_assert((eapdata->eapReqData != NULL), "eapReqData != NULL",
			 FALSE))
		return NULL;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP/GTC) Building response.\n");

	otpconf = (struct config_pwd_only *)eapdata->eap_conf_data;

	if (!xsup_assert((otpconf != NULL), "otpconf != NULL", FALSE))
		return NULL;

	ctx = event_core_get_active_ctx();

	if ((otpconf->password == NULL)
	    && ((ctx != NULL) && (ctx->prof != NULL)
		&& (ctx->prof->temp_password == NULL)))
		return NULL;

	if (new_response == TRUE) {
		if (eapdata->ident == NULL) {
			// The RADIUS server build in to my Cisco 1200 doesn't do an identity exchange as part of
			// phase 2.  Since we need to know the identity, we will have to dig it out of the context.
			// (ICK!)
			if ((ctx == NULL) || (ctx->prof == NULL)) {
				debug_printf(DEBUG_NORMAL,
					     "No profile was bound to your inner EAP method!?  This shouldn't happen!\n");
				eap_type_common_fail(eapdata);
				return NULL;
			}

			if (ctx->prof->temp_username != NULL) {
				eapdata->ident =
				    _strdup(ctx->prof->temp_username);
			} else if (ctx->prof->identity != NULL) {
				eapdata->ident = _strdup(ctx->prof->identity);
			} else {
				// ACK!  We don't know a username to send!?
				debug_printf(DEBUG_NORMAL,
					     "Unable to determine a valid username to send to the server.  Aborting the authentication.\n");
				eap_type_common_fail(eapdata);
				return NULL;
			}
		}

		if (otpconf->password != NULL) {
			pwd = otpconf->password;
		} else if ((ctx != NULL) && (ctx->prof != NULL)
			   && (ctx->prof->temp_password != NULL)) {
			pwd = ctx->prof->temp_password;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "Unable to find a valid password to use for authentication.  Aborting.\n");
			eap_type_common_fail(eapdata);
			return NULL;
		}

		datasize =
		    sizeof(struct eap_header) + strlen(RESPONSE_TEXT) +
		    strlen(eapdata->ident) + strlen(pwd) + 2;
	} else {
		if (otpconf->password != NULL) {
			datasize =
			    sizeof(struct eap_header) +
			    strlen(otpconf->password) + 1;
			pwd = otpconf->password;
		} else {
			datasize =
			    sizeof(struct eap_header) +
			    strlen(ctx->prof->temp_password) + 1;
			pwd = ctx->prof->temp_password;
		}
	}

	retdata = Malloc(datasize);
	if (retdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store result "
			     "data.\n");
		ipc_events_malloc_failed(NULL);
		FREE(ctx->prof->temp_password);
		return NULL;
	}

	eaphdr = (struct eap_header *)eapdata->eapReqData;
	reqId = eaphdr->eap_identifier;
	eapType = eaphdr->eap_type;

	eaphdr = (struct eap_header *)retdata;
	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = reqId;

#ifdef WINDOWS
	eaphdr->eap_length = htons(datasize - 1);	// The windows strcpy_s puts a null at the end of the string, but we don't want to send that.
#else
	eaphdr->eap_length = htons(datasize);
#endif
	eaphdr->eap_type = eapType;

	respofs = sizeof(struct eap_header);

	if (new_response == TRUE) {
		if (xsup_common_strcpy
		    ((char *)&retdata[respofs], (datasize - respofs),
		     RESPONSE_TEXT) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "Attempt to overflow a buffer in %s() at %d!\n",
				     __FUNCTION__, __LINE__);
			return NULL;
		}

		respofs += strlen(RESPONSE_TEXT);
		if (xsup_common_strcpy
		    ((char *)&retdata[respofs], (datasize - respofs),
		     eapdata->ident) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "Attempt to overflow a buffer in %s() at %d!\n",
				     __FUNCTION__, __LINE__);
			return NULL;
		}

		respofs += strlen(eapdata->ident);
		retdata[respofs] = 0x00;
		respofs++;
	}
	// Then, copy the response.
	if (xsup_common_strcpy
	    ((char *)&retdata[respofs], (datasize - respofs), pwd) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Attempt to overflow a buffer in %s() at %d!\n",
			     __FUNCTION__, __LINE__);
		return NULL;
	}

	FREE(ctx->prof->temp_password);

	eapdata->credsSent = TRUE;

	return retdata;
}

void eapotp_p2_pwd_callback(void *ctxptr, struct eap_sm_vars *p2sm,
			    uint8_t ** packet, uint16_t * pktsize)
{
	context *ctx = NULL;
	struct eap_otp_stored_frame *myFrame = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
		return;

	ctx = ctxptr;

	// Clear the callback.
	ctx->p2_pwd_callback = NULL;

	myFrame = ctx->pwd_callback_data;

	if (!xsup_assert((myFrame != NULL), "myFrame != NULL", FALSE))
		return;

	(*packet) = myFrame->eappkt;
	(*pktsize) = myFrame->eaplen;

	myFrame->eappkt = NULL;	// This is okay, because we passed the pointer out.

	// Back up our EAP ID so that we don't discard when we reprocess this frame.
	p2sm->lastId--;
	p2sm->ignore = FALSE;
}

/**
 * \brief This callback will be called when a password is set.  We need to reset the context to process the frame, kick it off,
 *        and clear the callback.  (Not necessarily in that order. ;)
 *
 * @param[in] ctxptr   A void pointer to the context that we are processing for.
 **/
void eapotp_pwd_callback(void *ctxptr)
{
	context *ctx = NULL;
	struct eap_otp_stored_frame *myFrame = NULL;
	void *temp = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
		return;

	ctx = ctxptr;

	event_core_set_active_ctx(ctx);

	// Clear the callback.
	ctx->pwd_callback = NULL;

	myFrame = ctx->pwd_callback_data;

	if (!xsup_assert((myFrame != NULL), "myFrame != NULL", FALSE))
		return;

	temp = ctx->recvframe;

	ctx->recvframe = myFrame->frame;
	ctx->recv_size = myFrame->length;

	myFrame->frame = NULL;	// This is okay, because we passed the pointer to ctx->recvframe.

	// Back up our EAP ID so that we don't discard when we reprocess this frame.
	ctx->eap_state->lastId--;
	ctx->statemachine->eapolEap = TRUE;
	ctx->eap_state->ignore = FALSE;	// Don't ignore anymore.

	SET_FLAG(ctx->flags, INT_REPROCESS);

	eapol_execute(ctx);	// Kick it off.

	FREE(ctx->recvframe);
	ctx->recvframe = temp;
}

/**
 * \brief Process GTC/OTP EAP Requests
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 **/
void eapotp_process(eap_type_data * eapdata)
{
	char *otp_chal = NULL;
	char *chalptr = NULL;	// Only a reference pointer, doesn't need to be freed.
	struct config_pwd_only *userdata = NULL;
	uint16_t eaplen = 0;
	struct eap_header *header = NULL;
	context *ctx = NULL;
	struct eap_otp_stored_frame *myFrame = NULL;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP/GTC) Processing.\n");

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert((eapdata->eapReqData != NULL),
			 "eapdata->eapReqData != NULL", FALSE))
		return;

	eapdata->decision = MAY_CONT;

	userdata = eapdata->eap_conf_data;

	if (!xsup_assert((userdata != NULL), "userdata != NULL", FALSE))
		return;

	header = (struct eap_header *)eapdata->eapReqData;

	eaplen = ntohs(header->eap_length);

	// Allocating 'eaplen' will result in a buffer that is a bit bigger than
	// we really need, but we will be deallocating it shortly. ;)
	otp_chal = (char *)Malloc(eaplen + 1);
	if (otp_chal == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for OTP/GTC "
			     "challenge!\n");
		ipc_events_malloc_failed(NULL);
		return;
	}

	chalptr = otp_chal;

	memcpy(otp_chal, &eapdata->eapReqData[sizeof(struct eap_header)],
	       eaplen - sizeof(struct eap_header));
	debug_printf(DEBUG_AUTHTYPES, "(GTC/OTP) Challenge : %s\n", otp_chal);

	if (strncmp(CHALLENGE_TEXT, otp_chal, strlen(CHALLENGE_TEXT)) == 0) {
		debug_printf(DEBUG_AUTHTYPES,
			     "Will use broken Cisco response method!\n");
		new_response = TRUE;
		chalptr += strlen(CHALLENGE_TEXT);	// Skip past the REQUEST= part of the EAP-FAST style challenge.
	}

	ctx = event_core_get_active_ctx();

	if ((userdata->password == NULL)
	    && ((ctx != NULL) && (ctx->prof != NULL)
		&& (ctx->prof->temp_password == NULL))) {
		debug_printf(DEBUG_NORMAL,
			     "No password available for EAP-GTC/OTP! (Trying to request one.)\n");
		if (ipc_events_request_eap_upwd("EAP-GTC", chalptr) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't request password from UI!  Failing.\n");
			eap_type_common_fail(eapdata);
			FREE(otp_chal);
			return;
		} else {
			eapdata->ignore = TRUE;	// Don't do anything just yet.
			eapdata->methodState = CONT;
			eapdata->decision = COND_SUCC;	// We may be able to succeed.

			if ((ctx != NULL) && (ctx->pwd_callback_data != NULL)) {
				eapotp_cleanup(ctx->pwd_callback_data);
				FREE(ctx->pwd_callback_data);
			}

			ctx->pwd_callback_data =
			    Malloc(sizeof(struct eap_otp_stored_frame));
			if (ctx->pwd_callback_data != NULL) {
				myFrame = ctx->pwd_callback_data;
				myFrame->frame = Malloc(FRAMESIZE);
				if (myFrame->frame == NULL) {
					FREE(ctx->pwd_callback_data);
				} else {
					memcpy(myFrame->frame, ctx->recvframe,
					       ctx->recv_size);
					myFrame->length = ctx->recv_size;

					myFrame->eaplen =
					    eap_type_common_get_eap_length
					    (eapdata->eapReqData);
					myFrame->eappkt =
					    Malloc(myFrame->eaplen);
					if (myFrame->eappkt != NULL) {
						memcpy(myFrame->eappkt,
						       eapdata->eapReqData,
						       myFrame->eaplen);
					}

					ctx->pwd_callback = eapotp_pwd_callback;
					ctx->p2_pwd_callback =
					    eapotp_p2_pwd_callback;

					// Since we return ignore, our EAP ID won't get updated.  But we need it to, so we
					// update it manually here.  (That way we discard retransmissions.)
					ctx->eap_state->lastId =
					    ctx->eap_state->reqId;
				}
			}
		}
		return;
	}
	// Otherwise, we are basically done.
	FREE(otp_chal);

	eapdata->methodState = MAY_CONT;
	eapdata->decision = COND_SUCC;
}

/**
 * \brief Return any keying material that we may have.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 * \retval FALSE   there is no keying material from OTP or GTC.
 **/
uint8_t eapotp_isKeyAvailable(eap_type_data * eapdata)
{
	return FALSE;		// No keys to return (ever)
}

/**
 * \brief Stub for key returning function.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 * \retval NULL   no keying material will be returned from OTP or GTC.
 **/
uint8_t *eapotp_getKey(eap_type_data * eapdata)
{
	debug_printf(DEBUG_NORMAL,
		     "There is an error in your build of Xsupplicant!" "\n");
	ipc_events_error(NULL, IPC_EVENT_ERROR_INVALID_KEY_REQUEST, NULL);
	return NULL;
}

/**
 * \brief Clean up the memory on the EAP-OTP/GTC data hook.
 *
 * @param[in] cbdata   The callback data stored in the context that we need to free.
 **/
void eapotp_cleanup(void *cbdata)
{
	struct eap_otp_stored_frame *myFrame = NULL;

	// Because of the nature of GTC/OTP, it is possible that cleanup will get called on a NULL pointer.
	// If that happens, silently move on.
	if (cbdata == NULL)
		return;

	myFrame = cbdata;

	if (myFrame != NULL) {
		FREE(myFrame->frame);
	}
}

/**
 * \brief Clean up after ourselves.  This will get called when we get a packet that
 * needs to be processed requests a different EAP type.  It will also be 
 * called on termination of the program.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 **/
void eapotp_deinit(eap_type_data * eapdata)
{
	context *ctx = NULL;

	// Clean up after ourselves.
	debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP) Cleaning up.\n");

	ctx = event_core_get_active_ctx();

	if (ctx != NULL) {
		eapotp_cleanup(ctx->pwd_callback_data);
		FREE(ctx->pwd_callback_data);
	}
}
