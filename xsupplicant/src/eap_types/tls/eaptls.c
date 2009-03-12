/**
 * EAPTLS (RFC 2716) Function implementations
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eaptls.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "src/xsup_err.h"
#include "src/xsup_ipc.h"
#include "src/ipc_callout.h"
#include "src/frame_structs.h"
#include "src/eap_sm.h"
#include "src/eap_types/tls/eaptls.h"
#include "src/eap_types/tls/tls_funcs.h"
#include "src/eap_types/tls/certificates.h"
#include "src/eap_types/eap_type_common.h"
#include "src/ipc_events.h"
#include "src/ipc_events_index.h"

#ifdef WINDOWS
#include <Winsock2.h>
#include "src/event_core_win.h"
#else
#include "src/event_core.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

/********************************************************************
 *
 * Allocate memory, needed to complete a TLS authentication.
 *
 ********************************************************************/
int eaptls_init(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	int retVal = 0;
	struct config_eap_tls *userdata = NULL;
	char *password = NULL;
	context *ctx = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return XEMALLOC;
	}

	userdata = (struct config_eap_tls *)eapdata->eap_conf_data;

	retVal = XENONE;

	if (eapdata->eap_data != NULL) {
		eaptls_deinit(eapdata);
	}
	// First, set up the structure to hold all of our instance specific
	// variables.
	eapdata->eap_data = (char *)Malloc(sizeof(struct tls_vars));
	if (!eapdata->eap_data) {
		ipc_events_malloc_failed(NULL);
		eap_type_common_fail(eapdata);
		return XEMALLOC;
	}

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	mytls_vars->resume =
	    TEST_FLAG(userdata->flags, EAP_TLS_FLAGS_SESSION_RESUME);
	mytls_vars->verify_cert = TRUE;

	mytls_vars->sessionkeyconst =
	    (uint8_t *) Malloc(TLS_SESSION_KEY_CONST_SIZE + 1);
	if (mytls_vars->sessionkeyconst == NULL)
		return XEMALLOC;

	if (Strncpy
	    ((char *)mytls_vars->sessionkeyconst,
	     TLS_SESSION_KEY_CONST_SIZE + 1, TLS_SESSION_KEY_CONST,
	     TLS_SESSION_KEY_CONST_SIZE) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Attempt to overflow destination string in %s() at %d!\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	mytls_vars->sessionkeylen = TLS_SESSION_KEY_CONST_SIZE;

	mytls_vars->keyblock = NULL;
	mytls_vars->handshake_done = FALSE;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TLS) Initialized.\n");

	if ((retVal = tls_funcs_init(mytls_vars, EAP_TYPE_TLS)) != XENONE) {
		debug_printf(DEBUG_NORMAL,
			     "Error initializing TLS functions!\n");
		return retVal;
	}

	if (certificates_load_root(mytls_vars, userdata->trusted_server) !=
	    XENONE) {
		debug_printf(DEBUG_NORMAL, "Error loading root certificate!\n");
		eap_type_common_fail(eapdata);
		return retVal;
	}

	ctx = event_core_get_active_ctx();
	if (ctx == NULL) {
		debug_printf(DEBUG_NORMAL, "No valid user password found!\n");
		eap_type_common_fail(eapdata);
		return XEGENERROR;
	}

	if (ctx->prof->temp_password == NULL) {
		if (userdata->user_key_pass == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "No valid user password found!\n");
			eap_type_common_fail(eapdata);
			return XEGENERROR;
		}

		password = _strdup(userdata->user_key_pass);
	} else {
		password = _strdup(ctx->prof->temp_password);
	}

	mytls_vars->certs_loaded &= ~ROOT_CERTS_LOADED;
	mytls_vars->handshake_done = FALSE;

	if (certificates_load_user
	    (mytls_vars, userdata->store_type, userdata->user_cert,
	     userdata->user_key, password) != XENONE) {
		debug_printf(DEBUG_NORMAL, "Error loading user certificate!\n");
		eap_type_common_fail(eapdata);
		FREE(password);
		return retVal;
	}
	FREE(password);

	if (tls_funcs_load_random(mytls_vars, userdata->random_file) != XENONE) {
		debug_printf(DEBUG_NORMAL, "Failed to load random data\n");
		eap_type_common_fail(eapdata);
		return -1;
	}
#ifndef WINDOWS
	if (userdata->sc.engine_id != NULL) {
		if (tls_funcs_load_engine(mytls_vars, &userdata->sc) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Failed to initialize the OpenSC "
				     "engine.\n");
			return XETLSINIT;
		}
	}
#endif

	eap_type_common_init_eap_data(eapdata);

	return XENONE;
}

/*************************************************************************
 *
 * Verify the packet is really a TLS packet.
 *
 *************************************************************************/
void eaptls_check(eap_type_data * eapdata)
{
	struct eap_header *myeap;
	struct config_eap_tls *tlsconf;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert((eapdata->eapReqData != NULL),
			 "eapdata->eapReqData != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	myeap = (struct eap_header *)eapdata->eapReqData;

	if (myeap == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No valid packet was passed in to %s!\n",
			     __FUNCTION__);
		eap_type_common_fail(eapdata);
		return;
	}

	if (myeap->eap_code != EAP_REQUEST_PKT) {
		debug_printf(DEBUG_NORMAL, "EAP isn't a request packet!?\n");
		eap_type_common_fail(eapdata);
		return;
	}

	if (myeap->eap_identifier == 0) {
		debug_printf(DEBUG_NORMAL, "Invalid EAP identifier!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	if (ntohs(myeap->eap_length) < (1 + sizeof(struct eap_header))) {
		debug_printf(DEBUG_NORMAL,
			     "Not enough data for valid EAP method.\n");
		eap_type_common_fail(eapdata);
		return;
	}

	tlsconf = (struct config_eap_tls *)eapdata->eap_conf_data;

#ifndef WINDOWS
	if (tlsconf->user_key_pass == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No password available for TLS certificate!\n");
		eap_type_common_fail(eapdata);
		return;
	}
#endif
}

/**
 * \brief Process a TLS request.
 *
 **/
void eaptls_process(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	if (!xsup_assert((eapdata->eapReqData != NULL),
			 "eapdata->eapReqData != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TLS) Processing.\n");

	if (eapdata->methodState == INIT) {
		debug_printf(DEBUG_AUTHTYPES, "(EAP-TLS) Requesting Init.\n");
		if (eaptls_init(eapdata) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Failed to properly initialize "
				     "memory structures for EAP-TLS!\n");
			eap_type_common_fail(eapdata);
			return;
		}
	}

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	eapdata->methodState = tls_funcs_process(eapdata->eap_data,
						 eapdata->eapReqData);

	if (mytls_vars->handshake_done == TRUE) {
		eapdata->decision = MAY_CONT;
		eapdata->credsSent = TRUE;
	} else {
		eapdata->decision = UNCOND_SUCC;
	}

	eapdata->ignore = FALSE;
}

/************************************************************************
 *
 *  Build a TLS response packet.
 *
 ************************************************************************/
uint8_t *eaptls_buildResp(eap_type_data * eapdata)
{
	struct eap_header *eaphdr;
	uint8_t reqId;
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_tls *eapconf;
	uint8_t *tlsres = NULL, *res = NULL;
	uint16_t res_size = 0, total_size = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return NULL;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return NULL;
	}

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return NULL;
	}

	eapconf = eapdata->eap_conf_data;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	if ((eapconf->chunk_size == 0) || (eapconf->chunk_size > MAX_CHUNK))
		eapconf->chunk_size = MAX_CHUNK;

	if (mytls_vars->handshake_done != TRUE) {
		if (tls_funcs_get_packet
		    (eapdata->eap_data, eapconf->chunk_size, &res,
		     &res_size) != XENONE) {
			eap_type_common_fail(eapdata);
			return NULL;
		}
	} else {
		res = Malloc(1);
		if (res == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory to store "
				     "TLS ACK!\n");
			ipc_events_malloc_failed(NULL);
			eap_type_common_fail(eapdata);
			return NULL;
		}
		res[0] = 0x00;
		res_size = 1;
	}

	if (res == NULL) {
		eap_type_common_fail(eapdata);
		return NULL;
	}

	eaphdr = (struct eap_header *)eapdata->eapReqData;
	reqId = eaphdr->eap_identifier;

	tlsres = Malloc(res_size + sizeof(struct eap_header));
	if (tlsres == NULL) {
		ipc_events_malloc_failed(NULL);
		eap_type_common_fail(eapdata);
		return NULL;
	}

	eaphdr = (struct eap_header *)tlsres;

	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = reqId;
	total_size = res_size + sizeof(struct eap_header);
	eaphdr->eap_length = htons(total_size);
	eaphdr->eap_type = EAP_TYPE_TLS;

	memcpy(&tlsres[sizeof(struct eap_header)], res, res_size);

	FREE(res);

	return tlsres;
}

/*************************************************************************
 *
 * Return keying material to the caller.
 *
 *************************************************************************/
uint8_t *eaptls_getKey(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	uint8_t *keydata;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return FALSE;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return FALSE;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	keydata = Malloc(64);
	if (keydata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store key "
			     "data!\n");
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	memcpy(keydata, mytls_vars->keyblock, 64);

	return keydata;
}

/**
 * \brief Determine if we have keying data available.
 *
 **/
uint8_t eaptls_isKeyAvailable(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return FALSE;

	if (eapdata->eap_data == NULL)
		return FALSE;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	if (mytls_vars->handshake_done == FALSE)
		return FALSE;

	FREE(mytls_vars->keyblock);

	mytls_vars->keyblock = tls_funcs_gen_keyblock(mytls_vars,
						      TLS_FUNCS_CLIENT_FIRST,
						      mytls_vars->
						      sessionkeyconst,
						      mytls_vars->
						      sessionkeylen);

	if (mytls_vars->keyblock != NULL)
		return TRUE;

	return FALSE;
}

/********************************************************************
 *
 * Clean up TLS data.
 *
 ********************************************************************/
void eaptls_deinit(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;
	tls_funcs_deinit(mytls_vars);

	FREE(mytls_vars->sessionkeyconst);
	FREE(mytls_vars);

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TLS) Cleaned up.\n");
}
