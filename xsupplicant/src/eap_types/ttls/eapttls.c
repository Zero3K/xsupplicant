/**
 * EAPTTLS Function implementations
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapttls.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#ifdef WINDOWS
#include <Winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "../../eap_sm.h"
#include "../../eap_types/tls/eaptls.h"
#include "../../eap_types/ttls/eapttls.h"
#include "../../eap_types/ttls/ttlsphase2.h"
#include "pap.h"
#include "../../eap_types/tls/tls_funcs.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "../tls/certificates.h"
#include "../../logon_creds.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 *  Init the memory needed for us to complete a TTLS authentication.
 **/
int eapttls_init(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_ttls *userdata = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TTLS) Initing.\n");

	userdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

	if (userdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "EAP-TTLS setup was passed NULL userdata!  We"
			     " cannot continue with this attempt at authentication!\n");
		return XENOUSERDATA;
	}
	// First, set up the structure to hold all of our instance specific
	// variables.
	if (eapdata->eap_data == NULL) {
		eapdata->eap_data = (char *)Malloc(sizeof(struct tls_vars));
		if (eapdata->eap_data == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Unable to allocate memory for "
				     "eapdata->eap_data in eapttls_setup()!\n");
			ipc_events_malloc_failed(NULL);
			return XEMALLOC;
		}

		mytls_vars = (struct tls_vars *)eapdata->eap_data;
	} else {
		mytls_vars = (struct tls_vars *)eapdata->eap_data;
	}

	mytls_vars->resume =
	    TEST_FLAG(userdata->flags, EAP_TLS_FLAGS_SESSION_RESUME);

	if (TEST_FLAG(userdata->flags, TTLS_FLAGS_VALIDATE_SERVER_CERT)) {
		mytls_vars->verify_cert = TRUE;
	} else {
		mytls_vars->verify_cert = FALSE;
	}

	FREE(mytls_vars->keyblock);
	FREE(mytls_vars->sessionkeyconst);

	mytls_vars->sessionkeyconst =
	    (uint8_t *) _strdup(TTLS_SESSION_KEY_CONST);

	mytls_vars->sessionkeylen = TTLS_SESSION_KEY_CONST_SIZE;

	if (tls_funcs_init(mytls_vars, EAP_TYPE_TTLS) != XENONE) {
		debug_printf(DEBUG_NORMAL, "Couldn't initialize SSL!\n");
		return XETLSINIT;
	}

	mytls_vars->handshake_done = FALSE;

	mytls_vars->certs_loaded &= ~ROOT_CERTS_LOADED;

	eap_type_common_init_eap_data(eapdata);

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TTLS) Initialized.\n");

	return XENONE;
}

/***********************************************************************
*
*  Once we are done with this EAP method, we need to clean up the memory
*  we were using.
*
***********************************************************************/
void eapttls_deinit(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	// Call ttls_phase2_deinit first.
	ttls_phase2_deinit(eapdata);

	tls_funcs_deinit(mytls_vars);

	FREE(mytls_vars->sessionkeyconst);
	FREE(mytls_vars->keyblock);
	FREE(eapdata->eap_data);

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TTLS) Cleaned up.\n");
}

/*****************************************************************
*
*  Check to be sure we have everything we need to complete an authentication.
*
******************************************************************/
void eapttls_check(eap_type_data * eapdata)
{
	struct config_eap_ttls *ttlsconf = NULL;
	struct tls_vars *mytls_vars = NULL;
	struct config_globals *globals = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata_conf_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	if (eapdata->methodState == INIT) {
		debug_printf(DEBUG_AUTHTYPES, "(EAP-TTLS) Requesting Init.\n");
		if (eapttls_init(eapdata) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Failed to properly initialize "
				     "memory structures for EAP-TTLS!\n");
			eap_type_common_fail(eapdata);
			return;
		}
	}

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	ttlsconf = (struct config_eap_ttls *)eapdata->eap_conf_data;

	if ((ttlsconf->user_key_pass == NULL) && (ttlsconf->user_key != NULL)) {
		debug_printf(DEBUG_NORMAL,
			     "No password available for TLS certificate in "
			     "EAP-TTLS phase 1!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	if ((mytls_vars->certs_loaded & ROOT_CERTS_LOADED) != ROOT_CERTS_LOADED) {
		if (!TEST_FLAG
		    (ttlsconf->flags, TTLS_FLAGS_VALIDATE_SERVER_CERT)) {
			// We were told not to verify certificates.  Spew out a warning, and
			// then do it!
			mytls_vars->verify_cert = FALSE;

			FREE(mytls_vars->cncheck);

			globals = config_get_globals();

			if (globals != NULL) {
				if (TEST_FLAG
				    (globals->flags,
				     CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
					debug_printf(DEBUG_NORMAL,
						     "WARNING - Verification of the Trusted Server's certificate is disabled.  The connection's security could be compromised.\n");
				}
			}
		} else {
			mytls_vars->verify_cert = TRUE;

			if (certificates_load_root
			    (mytls_vars, ttlsconf->trusted_server) != XENONE) {
				debug_printf(DEBUG_NORMAL,
					     "Unable to load root certificate(s)!\n");
				eap_type_common_fail(eapdata);
				return;
			}
			// The stuff below should be able to go soon.
		}
		mytls_vars->certs_loaded |= ROOT_CERTS_LOADED;
	}

	if ((mytls_vars->certs_loaded & USER_CERTS_LOADED) == 0x00) {
		if ((ttlsconf->user_cert != NULL)
		    && ((ttlsconf->user_key_pass != NULL))) {
			debug_printf(DEBUG_NORMAL,
				     "Using user certificate with TTLS!\n");
			tls_funcs_load_user_cert(mytls_vars,
						 ttlsconf->user_cert,
						 ttlsconf->user_key,
						 ttlsconf->user_key_pass);
		}
		mytls_vars->certs_loaded |= USER_CERTS_LOADED;
	}
	// Check our phase 2 data.
	ttls_phase2_check(eapdata);
}

/******************************************************************
 *
 * Process an EAP-TTLS request, and prepare the data that is needed to
 * build a valid response packet.
 *
 ******************************************************************/
void eapttls_process(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	uint8_t *resbuf = NULL;
	int16_t bufsiz;
	uint16_t resout;
	struct eap_header *eaphdr = NULL;

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

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TTLS) Processing.\n");

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	if ((eapdata->eapReqData[sizeof(struct eap_header)] == EAPTLS_START)
	    || (mytls_vars->handshake_done != TRUE)) {
		debug_printf(DEBUG_AUTHTYPES,
			     "(EAP-TTLS) Processing packet.\n");
		// Actually start to process the packet.
		eapdata->methodState = tls_funcs_process(eapdata->eap_data,
							 eapdata->eapReqData);

		if ((mytls_vars->handshake_done == TRUE)
		    && (eapdata->methodState != DONE)) {
			// Process phase 2 data.
			debug_printf(DEBUG_AUTHTYPES,
				     "Processing phase 2 data.\n");
			ttls_phase2_process(eapdata, NULL, 0);
		}
	} else {
		// We are in later packets of phase 2.
		eaphdr = (struct eap_header *)eapdata->eapReqData;
		resout = ntohs(eaphdr->eap_length) - sizeof(struct eap_header);

		if (tls_funcs_buffer(eapdata->eap_data,
				     &eapdata->
				     eapReqData[sizeof(struct eap_header)],
				     resout) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "There was an error buffering data "
				     "fragments.  Discarding fragment.\n");
			eapdata->ignore = FALSE;
			return;
		}

		bufsiz = tls_funcs_decrypt_ready(eapdata->eap_data);

		switch (bufsiz) {
		case 0:
			// Nothing to do yet.
			break;

		case -1:
			// Got an error.  Discard the frame.
			eap_type_common_fail(eapdata);
			break;

		default:
			// Data to be decrypted.
		  /*
			resbuf = Malloc(bufsiz);
			if (resbuf == NULL) {
				debug_printf(DEBUG_NORMAL,
					     "Couldn't allocate memory needed to"
					     " store decrypted data!\n");
				ipc_events_malloc_failed(NULL);
				eap_type_common_fail(eapdata);
				break;
			}

			resout = bufsiz;
		  */
			if (tls_funcs_decrypt
			    (eapdata->eap_data, &resbuf, &resout) != XENONE) {
				debug_printf(DEBUG_NORMAL,
					     "Decryption failed!\n");
				eap_type_common_fail(eapdata);
				break;
			}

			ttls_phase2_process(eapdata, resbuf, resout);

			FREE(resbuf);
			break;
		}
	}
}

/*********************************************************************
 *
 *  Build an EAP-TTLS response message to be sent back to the authentication
 *  server.
 *
 *********************************************************************/
uint8_t *eapttls_buildResp(eap_type_data * eapdata)
{
	uint8_t *res = NULL, *ttlsres = NULL;
	uint16_t res_size = 0, total_size = 0;
	struct eap_header *eaphdr = NULL;
	uint8_t reqId;
	uint8_t resbuf[1500];
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_ttls *eapconf = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return NULL;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return NULL;

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE))
		return NULL;

	eapconf = eapdata->eap_conf_data;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	if (mytls_vars->handshake_done == TRUE) {
		ttls_phase2_buildResp(eapdata, (uint8_t *) & resbuf,
				      (uint16_t *) & res_size);
		if (res_size == 0) {
			// Build ACK.
			return eap_type_common_buildAck(eapdata, EAP_TYPE_TTLS);
		} else {
			tls_funcs_encrypt(eapdata->eap_data, resbuf, res_size);
		}
	}

	if ((eapconf->chunk_size == 0) || (eapconf->chunk_size > MAX_CHUNK))
		eapconf->chunk_size = MAX_CHUNK;

	if (tls_funcs_get_packet(eapdata->eap_data, eapconf->chunk_size, &res,
				 &res_size) != XENONE) {
		return NULL;
	}

	if (res == NULL)
		return NULL;

	eaphdr = (struct eap_header *)eapdata->eapReqData;
	reqId = eaphdr->eap_identifier;

	ttlsres = Malloc(res_size + sizeof(struct eap_header));
	if (ttlsres == NULL) {
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	eaphdr = (struct eap_header *)ttlsres;

	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = reqId;
	total_size = res_size + sizeof(struct eap_header);
	eaphdr->eap_length = htons(total_size);
	eaphdr->eap_type = EAP_TYPE_TTLS;

	memcpy(&ttlsres[sizeof(struct eap_header)], res, res_size);

	FREE(res);

	return ttlsres;
}

/*******************************************************************
 *
 * Check to see if the EAP method returned any useful key material.
 *
 *******************************************************************/
uint8_t eapttls_isKeyAvailable(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return FALSE;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return FALSE;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	if (mytls_vars->handshake_done == FALSE)
		return FALSE;

	if (mytls_vars->keyblock == NULL) {
		mytls_vars->keyblock = tls_funcs_gen_keyblock(mytls_vars,
							      TLS_FUNCS_CLIENT_FIRST,
							      mytls_vars->
							      sessionkeyconst,
							      mytls_vars->
							      sessionkeylen);
	}

	if (mytls_vars->keyblock == NULL)
		return FALSE;

	return TRUE;
}

/*********************************************************************
 *
 *  Actually get the key data and return it.
 *
 *********************************************************************/
uint8_t *eapttls_getKey(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	uint8_t *keydata = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return NULL;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return NULL;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	keydata = Malloc(64);
	if (keydata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store keying "
			     "data!\n");
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	memcpy(keydata, mytls_vars->keyblock, 64);

	return keydata;
}

/**
 * \brief Return a username if we need to override it for some reason (such as a
 *			desire to use logon credentials.
 *
 * \note Any non-NULL value returned here will override any configuration file setting
 *			or user provided entry (if any).  This call should be USED WITH CARE!
 *
 * \retval NULL if no username is to be returned, ptr to the new username otherwise.
 **/
char *eapttls_get_username(void *config)
{
	struct config_eap_ttls *ttlsdata = NULL;

	ttlsdata = (struct config_eap_ttls *)config;

	// If we are configured to use logon creds we need to set the outer ID in the clear
	// since some servers (like Microsoft's NPS) won't accept anonymous as an outer ID.
	if (TEST_FLAG(ttlsdata->flags, TTLS_FLAGS_USE_LOGON_CREDS)) {
		if (logon_creds_username_available() == TRUE) {
			return logon_creds_get_username();
		}
	}

	return NULL;
}
