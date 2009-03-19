/**
 * EAP-PEAP Function implementations
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eappeap.c
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
#include "../../eap_types/tls/tls_funcs.h"
#include "eappeap.h"
#include "peap_phase2.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "../tls/certificates.h"
#include "../../logon_creds.h"

#ifdef WINDOWS
#include "../../event_core_win.h"
#include "../../platform/windows/win_impersonate.h"
#else
#include "../../event_core.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

/************************************************************************
 *
 * This is called if methodState == INIT.  It should set up all of the
 * memory that we will need to complete the authentication.
 *
 ************************************************************************/
uint8_t eappeap_init(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_peap *peapconf = NULL;
	struct config_globals *globals = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return FALSE;

	peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

	if (!xsup_assert((peapconf != NULL), "peapconf != NULL", FALSE))
		return FALSE;

	if (eapdata->eap_data == NULL) {
		eapdata->eap_data = Malloc(sizeof(struct tls_vars));
		if (eapdata->eap_data == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory to store PEAP "
				     "specific data structures.\n");
			ipc_events_malloc_failed(NULL);
			return FALSE;
		}

		mytls_vars = eapdata->eap_data;

		if (tls_funcs_init(mytls_vars, EAP_TYPE_PEAP) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't initialize SSL engine!\n");
			return FALSE;
		}
	}

	mytls_vars = eapdata->eap_data;

	mytls_vars->resume =
	    TEST_FLAG(peapconf->flags, EAP_TLS_FLAGS_SESSION_RESUME);

	FREE(mytls_vars->keyblock);

	if ((mytls_vars->certs_loaded & ROOT_CERTS_LOADED) == 0x00) {
		if (!TEST_FLAG
		    (peapconf->flags, FLAGS_PEAP_VALIDATE_SERVER_CERT)) {
			// We were told not to verify certificates.  Spew out a warning, and
			// then do it!
			mytls_vars->verify_cert = FALSE;

			FREE(mytls_vars->cncheck);

			globals = config_get_globals();

			if (globals != NULL) {
				if (TEST_FLAG(globals->flags,
					      CONFIG_GLOBALS_FRIENDLY_WARNINGS))
				{
					debug_printf(DEBUG_NORMAL,
						     "WARNING - Verification of the Trusted Server's certificate is disabled.  The connection's security could be compromised.\n");
				}
			}
		} else {
			mytls_vars->verify_cert = TRUE;

			if (certificates_load_root
			    (mytls_vars, peapconf->trusted_server) != XENONE) {
				debug_printf(DEBUG_NORMAL,
					     "Unable to load root certificate(s)!\n");
				return FALSE;
			}
		}

		mytls_vars->certs_loaded |= ROOT_CERTS_LOADED;
	}

	if (tls_funcs_load_random(mytls_vars, peapconf->random_file) != XENONE) {
		debug_printf(DEBUG_NORMAL, "Failed to load random data!\n");
		eap_type_common_fail(eapdata);
		return XEGENERROR;
	}

	if ((mytls_vars->certs_loaded & USER_CERTS_LOADED) == 0x00) {
		if ((peapconf->user_cert != NULL)
		    && (peapconf->user_key_pass != NULL)) {
			debug_printf(DEBUG_NORMAL,
				     "Using user certificate with PEAP!\n");
			tls_funcs_load_user_cert(mytls_vars,
						 peapconf->user_cert,
						 peapconf->user_key,
						 peapconf->user_key_pass);
		}
	}

	mytls_vars->handshake_done = FALSE;

	peap_phase2_init(eapdata);

	eap_type_common_init_eap_data(eapdata);
	eapdata->methodState = MAY_CONT;

	return TRUE;
}

/************************************************************************
 *
 * Check to see if we are ready to do a PEAP authentication.
 *
 ************************************************************************/
void eappeap_check(eap_type_data * eapdata)
{
	struct config_eap_peap *peapconf = NULL;
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	eapdata->ignore = FALSE;	// Start out assuming everything is okay.

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	debug_printf(DEBUG_AUTHTYPES, "(EAP-PEAP) Checking...\n");
	if (eapdata->methodState == INIT) {
		if (eappeap_init(eapdata) != TRUE) {
			debug_printf(DEBUG_NORMAL, "Failed to init PEAP!\n");
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

	peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

	if ((peapconf->user_key_pass == NULL) && (peapconf->user_key != NULL)) {
		debug_printf(DEBUG_NORMAL, "No PEAP phase 1 password!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	peap_phase2_check(eapdata);
}

/************************************************************************
 *
 * Process a PEAP request.
 *
 ************************************************************************/
void eappeap_process(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_peap *peapconf;
	struct phase2_data *p2d = NULL;
	uint8_t peap_version;
	uint8_t *tls_type = NULL;
	struct eap_header *eaphdr = NULL;
	uint8_t *resbuf = NULL;
	int decryptReadyBufSize = 0;
	uint16_t bufsiz = 0;
	context *ctx = NULL;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-PEAP) Processing.\n");
	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert((eapdata->eap_data != NULL),
			 "eapdata->eap_data != NULL", FALSE)) {
		eapdata->decision = EAP_FAIL;
		eapdata->ignore = TRUE;
		return;
	}

	ctx = event_core_get_active_ctx();
	// Check to see if we have a 'reprocess' request.  If we do, pass the inner data, and skip the decryption.
	if ((ctx != NULL) && (TEST_FLAG(ctx->flags, INT_REPROCESS))) {
		(*ctx->p2_pwd_callback) (ctx,
					 ((struct phase2_data *)eapdata)->sm,
					 &resbuf, &bufsiz);
		peap_phase2_process(eapdata, resbuf, bufsiz);
		FREE(resbuf);
		UNSET_FLAG(ctx->flags, INT_REPROCESS);
		event_core_set_active_ctx(NULL);
		return;
	}

	mytls_vars = eapdata->eap_data;

	if (eapdata->methodState == INIT) {
		if (eappeap_init(eapdata) == FALSE) {
			debug_printf(DEBUG_NORMAL,
				     "Failed the initialize EAP-PEAP.  We "
				     "cannot continue the authentication.\n");
			eapdata->decision = EAP_FAIL;
			eapdata->ignore = TRUE;
		}
	}

	p2d = mytls_vars->phase2data;

	if (p2d == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No phase 2 data structure available!\n");
		eapdata->decision = EAP_FAIL;
		eapdata->ignore = TRUE;
		return;
	}

	peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

	if (peapconf == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No valid PEAP configuration found in memory!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	tls_type = &eapdata->eapReqData[sizeof(struct eap_header)];
	peap_version = (tls_type[0] & PEAP_VERSION_MASK);

	if (peapconf->force_peap_version != 0xff) {
		if (peapconf->force_peap_version > HIGHEST_PEAP_SUPPORTED) {
			debug_printf(DEBUG_NORMAL,
				     "User requested that we force the PEAP version to a version "
				     "that we don't support.  We will negotiate with the server.\n");
			peapconf->force_peap_version = 0xff;	// So we don't try the wrong thing again.

			set_peap_version(p2d, peap_version);
		} else {
			if (peap_version != peapconf->force_peap_version) {
				debug_printf(DEBUG_NORMAL,
					     "Forcing PEAP version to %d, per configuration file!\n",
					     peapconf->force_peap_version);
			}

			set_peap_version(p2d, peapconf->force_peap_version);
		}
	} else {
		set_peap_version(p2d, peap_version);
	}

	tls_type[0] = (tls_type[0] & PEAP_MASK_OUT_VERSION);

	if ((eapdata->eapReqData[sizeof(struct eap_header)] == EAPTLS_START)
	    || (mytls_vars->handshake_done != TRUE)) {
		debug_printf(DEBUG_AUTHTYPES,
			     "(EAP-PEAP) Processing packet.\n");
		// Actually start to process the packet.
		eapdata->methodState = tls_funcs_process(eapdata->eap_data,
							 eapdata->eapReqData);

		if (eapdata->methodState == EAP_FAIL)
			eap_type_common_fail(eapdata);
	} else {
		// We are in later packets of phase 2.
		eaphdr = (struct eap_header *)eapdata->eapReqData;
		bufsiz = ntohs(eaphdr->eap_length) - sizeof(struct eap_header);

		if (tls_funcs_buffer(eapdata->eap_data,
				     &eapdata->
				     eapReqData[sizeof(struct eap_header)],
				     bufsiz) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "There was an error buffering data "
				     "fragments.  Discarding fragment.\n");
			eapdata->ignore = FALSE;
			return;
		}

		decryptReadyBufSize =
		    tls_funcs_decrypt_ready(eapdata->eap_data);

		switch (decryptReadyBufSize) {
		case 0:
			// Nothing to do yet.
			break;

		case -1:
			// Got an error.  Discard the frame.
			eap_type_common_fail(eapdata);
			break;

		default:
			// Data to be decrypted.
			if (tls_funcs_decrypt
			    (eapdata->eap_data, &resbuf,
			     (uint16_t *) & bufsiz) != XENONE) {
				debug_printf(DEBUG_NORMAL,
					     "Decryption failed!\n");
				ipc_events_error(NULL,
						 IPC_EVENT_ERROR_TLS_DECRYPTION_FAILED,
						 NULL);
				eap_type_common_fail(eapdata);
				break;
			}

			peap_phase2_process(eapdata, resbuf, bufsiz);

			FREE(resbuf);
			break;
		}
	}
}

/************************************************************************
 *
 * Build a PEAP response message.
 *
 ************************************************************************/
uint8_t *eappeap_buildResp(eap_type_data * eapdata)
{
	uint8_t *res = NULL, *peapres = NULL;
	uint16_t res_size = 0, total_size = 0;
	struct eap_header *eaphdr = NULL;
	uint8_t reqId;
	uint8_t resbuf[1500];
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_peap *eapconf = NULL;

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

	// If we are resuming, we don't want to let it go to phase 2.
	if (mytls_vars->handshake_done == TRUE) {
		peap_phase2_buildResp(eapdata, (uint8_t *) & resbuf,
				      (uint16_t *) & res_size);

		if (res_size == 0) {
			// If OpenSSL doesn't have anything queued either, then send an ACK.
			if (tls_funcs_data_pending(mytls_vars) <= 0) {
				// Build ACK.
				peapres =
				    eap_type_common_buildAck(eapdata,
							     EAP_TYPE_PEAP);
				peapres[sizeof(struct eap_header)] |=
				    get_peap_version(eapdata);
				return peapres;
			}
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

	peapres = Malloc(res_size + sizeof(struct eap_header));
	if (peapres == NULL) {
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	eaphdr = (struct eap_header *)peapres;

	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = reqId;
	total_size = res_size + sizeof(struct eap_header);
	eaphdr->eap_length = htons(total_size);
	eaphdr->eap_type = EAP_TYPE_PEAP;

	memcpy(&peapres[sizeof(struct eap_header)], res, res_size);

	peapres[sizeof(struct eap_header)] |= get_peap_version(eapdata);

	FREE(res);

	return peapres;
}

/************************************************************************
*
*  Set the key constants based on the PEAP version in use.
*
*************************************************************************/
void eappeap_set_key_const(struct tls_vars *mytls_vars, uint8_t ver)
{
	switch (ver) {
	case PEAP_VERSION0:
		debug_printf(DEBUG_AUTHTYPES,
			     "Setting Key Constant for PEAP v0!\n");
		mytls_vars->sessionkeyconst =
		    (uint8_t *) _strdup(PEAP_SESSION_KEY_CONST);
		mytls_vars->sessionkeylen = PEAP_SESSION_KEY_CONST_SIZE;
		break;

	case PEAP_VERSION1:
		debug_printf(DEBUG_AUTHTYPES,
			     "Setting Key Constant for PEAP v1!\n");
		mytls_vars->sessionkeyconst =
		    (uint8_t *) _strdup(PEAPv1_SESSION_KEY_CONST);
		mytls_vars->sessionkeylen = PEAPv1_SESSION_KEY_CONST_SIZE;
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown PEAP version %d!\n", ver);
		break;
	}
}

/************************************************************************
 *
 * Determine if keying material is available.
 *
 ************************************************************************/
uint8_t eappeap_isKeyAvailable(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;
	struct config_eap_peap *peapconf = NULL;
	uint8_t ver = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return FALSE;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return FALSE;

	if (!xsup_assert
	    ((eapdata->eap_conf_data != NULL), "eapdata->eap_conf_data != NULL",
	     FALSE))
		return FALSE;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;
	peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

	if (mytls_vars->handshake_done == FALSE)
		return FALSE;

	if (mytls_vars->keyblock != NULL)
		return TRUE;

	ver = get_peap_version(eapdata);

	if ((ver == 1)
	    && (TEST_FLAG(peapconf->flags, FLAGS_PEAP_PROPER_PEAPV1_KEYS))) {
		debug_printf(DEBUG_NORMAL,
			     "NOTICE : Most RADIUS servers do not do proper PEAP v1 keying! If your authentication succeeds, and traffic cannot flow, try turning off Proper_PEAP_V1_Keying!\n");
	} else {
		ver = 0;
	}

	eappeap_set_key_const(mytls_vars, ver);

	mytls_vars->keyblock = tls_funcs_gen_keyblock(mytls_vars,
						      TLS_FUNCS_CLIENT_FIRST,
						      mytls_vars->
						      sessionkeyconst,
						      mytls_vars->
						      sessionkeylen);

	if (mytls_vars->keyblock == NULL)
		return FALSE;

	return TRUE;
}

/************************************************************************
 *
 * If keying material is available, get the key.
 *
 ************************************************************************/
uint8_t *eappeap_getKey(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars;
	uint8_t *keydata;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return NULL;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
		return NULL;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	if (mytls_vars->keyblock == NULL) {
		debug_printf(DEBUG_NORMAL, "No keying material available!\n");
		return NULL;
	}

	keydata = Malloc(64);
	if (keydata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to return key "
			     "block!\n");
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	memcpy(keydata, mytls_vars->keyblock, 64);

	debug_printf(DEBUG_AUTHTYPES, "Generated keyblock : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, mytls_vars->keyblock, 64);

	return keydata;
}

/************************************************************************
 *
 * Clean up after ourselves.
 *
 ************************************************************************/
void eappeap_deinit(eap_type_data * eapdata)
{
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert((eapdata->eap_data != NULL),
			 "eapdata->eap_data != NULL", FALSE))
		return;

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

	peap_phase2_deinit(eapdata);
	tls_funcs_deinit(mytls_vars);

	FREE(mytls_vars->keyblock);

	FREE(eapdata->eap_data);

	debug_printf(DEBUG_AUTHTYPES, "(EAP-PEAP) Cleaned up.\n");
}

/**
 * \brief Create the "username" used for machine authentication.  For Windows,
 *			this is the machine name in "<Domain>\<Machine Name>" format.
 *
 * @param[in/out] ctx   The context for the interface that we need to generate the
 *							machine username on.
 **/
void eappeap_get_machineauth_name(context * ctx)
{
#ifdef WINDOWS
	char *machineName = NULL;
	char *result = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	machineName = win_impersonate_get_machine_name();
	if (machineName == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Unable to determine the machine's name.  Machine authentication failed.\n");
		return;
	}

	result = Malloc(strlen(machineName) + 10);
	if (result == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Unable to allocate memory needed to create the machine's username!\n");
		FREE(machineName);
		return;
	}

	sprintf(result, "host/%s", machineName);

	FREE(machineName);

	// Make sure the user isn't allowed to override the machine name via the config file.
	if (ctx->prof->identity != NULL)
		FREE(ctx->prof->identity);

	ctx->prof->temp_username = result;
#else
#warning Machine authentication is not available for your platform!
#endif
}

/**
 * \brief Determine what credentials are needed for PEAP.
 *
 * @param[in] config   A pointer to a PEAP configuration blob.
 *
 * \retval int  A bitmap containing the requirements for this connection.
 **/
int eappeap_creds_required(void *config)
{
	struct config_eap_peap *peap = NULL;

	peap = (struct config_eap_peap *)config;
	if (peap == NULL)
		return -1;	// This is bad, we can't determine anything.

	switch (peap->phase2->method_num) {
	case EAP_TYPE_MSCHAPV2:
		return eap_type_common_upw_required(peap->phase2->method_data);
		break;

	default:
		return -1;
	}

	return -1;
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
char *eappeap_get_username(void *config)
{
	context *ctx = NULL;
	struct config_eap_peap *peapdata = NULL;

	peapdata = (struct config_eap_peap *)config;

	// Only get the machine name if the machine auth flag is enabled.  If it is, then
	// we want to ignore all other available usernames.  So, our get_machineauth_name()
	// call should FREE() any usernames in the config in addition to providing our
	// machine name in the proper format.
	if (TEST_FLAG(peapdata->flags, FLAGS_PEAP_MACHINE_AUTH)) {
		ctx = event_core_get_active_ctx();

		if (ctx != NULL) {
			eappeap_get_machineauth_name(ctx);
			if ((ctx->prof != NULL)
			    && (ctx->prof->temp_username != NULL))
				return ctx->prof->temp_username;
		}
	}
	// If we are configured to use logon creds we need to set the outer ID in the clear
	// since some servers (like Microsoft's NPS) won't accept anonymous as an outer ID.
	if (TEST_FLAG(peapdata->flags, FLAGS_PEAP_USE_LOGON_CREDS)) {
		if (logon_creds_username_available() == TRUE) {
			return logon_creds_get_username();
		}
	}

	return NULL;
}
