/**
 * Handle keying for type 1 (RC4, non-TKIP) EAPOL Keys
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * \file eapol_key_type1.c
 *
 **/

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <string.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "eap_sm.h"
#include "wpa_common.h"
#include "frame_structs.h"
#include "platform/cardif.h"
#include "key_statemachine.h"
#include "eapol_key_type1.h"
#include "xsup_common.h"
#include "timer.h"
#include "ipc_events.h"
#include "ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 * \brief Write keydata into a logfile
 *
 * The purpose of this function is mainly for debugging during development.
 * It dumps the EAPoL key header data out to whatever the current logging
 * target is.
 *
 * @param[in] inframe   A properly formatted EAPoL Key frame.
 * @param[in] framesize   The size of the key frame that was passed in.
 *
 * \retval XENONE on success
 * \retval XEMALLOC if a NULL frame is passed in.
 */
int eapol_dump_keydata(char *inframe, int framesize)
{
	struct key_packet *keydata = NULL;
	uint16_t length = 0;

	if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
		return XEMALLOC;

	keydata = (struct key_packet *)inframe;

	debug_printf(DEBUG_KEY, "Key Descriptor   = %d\n", keydata->key_descr);

	memcpy(&length, keydata->key_length, 2);
	debug_printf(DEBUG_KEY, "Key Length       = %d\n", ntohs(length));
	debug_printf(DEBUG_KEY, "Replay Counter   = ");
	debug_hex_printf(DEBUG_KEY, keydata->replay_counter, 8);
	debug_printf(DEBUG_KEY, "Key IV           = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_iv, 16);
	debug_printf(DEBUG_KEY, "Key Index (RAW)  = %02X\n",
		     keydata->key_index);
	debug_printf(DEBUG_KEY, "Key Signature    = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_signature, 16);

	return XENONE;
}

/**
 * \brief Check the HMAC on the key packet we got.  If we can't validate the
 * HMAC, then we return FALSE, indicating an error.
 *
 * @param[in] ctx   The context for the interface we want to check the HMAC on
 *        the frame for.
 * @param[in] inframe   A pointer to the frame that we want to check the HMAC 
 *                       on.
 * @param[in] framesize   The size of the frame pointed to by 'inframe'.
 *
 * \retval TRUE if the HMAC on the frame is valid.
 * \retval FALSE if the HMAC on the frame is invalid.
 * \retval XEMALLOC on bad data passed in.
 **/
int eapol_key_type1_check_hmac(context * ctx, char *inframe, int framesize)
{
	struct key_packet *keydata = NULL;
	char *framecpy = NULL;
	char *calchmac = NULL;
	int outlen = 0;
	int retVal = 0;
	int length = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
		return XEMALLOC;

	if (ctx->eap_state->eapKeyData == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No keying material available!  Ignoring "
			     "key frame!\n");
		return XEMALLOC;
	}

	// First, make a copy of the frame.
	framecpy = (char *)Malloc(framesize);
	if (framecpy == NULL) {
	        ipc_events_malloc_failed(ctx);
		return XEMALLOC;
	}

	memcpy(framecpy, inframe, framesize);

	// Now, we want to zero out the HMAC.
	keydata = (struct key_packet *)&framecpy[4];

	memcpy(&length, keydata->key_length, 2);

	memset((char *)&keydata->key_signature, 0x00, 16);

	// Once we have done that, we need to calculate the HMAC.
	calchmac = (char *)Malloc(16);	// The resulting MAC is 16 bytes long.
	if (calchmac == NULL) {
		ipc_events_malloc_failed(ctx);
		return XEMALLOC;
	}

	HMAC(EVP_md5(), ctx->eap_state->eapKeyData + 32,
	     ctx->eap_state->eapKeyLen, (uint8_t *) framecpy, framesize,
	     (uint8_t *) calchmac, (unsigned int *)&outlen);

	// Now, we need to compare the calculated HMAC to the one sent to us.
	keydata = (struct key_packet *)&inframe[4];

	eapol_dump_keydata((char *)keydata, framesize);

	if (memcmp(calchmac, keydata->key_signature, 16) == 0) {
		// The HMAC is valid.
		retVal = TRUE;
	} else {
		retVal = FALSE;
	}

	// Clean up after ourselves.
	FREE(framecpy);
	FREE(calchmac);

	return retVal;
}

/**
 * \brief Get the RC4 key needed to do WEP.
 *
 * @param[in] ctx   The context for the interface we want to do WEP on.
 * @param[in] enckey   The encrypted key that was passed to us via the EAPoL
 *                     keyframe.
 * @param[out] deckey   The buffer to store the decrypted key that will be 
 *                      returned from this funciton.  (NOTE: This buffer should
 *                      be at least the same size as the buffer that 'enckey'
 *                      points to.)
 * @param[in] keylen   The length of the key passed in via 'enckey', and the 
 *                     length of the buffer that 'deckey' should point to.
 * @param[in] iv   The IV used in the decryption of the key.
 * @param[in] ivlen   The length of the IV pointed to by 'iv'.
 *
 * \retval XENONE if the key was properly decrypted and returned in 'deckey'.
 * \retval XEMALLOC if a memory allocation failed, or invalid data was passed
 *                  in to the function.
 **/
int eapol_key_type1_get_rc4(context * ctx, uint8_t * enckey,
			    uint8_t * deckey, int keylen, uint8_t * iv,
			    int ivlen)
{
	uint8_t *wholekey = NULL;
	RC4_KEY key;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((enckey != NULL), "enckey != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((deckey != NULL), "deckey != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((iv != NULL), "iv != NULL", FALSE))
		return XEMALLOC;

	wholekey = (uint8_t *) Malloc(sizeof(uint8_t) *
				      (ivlen + ctx->eap_state->eapKeyLen));
	if (wholekey == NULL) {
		ipc_events_malloc_failed(ctx);
		return XEMALLOC;
	}

	memcpy(wholekey, iv, ivlen);

	if (!ctx->eap_state->eapKeyData) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid keying material!  Keys will not be "
			     "handled correctly!\n");
		FREE(wholekey);
		return XEMALLOC;
	}

	memcpy(wholekey + ivlen, ctx->eap_state->eapKeyData,
	       ctx->eap_state->eapKeyLen);

	RC4_set_key(&key, ivlen + ctx->eap_state->eapKeyLen, wholekey);
	RC4(&key, keylen, enckey, deckey);

	FREE(wholekey);

	return XENONE;
}

/**
 * \brief Clear the WEP rekey problem timer.
 *
 * If our rekey timer expires, we should quietly remove it.  In the case of
 * this timer, we WANT it to expire with no events!  (Otherwise, the card
 * in use may have issues.)
 *
 * @param[in] ctx   The context that contains the timer used to determine if
 *                  the wireless interface resets when the WEP key is set.
 **/
void eapol_key_type1_clear_timer(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	debug_printf(DEBUG_KEY, "Clearing rekey problem timer.  (This is "
		     "harmless!)\n");
	timer_cancel(ctx, REKEY_PROB_TIMER);
}

/**
 * \brief Set up our timer to warn if the driver may have the card reset issue.
 *
 * In the early days of wireless on Linux, it was common for a wireless
 *  interface to reset when the WEP keys were applied to the interface.  This
 *  reset would drop the association, causing a new authentication, which 
 *  in turn caused new keys to be set.  (And on, and on.)  We set this timer
 *  to a fairly short timeout value so that we know if we are changing keys
 *  rapidly.  If we appear to be, we can scream so the user knows there is a
 *  problem with their card driver.
 *
 * @param[in] ctx   The context for the interface that we want to set up the
 *                  rekey timer on.
 **/
void eapol_key_type1_set_rekey_prob_timer(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (timer_check_existing(ctx, REKEY_PROB_TIMER)) {
		debug_printf(DEBUG_NORMAL,
			     "Less than %d seconds have elapsed since the "
			     "last key was set!  Either your AP has the rekey interval "
			     "set dangerously low, or your card may reset everytime new "
			     "keys are set!  Please check the rekey interval time on "
			     "your AP and report your card type, driver, and driver "
			     "version number to the list!\n",
			     REKEY_PROB_TIMEOUT);
		timer_reset_timer_count(ctx, REKEY_PROB_TIMER,
					REKEY_PROB_TIMEOUT);
	} else {
		// There isn't an existing counter, so set up a new one.
		timer_add_timer(ctx, REKEY_PROB_TIMER, REKEY_PROB_TIMEOUT, NULL,
				&eapol_key_type1_clear_timer);
	}
}

/**
 * \brief Display the stale key warning, and disable the timer that was running.
 *
 * The purpose of the stale key warning is purely cosmetic.  The idea is to 
 *  provide a way for a user to know if the length of time their key has been in
 *  use makes it more likely to be compromised.  Based on the advances in 
 *  breaking WEP keys, this timer is largely pointless.  People just shouldn't
 *  use WEP unless they have no other choice!
 *
 * @param[in] ctx   The interface that we want to display the stale key 
 *                  warning on, and then clear the timer.
 **/
void eapol_key_type1_stale_key_warn(context * ctx)
{
	struct config_globals *globals = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return;

	debug_printf(DEBUG_NORMAL, "Your unicast key has been in use for %d "
		     "minute(s).  Given the time it takes to crack WEP keys, your "
		     "data is now less secure than it was.  You should consider "
		     "asking your network administrator to lower the rekey interval"
		     " for your wireless network.\n\n"
		     " *** PLEASE NOTE ***  This is just a warning message, and does"
		     " not indicate that your WEP key has been broken!\n",
		     (globals->stale_key_timeout / 60));
	timer_cancel(ctx, STALE_KEY_WARN_TIMER);
}

/**
 * \brief Establish the stale key timer.
 *
 * Set a timer that watches how long a key has been in use.  (Should only
 * be used for unicast keys, since broadcast keys aren't very secure to
 * begin with!)  If the timer expires, then we need to warn the user that
 * their security may be weaker than it used to be.
 *
 * @param[in] ctx   The context that we want to set up the warning timer on.
 */
void eapol_key_type1_set_stale_key_warn_timer(context * ctx)
{
	struct config_globals *globals = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return;

	if (timer_check_existing(ctx, STALE_KEY_WARN_TIMER)) {
		timer_reset_timer_count(ctx, STALE_KEY_WARN_TIMER,
					globals->stale_key_timeout);
	} else {
		// Set up a new warning counter.
		timer_add_timer(ctx, STALE_KEY_WARN_TIMER,
				globals->stale_key_timeout, NULL,
				&eapol_key_type1_stale_key_warn);
	}
}

/**
 * \brief Decrypt the key, and set it on the interface.  If there isn't a key to
 * decrypt, then use the peer key.
 *
 * @param[in] ctx   The context that points to the interface we want to use
 *                  the new key with.
 * @param[in] inframe   The EAPoL key frame that contains the encrypted key that
 *                      we need to decrypt and apply.
 * @param[in] framesize   The size (in bytes) of the EAPoL key frame that we 
 *                        need to process.
 *
 * \retval TRUE if the key was successfully set.
 * \retval FALSE if the key couldn't be set.
 * \retval XEMALLOC if a memory allocation error occurred, or invalid parameters
 *                    were passed in.
 * \retval XEBADKEY if the key data in the key frame was invalid.
 **/
int eapol_key_type1_decrypt(context * ctx, char *inframe, int framesize)
{
	struct key_packet *keydata = NULL;
	int keylen, rc = 0;
	uint16_t length;
	uint8_t *newkey = NULL, *enckey = NULL;
	struct config_globals *globals = NULL;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
		return XEMALLOC;

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return FALSE;

	keydata = (struct key_packet *)&inframe[0];

	memcpy(&length, keydata->key_length, 2);
	keylen = ntohs(length);

	debug_printf(DEBUG_KEY_STATE,
		     "EAPoL Key Processed: %s [%d] %d bytes.\n",
		     keydata->key_index & UNICAST_KEY ? "unicast" : "broadcast",
		     (keydata->key_index & KEY_INDEX) + 1, keylen);

	if ((keylen != 0) && ((framesize) - sizeof(*keydata) >= keylen)) {
		newkey = (uint8_t *) Malloc(sizeof(uint8_t) * keylen);
		if (newkey == NULL) {
			ipc_events_malloc_failed(ctx);
			return XEMALLOC;
		}

		enckey = (uint8_t *) & inframe[sizeof(struct key_packet)];

		debug_printf(DEBUG_KEY, "Key before decryption : ");
		debug_hex_printf(DEBUG_KEY, enckey, keylen);

		if (eapol_key_type1_get_rc4(ctx, enckey, newkey, keylen,
					    keydata->key_iv, 16) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't decrypt new key!\n");
			return XEBADKEY;
		}

		debug_printf(DEBUG_KEY, "Key after decryption : ");
		debug_hex_printf(DEBUG_KEY, newkey, keylen);

		if (cardif_set_wep_key(ctx, newkey, keylen, keydata->key_index) != 0) {
			rc = FALSE;
		} else {

			//  If the unicast flag is set, start the warning timer.
			if (keydata->key_index & 0x80) {
				debug_printf(DEBUG_NORMAL,
					     "Set unicast WEP key. (%d bits)\n",
					     (keylen * 8));
				eapol_key_type1_set_rekey_prob_timer(ctx);
				eapol_key_type1_set_stale_key_warn_timer(ctx);

				if ((keylen * 8) == 104) {
					wctx->pairwiseKeyType = CIPHER_WEP104;
				} else {
					wctx->pairwiseKeyType = CIPHER_WEP40;
				}
			} else {
				debug_printf(DEBUG_NORMAL,
					     "Set broadcast/multicast WEP key. "
					     "(%d bits)\n", (keylen * 8));

				if ((keylen * 8) == 104) {
					wctx->groupKeyType = CIPHER_WEP104;
				} else {
					wctx->groupKeyType = CIPHER_WEP40;
				}
			}

			rc = TRUE;

			UNSET_FLAG(wctx->flags, WIRELESS_ROAMED);
		}

		FREE(newkey);
	} else {
		debug_printf(DEBUG_KEY, "Using peer key!\n");

		debug_printf(DEBUG_NORMAL, "Set unicast WEP key. (%d bits)\n",
			     (keylen * 8));

		globals = config_get_globals();

		if (globals) {
			if (TEST_FLAG(globals->flags,
			     CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
				debug_printf(DEBUG_NORMAL,
					     "*WARNING* This AP uses the key "
					     "generated during the authentication\nprocess.  If "
					     "reauthentication doesn't happen frequently enough "
					     "your connection\nmay not be very secure!\n");
			}
		}

		if (cardif_set_wep_key(ctx, ctx->eap_state->eapKeyData, keylen,
		     keydata->key_index) != 0) {
			rc = FALSE;
		} else {
			rc = TRUE;

			//  If the unicast flag is set, start the warning timer.
			if (keydata->key_index & 0x80) {
				eapol_key_type1_set_rekey_prob_timer(ctx);
				eapol_key_type1_set_stale_key_warn_timer(ctx);
			}
		}
	}

	// If we reach this point, then we should remember the length of the
	// keys for later comparison.
	if (keydata->key_index & UNICAST_KEY) {
		wctx->unicastKeyLen = keylen;
	} else {
		wctx->broadcastKeyLen = keylen;
	}

	return rc;
}

/**
 * \brief Process an EAPoL key frame.
 *
 * We are handed in an EAPoL key frame.  From that frame, we check the frame
 * to make sure it hasn't been changed in transit.  We then determine the 
 * correct key, and make the call to set it.
 *
 * @param[in] ctx   The context for the interface that has the frame we want
 *                  to process and set the key from.
 **/
void eapol_key_type1_process(context * ctx)
{
	struct key_packet *keydata = NULL;
	struct eapol_header *eapolheader = NULL;
	uint8_t *inframe = NULL;
	int framesize = 0;
	int framelen = 0;
	struct config_globals *globals = NULL;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return;

	inframe = ctx->recvframe;
	framesize = ctx->recv_size;

	eapolheader = (struct eapol_header *)&inframe[OFFSET_PAST_MAC];

	framelen = ntohs(eapolheader->eapol_length);

	keydata = (struct key_packet *)&inframe[OFFSET_TO_EAPOL + 4];

	if (keydata->key_descr != RC4_KEY_TYPE) {
		debug_printf(DEBUG_NORMAL, "Key type isn't RC4!\n");
		return;
	}

	if (eapol_key_type1_check_hmac(ctx, (char *)&inframe[OFFSET_TO_EAPOL],
	     framelen + 4) == FALSE) {
		debug_printf(DEBUG_NORMAL,
			     "HMAC failed on key data!  This key will be discarded.\n");
		return;
	}

	if (eapol_key_type1_decrypt(ctx, (char *)&inframe[OFFSET_TO_EAPOL + 4],
	     (framelen)) != TRUE) {
		debug_printf(DEBUG_NORMAL, "Failed to set wireless key!\n");
		return;
	}

	if ((wctx->unicastKeyLen != 0) && (wctx->broadcastKeyLen != 0) &&
	    (wctx->unicastKeyLen != wctx->broadcastKeyLen)) {

		if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
			debug_printf(DEBUG_NORMAL,
				     "[WARNING] Unicast and broadcast keys "
				     "are different lengths!  Some cards/drivers/APs do "
				     "not like this combination!\n");
		}
	}
	ctx->recv_size = 0;
}
