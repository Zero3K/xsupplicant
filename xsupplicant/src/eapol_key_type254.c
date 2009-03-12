/**
 * Handle keying for WPA keys.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol_key_type254.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#ifdef WINDOWS
#include <winsock2.h>
#endif

#include <openssl/rand.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "key_statemachine.h"
#include "eapol_key_type254.h"
#include "eapol.h"
#include "frame_structs.h"
#include "wpa.h"
#include "wpa_common.h"
#include "xsup_common.h"
#include "psk.h"
#include "mic.h"
#include "snmp.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "eap_types/mschapv2/mschapv2.h"
#include "eap_sm.h"
#include "statemachine.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "timer.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

uint8_t group_key_ver = 0, pairwise_key_ver = 0;

/**
 * Given a frame, parse all of the data that is contained in it, and
 * provide a human readable output that is useful for debugging.
 */
void eapol_key_type254_dump(char *framedata)
{
	uint16_t value16 = 0;
	int need_comma = 0;
	struct wpa_key_packet *keydata = NULL;

	if (!xsup_assert((framedata != NULL), "framedata != NULL", FALSE))
		return;

	keydata = (struct wpa_key_packet *)&framedata[OFFSET_TO_EAPOL + 4];

	debug_printf(DEBUG_KEY, "Key Descriptor      = %d\n",
		     keydata->key_descriptor);
	memcpy(&value16, keydata->key_information, 2);
	debug_printf(DEBUG_KEY, "Key Information     = %04X  (Flags : ",
		     ntohs(value16));
	if (ntohs(value16) & WPA_PAIRWISE_KEY) {
		debug_printf_nl(DEBUG_KEY, "Pairwise Key");
		need_comma = 1;
	}
	if (ntohs(value16) & WPA_INSTALL_FLAG) {
		if (need_comma)
			debug_printf_nl(DEBUG_KEY, ", ");
		debug_printf_nl(DEBUG_KEY, "Install Key");
		need_comma = 1;
	}
	if (ntohs(value16) & WPA_KEY_ACK_FLAG) {
		if (need_comma)
			debug_printf_nl(DEBUG_KEY, ", ");
		debug_printf_nl(DEBUG_KEY, "Key Ack");
		need_comma = 1;
	}
	if (ntohs(value16) & WPA_KEY_MIC_FLAG) {
		if (need_comma)
			debug_printf_nl(DEBUG_KEY, ", ");
		debug_printf_nl(DEBUG_KEY, "MIC");
		need_comma = 1;
	}
	if (ntohs(value16) & WPA_SECURE_FLAG) {
		if (need_comma)
			debug_printf_nl(DEBUG_KEY, ", ");
		debug_printf_nl(DEBUG_KEY, "Secure");
		need_comma = 1;
	}
	if (ntohs(value16) & WPA_ERROR_FLAG) {
		if (need_comma)
			debug_printf_nl(DEBUG_KEY, ", ");
		debug_printf_nl(DEBUG_KEY, "Error");
		need_comma = 1;
	}
	if (ntohs(value16) & WPA_REQUEST_FLAG) {
		if (need_comma)
			debug_printf_nl(DEBUG_KEY, ", ");
		debug_printf_nl(DEBUG_KEY, "Request");
		need_comma = 1;
	}

	debug_printf_nl(DEBUG_KEY, ")\n");

	switch (ntohs(value16) & WPA_KEYTYPE_MASK) {
	case 1:
		debug_printf(DEBUG_KEY,
			     "Key Descriptor Version : HMAC-MD5 for MIC and RC4 for encryption.\n");
		break;

	case 2:
		debug_printf(DEBUG_KEY,
			     "Key Descriptor Version : HMAC-SHA1-128 for MIC and AES for encryption.\n");
		break;
	}

	debug_printf(DEBUG_KEY, "Key Length          = %d\n",
		     ntohs(keydata->key_length));

	debug_printf(DEBUG_KEY, "Key Replay Counter  = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_replay_counter, 8);

	debug_printf(DEBUG_KEY, "Key NONCE           = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_nonce, 32);

	debug_printf(DEBUG_KEY, "Key IV              = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_iv, 16);

	debug_printf(DEBUG_KEY, "Key RSC             = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_rsc, 8);

	debug_printf(DEBUG_KEY, "Key ID              = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_id, 8);

	debug_printf(DEBUG_KEY, "Key MIC             = ");
	debug_hex_printf(DEBUG_KEY, keydata->key_mic, 16);

	value16 = ntohs(keydata->key_material_len);
	debug_printf(DEBUG_KEY, "Key Material Length = %d\n", value16);

	if (value16 > 0) {
		debug_printf(DEBUG_KEY, "Key Data : (%d)\n", value16);
		debug_hex_dump(DEBUG_KEY, keydata->keydata, value16);
	}
}

/*******************************************************
 *
 * Generate the pre-Temporal key. (PTK) Using the authenticator, and 
 * supplicant nonces.  (Anonce, and Snonce.)  The PTK is used for keying
 * when we are ready.
 *
 *******************************************************/
char *eapol_key_type254_gen_ptk(context * ctx, char *Anonce)
{
	char prfdata[76];	// 6*2 (MAC addrs) + 32*2 (nonces)
	char *retval = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return NULL;

	if (!xsup_assert((Anonce != NULL), "Anonce != NULL", FALSE))
		return NULL;

	memset((char *)&prfdata, 0x00, 76);

	debug_printf(DEBUG_KEY, "Dest MAC: ");
	debug_hex_printf(DEBUG_KEY, (uint8_t *) & ctx->dest_mac, 6);

	if (memcmp((char *)&ctx->source_mac, (char *)&ctx->dest_mac, 6) < 0) {
		memcpy((char *)&prfdata[0], (char *)&ctx->source_mac, 6);
		memcpy((char *)&prfdata[6], (char *)&ctx->dest_mac, 6);
	} else if (memcmp((char *)&ctx->source_mac, (char *)&ctx->dest_mac,
			  6) > 0) {
		memcpy((char *)&prfdata[0], (char *)&ctx->dest_mac, 6);
		memcpy((char *)&prfdata[6], (char *)&ctx->source_mac, 6);
	} else {
		debug_printf(DEBUG_NORMAL,
			     "Source and Destination MAC addresses "
			     "match!  The PTK won't be valid!\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_INVALID_PTK, ctx->desc);
		return NULL;
	}

	if (memcmp(ctx->statemachine->SNonce, Anonce, 32) < 0) {
		memcpy((char *)&prfdata[12], ctx->statemachine->SNonce, 32);
		memcpy((char *)&prfdata[44], Anonce, 32);
	} else if (memcmp(ctx->statemachine->SNonce, Anonce, 32) > 0) {
		memcpy((char *)&prfdata[12], Anonce, 32);
		memcpy((char *)&prfdata[44], ctx->statemachine->SNonce, 32);
	} else {
		debug_printf(DEBUG_NORMAL,
			     "ANonce and SNonce match!  The PTK won't"
			     " be valid!\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_INVALID_PTK, ctx->desc);
		return NULL;
	}

	retval = (char *)Malloc(80);
	if (retval == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for retval in %s "
			     "at %d!\n", __FUNCTION__, __LINE__);
		ipc_events_malloc_failed(ctx);
		return NULL;
	}

	debug_printf(DEBUG_KEY, "PMK : ");
	debug_hex_printf(DEBUG_KEY, (uint8_t *) ctx->statemachine->PMK, 32);
	wpa_PRF((uint8_t *) ctx->statemachine->PMK, 32,
		(uint8_t *) "Pairwise key " "expansion", 22,
		(uint8_t *) & prfdata, 76, (uint8_t *) retval, 64);

	debug_printf(DEBUG_KEY, "PTK : ");
	debug_hex_printf(DEBUG_KEY, (uint8_t *) retval, 64);

	return retval;
}

/*****************************************************************
 *
 * When a MIC failure occures, we need to send the AP a request for
 * a new key. (Reference 802.11i-D3.0.pdf page 43, line 8)
 *
 *****************************************************************/
void eapol_key_type254_request_new_key(context * ctx, char unicast)
{
	struct wpa_key_packet *outkeydata = NULL;
	uint16_t value16 = 0, keyindex = 0, len = 0;
	char key[16];

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	outkeydata =
	    (struct wpa_key_packet *)&ctx->sendframe[OFFSET_TO_EAPOL + 4];

	// Clear everything out.
	memset(&ctx->sendframe[OFFSET_TO_EAPOL + 4], 0x00,
	       sizeof(struct wpa_key_packet));

	outkeydata->key_descriptor = WPA_KEY_TYPE;

	value16 = (WPA_REQUEST_FLAG | WPA_ERROR_FLAG);

	if (unicast == 1) {
		// Set the key flags to indicate this is a pairwise key, with an
		// index of 0.
		keyindex = (WPA_PAIRWISE_KEY | pairwise_key_ver);
	} else {
		// Set the key flags to indicate this is a group key. We don't know the
		// index, so for now we will use 1.
		keyindex = ((1 << 4) | group_key_ver);
	}

	value16 = (value16 | keyindex);

	memcpy(outkeydata->key_information, &value16, 2);

	// Build the response.
	len = sizeof(struct wpa_key_packet);
	ctx->send_size = len + OFFSET_TO_EAPOL + 4;

	eapol_build_header(ctx, EAPOL_KEY,
			   (ctx->send_size - OFFSET_TO_EAPOL - 4),
			   (char *)ctx->sendframe);

	if (!ctx->statemachine->PTK) {
		debug_printf(DEBUG_NORMAL,
			     "No valid PTK available!  We will not be "
			     "able to request a new key!\n");
		return;
	}

	memcpy(key, ctx->statemachine->PTK, 16);
	mic_wpa_populate((char *)ctx->sendframe, ctx->send_size + 4, key, 16);

	cardif_sendframe(ctx);
	ctx->statemachine->eapolEap = FALSE;
}

/****************************************************************
 *
 * When we have completed the PTK piece, and the pairwise key has been
 * applied to the interface, we need to get the group key.  The authenticator
 * will send us a group key that is encrypted.  We should decrypt it, apply
 * it to our interface, and send the authenticator a message to let it know
 * that we have a group key.
 *
 ****************************************************************/
void eapol_key_type254_do_gtk(context * ctx)
{
	struct wpa_key_packet *inkeydata = NULL, *outkeydata = NULL;
	uint16_t value16 = 0, keyflags = 0, version = 0, keyindex = 0, len = 0;
	unsigned char *keydata = NULL;
	char key[32], rc4_ek[32];
	char zeros[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	xsup_assert((ctx->statemachine != NULL), "ctx->statemachine != NULL",
		    TRUE);

	if (!xsup_assert
	    ((ctx->intType == ETH_802_11_INT), "ctx->intType == ETH_802_11_INT",
	     FALSE))
		return;

	if (!xsup_assert
	    ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
		return;

	wctx = ctx->intTypeData;

	inkeydata =
	    (struct wpa_key_packet *)&ctx->recvframe[OFFSET_TO_EAPOL + 4];
	outkeydata =
	    (struct wpa_key_packet *)&ctx->sendframe[OFFSET_TO_EAPOL + 4];

	// First, make sure that the inkeydata replay counter is higher than
	// the last counter we saw.
	if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <=
	     0) && (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid replay counter!  Discarding!\n");
		debug_printf(DEBUG_KEY, "Recieved counter : ");
		debug_hex_printf(DEBUG_KEY, inkeydata->key_replay_counter, 8);
		debug_printf(DEBUG_KEY, "Our counter : ");
		debug_hex_printf(DEBUG_KEY, wctx->replay_counter, 8);
		ctx->recv_size = 0;
		return;
	}
	// Clear everything out.
	memset(&ctx->sendframe[OFFSET_TO_EAPOL + 4], 0x00,
	       sizeof(struct wpa_key_packet));

	outkeydata->key_descriptor = WPA_KEY_TYPE;

	memcpy(&value16, inkeydata->key_information, 2);
	value16 = ntohs(value16);

	keyflags = 0;
	keyflags = (value16 & WPA_KEYTYPE_MASK);
	version = keyflags;
	group_key_ver = version;
	keyindex = ((value16 & WPA_KEY_INDEX) >> 4);

	// Verify that our flags are correct.  (We don't check for the install flag,
	// for now.  Since the WPA spec doesn't explicitly require that the install
	// flag be set.)
	if (!((value16 & WPA_KEY_ACK_FLAG) &&
	      (value16 & WPA_KEY_MIC_FLAG) && (value16 & WPA_SECURE_FLAG))) {
		debug_printf(DEBUG_NORMAL, "Invalid flags in GTK message 1!\n");
		return;
	}

	value16 = ntohs(inkeydata->key_material_len);

	keydata = (unsigned char *)Malloc(value16 + 8);
	if (keydata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for key data!\n");
		return;
	}

	memcpy(keydata,
	       &ctx->recvframe[OFFSET_TO_EAPOL + 4 +
			       sizeof(struct wpa_key_packet)], value16);

	debug_printf(DEBUG_KEY,
		     "Setting GTK! (Version : %d  Length : %d  Slot : %d)" "\n",
		     version, value16, keyindex);

	if (!ctx->statemachine->PTK) {
		debug_printf(DEBUG_NORMAL,
			     "No valid PTK available!  You will probably"
			     " not be able to pass data.\n");
		FREE(keydata);
		return;
	}

	switch (version) {
	case 1:
		// Decrypt the GTK.
		if (ctx->statemachine->PTK == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "The PTK for this connection is NULL!\n");
			cardif_disassociate(ctx, DISASSOC_CIPHER_REJECT);
			return;
		}

		memset(rc4_ek, 0x00, 32);
		memcpy(rc4_ek, inkeydata->key_iv, 16);
		memcpy(&rc4_ek[16], &ctx->statemachine->PTK[16], 16);
		rc4_skip((uint8_t *) rc4_ek, 32, 256, keydata, value16);

		debug_printf_nl(DEBUG_KEY, "GTK (%d) : ", value16);
		debug_hex_printf(DEBUG_KEY, keydata, value16);

		wpa_common_set_key(ctx, NULL, keyindex, FALSE, (char *)keydata,
				   value16);
		break;

	case 2:
		// First, decrypt the GTK
		memset(key, 0x00, 32);
		if (aes_unwrap
		    ((uint8_t *) & ctx->statemachine->PTK[16],
		     (value16 - 8) / 8, keydata, (uint8_t *) key) != 0) {
			debug_printf(DEBUG_NORMAL, "Failed AES unwrap.\n");
			if (ctx->statemachine->PTK == NULL)
				debug_printf(DEBUG_NORMAL,
					     "Unwrap failed because PTK is NULL!\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_FAILED_AES_UNWRAP,
					 ctx->desc);
			cardif_disassociate(ctx, DISASSOC_CIPHER_REJECT);
			return;
		}

		wpa_common_set_key(ctx, NULL, keyindex, FALSE, (char *)keydata,
				   (value16 - 8));

		break;
	}

	debug_printf(DEBUG_NORMAL, "Interface '%s' set new group WPA key.\n",
		     ctx->desc);

	// Build the response.
	len = sizeof(struct wpa_key_packet);
	ctx->send_size = len + OFFSET_TO_EAPOL + 4;

	value16 =
	    ((version | (keyindex << 4)) | WPA_KEY_MIC_FLAG | WPA_SECURE_FLAG);
	value16 = htons(value16);
	memcpy(&outkeydata->key_information, &value16, 2);

	outkeydata->key_length = inkeydata->key_length;
	memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter,
	       8);

	eapol_build_header(ctx, EAPOL_KEY,
			   (ctx->send_size - OFFSET_TO_EAPOL - 4),
			   (char *)ctx->sendframe);

	memcpy(&key, ctx->statemachine->PTK, 16);
	mic_wpa_populate((char *)ctx->sendframe, ctx->send_size + 4, key, 16);

	// Dump what we built.
	eapol_key_type254_dump((char *)ctx->sendframe);

	if (ctx->conn->association.auth_type == AUTH_PSK) {
		// If we are using PSK, and we made it here, then we are in 
		// S_FORCE_AUTH state.
		statemachine_change_state(ctx, S_FORCE_AUTH);
	}
	// Drop unencrypted frames.
	cardif_drop_unencrypted(ctx, 1);

	FREE(keydata);

	// We need to let the event core know that we are done doing the PSK handshake.  This allows it to
	// go through the event loop one more time to verify that the AP didn't drop us.  If it did drop us,
	// it is a pretty sure indication that our PSK is invalid.  If it didn't, then we should be good.
	// Note that sometimes APs will drop us a few seconds after the association, even if the PSK is
	// valid.  This is *NOT* an indication that the key is wrong!
	if (TEST_FLAG
	    (((wireless_ctx *) ctx->intTypeData)->flags,
	     WIRELESS_SM_DOING_PSK)) {
		UNSET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
			   WIRELESS_SM_DOING_PSK);
		timer_cancel(ctx, PSK_DEATH_TIMER);
		ipc_events_ui(ctx, IPC_EVENT_PSK_SUCCESS, ctx->intName);
	}
}

/***************************************************************
 *
 * Handle the first packet in the four-way handshake.
 *
 ***************************************************************/
void eapol_key_type254_do_type1(context * ctx)
{
	struct wpa_key_packet *inkeydata = NULL, *outkeydata = NULL;
	uint16_t keyflags, len, value16;
	int version;
	uint8_t ielen;
	char key[16];
	uint8_t wpa_ie[26];
	char zeros[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert
	    ((ctx->intType == ETH_802_11_INT), "ctx->intType == ETH_802_11_INT",
	     FALSE))
		return;

	if (!xsup_assert
	    ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
		return;

	wctx = ctx->intTypeData;

	inkeydata =
	    (struct wpa_key_packet *)&ctx->recvframe[OFFSET_TO_EAPOL + 4];
	outkeydata =
	    (struct wpa_key_packet *)&ctx->sendframe[OFFSET_TO_EAPOL + 4];

	// First, make sure that the inkeydata replay counter is higher than
	// the last counter we saw.
	if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <=
	     0) && (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid replay counter!  Discarding!\n");
		ctx->recv_size = 0;
		return;
	}
	// Clear everything out.
	memset(&ctx->sendframe[OFFSET_TO_EAPOL + 4], 0x00,
	       sizeof(struct wpa_key_packet));

	RAND_bytes((uint8_t *) & outkeydata->key_nonce[0], 32);

	ctx->statemachine->SNonce = (uint8_t *) malloc(32);
	if (ctx->statemachine->SNonce == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for SNonce in "
			     "%s at %d!\n", __FUNCTION__, __LINE__);
		ipc_events_malloc_failed(ctx);
		return;
	}
	memcpy(ctx->statemachine->SNonce, (char *)&outkeydata->key_nonce[0],
	       32);

	// Calculate the PTK.
	FREE(ctx->statemachine->PTK);

	ctx->statemachine->PTK = (uint8_t *) eapol_key_type254_gen_ptk(ctx,
								       (char *)
								       &inkeydata->key_nonce);

	outkeydata->key_descriptor = WPA_KEY_TYPE;

	memcpy(&value16, inkeydata->key_information, 2);
	value16 = ntohs(value16);

	keyflags = 0;
	keyflags = (value16 & WPA_KEYTYPE_MASK);
	version = keyflags;
	pairwise_key_ver = version;
	keyflags |= (WPA_PAIRWISE_KEY | WPA_KEY_MIC_FLAG);
	keyflags = htons(keyflags);

	memcpy(&outkeydata->key_information, &keyflags, 2);

	len = sizeof(struct wpa_key_packet);
	ctx->send_size = len + OFFSET_TO_EAPOL + 4;

	outkeydata->key_length = inkeydata->key_length;

	memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter,
	       8);

	cardif_get_wpa_ie(ctx, wpa_ie, &ielen);

	memcpy(&ctx->sendframe
	       [OFFSET_TO_EAPOL + 4 + sizeof(struct wpa_key_packet)], &wpa_ie,
	       ielen);
	value16 = ielen;
	value16 = htons(value16);
	ctx->send_size += ielen;

	outkeydata->key_material_len = value16;

	eapol_build_header(ctx, EAPOL_KEY,
			   (ctx->send_size - OFFSET_TO_EAPOL - 4),
			   (char *)ctx->sendframe);

	memcpy(key, ctx->statemachine->PTK, 16);
	mic_wpa_populate((char *)ctx->sendframe, ctx->send_size + 4, key, 16);

	// Dump what we built.
	eapol_key_type254_dump((char *)ctx->sendframe);
}

/********************************************************
 *
 * Compare the IE that we got from a key packet to the IE that we got from
 * the AP, to see if they match.
 *
 ********************************************************/
char eapol_key_type254_cmp_ie(context * ctx, uint8_t * wpaie, char wpaielen)
{
	uint8_t *apie = NULL, apielen = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((wpaie != NULL), "wpaie != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((ctx->conn != NULL), "ctx->conn != NULL", FALSE))
		return XEMALLOC;

	if (ctx->conn->flags & CONFIG_NET_IS_HIDDEN) {
		debug_printf(DEBUG_NORMAL,
			     "Interface '%s' connected to a hidden SSID.  We don't know the IE that was used, so we won't check.  (Man-in-the-middle checks have been weakened.)\n",
			     ctx->desc);
		return 0;
	}

	debug_printf(DEBUG_KEY, "WPA IE from Key Packet (%d) : ", wpaielen);
	debug_hex_printf(DEBUG_KEY, wpaie, wpaielen);

	// Don't free apie, as it is a reference pointer only!!
	config_ssid_get_wpa_ie(ctx->intTypeData, &apie, &apielen);
	debug_printf(DEBUG_KEY, "WPA IE from AP Scan (%d)    : ", apielen);
	debug_hex_printf(DEBUG_KEY, apie, apielen);

	if (wpaielen != apielen) {
		debug_printf(DEBUG_NORMAL,
			     "IE from the AP and IE from the key messages"
			     " are different lengths!\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_IES_DONT_MATCH,
				 ctx->desc);
		return -1;
	}

	if (memcmp(wpaie, apie, apielen) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "IE from the AP and IE from the key messages"
			     " do not match!\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_IES_DONT_MATCH,
				 ctx->desc);
		return -1;
	}

	return XENONE;
}

/********************************************************
 *
 * Handle the third packet in the 4 way handshake.  We should be able to
 * generate the pairwise key at this point.
 *
 ********************************************************/
void eapol_key_type254_do_type3(context * ctx)
{
	struct wpa_key_packet *inkeydata = NULL, *outkeydata = NULL;
	uint16_t keyflags, len, value16, keyindex;
	int version;
	char key[32];
	char zeros[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert
	    ((ctx->intType == ETH_802_11_INT), "ctx->intType == ETH_802_11_INT",
	     FALSE))
		return;

	if (!xsup_assert
	    ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
		return;

	wctx = ctx->intTypeData;

	memset(key, 0x00, 32);

	inkeydata =
	    (struct wpa_key_packet *)&ctx->recvframe[OFFSET_TO_EAPOL + 4];
	outkeydata =
	    (struct wpa_key_packet *)&ctx->sendframe[OFFSET_TO_EAPOL + 4];

	// First, make sure that the inkeydata replay counter is higher than
	// the last counter we saw.
	if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <=
	     0) && (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid replay counter!  Discarding!\n");
		ctx->recv_size = 0;
		return;
	}
	// Update our replay counter.
	memcpy(wctx->replay_counter, &inkeydata->key_replay_counter, 8);

	// Clear everything out.
	memset(&ctx->sendframe[OFFSET_TO_EAPOL], 0x00,
	       sizeof(struct wpa_key_packet) + 28);

	outkeydata->key_descriptor = WPA_KEY_TYPE;

	memcpy(&value16, inkeydata->key_information, 2);
	value16 = ntohs(value16);

	keyflags = 0;
	keyflags = (value16 & WPA_KEYTYPE_MASK);
	version = keyflags;

	keyflags = 0;
	keyflags = (value16 & WPA_KEYTYPE_MASK);
	keyflags |= (WPA_PAIRWISE_KEY | WPA_KEY_MIC_FLAG);
	keyindex = ((value16 & WPA_KEY_INDEX) >> 4);

	// If the authenticator sets the secure flag, we need to do the same.
	if (value16 & WPA_SECURE_FLAG)
		keyflags |= WPA_SECURE_FLAG;
	keyflags = htons(keyflags);

	memcpy(&outkeydata->key_information, &keyflags, 2);

	len = sizeof(struct wpa_key_packet);
	ctx->send_size = len + OFFSET_TO_EAPOL + 4;

	outkeydata->key_length = inkeydata->key_length;

	memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter,
	       8);
	memcpy(&outkeydata->key_nonce, ctx->statemachine->SNonce, 32);

	memcpy(outkeydata->key_nonce, ctx->statemachine->SNonce, 32);

	eapol_build_header(ctx, EAPOL_KEY,
			   (ctx->send_size - OFFSET_TO_EAPOL - 4),
			   (char *)ctx->sendframe);

	if (!ctx->statemachine->PTK) {
		debug_printf(DEBUG_NORMAL,
			     "No valid PTK available!  You will probably"
			     " not get valid keys!  (And traffic will probably not "
			     "flow correctly.)\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_INVALID_PTK, ctx->desc);
		return;
	}

	memcpy(key, ctx->statemachine->PTK, 16);
	mic_wpa_populate((char *)ctx->sendframe, ctx->send_size + 4, key, 16);

	// Dump what we built.
	eapol_key_type254_dump((char *)ctx->sendframe);

	if (eapol_key_type254_cmp_ie(ctx, inkeydata->keydata,
				     ntohs(inkeydata->key_material_len)) !=
	    XENONE) {
		debug_printf(DEBUG_NORMAL,
			     "Error comparing IEs.  Possible attack in "
			     "progress!  Disconnecting.\n");
		cardif_disassociate(ctx, DISASSOC_INVALID_IE);
		return;
	}

	if (!ctx->statemachine->PTK) {
		debug_printf(DEBUG_NORMAL,
			     "No valid PTK available.  We will not be "
			     "able to get valid keys.  (And traffic will not flow "
			     "properly.\n");
		ipc_events_error(ctx, IPC_EVENT_ERROR_INVALID_PTK, ctx->desc);
		return;
	}
	// Get TK1
	value16 = ntohs(inkeydata->key_length);
	memcpy(key, (char *)&ctx->statemachine->PTK[32], value16);

	debug_printf(DEBUG_KEY, "TK1 : ");
	debug_hex_printf(DEBUG_KEY, (uint8_t *) key, value16);

	cardif_sendframe(ctx);
	ctx->statemachine->eapolEap = FALSE;
	ctx->send_size = 0;

	debug_printf(DEBUG_KEY, "Setting PTK1! (Index : %d Length : %d)\n",
		     keyindex, value16);

	switch (version) {
	case 1:
		wpa_common_set_key(ctx, ctx->dest_mac, keyindex, TRUE,
				   key, value16);
		break;

	case 2:
		wpa_common_set_key(ctx, ctx->dest_mac, keyindex, TRUE,
				   key, value16);
		break;
	}

	debug_printf(DEBUG_NORMAL, "Interface '%s' set new pairwise WPA key.\n",
		     ctx->desc);
}

void eapol_key_type254_determine_key(context * ctx)
{
	struct wpa_key_packet *keydata = NULL;
	int keyflags = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert
	    ((ctx->recvframe != NULL), "ctx->recvframe != NULL", FALSE))
		return;

	keydata = (struct wpa_key_packet *)&ctx->recvframe[OFFSET_TO_EAPOL + 4];
	memcpy(&keyflags, keydata->key_information, 2);

	keyflags = ntohs(keyflags);

	if (keyflags & WPA_KEY_MIC_FLAG) {
		if (mic_wpa_validate((char *)ctx->recvframe, ctx->recv_size,
				     (char *)ctx->statemachine->PTK,
				     16) == FALSE) {
			ctx->statemachine->MICVerified = TRUE;
			ctx->statemachine->IntegrityFailed = TRUE;
			debug_printf(DEBUG_KEY, "MIC failure!\n");
			return;	// Silently discard.
		} else {
			ctx->statemachine->IntegrityFailed = FALSE;
			ctx->statemachine->MICVerified = TRUE;
		}
	}

	if ((keyflags & WPA_PAIRWISE_KEY) && (keyflags & WPA_KEY_ACK_FLAG) &&
	    (keyflags & WPA_KEY_MIC_FLAG) && (keyflags & WPA_INSTALL_FLAG)) {
		debug_printf(DEBUG_KEY, "Key Packet #3 (response) :\n");
		eapol_key_type254_do_type3(ctx);
	} else if ((keyflags & WPA_PAIRWISE_KEY)
		   && (keyflags & WPA_KEY_ACK_FLAG)) {
		debug_printf(DEBUG_KEY, "Key Packet #1 (response) :\n");
		eapol_key_type254_do_type1(ctx);
	} else if ((keyflags & WPA_KEY_MIC_FLAG)
		   && (keyflags & WPA_PAIRWISE_KEY)) {
		debug_printf(DEBUG_NORMAL,
			     "Got Key Packet #2 or #4!  (This shouldn't happen!)\n");
	} else if (!(keyflags & WPA_PAIRWISE_KEY)) {
		// We have a group key packet.
		eapol_key_type254_do_gtk(ctx);
	}

	if (ctx->recv_size > 0) {
		eapol_build_header(ctx, EAPOL_KEY,
				   (ctx->recv_size - OFFSET_TO_EAPOL - 4),
				   (char *)ctx->recvframe);
		cardif_sendframe(ctx);
		ctx->statemachine->eapolEap = FALSE;
	}
}

/**
 * \brief If we are doing PSK, and this is called, then the handshake stalled.
 **/
int8_t eapol_key_type254_psk_timeout(context * ctx)
{
	debug_printf(DEBUG_INT, "Clearing bad PSK flag.\n");
	UNSET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
		   WIRELESS_SM_DOING_PSK);

	timer_cancel(ctx, PSK_DEATH_TIMER);
	debug_printf(DEBUG_NORMAL,
		     "Timeout attempting to establish PSK connection on %s.\n",
		     ctx->desc);

	ipc_events_ui(ctx, IPC_EVENT_PSK_TIMEOUT, ctx->intName);

	return 0;
}

/**
 *
 * Process a WPA frame that we get from the authenticator.
 *
 **/
void eapol_key_type254_process(context * ctx)
{
	uint8_t *inframe = NULL;
	int insize;
	char tpmk[254];
	wireless_ctx *wctx = NULL;
	char *pskptr = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	inframe = ctx->recvframe;
	insize = ctx->recv_size;

	debug_printf(DEBUG_KEY, "Processing WPA key message!\n");

	eapol_key_type254_dump((char *)inframe);

	if (ctx->conn == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Got a key message on '%s' when we don't have a valid configuration defined?  Make sure you don't have another supplicant running.\n",
			     ctx->desc);
		return;
	}

	if (ctx->conn->association.psk != NULL)
		pskptr = ctx->conn->association.psk;

	// Make sure the one below always comes last so that it if the user overrides it via the UI
	// that the one from the UI is the one used.
	if (ctx->conn->association.temp_psk != NULL)
		pskptr = ctx->conn->association.temp_psk;

	if (ctx->conn->association.auth_type == AUTH_PSK) {
		wctx = (wireless_ctx *) ctx->intTypeData;

		if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
			return;

		SET_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK);

		if (timer_check_existing(ctx, PSK_DEATH_TIMER) != TRUE) {
			// Give us some time to complete PSK, or timeout
			timer_add_timer(ctx, PSK_DEATH_TIMER,
					PSK_FAILURE_TIMEOUT, NULL,
					eapol_key_type254_psk_timeout);
		} else {
			timer_reset_timer_count(ctx, PSK_DEATH_TIMER,
						PSK_FAILURE_TIMEOUT);
		}

		if (pskptr != NULL) {
			if (wctx->cur_essid == NULL) {
				debug_printf(DEBUG_NORMAL,
					     "Unknown SSID, checking!\n");
				wctx->cur_essid = (char *)Malloc(33);
				if (wctx->cur_essid == NULL) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't allocate memory! "
						     "(%s:%d)\n", __FUNCTION__,
						     __LINE__);
					ipc_events_malloc_failed(ctx);
					return;
				}

				if (cardif_GetSSID(ctx, wctx->cur_essid, 33) !=
				    XENONE) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't get ESSID!\n");
					FREE(wctx->cur_essid);
					return;
				}
			}
			// We have an ASCII password, so calculate it.
			if (psk_wpa_pbkdf2(pskptr, (uint8_t *) wctx->cur_essid,
					   strlen(wctx->cur_essid),
					   (uint8_t *) & tpmk)
			    == TRUE) {
				FREE(ctx->statemachine->PMK);

				ctx->statemachine->PMK = (uint8_t *) Malloc(32);
				if (ctx->statemachine->PMK == NULL) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't allocate memory for"
						     " ctx->statemachine->PMK in %s:%d!\n",
						     __FUNCTION__, __LINE__);
					ipc_events_malloc_failed(ctx);
					return;
				}

				memcpy(ctx->statemachine->PMK, (char *)&tpmk,
				       32);
			}
		} else if (ctx->conn->association.psk_hex != NULL) {
			// We have a hex key, we need to convert it from ASCII to real
			// hex.
			if (ctx->conn->association.psk_hex == NULL
			    || strlen(ctx->conn->association.psk_hex) != 64) {
				debug_printf(DEBUG_NORMAL,
					     "Invalid HEX key defined for "
					     "WPA-PSK!\n");
				return;
			}
			process_hex(ctx->conn->association.psk_hex,
				    strlen(ctx->conn->association.psk_hex),
				    (char *)&tpmk);

			FREE(ctx->statemachine->PMK);

			ctx->statemachine->PMK = (uint8_t *) Malloc(32);
			if (ctx->statemachine->PMK == NULL) {
				debug_printf(DEBUG_NORMAL,
					     "Couldn't allocate memory for "
					     "ctx->statemachine->PMK in %s:%d!\n",
					     __FUNCTION__, __LINE__);
				ipc_events_malloc_failed(ctx);
				return;
			}
		}

		if (ctx->statemachine->PMK == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "There is no PMK available!  WPA cannot"
				     " continue!\n");
			ipc_events_error(ctx, IPC_EVENT_ERROR_PMK_UNAVAILABLE,
					 ctx->desc);

			// Drop our connection.
			context_disconnect(ctx);

			return;
		}
	}

	eapol_key_type254_determine_key(ctx);

	if (ctx->send_size > 0) {
		cardif_sendframe(ctx);
		ctx->statemachine->eapolEap = FALSE;
	}

}
