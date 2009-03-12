/**
 * \file wpa.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>

#ifndef WINDOWS
#include <inttypes.h>
#include <unistd.h>
#endif

#include <sys/types.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "wpa.h"
#include "platform/cardif.h"
#include "config_ssid.h"
#include "wpa_common.h"
#include "xsup_err.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

const char wpaoui[3] = { 0x00, 0x50, 0xf2 };

/*************************************************************************
 *
 * Get the pairwise cipher that we want to use.  If one is configured in the
 * config file, then we will use that one.  Otherwise, we will make a decision
 * based on the information provided by the AP, and provided by the wireless
 * card.
 *
 *************************************************************************/
uint8_t wpa_get_pairwise_crypt(context * ctx)
{
	uint8_t available_pair = 0, wpa_ie_len = 0;
	uint8_t *pairptr;
	uint8_t *wpa_ie = NULL;
	uint8_t i;
	uint16_t *ciphers;
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	config_ssid_get_wpa_ie(ctx->intTypeData, &wpa_ie, &wpa_ie_len);

	if (wpa_ie == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "This SSID didn't return a WPA IE in our "
			     "scan!  We won't be able to connect!\n");
		return -1;
	}

	if ((wpa_ie_len <= 0) && (ctx->conn->association.pairwise_keys == 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Insufficient information to build WPA "
			     "IE.  Please set 'wpa_pairwise_crypt' value in your network"
			     " clause for this network.\n");
		return -1;
	}
	// If the user has manually set a crypto type, then use it.
	if (ctx->conn->association.pairwise_keys != 0)
		return ctx->conn->association.pairwise_keys;

	// Otherwise, see what the card has told us we can support, and compare it
	// to what the AP claims to support.
	ciphers = (uint16_t *) & wpa_ie[12];

	debug_printf(DEBUG_KEY, "There are %d pairwise cipher(s) in this IE.\n",
		     *ciphers);
	pairptr = (uint8_t *) & wpa_ie[14];

	for (i = 0; i < (*ciphers); i++) {
		if (memcmp(pairptr, &wpaoui, 3) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "One of this AP's pairwise key settings "
				     "seems to be proprietary.  Skipping.\n");
			pairptr += 4;	// Skip this.
		} else {
			pairptr += 3;

			if ((*pairptr) == CIPHER_WEP40)
				available_pair |= DOES_WEP40;
			if ((*pairptr) == CIPHER_WEP104)
				available_pair |= DOES_WEP104;
			if ((*pairptr) == CIPHER_TKIP)
				available_pair |= DOES_TKIP;
			if ((*pairptr) == CIPHER_CCMP)
				available_pair |= DOES_CCMP;

			pairptr++;
		}
	}

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return -1;

	// We want to test for cipher types from the best down to the worst, so
	// that we will select the best cipher possible.
	if (available_pair & DOES_CCMP) {
		if (wctx->enc_capa & DOES_CCMP) {
			return CIPHER_CCMP;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use CCMP"
				     " for the pairwise cipher.  But, your card reports that"
				     " it doesn't support CCMP.  If you are sure that your"
				     " card supports CCMP, you should add "
				     "'wpa_pairwise_cipher = CCMP' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}

	if (available_pair & DOES_TKIP) {
		if (wctx->enc_capa & DOES_TKIP) {
			return CIPHER_TKIP;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use TKIP"
				     " for the pairwise cipher.  But, your card reports that"
				     " it doesn't support TKIP.  If you are sure that your"
				     " card supports TKIP, you should add "
				     "'wpa_pairwise_cipher = TKIP' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}

	if (available_pair & DOES_WEP104) {
		if (wctx->enc_capa & DOES_WEP104) {
			return CIPHER_WEP104;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use WEP104"
				     " for the pairwise cipher.  But, your card reports that"
				     " it doesn't support WEP104.  If you are sure that your"
				     " card supports WEP104, you should add "
				     "'wpa_pairwise_cipher = WEP104' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}

	if (available_pair & DOES_WEP40) {
		if (wctx->enc_capa & DOES_WEP40) {
			return CIPHER_WEP40;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use WEP40"
				     " for the pairwise cipher.  But, your card reports that"
				     " it doesn't support WEP40.  If you are sure that your"
				     " card supports WEP40, you should add "
				     "'wpa_pairwise_cipher = WEP40' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}
	// If we get here, then the AP has requested a cipher type we don't 
	// understand.
	debug_printf(DEBUG_NORMAL, "The AP has requested a cipher type that we "
		     "don't understand.\n");
	return -1;
}

/**********************************************************************
 *
 * Determine the group cipher that we should use.  If a value is set in the
 * configuration file, then we will make use of that.  Otherwise, we will
 * decide based on what the IE from the AP indicates, and the capabilities
 * that are supported by the card.
 *
 **********************************************************************/
uint8_t wpa_get_group_crypt(context * ctx)
{
	uint8_t desired_group = -1, wpa_ie_len = 0;
	uint8_t *grpptr;
	uint8_t *wpa_ie;
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	config_ssid_get_wpa_ie(ctx->intTypeData, &wpa_ie, &wpa_ie_len);

	if (!wpa_ie) {
		debug_printf(DEBUG_NORMAL,
			     "This SSID didn't return a WPA IE in our "
			     "scan!  We won't be able to connect!\n");
		return -1;
	}

	if ((wpa_ie_len <= 0) && (ctx->conn->association.group_keys == 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Insufficient information to build WPA "
			     "IE.  Please set 'wpa_group_crypt' value in your network"
			     " clause for this network.\n");
		return -1;
	}
	// If the user has manually set a crypto type, then use it.
	if (ctx->conn->association.group_keys != 0)
		return ctx->conn->association.group_keys;

	// Otherwise, see what the card has told us we can support, and compare it
	// to what the AP claims to support.
	grpptr = (uint8_t *) & wpa_ie[8];
	if (memcmp(grpptr, &wpaoui, 3) != 0) {
		debug_printf(DEBUG_NORMAL, "AP's group key setting seems to be "
			     "proprietary.  This is unsupported.\n");
		return -1;
	}
	// Get the key type that is desired.
	desired_group = grpptr[3];

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return -1;

	if (desired_group == CIPHER_WEP40) {
		if (wctx->enc_capa & DOES_WEP40) {
			return CIPHER_WEP40;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use WEP40"
				     " for the group cipher.  But, your card reports that"
				     " it doesn't support WEP40.  If you are sure that your"
				     " card supports WEP40, you should add "
				     "'wpa_group_cipher = WEP40' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}

	if (desired_group == CIPHER_WEP104) {
		if (wctx->enc_capa & DOES_WEP104) {
			return CIPHER_WEP104;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use WEP104"
				     " for the group cipher.  But, your card reports that"
				     " it doesn't support WEP104.  If you are sure that your"
				     " card supports WEP104, you should add "
				     "'wpa_group_cipher = WEP104' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}

	if (desired_group == CIPHER_TKIP) {
		if (wctx->enc_capa & DOES_TKIP) {
			return CIPHER_TKIP;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use TKIP"
				     " for the group cipher.  But, your card reports that"
				     " it doesn't support TKIP.  If you are sure that your"
				     " card supports TKIP, you should add "
				     "'wpa_group_cipher = TKIP' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}

	if (desired_group == CIPHER_CCMP) {
		if (wctx->enc_capa & DOES_CCMP) {
			return CIPHER_CCMP;
		} else {
			debug_printf(DEBUG_NORMAL,
				     "The AP has requested that we use CCMP"
				     " for the group cipher.  But, your card reports that"
				     " it doesn't support CCMP.  If you are sure that your"
				     " card supports CCMP, you should add "
				     "'wpa_group_cipher = CCMP' to your network clause for"
				     " this network.\n");
			return -1;
		}
	}
	// If the desired group cipher is set to 0, then we should use the same
	// cipher as the pairwise cipher.
	if (desired_group == 0) {
		return wpa_get_pairwise_crypt(ctx);
	}
	// If we get here, then the AP has requested a cipher type we don't 
	// understand.
	debug_printf(DEBUG_NORMAL, "The AP has requested a cipher type that we "
		     "don't understand.  Type %d.\n", desired_group);
	return -1;
}

void wpa_gen_ie(context * ctx, char *iedata)
{
	struct config_globals *globals;
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return;

	wctx = (wireless_ctx *) ctx->intTypeData;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return;

	// The first byte is the Element ID for WPA, which is 0xdd.
	iedata[0] = WPA_EID;

	// For WPA (without capabilities), the length value will always be 22.
	iedata[1] = 22;

	// For WPA, we need to add the "special" OUI before the version #.
	memcpy(&iedata[2], wpaoui, 3);
	iedata[5] = 0x01;

	// Set the version #
	iedata[6] = 0x01;
	iedata[7] = 0x00;

	// The group key cipher suite.
	memcpy(&iedata[8], wpaoui, 3);

	if ((iedata[11] = wpa_get_group_crypt(ctx)) == -1) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't build WPA IE!  (Error getting "
			     "group cipher information!\n");
		iedata[1] = 0;
		return;
	}

	debug_printf(DEBUG_KEY, "Using Group Cipher Suite : ");
	wpa_print_cipher_suite(DEBUG_KEY, iedata[11]);

	// We can only have 1 pairwise cipher suite!
	iedata[12] = 0x01;
	iedata[13] = 0x00;

	// The pairwise cipher suite.
	memcpy(&iedata[14], wpaoui, 3);

	if ((iedata[17] = wpa_get_pairwise_crypt(ctx)) == -1) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't build WPA IE!  (Error getting "
			     "pairwise cipher information!\n");
		iedata[1] = 0;
		return;
	}

	debug_printf(DEBUG_KEY, "Using Pairwise Cipher Suite : ");
	wpa_print_cipher_suite(DEBUG_KEY, iedata[17]);

	if ((wctx->groupKeyType == CIPHER_TKIP) &&
	    ((wctx->pairwiseKeyType == CIPHER_WRAP) ||
	     (wctx->pairwiseKeyType == CIPHER_CCMP))) {

		if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
			debug_printf(DEBUG_NORMAL,
				     "WARNING : Group cipher is TKIP and "
				     "pairwise cipher is using AES.  Many wireless cards "
				     "have problems with this combination!\n");
		}
	}

	if (((wctx->groupKeyType == CIPHER_WEP40) ||
	     (wctx->groupKeyType == CIPHER_WEP104)) &&
	    ((wctx->pairwiseKeyType == CIPHER_WRAP) ||
	     (wctx->pairwiseKeyType == CIPHER_CCMP))) {

		if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_FRIENDLY_WARNINGS)) {
			debug_printf(DEBUG_NORMAL,
				     "WARNING : Group cipher is WEP and "
				     "pairwise cipher is using AES.  Many wireless cards "
				     "have problems with this combination!\n");
		}
	}
	// For the authenticated key management suite, we can also only have 1.
	iedata[18] = 0x01;
	iedata[19] = 0x00;

	// The authenticated key management suite.
	memcpy(&iedata[20], wpaoui, 3);

	if (((ctx->conn->association.association_type == ASSOC_WPA)
	     || (ctx->conn->association.association_type == ASSOC_WPA2))
	    && (ctx->conn->association.auth_type == AUTH_PSK)) {
		iedata[23] = 2;	// WPA-PSK
		debug_printf(DEBUG_KEY, "Using WPA-PSK.\n");
	} else {
		if ((ctx->prof == NULL) || (ctx->prof->method == NULL)) {
			debug_printf(DEBUG_NORMAL,
				     "No valid EAP methods defined for this "
				     "network!\n");
			return;
		}

		iedata[23] = 1;	// WPA with 802.1X
		debug_printf(DEBUG_KEY, "Using WPA with 802.1X\n");
	}
}

void wpa_gen_ie_caps(context * ctx, char *iedata)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return;

	wpa_gen_ie(ctx, iedata);

	iedata[1] = 24;
	iedata[24] = 0x00;
	iedata[25] = 0x00;
}

/*************************************************************************
 *
 * Parse an information element.  Returns IE length  if it is a valid IE, 
 * and -1 if it isn't.
 *
 *************************************************************************/
int wpa_parse_ie(char *iedata)
{
	struct wpa_ie_struct *ie_struct;
	char wpa_oui[3] = { 0x00, 0x50, 0xf2 };
	char suite_id[4];
	int i, ieptr;
	uint16_t value16;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return XEMALLOC;

	ie_struct = (struct wpa_ie_struct *)iedata;

	if (ie_struct->wpaid != 0xdd) {
		debug_printf(DEBUG_NORMAL,
			     "IE is not a valid WPA IE! (Invalid vendor value!)\n");
		return -1;
	}

	debug_printf(DEBUG_KEY, "--- WPA Data ---\n");

	if ((memcmp(ie_struct->oui, wpa_oui, 3) != 0)
	    && (ie_struct->oui[3] != 0x01)) {
		debug_printf(DEBUG_NORMAL,
			     "IE is not a valid WPA IE! (Invalid OUI value!)\n");
		return -1;
	}

	value16 = ie_struct->wpa_ver;
	byte_swap(&value16);

	debug_printf(DEBUG_KEY, "WPA Version : %d\n", value16);
	if (value16 > MAX_WPA_VER) {
		debug_printf(DEBUG_NORMAL,
			     "The requested WPA version of %d is greater"
			     " than the highest version we support of %d.\n",
			     value16, MAX_WPA_VER);
		return -1;
	}
	// From here, everything else is technically optional.
	if (ie_struct->wpalen <= 6) {
		// Nothing after the version #.
		debug_printf(DEBUG_NORMAL,
			     "Short WPA IE.  Should assume TKIP/TKIP for "
			     "keying!\n");
		return ie_struct->wpalen;
	}			// Otherwise, we have a group cipher suite.

	debug_printf(DEBUG_KEY, "Group Key Cipher Suite : ");
	wpa_print_cipher_suite(DEBUG_KEY, ie_struct->group_cipher[3]);

	if (ie_struct->wpalen <= 10) {
		debug_printf(DEBUG_NORMAL,
			     "Short WPA IE.  Should assume TKIP for "
			     "pairwise cipher.\n");
		return ie_struct->wpalen;
	}

	value16 = ie_struct->pk_suite_cnt;
	byte_swap(&value16);

	debug_printf(DEBUG_KEY, "Pairwise Key Cipher Suite Count : %d\n",
		     value16);

	ieptr = sizeof(struct wpa_ie_struct);

	for (i = 0; i < value16; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid WPA IE!  The number of "
				     "cipher suites is too high for the length of the IE!"
				     "\n");
			return ie_struct->wpalen;
		}

		debug_printf(DEBUG_KEY, "Cipher Suite : ");
		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		if (memcmp(suite_id, wpa_oui, 3) != 0) {
			debug_printf_nl(DEBUG_KEY, "Proprietary\n");
		} else {
			wpa_print_cipher_suite(DEBUG_KEY, suite_id[3]);
		}

		ieptr += 4;
	}

	if (ie_struct->wpalen < (ieptr - 2) + 2) {
		debug_printf(DEBUG_NORMAL,
			     "Short IE.  Should assume an AKM of EAP.\n");
		return ie_struct->wpalen;
	}

	memcpy((char *)&value16, (char *)&iedata[ieptr], 2);
	ieptr += 2;
	byte_swap(&value16);
	debug_printf(DEBUG_KEY,
		     "Authenticated Key Management Suite Count : %d\n",
		     value16);

	for (i = 0; i < value16; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Truncated IE!  The length provided in "
				     "the IE isn't long enough to include the number of "
				     "Authenticated Key Management Suites claimed!\n");
			return -1;
		}

		debug_printf(DEBUG_KEY, "Authentication Suite : ");
		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		if (memcmp(suite_id, wpa_oui, 3) != 0) {
			debug_printf_nl(DEBUG_KEY, "Proprietary\n");
		} else {
			wpa_print_auth_suite(DEBUG_KEY, suite_id[3]);
		}
		ieptr += 4;
	}

	if ((ieptr - 2) < ie_struct->wpalen) {
		memcpy((char *)&value16, (char *)&iedata[ieptr], 2);
		debug_printf(DEBUG_KEY, "RSN Capabilities : %04X\n\n", value16);
	}

	return ie_struct->wpalen;
}

/**
 *  \brief Parse a WPA IE and return a byte that contains the bit flags indicating the
 *			the type of authentication that is in use.
 *
 * @param[in] iedata   A well formed WPA information element
 *
 * \retval 0xff on error, otherwise WPA_DOT1X or WPA_PSK bitflags indicating the auth type in use.
 **/
uint8_t wpa_parse_auth_type(char *iedata)
{
	struct wpa_ie_struct *ie_struct = NULL;
	char wpa_oui[3] = { 0x00, 0x50, 0xf2 };
	char suite_id[4];
	int i, ieptr;
	uint16_t value16 = 0;
	uint8_t retval = 0;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return XEMALLOC;

	ie_struct = (struct wpa_ie_struct *)iedata;

	if (ie_struct->wpaid != 0xdd) {
		debug_printf(DEBUG_NORMAL,
			     "IE is not a valid WPA IE! (Invalid vendor value!)\n");
		return -1;
	}

	if ((memcmp(ie_struct->oui, wpa_oui, 3) != 0)
	    && (ie_struct->oui[3] != 0x01)) {
		debug_printf(DEBUG_NORMAL,
			     "IE is not a valid WPA IE! (Invalid OUI value!)\n");
		return -1;
	}

	value16 = ie_struct->wpa_ver;
	byte_swap(&value16);

	if (value16 > MAX_WPA_VER) {
		debug_printf(DEBUG_NORMAL,
			     "The requested WPA version of %d is greater"
			     " than the highest version we support of %d.\n",
			     value16, MAX_WPA_VER);
		return -1;
	}
	// From here, everything else is technically optional.
	if (ie_struct->wpalen <= 6) {
		// Nothing after the version #.
		debug_printf(DEBUG_NORMAL,
			     "Short WPA IE.  Should assume TKIP/TKIP for "
			     "keying!\n");
		return -1;
	}			// Otherwise, we have a group cipher suite.

	if (ie_struct->wpalen <= 10) {
		debug_printf(DEBUG_NORMAL,
			     "Short WPA IE.  Should assume TKIP for "
			     "pairwise cipher.\n");
		return -1;
	}

	value16 = ie_struct->pk_suite_cnt;
	byte_swap(&value16);

	ieptr = sizeof(struct wpa_ie_struct);

	for (i = 0; i < value16; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid WPA IE!  The number of "
				     "cipher suites is too high for the length of the IE!"
				     "\n");
			return -1;
		}

		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		ieptr += 4;
	}

	if (ie_struct->wpalen < (ieptr - 2) + 2) {
		debug_printf(DEBUG_NORMAL,
			     "Short IE.  Should assume an AKM of EAP.\n");
		return WPA_DOT1X;
	}

	memcpy((char *)&value16, (char *)&iedata[ieptr], 2);
	ieptr += 2;
	byte_swap(&value16);
	debug_printf(DEBUG_KEY,
		     "Authenticated Key Management Suite Count : %d\n",
		     value16);

	for (i = 0; i < value16; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Truncated IE!  The length provided in "
				     "the IE isn't long enough to include the number of "
				     "Authenticated Key Management Suites claimed!\n");
			return -1;
		}

		debug_printf(DEBUG_KEY, "Authentication Suite : ");
		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		if (memcmp(suite_id, wpa_oui, 3) != 0) {
			debug_printf_nl(DEBUG_KEY, "Proprietary\n");
		} else {
			wpa_print_auth_suite(DEBUG_KEY, suite_id[3]);

			switch (suite_id[3]) {
			case AUTH_SUITE_RESERVED:
				debug_printf_nl(DEBUG_KEY, "Reserved\n");
				break;

			case AUTH_SUITE_DOT1X:
				debug_printf_nl(DEBUG_KEY,
						"Unspecified authentication over 802.1X\n");
				retval |= WPA_DOT1X;
				break;

			case AUTH_SUITE_PSK:
				debug_printf_nl(DEBUG_KEY, "None/WPA-PSK\n");
				retval |= WPA_PSK;
				break;
			}
		}

		ieptr += 4;
	}

	return retval;
}

/* These functions are defined by 802.11i-D3.0 */
void wpa_STADisconnect()
{

}

void wpa_RemoveGTK()
{

}
