/**
 * \file wpa2.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>

#ifndef WINDOWS
#include <inttypes.h>
#endif

#include <openssl/hmac.h>
#include <openssl/aes.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "wpa.h"
#include "wpa_common.h"
#include "wpa2.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "xsup_err.h"

const char wpa2oui[3] = { 0x00, 0x0f, 0xac };

uint16_t wpa2_ver = 1;

/********************************************************************
 *
 * Determine the pairwise crypto type to use.  If something is set in the
 * config file, we will use that no matter what the card reports as it's
 * capabilitites.  Otherwise, we will look at what the AP sent us in it's
 * IE, and attempt to match it.
 *
 ********************************************************************/
uint8_t wpa2_get_pairwise_crypt(context * ctx)
{
	uint8_t available_pair = 0, rsn_ie_len = 0;
	uint8_t *pairptr;
	uint8_t keytype;
	uint8_t *rsn_ie, i;
	uint16_t *ciphers;
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	config_ssid_get_rsn_ie(ctx->intTypeData, &rsn_ie, &rsn_ie_len);

	if (!rsn_ie) {
		debug_printf(DEBUG_NORMAL,
			     "This SSID didn't return an RSN IE in our "
			     "scan!  We probably won't be able to connect!\n");
		return -1;
	}

	if ((rsn_ie_len <= 0) && (ctx->conn->association.pairwise_keys == 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Insufficient information to build WPA2 "
			     "IE.  Please set 'wpa_pairwise_crypt' value in your network"
			     " clause for this network.\n");
		return -1;
	}
	// If the user has manually set a crypto type, then use it.
	// If there is more than one pairwise type assigned, then we choose the
	// one that provides the best encryption.
	keytype = ctx->conn->association.pairwise_keys;

	if (keytype != 0) {
		if (keytype & CRYPT_FLAGS_CCMP)
			return CIPHER_CCMP;
		if (keytype & CRYPT_FLAGS_TKIP)
			return CIPHER_TKIP;
		if (keytype & CRYPT_FLAGS_WEP104)
			return CIPHER_WEP104;
		if (keytype & CRYPT_FLAGS_WEP40)
			return CIPHER_WEP40;
	}
	// Otherwise, see what the card has told us we can support, and compare it
	// to what the AP claims to support.
	ciphers = (uint16_t *) & rsn_ie[8];

	debug_printf(DEBUG_KEY, "There are %d pairwise cipher(s) in this IE.\n",
		     *ciphers);
	pairptr = (uint8_t *) & rsn_ie[10];

	for (i = 0; i < (*ciphers); i++) {
		if (memcmp(pairptr, &wpa2oui, 3) != 0) {
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
				     "CCMP to the <Association> section of the <Connection> clause.\n");
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
				     "TKIP to the <Association> block to your <Connections> clause.\n");
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
				     "WEP104 to your <Association> block in the <Connection>.\n");
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
				     "WEP40 to your <Association> block in the <Connection>.\n");
			return -1;
		}
	}
	// If we get here, then the AP has requested a cipher type we don't 
	// understand.
	debug_printf(DEBUG_NORMAL, "The AP has requested a cipher type that we "
		     "don't understand.\n");
	return -1;
}

/***************************************************************************
 *
 * Determine the proper group cipher to use. If something was set in the
 * configuration file, then we will use that.  Otherwise we will attempt to 
 * figure out we should used based on what the AP tells us in the IE, and
 * the capabilities the card reports.
 *
 ***************************************************************************/
uint8_t wpa2_get_group_crypt(context * ctx)
{
	uint8_t desired_group = -1, rsn_ie_len = 0;
	uint8_t *grpptr;
	uint8_t *rsn_ie;
	wireless_ctx *wctx;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	config_ssid_get_rsn_ie(ctx->intTypeData, &rsn_ie, &rsn_ie_len);

	if (!rsn_ie) {
		debug_printf(DEBUG_NORMAL,
			     "This SSID didn't return an RSN IE in our "
			     "scan!  We probably won't be able to connect!\n");
		return -1;
	}

	if ((rsn_ie_len <= 0) && (ctx->conn->association.group_keys == 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Insufficient information to build WPA2 "
			     "IE.  Please set 'wpa_group_crypt' value in your network"
			     " clause for this network.\n");
		return -1;
	}
	// If the user has manually set a crypto type, then use it.
	if (ctx->conn->association.group_keys != 0)
		return ctx->conn->association.group_keys;

	// Otherwise, see what the card has told us we can support, and compare it
	// to what the AP claims to support.
	grpptr = (uint8_t *) & rsn_ie[4];
	if (memcmp(grpptr, &wpa2oui, 3) != 0) {
		debug_printf(DEBUG_NORMAL, "AP's group key setting seems to be "
			     "proprietary.  This is unsupported.\n");
		return -1;
	}

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return -1;

	// Get the key type that is desired.
	desired_group = grpptr[3];

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
	// If the desired group cipher is set to 0, then it means that we should
	// use the same cipher as the pairwise cipher.
	if (desired_group == 0) {
		return wpa2_get_pairwise_crypt(ctx);
	}
	// If we get here, then the AP has requested a cipher type we don't 
	// understand.
	debug_printf(DEBUG_NORMAL, "The AP has requested a cipher type that we "
		     "don't understand.  Type %d.\n", desired_group);
	return -1;
}

/**************************************************************************
 *
 * Generate the IE needed to associate correctly to a WPA2 network.
 *
 **************************************************************************/
void wpa2_gen_ie(context * ctx, unsigned char *iedata, int *ielen)
{
	struct config_globals *globals = NULL;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return;

	if (!xsup_assert((ielen != NULL), "ielen != NULL", FALSE))
		return;

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return;

	// The first byte is the Element ID for WPA2, which is 0x30.
	iedata[0] = WPA2_EID;

	// A simple IE with capabilities should be 20 bytes long.
	iedata[1] = 20;

	// Set the version #
	iedata[2] = 0x01;
	iedata[3] = 0x00;

	debug_printf(DEBUG_INT, "Created IE DUMP :\n");
	debug_hex_printf(DEBUG_INT, iedata, 4);

	// The group key cipher suite.
	memcpy(&iedata[4], wpa2oui, 3);

	if ((iedata[7] = wpa2_get_group_crypt(ctx)) == -1) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't build WPA2 IE!  (Error getting "
			     "group cipher information.)\n");
		*ielen = 0;
		return;
	}

	debug_printf(DEBUG_KEY, "Using Group Cipher Suite : ");
	wpa_print_cipher_suite(DEBUG_KEY, iedata[7]);

	debug_printf(DEBUG_INT, "Created IE DUMP :\n");
	debug_hex_printf(DEBUG_INT, iedata, 8);

	// We can only support 1 pairwise cipher suite!
	iedata[8] = 0x01;
	iedata[9] = 0x00;

	// The pairwise cipher suite.
	memcpy(&iedata[10], wpa2oui, 3);

	if ((iedata[13] = wpa2_get_pairwise_crypt(ctx)) == -1) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't build WPA2 IE!  (Error getting "
			     "pairwise cipher information.)\n");
		*ielen = 0;
		return;
	}

	debug_printf(DEBUG_KEY, "Using Pairwise Cipher Suite : ");
	wpa_print_cipher_suite(DEBUG_KEY, iedata[13]);

	debug_printf(DEBUG_INT, "Created IE DUMP :\n");
	debug_hex_printf(DEBUG_INT, iedata, 14);

	if ((ctx->conn->association.group_keys == CIPHER_TKIP) &&
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
	iedata[14] = 0x01;
	iedata[15] = 0x00;

	// The authenticated key management suite.
	memcpy(&iedata[16], wpa2oui, 3);

	debug_printf(DEBUG_INT, "Created IE DUMP :\n");
	debug_hex_printf(DEBUG_INT, iedata, 19);

	if (ctx->conn->association.auth_type == AUTH_PSK) {
		iedata[19] = 2;	// PSK
		debug_printf(DEBUG_KEY, "Using PSK.\n");
	} else {
		if ((ctx->prof == NULL) || (ctx->prof->method == NULL)) {
			debug_printf(DEBUG_NORMAL,
				     "No valid EAP methods defined for this "
				     "network!\n");
			*ielen = 0;
			return;
		}

		iedata[19] = 1;	// 802.1X
		debug_printf(DEBUG_KEY, "Using 802.1X\n");
	}

	debug_printf(DEBUG_INT, "Created IE DUMP :\n");
	debug_hex_printf(DEBUG_INT, iedata, 20);

	// We don't support capabilities yet.
	iedata[20] = 0x00;
	iedata[21] = 0x00;

	(*ielen) = 22;

	debug_printf(DEBUG_INT, "Created IE DUMP :\n");
	debug_hex_printf(DEBUG_INT, iedata, (*ielen));
}

void wpa2_gen_ie_caps(context * thisint, char *iedata)
{
	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
		return;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return;

	wpa_gen_ie(thisint, iedata);

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
int wpa2_parse_ie(char *iedata)
{
	struct wpa2_ie_struct *ie_struct;
	char suite_id[4];
	int i, ieptr;
	uint16_t value16;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return XEMALLOC;

	ie_struct = (struct wpa2_ie_struct *)iedata;

	if (ie_struct->wpaid != WPA2_EID) {
		debug_printf(DEBUG_NORMAL,
			     "IE is not a valid WPA2/802.11i IE! (Invalid vendor value!)\n");
		return -1;
	}

	debug_printf(DEBUG_KEY, "--- WPA2/802.11i Data ---\n");

	byte_swap(&ie_struct->rsn_ver);
	debug_printf(DEBUG_KEY, "WPA2/802.11i Version : %d\n",
		     ie_struct->rsn_ver);

	if (ie_struct->rsn_ver > MAX_WPA2_VER) {
		debug_printf(DEBUG_NORMAL,
			     "The IEEE 802.11i/WPA2 version requested is "
			     "%d.  But we only support versions up to %d.\n",
			     ie_struct->rsn_ver, MAX_WPA2_VER);
		return -1;
	}

	if (ie_struct->wpalen <= 2) {
		debug_printf(DEBUG_NORMAL,
			     "Short IE.  Should assume TKIP/TKIP for "
			     "ciphers!\n");
		return ie_struct->wpalen;
	}

	debug_printf(DEBUG_KEY, "Group Key Cipher Suite : ");
	wpa_print_cipher_suite(DEBUG_KEY, ie_struct->group_cipher[3]);

	if (ie_struct->wpalen <= 6) {
		debug_printf(DEBUG_NORMAL, "Short IE.  Should assume TKIP for "
			     "pairwise cipher.\n");
		return ie_struct->wpalen;
	}

	byte_swap(&ie_struct->pk_suite_cnt);
	debug_printf(DEBUG_KEY, "Pairwise Key Cipher Suite Count : %d\n",
		     ie_struct->pk_suite_cnt);

	ieptr = sizeof(struct wpa2_ie_struct);

	for (i = 0; i < ie_struct->pk_suite_cnt; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid IE!  The length specified by the"
				     " IE isn't long enough to cover the number of "
				     "pairwise ciphers the IE claims it lists!\n");
			return -1;
		}

		debug_printf(DEBUG_KEY, "Cipher Suite : ");
		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		if (memcmp(suite_id, wpa2oui, 3) != 0) {
			debug_printf_nl(DEBUG_KEY, "Proprietary\n");
		} else {
			wpa_print_cipher_suite(DEBUG_KEY, suite_id[3]);
		}

		ieptr += 4;
	}

	if (ie_struct->wpalen < (ieptr - 2) + 2) {
		debug_printf(DEBUG_NORMAL,
			     "Short IE.  Should assume an AKM of EAP!\n");
		return ie_struct->wpalen;
	}

	memcpy((char *)&value16, (char *)&iedata[ieptr], 2);
	ieptr += 2;
	debug_printf(DEBUG_KEY,
		     "Authenticated Key Management Suite Count : %d\n",
		     value16);

	for (i = 0; i < value16; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid IE!  The length claimed by the "
				     "IE isn't long enough to cover the number of "
				     "Authenticated Key Management suites it claims!\n");
			return -1;
		}

		debug_printf(DEBUG_KEY, "Authentication Suite : ");
		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		if (memcmp(suite_id, wpa2oui, 3) != 0) {
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
 * \brief Parse an RSN IE and determine the authentication methods that we should use.
 *
 * @param[in] iedata   The 
 **/
uint8_t wpa2_parse_auth_type(char *iedata)
{
	struct wpa2_ie_struct *ie_struct = NULL;
	char suite_id[4];
	int i, ieptr;
	uint16_t value16 = 0;
	uint8_t retval = 0;

	if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
		return XEMALLOC;

	ie_struct = (struct wpa2_ie_struct *)iedata;

	if (ie_struct->wpaid != WPA2_EID) {
		debug_printf(DEBUG_NORMAL,
			     "IE is not a valid WPA2/802.11i IE! (Invalid vendor value!)\n");
		return -1;
	}

	byte_swap(&ie_struct->rsn_ver);

	if (ie_struct->rsn_ver > MAX_WPA2_VER) {
		debug_printf(DEBUG_NORMAL,
			     "The IEEE 802.11i/WPA2 version requested is "
			     "%d.  But we only support versions up to %d.\n",
			     ie_struct->rsn_ver, MAX_WPA2_VER);
		return -1;
	}

	if (ie_struct->wpalen <= 2) {
		debug_printf(DEBUG_NORMAL,
			     "Short IE.  Should assume TKIP/TKIP for "
			     "ciphers!\n");
		return -1;
	}

	if (ie_struct->wpalen <= 6) {
		debug_printf(DEBUG_NORMAL, "Short IE.  Should assume TKIP for "
			     "pairwise cipher.\n");
		return -1;
	}

	byte_swap(&ie_struct->pk_suite_cnt);

	ieptr = sizeof(struct wpa2_ie_struct);

	for (i = 0; i < ie_struct->pk_suite_cnt; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid IE!  The length specified by the"
				     " IE isn't long enough to cover the number of "
				     "pairwise ciphers the IE claims it lists!\n");
			return -1;
		}

		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		ieptr += 4;
	}

	if (ie_struct->wpalen < (ieptr - 2) + 2) {
		debug_printf(DEBUG_NORMAL,
			     "Short IE.  Should assume an AKM of EAP!\n");
		return RSN_DOT1X;
	}

	memcpy((char *)&value16, (char *)&iedata[ieptr], 2);
	ieptr += 2;

	for (i = 0; i < value16; i++) {
		if (ie_struct->wpalen < (ieptr - 2) + 4) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid IE!  The length claimed by the "
				     "IE isn't long enough to cover the number of "
				     "Authenticated Key Management suites it claims!\n");
			return -1;
		}

		debug_printf(DEBUG_KEY, "Authentication Suite : ");
		memcpy((char *)&suite_id, (char *)&iedata[ieptr], 4);

		if (memcmp(suite_id, wpa2oui, 3) != 0) {
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
				retval |= RSN_DOT1X;
				break;

			case AUTH_SUITE_PSK:
				debug_printf_nl(DEBUG_KEY, "None/WPA-PSK\n");
				retval |= RSN_PSK;
				break;
			}
		}
		ieptr += 4;
	}

	return retval;
}
