/**
 * \file wpa_common.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * The rc4_skip() and aes_unwrap() functions are taken from wpa_supplicant,
 * and are licensed under the terms below :
 *
 * --- Begin wpa_supplicant license ---
 *
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / RC4
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * --- End wpa_supplicant license ---
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
#include "wpa_common.h"
#include "xsup_err.h"
#include "platform/cardif.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

//Taken from wpa_supplicant.  (And modified)
int aes_unwrap(uint8_t * kek, int n, uint8_t * cipher, uint8_t * plain)
{
	uint8_t a[8], *r, b[16];
	int i, j;
	AES_KEY key;

	if (!xsup_assert((kek != NULL), "kek != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((cipher != NULL), "cipher != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((plain != NULL), "plain != NULL", FALSE))
		return XEMALLOC;

	/* 1) Initialize variables. */
	memcpy(a, cipher, 8);
	r = plain;
	memcpy(r, cipher + 8, 8 * n);

	AES_set_decrypt_key(kek, 128, &key);

	/* 2) Compute intermediate values.
	 * For j = 5 to 0
	 *     For i = n to 1
	 *         B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
	 *         A = MSB(64, B)
	 *         R[i] = LSB(64, B)
	 */
	for (j = 5; j >= 0; j--) {
		r = plain + (n - 1) * 8;
		for (i = n; i >= 1; i--) {
			memcpy(b, a, 8);
			b[7] ^= n * j + i;

			memcpy(b + 8, r, 8);
			AES_decrypt(b, b, &key);
			memcpy(a, b, 8);
			memcpy(r, b + 8, 8);
			r -= 8;
		}
	}

	/* 3) Output results.
	 *
	 * These are already in @plain due to the location of temporary
	 * variables. Just verify that the IV matches with the expected value.
	 */
	for (i = 0; i < 8; i++) {
		if (a[i] != 0xa6) {
			return -1;
		}
	}

	return 0;
}

#define S_SWAP(a,b) do { uint8_t t = S[a]; S[a] = S[b]; S[b] = t; } while(0)

// Taken from WPA_supplicant.
void rc4_skip(uint8_t * key, int keylen, int skip, uint8_t * data, int data_len)
{
	uint32_t i, j, k;
	uint8_t S[256], *pos;
	int kpos;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return;

	if (!xsup_assert((data != NULL), "data != NULL", FALSE))
		return;

	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= keylen)
			kpos = 0;
		S_SWAP(i, j);
	}

	/* Skip the start of the stream */
	i = j = 0;
	for (k = 0; k < skip; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data */
	pos = data;
	for (k = 0; k < data_len; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}
}

void wpa_print_auth_suite(unsigned char debuglevel, unsigned char asuite)
{
	switch (asuite) {
	case AUTH_SUITE_RESERVED:
		debug_printf_nl(debuglevel, "Reserved\n");
		break;

	case AUTH_SUITE_DOT1X:
		debug_printf_nl(debuglevel,
				"Unspecified authentication over 802.1X\n");
		break;

	case AUTH_SUITE_PSK:
		debug_printf_nl(debuglevel, "None/WPA-PSK\n");
	}
}

void wpa_print_cipher_suite(unsigned char debuglevel, unsigned char csuite)
{
	switch (csuite) {
	case CIPHER_NONE:
		debug_printf_nl(debuglevel, "None or same as Group\n");
		break;

	case CIPHER_WEP40:
		debug_printf_nl(debuglevel, "WEP-40\n");
		break;

	case CIPHER_TKIP:
		debug_printf_nl(debuglevel, "TKIP\n");
		break;

	case CIPHER_WRAP:
		debug_printf_nl(debuglevel, "WRAP\n");
		break;

	case CIPHER_CCMP:
		debug_printf_nl(debuglevel, "CCMP\n");
		break;

	case CIPHER_WEP104:
		debug_printf_nl(debuglevel, "WEP-104\n");
		break;

	}
}

/* Code taken from the PRF reference code in 802.11i-D3.0 */
void wpa_PRF(unsigned char *key, int key_len, unsigned char *prefix,
	     int prefix_len, unsigned char *data, int data_len,
	     unsigned char *output, int len)
{
	int i;
	unsigned char input[1024];
	int currentindex = 0, k;
	int total_len;

	if (key == NULL)
		return;

	if (!xsup_assert((prefix != NULL), "prefix != NULL", FALSE))
		return;

	if (!xsup_assert((data != NULL), "data != NULL", FALSE))
		return;

	if (!xsup_assert((output != NULL), "output != NULL", FALSE))
		return;

	memcpy(input, prefix, prefix_len);
	input[prefix_len] = 0;
	memcpy(&input[prefix_len + 1], data, data_len);
	total_len = prefix_len + 1 + data_len;
	input[total_len] = 0;
	total_len++;
	for (i = 0; i < (len + 19) / 20; i++) {
		// This is a little different than the reference implementation, 
		// because OpenSSL takes parameters in a different order.
		HMAC(EVP_sha1(), key, key_len, input, total_len,
		     &output[currentindex], (unsigned int *)&k);
		currentindex += 20;
		input[total_len - 1]++;
	}
}

/***************************************************************
 *
 * Since we are the supplicant, the RX and TX MIC values will be the opposite
 * of what we expect them to be.  So, we need to swap them.
 *
 ***************************************************************/
void wpa_common_swap_rx_tx_mic(uint8_t * key)
{
	char tmpswap[8];

	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return;

	memcpy(&tmpswap, &key[16], 8);
	memcpy(&key[16], &key[24], 8);
	memcpy(&key[24], &tmpswap, 8);
}

/*********************************************************************
 *
 * Based on the key length, set the correct type of key.
 *
 *********************************************************************/
void wpa_common_set_key(context * intdata, char *dest,
			int keyindex, int txkey, char *key, int keylen)
{
	wireless_ctx *wctx;

	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
		return;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return;

	wctx = (wireless_ctx *) intdata->intTypeData;
	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
		return;

	switch (keylen) {
	case 5:
		// WEP-40 keys.
		if (txkey == 1) {
			wctx->pairwiseKeyType = CIPHER_WEP40;
		} else {
			wctx->groupKeyType = CIPHER_WEP40;
		}
		cardif_set_wep_key(intdata, (uint8_t *) key, keylen, keyindex);
		break;

	case 13:
		// These are WEP-104 keys.
		if (txkey == 1) {
			wctx->pairwiseKeyType = CIPHER_WEP104;
		} else {
			wctx->groupKeyType = CIPHER_WEP104;
		}
		cardif_set_wep_key(intdata, (uint8_t *) key, keylen, keyindex);
		break;

	case 16:
		// It's a CCMP key.
		if (txkey == 1) {
			wctx->pairwiseKeyType = CIPHER_CCMP;
		} else {
			wctx->groupKeyType = CIPHER_CCMP;
		}
		cardif_set_ccmp_key(intdata, dest, keyindex, txkey, (char *)key,
				    keylen);
		break;

	case 32:
		// It's a TKIP key.
		if (txkey == 1) {
			wctx->pairwiseKeyType = CIPHER_TKIP;
		} else {
			wctx->groupKeyType = CIPHER_TKIP;
		}
		wpa_common_swap_rx_tx_mic((uint8_t *) key);

		cardif_set_tkip_key(intdata, dest, keyindex, txkey, (char *)key,
				    keylen);
		break;

	default:
		debug_printf(DEBUG_NORMAL,
			     "Unknown key type requested.  Key length"
			     " was %d!\n", keylen);
		break;
	}
}

#ifdef __APPLE__
#undef WORDS_BIGENDIAN
#ifdef __BIG_ENDIAN__
#define WORDS_BIGENDIAN
#endif
#ifdef __LITTLE_LENDIAN__
#undef WORDS_BIGENDIAN
#endif
#endif

#ifdef WORDS_BIGENDIAN
/**********************************************************************
 *
 * On big endian machines, we need to swap the bytes in the 16 bit numbers
 * so that they are correct.
 *
 **********************************************************************/
void byte_swap(uint16_t * toswap)
{
	uint8_t hi = 0, lo = 0;

	lo = ((*toswap) & 0x00ff);
	hi = ((*toswap) >> 8);

	*toswap = (lo << 8) + hi;
}
#else
void byte_swap(uint16_t * toswap)
{
	// Do nothing.
}
#endif
