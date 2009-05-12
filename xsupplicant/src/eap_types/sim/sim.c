/**
 * EAPOL Function implementations for supplicant
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file sim.c
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error events
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/

#ifdef EAP_SIM_ENABLE

#ifndef WINDOWS
#include <strings.h>
#include <inttypes.h>
#else
#include "../../stdintwin.h"
#endif

#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "winscard.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../xsup_common.h"
#include "../../eap_sm.h"
#include "sim.h"
#include "eapsim.h"
#include "simd5.h"
#include "simd11.h"
#include "sm_handler.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "fips.h"
#include "../eap_type_common.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

int sim_build_start(struct eaptypedata *eapdata, uint8_t * out, int *outptr)
{
	struct typelength *typelen = NULL;
	struct typelengthres *typelenres = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got SIM_START!\n");
	memset(out, 0x00, 100);

	typelen = (struct typelength *)&out[0];
	typelen->type = SIM_START;
	typelen->length = 0;

	typelenres = (struct typelengthres *)&out[3];
	typelenres->type = AT_NONCE_MT;
	typelenres->length = 5;
	typelenres->reserved = 0;

	// Generate a few random bytes for our NONCE MT.
	eapdata->nonce_mt = (char *)Malloc(16);
	if (eapdata->nonce_mt == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for NONCE MT! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	RAND_bytes(eapdata->nonce_mt, 16);

	debug_printf(DEBUG_AUTHTYPES, "NONCE MT = ");
	debug_hex_printf(DEBUG_AUTHTYPES, eapdata->nonce_mt, 16);

	*outptr = 7;
	memcpy(&out[*outptr], eapdata->nonce_mt, 16);
	*outptr += 16;

	return XENONE;
}

int sim_build_fullauth(char *username, uint8_t * dataoffs,
		       uint16_t * packet_offset, uint8_t * out,
		       uint16_t * outptr)
{
	struct typelengthres *typelenres = NULL;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES,
		     "Got AT_FULLAUTH_ID_REQ or AT_PERMANENT_ID_REQ!\n");
	typelenres = (struct typelengthres *)&dataoffs[*packet_offset];
	if ((typelenres->length != 5) && (typelenres->length != 1)) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid AT_FULLAUTH_ID_REQ length!\n");
		return XESIMBADLEN;
	}

	*packet_offset += 4;	// Skip the reserved and length bytes.

	// Build an AT_IDENTITY response.
	typelenres = (struct typelengthres *)&out[*outptr];
	typelenres->type = AT_IDENTITY;
	typelenres->length = (strlen(username) / 4) + 1;
	if ((strlen(username) % 4) != 0) {
		// We have a number that isn't evenly divisible by 4.  We need to
		// add one more to the length to account for it.
		typelenres->length++;
	}
	typelenres->reserved = htons(strlen(username));
	*outptr += sizeof(struct typelengthres);

	memcpy(&out[*outptr], username, strlen(username));

//  *outptr += strlen(username) + (4-(strlen(username) % 4));
	*outptr += ((typelenres->length * 4) - sizeof(struct typelengthres));

	return XENONE;
}

int sim_at_version_list(char *username, struct eaptypedata *eapdata,
			uint8_t * dataoffs, uint16_t * packet_offset,
			uint8_t * out, uint16_t * outptr)
{
	int numVers = 0, maxver = 0, i = 0, value16 = 0;
	struct typelengthres *typelenres = NULL;

	if (!xsup_assert((username != NULL), "username != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got an AT_VERSION_LIST request!\n");
	typelenres = (struct typelengthres *)&dataoffs[*packet_offset];

	debug_printf(DEBUG_AUTHTYPES, "Version List Length (# versions) : %d\n",
		     typelenres->length);
	numVers = typelenres->length;

	eapdata->verlistlen = ntohs(typelenres->reserved);
	debug_printf(DEBUG_AUTHTYPES, "Version List Length (bytes) : %d\n",
		     eapdata->verlistlen);
	*packet_offset += sizeof(struct typelengthres);
	maxver = 0;		// Set the starting value to be 0.

	eapdata->verlist = (char *)Malloc(eapdata->verlistlen);
	if (eapdata->verlist == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for version list! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	memcpy(eapdata->verlist, &dataoffs[*packet_offset],
	       eapdata->verlistlen);

	for (i = 0; i < numVers; i++) {
		memcpy(&value16, &dataoffs[*packet_offset], 2);
		value16 = ntohs(value16);
		debug_printf(DEBUG_AUTHTYPES, "AT_VERSION_LIST Value : %d\n",
			     value16);
		if (value16 > maxver)
			maxver = value16;

		*packet_offset += 2;
	}

	if (maxver > EAPSIM_MAX_SUPPORTED_VER)
		maxver = EAPSIM_MAX_SUPPORTED_VER;

	debug_printf(DEBUG_AUTHTYPES, "Setting version to %d\n", maxver);
	typelenres = (struct typelengthres *)&out[*outptr];
	typelenres->type = AT_SELECTED_VERSION;
	typelenres->length = 1;
	typelenres->reserved = htons(maxver);
	*outptr += sizeof(struct typelengthres);

	eapdata->workingversion = maxver;

	return XENONE;
}

int sim_skip_not_implemented(uint8_t * dataoffs, uint16_t * packet_offset)
{
	struct typelengthres *typelenres = NULL;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	typelenres = (struct typelengthres *)&dataoffs[*packet_offset];
	debug_printf(DEBUG_NORMAL, "Skipping unknown type! (%02X)\n",
		     dataoffs[*packet_offset]);
	*packet_offset += (typelenres->length * 4);

	return XENONE;
}

int sim_do_at_mac(eap_type_data * eapdata, struct eaptypedata *mydata,
		  uint8_t * dataoffs, int insize, uint16_t * packet_offset,
		  uint8_t * out, uint16_t * outptr, char *K_int)
{
	int saved_offset;
	char mac_val[16], mac_calc[16];

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((K_int != NULL), "K_int != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got an AT_MAC\n");

	memset(&mac_calc[0], 0x00, 16);
	memset(&mac_val[0], 0x00, 16);

	saved_offset = (*packet_offset);

	memcpy(&mac_val[0], &dataoffs[*packet_offset + 4], 16);
	*packet_offset += 20;

	if (mydata->workingversion == 0) {
		if (do_v0_at_mac(eapdata, K_int, dataoffs, insize,
				 saved_offset, &mac_calc[0]) == -1) {
			debug_printf(DEBUG_NORMAL,
				     "Error calculating AT_MAC for Version 0!\n");
			return XESIMBADMAC;
		}
	} else {
		debug_printf(DEBUG_AUTHTYPES, "K_int = ");
		debug_hex_printf(DEBUG_AUTHTYPES, K_int, 16);
		if (do_v1_at_mac(eapdata, K_int, dataoffs, insize,
				 saved_offset, mydata->nonce_mt,
				 mydata->verlist, mydata->verlistlen,
				 mydata->workingversion, &mac_calc[0]) == -1) {
			debug_printf(DEBUG_NORMAL,
				     "Error calculating AT_MAC for Version 1!\n");
			return XESIMBADMAC;
		}
	}

	if (memcmp(&mac_calc[0], &mac_val[0], 16) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "ERROR : AT_MAC failed MAC check!\n");
		debug_printf(DEBUG_AUTHTYPES, "mac_calc = ");
		debug_hex_printf(DEBUG_AUTHTYPES, &mac_calc[0], 16);
		debug_printf(DEBUG_AUTHTYPES, "mac_val  = ");
		debug_hex_printf(DEBUG_AUTHTYPES, &mac_val[0], 16);
		return XESIMBADMAC;
	}

	return XENONE;
}

int sim_do_v1_response(eap_type_data * eapdata, char *out,
		       uint16_t * outptr, char *nsres, char *K_int)
{
	int i = 0, value16 = 0;
	char *framecpy = NULL, mac_calc[20];

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((nsres != NULL), "nsres != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((K_int != NULL), "K_int != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_NORMAL, "nsres = ");
	debug_hex_printf(DEBUG_NORMAL, nsres, 12);

	framecpy = (char *)Malloc((*outptr) + 8 + 20 + (8 * 3));
	if (framecpy == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for frame copy! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	framecpy[0] = 2;
	framecpy[1] = eap_type_common_get_eap_reqid(eapdata->eapReqData);
	value16 = htons((*outptr) + 5 + 20);
	memcpy(&framecpy[2], &value16, 2);
	framecpy[4] = EAP_TYPE_SIM;
	memcpy(&framecpy[5], &out[0], (*outptr));

	framecpy[5 + (*outptr)] = AT_MAC;
	framecpy[5 + (*outptr) + 1] = 5;
	memcpy(&framecpy[5 + (*outptr) + 20], nsres, (4 * 3));

	debug_printf(DEBUG_AUTHTYPES, "Hashing against :\n");
	debug_hex_dump(DEBUG_AUTHTYPES, &framecpy[0], (*outptr) + 25 + 12);

	HMAC(EVP_sha1(), K_int, 16, framecpy, ((*outptr) + 5 + 20 + 12),
	     &mac_calc[0], &i);
	memcpy(&out[(*outptr)], &framecpy[5 + (*outptr)], 20);
	memcpy(&out[(*outptr) + 4], &mac_calc[0], 16);
	*outptr += 20;

	FREE(framecpy);

	return XENONE;
}

int sim_v0_final_hash(struct eaptypedata *eapdata, char *sha1resp,
		      uint8_t * out, uint16_t * outptr, char *K_sres)
{
	struct typelengthres *typelenres = NULL;
	char *hash = NULL;
	int i = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((sha1resp != NULL), "sha1resp != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((K_sres != NULL), "K_sres != NULL", FALSE))
		return XEMALLOC;

	hash = (char *)Malloc((4 * 3) + 16);
	if (hash == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for hash data!"
			     " (%s:%d)\n", __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	memcpy(&hash[0], eapdata->triplet[0].response, 4);
	memcpy(&hash[4], eapdata->triplet[1].response, 4);
	memcpy(&hash[8], eapdata->triplet[2].response, 4);
	hash[12] = 11;

	HMAC(EVP_sha1(), K_sres, 16, &hash[0], 13, sha1resp, &i);
	debug_printf(DEBUG_AUTHTYPES, "Final return value : ");
	debug_hex_printf(DEBUG_AUTHTYPES, sha1resp, i);

	typelenres = (struct typelengthres *)&out[*outptr];
	typelenres->type = AT_MAC_SRES;
	typelenres->length = 5;
	typelenres->reserved = 0;

	*outptr += sizeof(struct typelengthres);
	memcpy(&out[*outptr], &sha1resp, i);
	*outptr += i;

	return XENONE;
}

int sim_do_at_rand(struct eaptypedata *eapdata, char *username,
		   char *nsres, uint8_t * dataoffs, uint16_t * packet_offset,
		   uint8_t * out, uint16_t * outptr, char *K_int)
{
	struct typelengthres *typelenres = NULL;
	int value16 = 0, tlen = 0, retval = 0;
	char *hash = NULL, sha1resp[20], *at_mac_sres =
	    NULL, K_sres[16], K_encr[16], K_recv[32];
	char K_send[32];
	char *tusername = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((username != NULL), "username != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((nsres != NULL), "nsres != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((outptr != NULL), "outptr != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((K_int != NULL), "K_int != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got an AT_RAND.\n");
	typelenres = (struct typelengthres *)&dataoffs[*packet_offset];
	*packet_offset += 4;

	memcpy(eapdata->triplet[0].random, &dataoffs[*packet_offset], 16);
	debug_printf(DEBUG_AUTHTYPES, "Random1 = ");
	debug_hex_printf(DEBUG_AUTHTYPES, eapdata->triplet[0].random, 16);
	sm_handler_do_2g_auth(&eapdata->shdl, eapdata->card_mode,
			      eapdata->triplet[0].random,
			      eapdata->triplet[0].response,
			      eapdata->triplet[0].ckey);
	debug_printf(DEBUG_AUTHTYPES, "Response = ");
	debug_hex_printf(DEBUG_AUTHTYPES, eapdata->triplet[0].response, 4);
	debug_printf(DEBUG_AUTHTYPES, "CKEY = ");
	debug_hex_printf(DEBUG_AUTHTYPES, eapdata->triplet[0].ckey, 8);
	*packet_offset += 16;

	memcpy(eapdata->triplet[1].random, &dataoffs[*packet_offset], 16);
	debug_printf(DEBUG_AUTHTYPES, "Random2 = ");
	debug_hex_printf(DEBUG_AUTHTYPES, eapdata->triplet[1].random, 16);
	sm_handler_do_2g_auth(&eapdata->shdl, eapdata->card_mode,
			      eapdata->triplet[1].random,
			      eapdata->triplet[1].response,
			      eapdata->triplet[1].ckey);
	*packet_offset += 16;

	memcpy(eapdata->triplet[2].random, &dataoffs[*packet_offset], 16);
	debug_printf(DEBUG_AUTHTYPES, "Random3 = ");
	debug_hex_printf(DEBUG_AUTHTYPES, eapdata->triplet[2].random, 16);
	sm_handler_do_2g_auth(&eapdata->shdl, eapdata->card_mode,
			      eapdata->triplet[2].random,
			      eapdata->triplet[2].response,
			      eapdata->triplet[2].ckey);
	*packet_offset += 16;

	if (eapdata->workingversion == 0) {
		hash = (char *)Malloc((8 * 3) + 16);	// 3 keys + 16 byte nonce.
		if (hash == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory to build hash!\n");
			return XEMALLOC;
		}

		memcpy(&hash[0], eapdata->triplet[0].ckey, 8);
		memcpy(&hash[8], eapdata->triplet[1].ckey, 8);
		memcpy(&hash[16], eapdata->triplet[2].ckey, 8);
		memcpy(&hash[24], eapdata->nonce_mt, 16);

		SHA1(hash, 40, &sha1resp[0]);
	} else {
		tlen =
		    strlen(username) + (8 * 3) + 16 + eapdata->verlistlen + 2;

		hash = (char *)Malloc(tlen + 10);
		if (hash == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory for hash! "
				     "(%s:%d)\n", __FUNCTION__, __LINE__);
			return XEMALLOC;
		}

		memset(nsres, 0x00, 12);
		memcpy(&nsres[0], eapdata->triplet[0].response, 4);
		memcpy(&nsres[4], eapdata->triplet[1].response, 4);
		memcpy(&nsres[8], eapdata->triplet[2].response, 4);

		if (username[0] == '1') {
			tusername = strdup(username);
		} else {
			tusername = Malloc(strlen(username) + 3);
			if (tusername == NULL) {
				debug_printf(DEBUG_NORMAL,
					     "Unable to allocate memory to create a valid IMSI!\n");
				return XEMALLOC;
			}

			tusername[0] = '1';
			strcat(tusername, username);
		}

		memset(hash, 0x00, tlen);
		memcpy(&hash[0], tusername, strlen(tusername));
		memcpy(&hash[strlen(tusername)], eapdata->triplet[0].ckey, 8);
		memcpy(&hash[strlen(tusername) + 8], eapdata->triplet[1].ckey,
		       8);
		memcpy(&hash[strlen(tusername) + 16], eapdata->triplet[2].ckey,
		       8);
		memcpy(&hash[strlen(tusername) + 24], eapdata->nonce_mt, 16);
		memcpy(&hash[strlen(tusername) + 24 + 16],
		       eapdata->verlist, eapdata->verlistlen);

		value16 = htons(eapdata->workingversion);
		memcpy(&hash[strlen(tusername) + 24 + 16 + eapdata->verlistlen],
		       &value16, 2);

		debug_printf(DEBUG_AUTHTYPES, "Building K_aut from :\n");
		debug_hex_dump(DEBUG_AUTHTYPES, hash,
			       (strlen(tusername) + 24 + 16 +
				eapdata->verlistlen + 2));

		SHA1(hash,
		     (strlen(tusername) + 24 + 16 + eapdata->verlistlen + 2),
		     sha1resp);

		FREE(tusername);
		FREE(hash);
	}

	debug_printf(DEBUG_AUTHTYPES, "MK = ");
	debug_hex_printf(DEBUG_AUTHTYPES, &sha1resp[0], 20);

	at_mac_sres = (char *)Malloc(120);
	if (at_mac_sres == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't malloc at_mac_sres!\n");
		return XEMALLOC;
	}

	fips186_2_prng(sha1resp, 20, NULL, 0, at_mac_sres, 120);

	if (eapdata->workingversion == 0) {
		memcpy(&K_sres[0], &at_mac_sres[0], 16);
		memcpy(&K_encr[0], &at_mac_sres[16], 16);
		memcpy(&K_int[0], &at_mac_sres[32], 16);

		memset(&K_recv[0], 0x00, 32);
		memset(&K_send[0], 0x00, 32);

		memcpy(&K_recv[0], &at_mac_sres[48], 20);
		memcpy(&K_send[0], &at_mac_sres[68], 20);
	} else {
		// K_int is the same as K_aut in Version 1.
		memcpy(&K_int[0], &at_mac_sres[16], 16);
		memcpy(&K_recv[0], &at_mac_sres[32], 32);
		memcpy(&K_send[0], &at_mac_sres[64], 32);
	}

	debug_printf(DEBUG_AUTHTYPES, "K_aut = ");
	debug_hex_printf(DEBUG_AUTHTYPES, K_int, 16);

	// We should be done with at_mac_sres, so free it.
	FREE(at_mac_sres);
	FREE(eapdata->keyingMaterial);

	eapdata->keyingMaterial = (char *)Malloc(64);
	if (eapdata->keyingMaterial == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for keying material"
			     "! (%s:%d)\n", __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	memcpy(eapdata->keyingMaterial, &K_recv[0], 32);
	memcpy(&eapdata->keyingMaterial[32], &K_send[0], 32);

	if (eapdata->workingversion == 0) {
		retval =
		    sim_v0_final_hash(eapdata, sha1resp, out, outptr,
				      &K_sres[0]);
		if (retval != XENONE)
			return retval;
	}

	return XENONE;
}

#endif
