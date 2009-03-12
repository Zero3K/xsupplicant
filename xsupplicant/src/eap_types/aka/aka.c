/**
 * EAPOL Function implementations for supplicant
 * 
 * \file aka.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error message signaling.
 *
 **/

/**
 *
 * The development of the EAP/AKA support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 **/

#ifdef EAP_SIM_ENABLE

#ifndef WINDOWS
#include <inttypes.h>
#else
#include "../../stdintwin.h"
#endif

#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "winscard.h"
#include "xsupconfig.h"
#include "../../context.h"
#include "../../xsup_common.h"
#include "../../eap_sm.h"
#include "../../frame_structs.h"
#include "../sim/eapsim.h"
#include "eapaka.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../sim/sm_handler.h"
#include "../sim/fips.h"
#include "../eap_type_common.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

char *do_sha1(char *tohash, int size);

int aka_do_at_identity(struct aka_eaptypedata *mydata, uint8_t * dataoffs,
		       uint16_t * packet_offset)
{
	struct typelength *typelen = NULL;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got an AT_IDENTITY (of some sort).\n");
	typelen = (struct typelength *)&dataoffs[*packet_offset];
	*packet_offset += 2;

	return XENONE;
}

int aka_do_at_rand(struct aka_eaptypedata *mydata, uint8_t * dataoffs,
		   uint16_t * packet_offset)
{
	struct typelengthres *typelenres = NULL;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got an AT_RAND.\n");
	typelenres = (struct typelengthres *)&dataoffs[(*packet_offset)];
	(*packet_offset) += 4;

	memcpy(&mydata->random_num[0], &dataoffs[(*packet_offset)], 16);
	debug_printf(DEBUG_AUTHTYPES, "Random = ");
	debug_hex_printf(DEBUG_AUTHTYPES, mydata->random_num, 16);
	(*packet_offset) += 16;

	return XENONE;
}

int aka_skip_not_implemented(uint8_t * dataoffs, uint16_t * packet_offset)
{
	struct typelengthres *typelenres = NULL;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	typelenres = (struct typelengthres *)&dataoffs[*packet_offset];
	debug_printf(DEBUG_NORMAL, "Skipping unknown type! (%02X)\n",
		     typelenres->type);
	(*packet_offset) += (typelenres->length * 4);

	return XENONE;
}

int aka_do_at_autn(struct aka_eaptypedata *mydata, uint8_t * dataoffs,
		   uint16_t * packet_offset)
{
	struct typelengthres *typelenres;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got AT_AUTN!\n");
	typelenres = (struct typelengthres *)&dataoffs[*packet_offset];
	*packet_offset += 4;

	memcpy(mydata->autn, &dataoffs[*packet_offset], 16);
	debug_printf(DEBUG_AUTHTYPES, "AUTN = ");
	debug_hex_printf(DEBUG_AUTHTYPES, mydata->autn, 16);
	*packet_offset += 16;

	return XENONE;
}

int aka_do_at_mac(eap_type_data * eapdata,
		  struct aka_eaptypedata *mydata, uint8_t * dataoffs,
		  int insize, uint16_t * packet_offset, char *username)
{
	int saved_offset, i, value16, x;
	unsigned char reslen = 0;
	unsigned char auts[16], sres[16], ck[16], mac_val[16];
	unsigned char mac_calc[20], ik[16], kc[16];
	unsigned char *mk = NULL, *keydata = NULL, *tohash = NULL, *framecpy =
	    NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((dataoffs != NULL), "dataoffs != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((packet_offset != NULL), "packet_offset != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((username != NULL), "username != NULL", FALSE))
		return XEMALLOC;

	debug_printf(DEBUG_AUTHTYPES, "Got an AT_MAC\n");

	saved_offset = (*packet_offset);

#ifndef RADIATOR_TEST
	//First thing we need to do, is get our ik & ck.
	if (sm_handler_do_3g_auth(&mydata->shdl, mydata->card_mode,
				  mydata->random_num, mydata->autn,
				  (unsigned char *)&auts,
				  (unsigned char *)&reslen,
				  (unsigned char *)&sres,
				  (unsigned char *)&ck, (unsigned char *)&ik,
				  (unsigned char *)&kc) == -2) {
		// We have a sync failure.  So, return it.
		memcpy((unsigned char *)&mydata->auts, (unsigned char *)&auts,
		       16);
		return XEAKASYNCFAIL;
	}
#else
	// Copy in the fake vectors that Radiator uses.
	memcpy(sres, "2222222222222222", 16);
	reslen = 16;
	memcpy(ik, "3333333333333333", 16);
	memcpy(ck, "4444444444444444", 16);
#endif

	debug_printf(DEBUG_AUTHTYPES, "SRES (%d) = ", reslen);
	debug_hex_printf(DEBUG_AUTHTYPES, sres, reslen);
	memcpy((uint8_t *) & mydata->res[0], sres, reslen);
	mydata->reslen = reslen;
	debug_printf(DEBUG_AUTHTYPES, "CK = ");
	debug_hex_printf(DEBUG_AUTHTYPES, ck, 16);
	debug_printf(DEBUG_AUTHTYPES, "IK = ");
	debug_hex_printf(DEBUG_AUTHTYPES, ik, 16);

	tohash = (char *)Malloc(strlen(username) + 33);	// IK & CK are 16 bytes.
	if (!tohash) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for hash string!\n");
		return XEMALLOC;
	}

	if (Strncpy
	    (tohash, (strlen(username) + 33), username,
	     strlen(username) + 1) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Attempt to overflow buffer in %s() at %d!\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	memcpy((char *)&tohash[strlen(username)], (char *)&ik[0], 16);
	memcpy((char *)&tohash[strlen(username) + 16], (char *)&ck[0], 16);

	mk = do_sha1((char *)&tohash[0], (strlen(username) + 32));

	if (mk == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "An MK couldn't be created!  Authentication cannot be completed! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return XESIMGENERR;
	}

	FREE(tohash);

	debug_printf(DEBUG_AUTHTYPES, "MK = ");
	debug_hex_printf(DEBUG_AUTHTYPES, mk, 20);

	keydata = (char *)Malloc(160);
	if (keydata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for keydata! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}
	// Next, put the mk in to the fips prng.
	fips186_2_prng(mk, 20, NULL, 0, keydata, 160);

	FREE(mk);

	memcpy(&mydata->K_encr[0], &keydata[0], 16);
	debug_printf(DEBUG_AUTHTYPES, "K_encr = ");
	debug_hex_printf(DEBUG_AUTHTYPES, &mydata->K_encr[0], 16);

	memcpy(&mydata->K_aut[0], (uint8_t *) & keydata[16], 16);
	debug_printf(DEBUG_AUTHTYPES, "K_aut = ");
	debug_hex_printf(DEBUG_AUTHTYPES, &mydata->K_aut[0], 16);

	memcpy(&mydata->msk[0], (uint8_t *) & keydata[32], 64);
	debug_printf(DEBUG_AUTHTYPES, "MSK = ");
	debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) & mydata->msk[0], 64);
	mydata->keyingMaterial = (uint8_t *) & mydata->msk[0];

	memcpy(&mydata->emsk[0], (uint8_t *) & keydata[96], 64);
	debug_printf(DEBUG_AUTHTYPES, "EMSK = ");
	debug_hex_printf(DEBUG_AUTHTYPES, mydata->emsk, 64);

	memcpy(&mac_val[0], &dataoffs[(*packet_offset) + 4], 16);

	debug_printf(DEBUG_AUTHTYPES, "MAC = ");
	debug_hex_printf(DEBUG_AUTHTYPES, (char *)&mac_val[0], 16);

	debug_printf(DEBUG_AUTHTYPES, "Packet : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, dataoffs, insize);

	FREE(keydata);

	// Now, we need a copy of the frame to work against.
	framecpy = (char *)Malloc(insize + 5);
	if (framecpy == NULL)
		return XEMALLOC;

	framecpy[0] = 1;	// It was a request.
	framecpy[1] = eap_type_common_get_eap_reqid(eapdata->eapReqData);
	value16 = insize + 5;
	value16 = htons(value16);

	memcpy((char *)&framecpy[2], &value16, 2);
	framecpy[4] = EAP_TYPE_AKA;

	memcpy((char *)&framecpy[5], dataoffs, insize);

	// Zero out the mac.
	memset((char *)&framecpy[(*packet_offset) + 4 + 5], 0x00, 16);
	debug_printf(DEBUG_AUTHTYPES, "Frame to hash : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, framecpy, insize + 5);

	HMAC(EVP_sha1(), mydata->K_aut, 16, framecpy,
	     (insize + 5), (char *)&mac_calc[0], &i);

	debug_printf(DEBUG_AUTHTYPES, "mac_calc = ");
	debug_hex_printf(DEBUG_AUTHTYPES, &mac_calc[0], 16);

	FREE(framecpy);
	framecpy = NULL;

	*packet_offset += 20;

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

uint8_t *aka_do_sync_fail(struct aka_eaptypedata * mydata, uint8_t reqId)
{
	struct typelength *typelen = NULL;
	int outptr = 0;
	uint8_t *eapres = NULL;
	uint16_t buffersize = 0;
	struct eap_header *eaphdr = NULL;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return NULL;

	debug_printf(DEBUG_AUTHTYPES, "Building AKA Sync Failure!\n");

	buffersize = sizeof(struct eap_header) + sizeof(struct typelength) + 1 +
	    sizeof(struct typelength) + 14;

	eapres = Malloc(buffersize + 1);
	if (eapres == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for AKA sync "
			     "failure result!\n");
		return NULL;
	}

	eaphdr = (struct eap_header *)eapres;

	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = reqId;
	eaphdr->eap_type = EAP_TYPE_AKA;
	eaphdr->eap_length = htons(buffersize);

	outptr = sizeof(struct eap_header);
	typelen = (struct typelength *)&eapres[outptr];

	typelen->type = AKA_SYNC_FAILURE;
	typelen->length = 0;
	outptr += sizeof(struct typelength) + 1;

	typelen = (struct typelength *)&eapres[outptr];
	outptr += sizeof(struct typelength);

	typelen->type = AT_AUTS;
	typelen->length = 4;

	memcpy(&eapres[outptr], mydata->auts, 14);
	outptr += 14;

	return eapres;
}

/**
 * \brief Build an AKA response Identity message.
 **/
uint8_t *aka_resp_identity(struct aka_eaptypedata * mydata, uint8_t reqId,
			   char *imsi)
{
	struct typelength *typelen = NULL;
	struct typelengthres *typelenres = NULL;
	int outptr = 0;
	uint8_t *eapres = NULL;
	uint16_t buffersize = 0;
	struct eap_header *eaphdr = NULL;

	if (!xsup_assert((mydata != NULL), "mydata != NULL", FALSE))
		return NULL;

	debug_printf(DEBUG_AUTHTYPES, "Building AKA Identity!\n");

	buffersize =
	    sizeof(struct eap_header) + sizeof(struct typelength) +
	    sizeof(struct typelengthres) + strlen(imsi) - 1;

	buffersize += (buffersize % 4);

	eapres = Malloc(buffersize + 5);
	if (eapres == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for AKA sync "
			     "failure result!\n");
		return NULL;
	}

	eaphdr = (struct eap_header *)eapres;

	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = reqId;
	eaphdr->eap_type = EAP_TYPE_AKA;
	eaphdr->eap_length = htons(buffersize);

	outptr = sizeof(struct eap_header);
	typelen = (struct typelength *)&eapres[outptr];

	typelen->type = AKA_IDENTITY;
	typelen->length = 0;
	outptr += 3;

	typelenres = (struct typelengthres *)&eapres[outptr];
	outptr += 4;

	typelenres->type = AT_IDENTITY;
	typelenres->length =
	    ((strlen(imsi) + sizeof(struct typelengthres)) / 4);
	typelenres->reserved =
	    htons(strlen(imsi) + sizeof(struct typelengthres));

	strcpy(&eapres[outptr], imsi);

	outptr += strlen(imsi) - 1;

	return eapres;
}

#endif
