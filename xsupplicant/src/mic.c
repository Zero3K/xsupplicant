/**
 * Handle MIC routines.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE for more info.)
 *
 * \file mic.c
 *
 * \author chris@open1x.org
 *
 **/

#include <openssl/hmac.h>
#include <string.h>

#ifdef WINDOWS
#include <Winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "eapol_key_type254.h"
#include "frame_structs.h"
#include "timer.h"
#include "platform/cardif.h"
#include "mic.h"
#include "frame_structs.h"
#include "ipc_events.h"
#include "ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
struct eapol_minus_type {
	uint8_t eapol_version;
	uint8_t eapol_type;
	uint16_t eapol_length;
};
#else
struct eapol_minus_type {
	uint8_t eapol_version;
	uint8_t eapol_type;
	uint16_t eapol_length;
} __attribute__ ((__packed__));
#endif

#ifdef WINDOWS
#pragma pack()
#endif

/************************************************************************
 *
 * Calculate the MIC value for a key packet, and return it.
 *
 ************************************************************************/
void mic_process(char *key, int keylen, char *datain, int insize, uint16_t version,
		 char *mic)
{
	char *sha_hmac = NULL;
	struct eapol_minus_type *header = NULL;
	int i = 0;
	uint16_t rlen = 0;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return;

	if (!xsup_assert((datain != NULL), "datain != NULL", FALSE))
		return;

	if ((insize < 0) || (insize > 1522)) {
		debug_printf(DEBUG_NORMAL, "Invalid data size of %d! (%s:%d)\n",
			     insize, __FUNCTION__, __LINE__);
		return;
	}

	if (!xsup_assert((mic != NULL), "mic != NULL", FALSE))
		return;

	debug_printf(DEBUG_KEY, "Calculating MIC for Version %d!\n", version);

	// Some drivers may pass some extra stuff up that is beyond the end
	// of the data we are interested in.  So, we want to make sure we only
	// MIC the data that we should.
	header = (struct eapol_minus_type *)datain;
	rlen = ntohs(header->eapol_length);
	rlen += 4;

	switch (version) {
	case 1:
		/* Do an MD5 HMAC */
		HMAC(EVP_md5(), key, keylen, (uint8_t *) datain, rlen,
		     (uint8_t *) mic, (unsigned int *)&i);
		break;

	case 2:
		/* Do an SHA1 HMAC  
		 * Since the HMAC will be 20 bytes, and we only need 16, we must use
		 * a temporary variable. */
		sha_hmac = (char *)Malloc(20);
		if (!xsup_assert((sha_hmac != NULL), "sha_hmac != NULL", FALSE))
			return;

		HMAC(EVP_sha1(), key, keylen, (uint8_t *) datain, rlen,
		     (uint8_t *) sha_hmac, (unsigned int *)&i);
		memcpy(mic, sha_hmac, 16);
		FREE(sha_hmac);
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown MIC version!  (%d)\n",
			     version);
		ipc_events_error(NULL, IPC_EVENT_ERROR_INVALID_MIC_VERSION,
				 NULL);
		break;
	}
}

/*******************************************************************
 *
 * Given a frame, pull the MIC out, and check it.  If it matches,
 * return TRUE.  Otherwise, return FALSE.
 *
 *******************************************************************/
int mic_wpa_validate(char *inframe, int framesize, char *key, int keylen)
{
	struct wpa_key_packet *keydata;
	char *tempframe;
	char oldmic[16], newmic[16];
	uint16_t value16;
	int rc = FALSE;

	if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
		return FALSE;

	if (!xsup_assert((framesize > 0), "framesize > 0", FALSE))
		return FALSE;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return FALSE;

	if (!xsup_assert((keylen > 0), "keylen > 0", FALSE))
		return FALSE;

	tempframe = (char *)Malloc(framesize);
	if (tempframe == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory at %s line %d!\n",
			     __FUNCTION__, __LINE__);
		ipc_events_malloc_failed(NULL);
		return FALSE;
	}

	memcpy(tempframe, inframe, framesize);

	/* First, get the keydata struct pointing to the correct place. */
	keydata = (struct wpa_key_packet *)&tempframe[OFFSET_TO_EAPOL + 4];

	memcpy(oldmic, keydata->key_mic, 16);
	memset(keydata->key_mic, 0x00, 16);

	memcpy(&value16, keydata->key_information, 2);
	value16 = ntohs(value16);
	value16 &= WPA_KEYTYPE_MASK;

	mic_process(key, keylen, (char *)&tempframe[OFFSET_TO_EAPOL],
		    framesize - OFFSET_TO_EAPOL, value16, newmic);

	if (memcmp(oldmic, newmic, 16) == 0)
		rc = TRUE;

	FREE(tempframe);

	return rc;
}

/*******************************************************************
 *
 * Given a frame, calculate the MIC, and stick it in the frame.
 *
 *******************************************************************/
void mic_wpa_populate(char *inframe, int framesize, char *key, int keylen)
{
	struct wpa_key_packet *keydata;
	char newmic[16];
	uint16_t value16;

	if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
		return;

	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return;

	if ((framesize > 1522) || (framesize < 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid frame size of %d! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return;
	}

	/* First, get the keydata struct pointing to the correct place.  */
	keydata = (struct wpa_key_packet *)&inframe[OFFSET_TO_EAPOL + 4];

	memset(keydata->key_mic, 0x00, 16);

	memcpy(&value16, &keydata->key_information, 2);
	value16 = ntohs(value16);
	value16 &= WPA_KEYTYPE_MASK;

	mic_process(key, keylen, &inframe[OFFSET_TO_EAPOL],
		    framesize - OFFSET_TO_EAPOL - 4, value16, newmic);

	memcpy(keydata->key_mic, newmic, 16);
}

/*************************************
 *
 * When countermeasures have been enabled, this is the function that will
 * be called once they are ready to be disabled.
 *
 *************************************/
void mic_disable_countermeasures(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	debug_printf(DEBUG_NORMAL, "MIC countermeasures disabled.\n");

	cardif_countermeasures(ctx, FALSE);
	timer_cancel(ctx, COUNTERMEASURE_TIMER);
}
