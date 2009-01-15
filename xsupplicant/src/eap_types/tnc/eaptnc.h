/**
 *
 * License under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eaptnc.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EAPTNC_H_
#define _EAPTNC_H_

#ifdef HAVE_TNC

#include "liblist/queue.h"

/***************************************************************
 *
 *  The TNC Flags/Version byte looks similar to the Flags/Version byte in
 *  PEAP.  It's format is :
 *
 *  L M S R R V V V   --  (Each character is one bit.)
 *
 ***************************************************************/

#define TNC_VERSION_MASK     0x07
#define TNC_LENGTH_FLAG      0x80
#define TNC_MORE_FLAG        0x40
#define TNC_START_FLAG       0x20
#define TNC_RESERVED_FLAGS   0x18
#define TNC_MASK_OUT_VER     0xf8

#define TNC_RESULT_SUCCESS 0

#define TNC_MAX_VERSION_SUPPORTED     1

struct tnc_data {
	queue_data *tncinqueue;
	uint32_t expected_in;
	queue_data *tncoutqueue;
};

void eaptnc_check(eap_type_data *);
void eaptnc_process(eap_type_data *);
uint8_t *eaptnc_buildResp(eap_type_data *);
uint8_t eaptnc_isKeyAvailable(eap_type_data *);
uint8_t *eaptnc_getKey(eap_type_data *);
void eaptnc_deinit(eap_type_data *);

#endif // HAVE_TNC

#endif
