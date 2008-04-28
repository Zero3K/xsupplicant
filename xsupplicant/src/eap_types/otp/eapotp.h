/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapotp.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _EAPOTP_H_
#define _EAPOTP_H_

#include "../../context.h"

#define RESPONSE_TEXT  "RESPONSE="
#define CHALLENGE_TEXT "CHALLENGE="

struct eap_otp_stored_frame {
	uint8_t *frame;
	uint16_t length;
	uint8_t *eappkt;
	uint16_t eaplen;
};

void eapotp_check(eap_type_data *);
void eapotp_process(eap_type_data *);
void eapotp_cleanup(void *cbdata);
uint8_t *eapotp_buildResp(eap_type_data *);
uint8_t eapotp_isKeyAvailable(eap_type_data *);
uint8_t *eapotp_getKey(eap_type_data *);
void eapotp_deinit(eap_type_data *);

#endif
