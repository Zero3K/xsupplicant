/**
 *
 * License under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapmd5.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EAPMD5_H_
#define _EAPMD5_H_

#include "../../context.h"

struct md5_values {
  uint8_t length;
  uint8_t randval[16];
};

void eapmd5_check(eap_type_data *);
void eapmd5_process(eap_type_data *);
uint8_t *eapmd5_buildResp(eap_type_data *);
uint8_t eapmd5_isKeyAvailable(eap_type_data *);
uint8_t *eapmd5_getKey(eap_type_data *);
void eapmd5_deinit(eap_type_data *);

#endif
