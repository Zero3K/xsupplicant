/*******************************************************************
 * EAPTTLS Function header
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapttls.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _EAPTTLS_H_
#define _EAPTTLS_H_

#include <openssl/ssl.h>

#ifndef WINDOWS
#include <netinet/in.h>
#endif

#include "../../context.h"

#define TTLS_SESSION_KEY_CONST   "ttls keying material"
#define TTLS_SESSION_KEY_CONST_SIZE    20


void eapttls_check(eap_type_data *);
void eapttls_process(eap_type_data *);
uint8_t *eapttls_buildResp(eap_type_data *);
uint8_t eapttls_isKeyAvailable(eap_type_data *);
uint8_t *eapttls_getKey(eap_type_data *);
void eapttls_deinit(eap_type_data *);

#endif
