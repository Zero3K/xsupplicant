/*******************************************************************
 * EAP PEAP Function header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file eappeap.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _EAPPEAP_H_
#define _EAPPEAP_H_

#ifndef WINDOWS
#include <netinet/in.h>
#endif

#define PEAP_VERSION0    0
#define PEAP_VERSION1    1
#define HIGHEST_PEAP_SUPPORTED   PEAP_VERSION1


#define PEAP_SESSION_KEY_CONST         "client EAP encryption"
#define PEAP_SESSION_KEY_CONST_SIZE    21

#define PEAPv1_SESSION_KEY_CONST       "client PEAP encryption"
#define PEAPv1_SESSION_KEY_CONST_SIZE  22

#define PEAP_VERSION_MASK              0x03
#define PEAP_MASK_OUT_VERSION          0xfc

void eappeap_check(eap_type_data *);
void eappeap_process(eap_type_data *);
uint8_t *eappeap_buildResp(eap_type_data *);
uint8_t eappeap_isKeyAvailable(eap_type_data *);
uint8_t *eappeap_getKey(eap_type_data *);
void eappeap_deinit(eap_type_data *);

#endif
