/*******************************************************************
 * EAPTTLS Phase 2 EAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ttls_eap.h
 *
 * \author chris@open1x.org
 *
 ******************************************************************/

#ifndef __TTLS_PHASE2_EAP_H__
#define __TTLS_PHASE2_EAP_H__

#define EAP_DIAMETER_TYPE 0x004f

void ttls_eap_check(eap_type_data *);
void ttls_eap_process(eap_type_data *, uint8_t *, uint16_t);
uint8_t *ttls_eap_get_eap(uint8_t *, uint16_t);
void ttls_eap_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void ttls_eap_deinit(eap_type_data *eapdata);

#endif

