/*******************************************************************
 * EAPTTLS Phase 2 CHAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file chap.h
 *
 * \author chris@open1x.org
 *
 ******************************************************************/

#ifndef __TTLS_PHASE2_CHAP_H__
#define __TTLS_PHASE2_CHAP_H__

void chap_check(eap_type_data *);
void chap_process(eap_type_data *, uint8_t *, uint16_t);
void chap_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void chap_deinit(eap_type_data *eapdata);

#endif

