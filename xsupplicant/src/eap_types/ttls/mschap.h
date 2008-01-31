/*******************************************************************
 * EAPTTLS Phase 2 MS-CHAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file mschap.h
 *
 * \author chris@open1x.org
 *
 ******************************************************************/

#ifndef __TTLS_PHASE2_MSCHAP_H__
#define __TTLS_PHASE2_MSCHAP_H__

void mschap_check(eap_type_data *);
void mschap_process(eap_type_data *, uint8_t *, uint16_t);
void mschap_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void mschap_deinit(eap_type_data *eapdata);

#endif

