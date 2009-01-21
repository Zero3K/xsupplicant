/**
 * EAPTTLS Phase 2 MS-CHAPv2 Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file p2mschapv2.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __TTLS_PHASE2_MSCHAPV2_H__
#define __TTLS_PHASE2_MSCHAPV2_H__

void mschapv2_check(eap_type_data *);
void mschapv2_process(eap_type_data *, uint8_t *, uint16_t);
void mschapv2_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void mschapv2_deinit(eap_type_data *eapdata);

#endif

