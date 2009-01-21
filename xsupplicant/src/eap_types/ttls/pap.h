/**
 * EAPTTLS Phase 2 PAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file pap.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __TTLS_PHASE2_PAP_H__
#define __TTLS_PHASE2_PAP_H__

void pap_check(eap_type_data *);
void pap_process(eap_type_data *, uint8_t *, uint16_t);
void pap_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void pap_deinit(eap_type_data *eapdata);

#endif

