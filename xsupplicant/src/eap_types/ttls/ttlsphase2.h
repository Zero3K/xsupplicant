/**
 * EAPTTLS Phase 2 Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ttlsphase2.c
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _TTLS_PHASE2_H
#define _TTLS_PHASE2_H

// Mirror the function that are called from the eap state machine, just to
// keep things clear.  Note that the keying function calls are missing 
// because we shouldn't need keying material out of these calls.
void ttls_phase2_check(eap_type_data *);
void ttls_phase2_process(eap_type_data *, uint8_t *, uint16_t);
void ttls_phase2_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void ttls_phase2_deinit(eap_type_data *);

#endif
