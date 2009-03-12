/**
 * PEAP Phase 2 Function Headers
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file peap_phase2.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef PEAP_PHASE2_H
#define PEAP_PHASE2_H

#define PEAP_EAP_EXTENSION    33

#define PEAP_SESSION_KEY_CONST         "client EAP encryption"
#define PEAP_SESSION_KEY_CONST_SIZE    21

#define PEAPv1_SESSION_KEY_CONST       "client PEAP encryption"
#define PEAPv1_SESSION_KEY_CONST_SIZE  22

struct phase2_data {
	eap_sm *sm;
	uint8_t *result_data;
	uint16_t result_size;
	int peap_version;
};

uint8_t peap_phase2_init(eap_type_data *);
uint8_t set_peap_version(struct phase2_data *, uint8_t);
uint8_t get_peap_version(eap_type_data *);
void peap_phase2_check(eap_type_data *);
void peap_phase2_process(eap_type_data *, uint8_t *, uint16_t);
void peap_phase2_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void peap_phase2_deinit(eap_type_data *);

#endif
