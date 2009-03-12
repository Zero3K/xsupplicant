/**
 * EAPTTLS phase 2 common Function header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file phase2_common.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __TTLS_PHASE2_COMMON_H__
#define __TTLS_PHASE2_COMMON_H__

// A few numbers from the radius dictionary. 8-)
#define USER_NAME_AVP        1
#define USER_PASSWORD_AVP    2
#define CHAP_PASSWORD_AVP    3
#define CHAP_CHALLENGE_AVP   60
#define EAP_MESSAGE          79

// Defines for MS-CHAP values also from the dictionary.
#define MS_VENDOR_ATTR       311
#define MS_CHAP_RESPONSE     1
#define MS_CHAP_CHALLENGE    11
#define MS_CHAP2_RESPONSE    25

// Defines for TNC Integrity Checking
// Integrity Messages are passed between IMC modules in the client and IMV modules
// in the server through OSC-Integrity-Message AVPs, which are tunnelled
// through the TTLS tunnel.
#define OSC_VENDOR_ATTR       9048
#define OSC_INTEGRITY_MESSAGE 5

#define MANDITORY_FLAG       0x40
#define VENDOR_FLAG          0x80
#define TTLS_CHALLENGE       (uint8_t *)"ttls challenge"	// Need to generate implied challenge.
#define TTLS_CHALLENGE_SIZE  14

#define TTLS_PHASE2_DEBUG    1

void build_avp(uint32_t, uint32_t, uint64_t, uint8_t *, uint64_t, uint8_t *,
	       uint16_t *);
uint8_t *implicit_challenge(eap_type_data *);
struct config_ttls_phase2 *get_phase2_conf(struct config_ttls_phase2 *,
					   uint8_t);
uint8_t *build_request_id(uint8_t);
#endif
