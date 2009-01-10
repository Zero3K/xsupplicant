/**
 * EAP-MSCHAPv2 Function Headers
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapmschapv2.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EAP_MSCHAPV2_H_
#define _EAP_MSCHAPV2_H_

#ifndef WINDOWS
#include <inttypes.h>
#endif

#include "../../context.h"

#define MS_CHAPV2_CHALLENGE     1
#define MS_CHAPV2_RESPONSE      2
#define MS_CHAPV2_SUCCESS       3
#define MS_CHAPV2_FAILURE       4
#define MS_CHAPV2_CHANGE_PWD    7

struct mschapv2_vars {
  uint8_t *AuthenticatorChallenge;
  uint8_t *PeerChallenge;
  uint8_t *NtResponse;
  uint8_t *keyingMaterial;
  uint8_t MS_CHAPv2_ID;
  uint8_t eap_fast_mode;
  char *password;
};

struct mschapv2_challenge {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t Value_Size;
  uint8_t Challenge[16];
  // Everything else in the packet should be the name of the RADIUS server.
};

struct mschapv2_response {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t Value_Size;
  uint8_t Peer_Challenge[16];
  uint8_t Reserved[8];
  uint8_t NT_Response[24];
  uint8_t Flags;
};

struct mschapv2_success_request {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t MsgField[42];   // S=<auth_string>
};

struct mschapv2_fail_request {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t MsgField[0];
};

struct eap_mschapv2_stored_frame {
	uint8_t *frame;
	uint16_t length;
	uint8_t *eappkt;
	uint16_t eaplen;
};

// Define the failure codes listed in the internet draft standard.
#define MSCHAPV2_RESTRICTED_LOGON_HOURS   646
#define MSCHAPV2_ACCT_DISABLED            647
#define MSCHAPV2_PASSWD_EXPIRED           648
#define MSCHAPV2_NO_DIALIN_PERMISSION     649
#define MSCHAPV2_AUTHENTICATION_FAILURE   691
#define MSCHAPV2_CHANGING_PASSWORD        709

// The password changing protocol supported by this version of EAP-MSCHAPv2.
#define MSCHAPV2_PASSWORD_CHANGE_VER        3

// A success response is a single byte 0x03, so we really don't need a 
// structure.

void eapmschapv2_check(eap_type_data *);
void eapmschapv2_process(eap_type_data *);
uint8_t *eapmschapv2_buildResp(eap_type_data *);
uint8_t eapmschapv2_isKeyAvailable(eap_type_data *);
uint8_t *eapmschapv2_getKey(eap_type_data *);
void eapmschapv2_deinit(eap_type_data *);
uint8_t eapmschapv2_set_challenges(uint8_t *, uint8_t *);
void eapmschapv2_set_eap_fast_anon_mode(eap_type_data *, uint8_t);
int eapmschapv2_creds_required(void *);
#endif
