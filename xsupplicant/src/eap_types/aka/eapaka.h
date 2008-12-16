/**
 * EAPAKA Header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapaka.h
 *
 * \author chris@open1x.org
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/AKA support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/

#ifndef _EAP_AKA_H_
#define _EAP_AKA_H_

#ifdef EAP_SIM_ENABLE

// These are defined in section 8 of Arkko-12
// EAP-AKA Subtype values.
#define AKA_CHALLENGE             1
#define AKA_AUTHENTICATION_REJECT 2
#define AKA_SYNC_FAILURE          4
#define AKA_IDENTITY              5
#define AKA_NOTIFICATION         12
#define AKA_REAUTHENTICATION     13
#define AKA_CLIENT_ERROR         14

// EAP-AKA Subtype Attribute values
#define AT_RAND               1
#define AT_AUTN               2
#define AT_RES                3
#define AT_AUTS               4
#define AT_PADDING            6
#define AT_PERMANENT_ID_REQ  10
#define AT_MAC               11
#define AT_NOTIFICATION      12
#define AT_ANY_ID_REQ        13
#define AT_IDENTITY          14
#define AT_FULLAUTH_ID_REQ   17
#define AT_COUNTER           19
#define AT_COUNTER_TOO_SMALL 20
#define AT_NONCE_S           21
#define AT_CLIENT_ERROR_CODE 22

#define AT_IV               129
#define AT_ENCR_DATA        130
#define AT_NEXT_PSEUDONYM   132
#define AT_NEXT_REAUTH_ID   133
#define AT_CHECKCODE        134
#define AT_RESULT_IND       135

// These are values that can be returned by AT_NOTIFICATION
// These are defined in 7.19.
#define GENERAL_FAILURE_POST_AUTH       0
#define GENERAL_FAILURE_PRE_AUTH    16384
#define USER_AUTHENTICATED          32768
#define USER_DENIED                  1026
#define USER_NO_SUBSCRIPTION         1031

struct aka_eaptypedata {
  uint8_t numrands;
  uint8_t *nonce_mt;
  uint8_t random_num[16];
  uint8_t autn[16];
  uint8_t auts[16];
  uint8_t res[16];
  uint16_t reslen;
  uint8_t K_encr[16], K_aut[16], msk[64], emsk[64];
  uint8_t *keyingMaterial;
  SCARDCONTEXT scntx;
  SCARDHANDLE shdl;
  uint8_t card_mode;
  uint8_t *readers;
  uint8_t chal_type;
  uint8_t sync_fail;
};  

// Get the IMSI as the username.
int eapaka_get_username(context *);
int eapaka_is_pin_needed(context *ctx, struct config_eap_aka *userdata);

void eapaka_check(eap_type_data *);
void eapaka_process(eap_type_data *);
uint8_t *eapaka_buildResp(eap_type_data *);
uint8_t eapaka_isKeyAvailable(eap_type_data *);
uint8_t *eapaka_getKey(eap_type_data *);
void eapaka_deinit(eap_type_data *);

#endif
#endif
