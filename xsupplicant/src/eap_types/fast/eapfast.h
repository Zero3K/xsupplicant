/**************************************************************************
 * EAP-FAST function headers
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapfast.h
 *
 * \author  chris@open1x.org
 *
 **************************************************************************/

#ifdef EAP_FAST

#ifndef _EAPFAST_H_
#define _EAPFAST_H_

#define FAST_VERSION1  1
#define FAST_MAX_VER   FAST_VERSION1

#define FAST_VERSION_MASK 0x07      // Three bits for version.
#define FAST_VERSION_MASK_OUT 0xf8 

#define FAST_PAC_KEY        1
#define FAST_PAC_OPAQUE     2
#define FAST_CRED_LIFETIME  3
#define FAST_AUTHORITY_ID   4
#define FAST_INFO_ID        5
#define FAST_AUTH_ID_INFO   7
#define FAST_PAC_ACK        8
#define FAST_PAC_INFO       9
#define FAST_PAC_TYPE      10

#define FAST_RESULT_TLV              3
#define FAST_NAK_TLV                 4
#define FAST_ERROR_TLV               5
#define FAST_VENDOR_SPECIFIC_TLV     7
#define FAST_EAP_PAYLOAD_TLV         9
#define FAST_INTERMEDIATE_RESULT_TLV 10
#define FAST_PAC_TLV                 11
#define FAST_CRYPTO_BINDING_TLV      12
#define FAST_SERVER_TRUSTED_ROOT_TLV 18
#define FAST_REQUEST_ACTION_TLV      19
#define FAST_PKCS7_TLV               20

// RESULT_TLV values
#define FAST_RESULT_SUCCESS          1
#define FAST_RESULT_FAILURE          2

// ERROR TLV values
#define FAST_TUNNEL_COMPROMISE_ERROR   2001
#define FAST_UNEXPECTED_TLVS_EXCHANGED 2002

// REQUEST ACTION TLV values
#define FAST_REQUEST_PROCESS_TLV     1
#define FAST_REQUEST_NEGOTIATE_EAP   2

// Session Ticket TLS Extension
#define FAST_SESSION_TICKET          35

struct eapfast_tlv {
  uint16_t type;
  uint16_t length;
  uint8_t data[0];
} __attribute__((__packed__));

struct eapfast_tlv_error {
  uint16_t type;
  uint16_t length;
  uint32_t error_code;
};

struct eapfast_tlv_request_action {
  uint16_t type;
  uint16_t length;
  uint16_t action;
} __attribute__((__packed__));

struct eapfast_tlv_result {
  uint16_t type;
  uint16_t length;
  uint16_t status;
} __attribute__((__packed__));

struct provisioning_keys {
  uint8_t session_key_seed[40];
  uint8_t MSCHAPv2_ServerChallenge[16];
  uint8_t MSCHAPv2_ClientChallenge[16];
};

struct tls_server_hello {
  uint8_t content_type;
  uint16_t rec_version;
  uint16_t rec_length;
  uint8_t handshake_type;

  // The handshake length value is three bytes.  We don't do anything with it,
  // so we just need padding to make sure we parse the right bytes that follow.
  uint8_t shake_length_pre;
  uint16_t shake_length;

  uint16_t shake_version;
  uint8_t server_random[32];
  // We are looking for the random, so we don't care about the rest.
} __attribute__((__packed__));

#define TLS_HANDSHAKE_TYPE                 22
#define TLS_SERVER_HELLO                   2 
 

#define FAST_PROVISIONING_SESSION_KEY      "key expansion"
#define FAST_PROVISIONING_SESSION_KEY_LEN   13

#define FAST_IMCK_LABEL                    "Inner Methods Compound Keys"
#define FAST_PAC_TO_MSLH                   "PAC to master secret label hash"

#define FAST_SESSION_KEY                   "Session Key Generating Function"
#define FAST_EXTENDED_SESSION_KEY          "Extended Session Key Generating Function"

struct eapfast_phase2 {
  uint8_t version;
  eap_sm *sm;
  uint8_t *result_data;
  uint16_t result_size;
  uint8_t provisioning;        // Do we want to provision a PAC?
  struct provisioning_keys *pkeys;
  struct pac_values *pacs;
  uint8_t need_ms;
  uint8_t *simckj;            // The current S-IMCK[j].
};

void eapfast_check(eap_type_data *);
void eapfast_process(eap_type_data *);
uint8_t *eapfast_buildResp(eap_type_data *);
uint8_t eapfast_isKeyAvailable(eap_type_data *);
uint8_t *eapfast_getKey(eap_type_data *);
void eapfast_deinit(eap_type_data *);

uint8_t eapfast_get_ver(eap_type_data *);

#endif

#endif // EAP_FAST
