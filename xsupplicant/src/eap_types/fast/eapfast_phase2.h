/**
 * EAP-FAST provisioning function headers
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapfast_provision.h
 *
 * \author  chris@open1x.org
 *
 **/

#include <openssl/ssl.h>

#ifdef OPENSSL_HELLO_EXTENSION_SUPPORTED

#ifndef __EAP_FAST_PHASE2__
#define __EAP_FAST_PHASE2__

#define MANDATORY_TLV          0x8000
#define MANDATORY_TLV_MASK_OUT 0x7fff

#define FAST_CRYPTO_BIND_VERSION    1

#define FAST_BINDING_REQUEST        0
#define FAST_BINDING_RESPONSE       1

#ifdef WINDOWS

#pragma pack(1)
struct eapfast_pac_request_tlv {
	uint16_t type;
	uint16_t length;
	uint16_t pac_type;
	uint16_t pac_length;
	uint16_t req_type;
};

struct eapfast_crypto_binding_tlv {
	uint16_t type;
	uint16_t length;
	uint8_t reserved;
	uint8_t version;
	uint8_t eap_version;
	uint8_t subtype;
	uint8_t nonce[32];
	uint8_t compound_mac[20];
};

struct pac_info {
	uint8_t cred_lifetime[4];
	uint8_t *aid;
	uint16_t aid_len;
	uint8_t *iid;
	uint16_t iid_len;
	uint8_t *aid_info;
	uint16_t aid_info_len;
	uint16_t pac_type;
};

struct pac_values {
	uint8_t pac_key[32];
	uint8_t *pac_opaque;
	uint16_t pac_opaque_len;
	struct pac_info pacinfo;
};

struct pac_info_pac_type {
	uint16_t type;
	uint16_t length;
	uint16_t pac_type;
};

struct nak_tlvs {
	uint32_t vendorid;
	uint16_t naktype;

	// TLVs are currently optional, and not supported.
};

struct vendor_tlv_type {
	uint16_t type;
	uint16_t length;
	uint32_t vendor_id;
	uint8_t data[0];
};

#pragma pack()

#else
struct eapfast_pac_request_tlv {
	uint16_t type;
	uint16_t length;
	uint16_t pac_type;
	uint16_t pac_length;
	uint16_t req_type;
} __attribute__ ((__packed__));

struct eapfast_crypto_binding_tlv {
	uint16_t type;
	uint16_t length;
	uint8_t reserved;
	uint8_t version;
	uint8_t eap_version;
	uint8_t subtype;
	uint8_t nonce[32];
	uint8_t compound_mac[20];
} __attribute__ ((__packed__));

struct pac_info {
	uint8_t cred_lifetime[4];
	uint8_t *aid;
	uint16_t aid_len;
	uint8_t *iid;
	uint16_t iid_len;
	uint8_t *aid_info;
	uint16_t aid_info_len;
	uint16_t pac_type;
} __attribute__ ((__packed__));

struct pac_values {
	uint8_t pac_key[32];
	uint8_t *pac_opaque;
	uint16_t pac_opaque_len;
	struct pac_info pacinfo;
} __attribute__ ((__packed__));

struct pac_info_pac_type {
	uint16_t type;
	uint16_t length;
	uint16_t pac_type;
} __attribute__ ((__packed__));

struct nak_tlvs {
	uint32_t vendorid;
	uint16_t naktype;

	// TLVs are currently optional, and not supported.
} __attribute__ ((__packed__));

struct vendor_tlv_type {
	uint16_t type;
	uint16_t length;
	uint32_t vendor_id;
	uint8_t data[0];
} __attribute__ ((__packed__));

#endif

uint8_t *eapfast_phase2_t_prf(uint8_t *, uint16_t, char *, uint8_t *,
			      uint16_t, uint16_t);
uint8_t *eapfast_phase2_get_simckj(eap_type_data * eapdata);

void eapfast_phase2_init(eap_type_data *);
void eapfast_phase2_check(eap_type_data *);
void eapfast_phase2_process(eap_type_data *, uint8_t *, uint16_t);
void eapfast_phase2_buildResp(eap_type_data *, uint8_t *, uint16_t *);
void eapfast_phase2_deinit(eap_type_data *);

#endif				// __EAP_FAST_PHASE2__
#endif				//  OPENSSL_HELLO_EXTENSION_SUPPORTED
