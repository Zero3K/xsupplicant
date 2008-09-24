/**
 * PEAP Extensions Handler
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * NOTE : This code was developed using documentation from Microsoft.  Please
 *		  see Microsofts Open Specification Promise (available here: http://www.microsoft.com/interop/osp),
 *		  for information on any licenseing restrictions your usage may
 *		  have.
 *
 * \file peap_extensions.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _PEAP_EXTENSIONS_H_
#define _PEAP_EXTENSIONS_H_

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
typedef struct {
	uint16_t tlv_type;
	uint16_t tlv_length;
} peap_tlv_header;
#else
typedef struct {
	uint16_t tlv_type;
	uint16_t tlv_length;
} peap_tlv_header __attribute__((__packed__));
#endif

#ifdef WINDOWS
typedef struct {
	uint8_t reserved;
	uint8_t version;
	uint8_t recvVersion;
	uint8_t subType;
	uint8_t nonce[32];
	uint8_t compoundMac[20];
} peap_tlv_cryptobinding_data;
#else
typedef struct {
	uint8_t reserved;
	uint8_t version;
	uint8_t recvVersion;
	uint8_t subType;
	uint8_t nonce[32];
	uint8_t compoundMac[20];
} peap_tlv_cryptobinding_data __attribute__((__packed__));
#endif

#ifdef WINDOWS
#pragma pack()
#endif

#define PEAP_TLV_TYPE_FLAGS  0xc000

#define PEAP_TLV_MANDATORY_FLAG 0x8000
#define PEAP_TLV_RESERVED_FLAG  0x4000

#define PEAP_TLV_CRYPTOBINDING  0x0c
#define PEAP_TLV_RESULT			0x03
#define PEAP_TLV_SOH_RESPONSE	0x03

#define PEAP_TLV_RESULT_RESERVED	0x00
#define PEAP_TLV_RESULT_SUCCESS		0x01
#define PEAP_TLV_RESULT_FAILURE		0x02

#define PEAP_CRYPTOBINDING_IPMK_SEED_STR      "Inner Methods Compound Keys"
#define PEAP_CRYPTOBINDING_IPMK_SEED_STR_LEN  27
#define PEAP_CRYPTOBINDING_IPMK_SEED_LEN      59
int peap_extensions_process(eap_type_data *eapdata, struct phase2_data *p2d, uint8_t *in, uint16_t in_size, 
		      uint8_t *out, uint16_t *out_size);

#endif  // _PEAP_EXTENSIONS_H_
