/**
 * EAPPSK Header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eappsk.h
 *
 * \author chris@open1x.org
 *
 **/

#ifdef EXPERIMENTAL

#ifndef _EAPPSK_H_

#define EAP_PSK_FLAGS_CONT    0x40
#define EAP_PSK_FLAGS_SUCCESS 0x80
#define EAP_PSK_FLAGS_FAILURE 0xc0

typedef struct {
	uint8_t rand_s[16];
	uint8_t rand_p[16];
	uint8_t ak[16];
	uint8_t kdk[16];
	uint8_t mac_s[16];
	uint8_t nonce[4];
	uint8_t *id_s;
	uint8_t *keydata;
	uint8_t packetnum;
} eappsk_data;

// Frame data templates
#ifdef WINDOWS
#pragma pack(1)

typedef struct {
	uint8_t rand_s[16];
	uint8_t nai_id[0];
} eappsk_packet0;

typedef struct {
	uint8_t flags;
	uint8_t rand_s[16];
	uint8_t rand_p[16];
	uint8_t mac_p[16];
	uint8_t nai_p[0];
} eappsk_packet1;

typedef struct {
	uint8_t flags;
	uint8_t rand_s[16];
	uint8_t mac_s[16];
	uint8_t pchn_nonce[4];
	uint8_t pchn_tag[16];
	uint8_t pchn_flags;
} eappsk_packet2;

typedef struct {
	uint8_t flags;
	uint8_t rand_s[16];
	uint8_t pchn_nonce[4];
	uint8_t pchn_tag[16];
	uint8_t pchn_flags;
} eappsk_packet3;

typedef struct {
	uint8_t nonce[4];
	uint8_t tag[16];
	uint8_t flags;       // Contains R, E, and Reserved.
} pchannel_default;

#pragma pack()
#else

typedef struct {
	uint8_t rand_s[16];
	uint8_t nai_id[0];
} eappsk_packet0 __attribute__((__packed__));

typedef struct {
	uint8_t flags;
	uint8_t rand_s[16];
	uint8_t rand_p[16];
	uint8_t mac_p[16];
	uint8_t nai_p[0];
} eappsk_packet1 __attribute__((__packed__));

typedef struct {
	uint8_t flags;
	uint8_t rand_s[16];
	uint8_t mac_s[16];
	uint8_t pchn_nonce[4];
	uint8_t pchn_tag[16];
	uint8_t pchn_flags;
} eappsk_packet2 __attribute__((__packed__));

typedef struct {
	uint8_t flags;
	uint8_t rand_s[16];
	uint8_t pchannel[0];
} eappsk_packet3 __attribute__((__packed__));

typedef struct {
	uint8_t nonce[4];
	uint8_t tag[16];
	uint8_t flags;       // Contains R, E, and Reserved.
} pchannel_default __attribute__((__packed__));

#endif

void eappsk_check(eap_type_data *);
void eappsk_process(eap_type_data *);
uint8_t *eappsk_buildResp(eap_type_data *);
uint8_t eappsk_isKeyAvailable(eap_type_data *);
uint8_t *eappsk_getKey(eap_type_data *);
void eappsk_deinit(eap_type_data *);

#endif

#endif     // EXPERIMENTAL
