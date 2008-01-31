/**
 * Handle keying for type 254 (WPA) EAPOL Keys
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol_key_type254.h
 *
 * \author chris@open1x.org
 *
 */

#ifndef _EAPOL_KEY_TYPE254_H_
#define _EAPOL_KEY_TYPE254_H_

#ifndef WINDOWS
#include <stdint.h>
#endif

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
struct wpa_key_packet {
  uint8_t key_descriptor;
  uint8_t key_information[2];
  uint16_t key_length;
  uint8_t key_replay_counter[8];
  uint8_t key_nonce[32];
  uint8_t key_iv[16];
  uint8_t key_rsc[8];
  uint8_t key_id[8];
  uint8_t key_mic[16];
  uint16_t key_material_len;
  uint8_t keydata[0];
  
  // The n octets that follow is the keying material.
};
#else
struct wpa_key_packet {
  uint8_t key_descriptor;
  uint8_t key_information[2];
  uint16_t key_length;
  uint8_t key_replay_counter[8];
  uint8_t key_nonce[32];
  uint8_t key_iv[16];
  uint8_t key_rsc[8];
  uint8_t key_id[8];
  uint8_t key_mic[16];
  uint16_t key_material_len;
  uint8_t keydata[0];

  // The n octets that follow is the keying material.
} __attribute__((__packed__));
#endif

#ifdef WINDOWS
#pragma pack()
#endif

#define WPA_KEYTYPE_MASK 0x0007
#define WPA_PAIRWISE_KEY 0x0008
#define WPA_KEY_INDEX    0x0030
#define WPA_INSTALL_FLAG 0x0040
#define WPA_KEY_ACK_FLAG 0x0080
#define WPA_KEY_MIC_FLAG 0x0100
#define WPA_SECURE_FLAG  0x0200
#define WPA_ERROR_FLAG   0x0400
#define WPA_REQUEST_FLAG 0x0800

void eapol_key_type254_process(context *);
void eapol_key_type254_request_new_key(context *, char);

#endif
