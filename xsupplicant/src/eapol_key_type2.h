/**
 * Handle keying for type 2 (WPA2) EAPOL Keys
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol_key_type2.h
 *
 * \author chris@open1x.org
 *
 */

#ifndef _EAPOL_KEY_TYPE2_H_
#define _EAPOL_KEY_TYPE2_H__

#ifndef WINDOWS
#include <stdint.h>
#endif

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
struct wpa2_key_packet {
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
struct wpa2_key_packet {
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

#define WPA2_KEYTYPE_MASK 0x0007
#define WPA2_PAIRWISE_KEY 0x0008
#define WPA2_INSTALL_FLAG 0x0040
#define WPA2_KEY_ACK_FLAG 0x0080
#define WPA2_KEY_MIC_FLAG 0x0100
#define WPA2_SECURE_FLAG  0x0200
#define WPA2_ERROR_FLAG   0x0400
#define WPA2_REQUEST_FLAG 0x0800
#define WPA2_ENCRYPTED_DATA 0x1000

#define WPA2_EXTENDED_KEY_DATA  0xdd
#define WPA2_KEY_INDEX_MASK 0x03
#define WPA2_TX_KEY_MASK    0x04

// When we bump in to extended data, we need to determine what type it is.
// These values will be the return from eapol_key_type2_parse_extended()
// Which will allow us to determine how to handle the data.

#define WPA2_EMBEDDED_WPA_IE       -4
#define WPA2_EXTENDED_UNKNOWN_DATA -3
#define WPA2_EXTENDED_UNKNOWN_OUI  -2
#define WPA2_EXTENDED_KEY_RESERVED -1
#define WPA2_EXTENDED_GTK_KEY      1
#define WPA2_EXTENDED_STA_KEY      2
#define WPA2_EXTENDED_MAC_ADDRESS  3
#define WPA2_EXTENDED_PMKID        4
#define WPA2_EXTENDED_PADDING      255

void eapol_key_type2_process(context *);
void eapol_key_type2_request_new_key(context *, char);

#endif
