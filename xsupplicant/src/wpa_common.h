/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wpa_common.h
 *
 **/

#ifndef _WPA_COMMON_H_
#define _WPA_COMMON_H_

#define AUTH_SUITE_RESERVED 0x00
#define AUTH_SUITE_DOT1X    0x01
#define AUTH_SUITE_PSK      0x02

#define CIPHER_NONE         0x00
#define CIPHER_WEP40        0x01
#define CIPHER_TKIP         0x02
#define CIPHER_WRAP         0x03
#define CIPHER_CCMP         0x04
#define CIPHER_WEP104       0x05

#define MAX_IE_LEN          255

int aes_unwrap(uint8_t *, int, uint8_t *, uint8_t *);
void rc4_skip(uint8_t *, int, int, uint8_t *, int);
void wpa_print_cipher_suite(unsigned char, unsigned char);
void wpa_print_auth_suite(unsigned char, unsigned char);
void wpa_PRF(unsigned char *, int, unsigned char *, int, unsigned char *, int,
	     unsigned char *, int);
void wpa_common_swap_rx_tx_mic(uint8_t *);
void wpa_common_set_key(context *, char *, int, int, char *, int);
void byte_swap(uint16_t *);

#endif
