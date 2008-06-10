/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wpa.h
 *
 *******************************************************************/

#ifndef __WPA_H__
#define __WPA_H__

#define WPA_EID        0xdd
#define MAX_WPA_VER    1

#define WPA_DOT1X		BIT(0)
#define WPA_PSK			BIT(1)

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
struct wpa_ie_struct {
  unsigned char wpaid;
  unsigned char wpalen;
  unsigned char oui[4];
  uint16_t wpa_ver;
  unsigned char group_cipher[4];
  uint16_t pk_suite_cnt;

  // The rest of the IE is variable, and can be structured here.
};
#else
struct wpa_ie_struct {
  unsigned char wpaid;
  unsigned char wpalen;
  unsigned char oui[4];
  uint16_t wpa_ver;
  unsigned char group_cipher[4];
  uint16_t pk_suite_cnt;

  // The rest of the IE is variable, and can be structured here.
} __attribute__((__packed__));
#endif

#ifdef WINDOWS
#pragma pack()
#endif

int wpa_parse_ie(char *);
void wpa_gen_ie(context *, char *);
void wpa_gen_ie_caps(context *, char *);
char *wpa_minmax(char *, char *, int, char);
uint8_t wpa_get_pairwise_crypt(context *);
uint8_t wpa_get_group_crypt(context *);
uint8_t wpa_parse_auth_type(char *iedata);

#endif
