/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wpa2.h
 *
 **/

#ifndef __WPA2_H__
#define __WPA2_H__

#define WPA2_EID        0x30
#define MAX_WPA2_VER    1

#define RSN_DOT1X		BIT(0)
#define RSN_PSK			BIT(1)

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
struct wpa2_ie_struct {
  unsigned char wpaid;
  unsigned char wpalen;
  uint16_t rsn_ver;
  unsigned char group_cipher[4];
  uint16_t pk_suite_cnt;

  // The rest of the IE is variable, and can't be structured here.
};
#else
struct wpa2_ie_struct {
  unsigned char wpaid;
  unsigned char wpalen;
  uint16_t rsn_ver;
  unsigned char group_cipher[4];
  uint16_t pk_suite_cnt;

  // The rest of the IE is variable, and can't be structured here.
} __attribute__((__packed__));
#endif

#ifdef WINDOWS
#pragma pack()
#endif

void wpa2_gen_ie(context *, unsigned char *, int *);
void wpa2_gen_ie_caps(context *, char *);
char *wpa_minmax(char *, char *, int, char);
int wpa2_parse_ie(char *iedata);
uint8_t wpa2_get_group_crypt(context *);
uint8_t wpa2_get_pairwise_crypt(context *);

#endif
