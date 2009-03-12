/**
 * Windows wireless extensions interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_dot11.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _CARDIF_WINDOWS_DOT11_
#define _CARDIF_WINDOWS_DOT11_

// Define encryption types that we need
#define ALG_WEP  1
#define ALG_TKIP 2
#define ALG_CCMP 3

extern struct cardif_funcs cardif_windows_dot11_driver;

void cardif_windows_dot11_parse_ies(context *, uint8_t *, int);

int cardif_windows_dot11_set_WEP_key(context *, uint8_t *, int, int);
int cardif_windows_dot11_set_bssid(context *, uint8_t *);
int cardif_windows_dot11_check_ssid(context *);
int cardif_windows_dot11_get_bssid(context *, char *);
int cardif_windows_dot11_set_ssid(context *, char *);
int cardif_windows_dot11_wep_associate(context *, int);
int cardif_windows_dot11_get_ssid(context *, char *, unsigned int);
int cardif_windows_dot11_scan(context *, char);
void cardif_windows_dot11_associate(context *);
void cardif_windows_dot11_use_temp_keys(char);
int cardif_windows_dot11_enc_open(context *);
int cardif_windows_dot11_enc_disable(context * thisint);
void cardif_windows_dot11_set_zero_keys(context *);
void cardif_windows_dot11_zero_keys(context *);
int cardif_windows_dot11_wpa_state(context *, char);
int cardif_windows_dot11_set_wpa_ie(context *, unsigned char *, unsigned int);
int cardif_windows_dot11_set_iwauth(context *, int, uint32_t, char *);
int cardif_windows_dot11_set_key_ext(context *, int,
				     unsigned char *, int, int, char *, int,
				     char *, int);

void cardif_windows_dot11_enc_capabilities(context *);

#endif
