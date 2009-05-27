/**
 * Linux wireless extensions interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_linux.h
 *
 * \author chris@open1x.org
 *
 */

#ifndef _CARDIF_LINUX_WEXT_
#define _CARDIF_LINUX_WEXT_

extern struct cardif_funcs cardif_linux_wext_driver;

int cardif_linux_wext_set_WEP_key(context *, uint8_t *, int, int);
int cardif_linux_wext_set_ssid(context *, char *);
int cardif_linux_wext_set_bssid(context *, uint8_t *);
int cardif_linux_wext_check_ssid(context *);
int cardif_linux_wext_get_bssid(context *, char *);
int cardif_linux_wext_set_ssid(context *, char *);
int cardif_linux_wext_wep_associate(context *, int);
int cardif_linux_wext_get_ssid(context *, char *, unsigned int);
int cardif_linux_wext_scan(context *, char);
void cardif_linux_wext_associate(context *);
void cardif_linux_wext_use_temp_keys(char);
int cardif_linux_wext_enc_open(context *);
int cardif_linux_wext_enc_disable(context * thisint);
void cardif_linux_wext_set_zero_keys(context *);
void cardif_linux_wext_zero_keys(context *);
int cardif_linux_wext_wpa_state(context *, char);
int cardif_linux_wext_set_wpa_ie(context *, unsigned char *, unsigned int);
int cardif_linux_wext_set_iwauth(context *, int, uint32_t, char *);
int cardif_linux_wext_set_key_ext(context *, int,
				  unsigned char *, int, int, char *, int,
				  char *, int);
double cardif_linux_wext_set_freq(context *);
void cardif_linux_wext_enc_capabilities(context *);

int cardif_linux_wext_set_tkip_key(context *, unsigned char *, int, int, char *,
				   int);
int cardif_linux_wext_set_ccmp_key(context *, unsigned char *, int, int, char *,
				   int);
int cardif_linux_wext_delete_key(context *, int, int);
int cardif_linux_wext_wpa(context *, char);
int cardif_linux_wext_countermeasures(context *, char);
int cardif_linux_wext_drop_unencrypted(context *, char);
int cardif_linux_wext_get_wpa2_ie(context *, uint8_t *, uint8_t *);
int cardif_linux_wext_disassociate(context *, int);
int cardif_linux_wext_get_wpa_ie(context *, uint8_t *, uint8_t *);

#endif
