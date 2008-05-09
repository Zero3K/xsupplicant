/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __CONFIG_SSID_H__
#define __CONFIG_SSID_H__

struct found_ssids {
  char *ssid_name;
  uint8_t abilities;
  uint8_t *wpa_ie;
  uint8_t wpa_ie_len;
  uint8_t *rsn_ie;
  uint8_t rsn_ie_len;
  uint8_t mac[6];
  unsigned int freq;
  unsigned char quality;
  char signal;
  char noise;

  struct found_ssids *next;
};

void config_ssid_clear(wireless_ctx *);
char *config_ssid_get_desired_ssid(context *);
uint8_t config_ssid_get_ssid_abilities(wireless_ctx *);
void config_ssid_get_wpa_ie(wireless_ctx *, uint8_t **, uint8_t *);
void config_ssid_get_rsn_ie(wireless_ctx *, uint8_t **, uint8_t *);
unsigned int config_ssid_get_freq(wireless_ctx *);
uint8_t *config_ssid_get_mac(wireless_ctx *);
void config_ssid_dump(wireless_ctx *);
//void config_ssid_set_active_ssid(wireless_ctx *, char *);
int config_ssid_using_wep(wireless_ctx *);
int config_ssid_ssid_known(wireless_ctx *, char *);
void config_ssid_get_by_mac(context *, uint8_t *);
struct found_ssids *config_ssid_find_by_name(wireless_ctx *wctx, char *ssid_name);
struct found_ssids *config_ssid_best_signal(struct found_ssids *one, struct found_ssids *two);

// Functions to add information to an existing ESSID node.
void config_ssid_add_freq(wireless_ctx *, unsigned int);
void config_ssid_add_bssid(wireless_ctx *, char *);
void config_ssid_add_rsn_ie(wireless_ctx *, uint8_t *, uint8_t);
void config_ssid_add_wpa_ie(wireless_ctx *, uint8_t *, uint8_t);
void config_ssid_add_ssid_name(wireless_ctx *, char *);
void config_ssid_update_abilities(wireless_ctx *, uint8_t);
void config_ssid_add_qual(wireless_ctx *, unsigned char, char, char);

#endif
