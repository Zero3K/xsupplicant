/**
 * Card driver specific interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _CARDIF_H_
#define _CARDIF_H_

#include "src/context.h"
#include "src/pmksa.h"

// Alg methods to use when doing WPA.
#define WPA_NONE 0
#define WPA_WEP  1
#define WPA_TKIP 2
#define WPA_CCMP 3

// Abilities that will be stored in the SSID cache, for a "quick look" at
// what the SSID supports.
#define ABIL_ENC		  0x02
#define ABIL_WPA_IE		  0x04
#define ABIL_RSN_IE       0x08
#define ABIL_WPA_DOT1X	  0x10
#define ABIL_WPA_PSK	  0x20
#define ABIL_RSN_DOT1X	  0x40
#define ABIL_RSN_PSK	  0x80

#define DRIVER_NONE        0
#define DRIVER_WEXT        1
#define DRIVER_ATMEL       3

#define FRAMESIZE          1520

// Reasons for a disassociation.
// Valid sections include 7.3.1.7 in 802.11i-2004.
#define DISASSOC_UNSPECIFIED          1     // Unspecified reason
#define DISASSOC_INVALID_IE           13    // Invalid information element
#define DISASSOC_MIC_FAILURE          14    // MIC failure
#define DISASSOC_4WAY_TIMEOUT         15    // 4-way handshake timeout
#define DISASSOC_GROUPKEY_TIMEOUT     16    // group key handshake timeout
#define DISASSOC_DIFF_IE              17    // IEs in assoc, and 4-way differ.
#define DISASSOC_INVALID_GROUP_CIPHER 18    // Invalid group cipher
#define DISASSOC_INVALID_PAIR_CIPHER  19    // Invalid pairwise cipher
#define DISASSOC_INVALID_AKMP         20    // Invalid AKMP
#define DISASSOC_BAD_RSN_VERSION      21    // Unsupported RSN version
#define DISASSOC_INVALID_RSN_CAPS     22    // Invalid RSN capabilities
#define DISASSOC_DOT1X_FAILURE        23    // 802.1X authentication failure.
#define DISASSOC_CIPHER_REJECT        24    // Cipher suite rejected.

// Return values for associated, and unassociated.
#define IS_ASSOCIATED                 1
#define IS_UNASSOCIATED               2

// Different encryption/authentication modes that are supported.  (Since
// any interface should be able to do 802.1X, we don't flag that here.)
#define DOES_WPA                      0x00000001
#define DOES_WPA2                     0x00000002
#define DOES_WEP40                    0x00000004
#define DOES_WEP104                   0x00000008
#define DOES_TKIP                     0x00000010
#define DOES_CCMP                     0x00000020

/* RFC 2863 operational status (using different names to avoid compile problems) */
enum {
  XIF_OPER_UNKNOWN,
  XIF_OPER_NOTPRESENT,
  XIF_OPER_DOWN,
  XIF_OPER_LOWERLAYERDOWN,
  XIF_OPER_TESTING,
  XIF_OPER_DORMANT,
  XIF_OPER_UP,
};

enum {
  XIF_LINK_MODE_DEFAULT,
  XIF_LINK_MODE_DORMANT,
};

struct cardif_funcs {

  // Issue a scan request.
  int (*scan)(context *, char);

  // Send a disassociate message to the AP
  int (*disassociate)(context *, int);

  // Set a WEP key
  int (*set_wep_key)(context *, uint8_t *, int, int);

  // Set a TKIP key.
  int (*set_tkip_key)(context *, unsigned char *, int, int, 
		      char *, int);

  // Set a CCMP (AES) key.
  int (*set_ccmp_key)(context *, unsigned char *, int, int,
		      char *, int);

  // Delete a key.
  int (*delete_key)(context *, int, int);

  // Tell the card to associate to a specific SSID.
  void (*associate)(context *);

  // Request the SSID for this card.
  int (*get_ssid)(context *, char *, unsigned int);

  // Request the BSSID.
  int (*get_bssid)(context *, char *);

  // Enable the WPA state.  (Set the IEs, etc.)
  int (*wpa_state)(context *, char);

  // Enable WPA in the card.
  int (*wpa)(context *, char);

  // Set WEP keys needed to connect to a new AP.
  int (*wep_associate)(context *, int);

  // Tell the driver to enable countermeasures.
  int (*countermeasures)(context *, char);

  // Tell the driver to drop all unencrypted frames.
  int (*drop_unencrypted)(context *, char);

  // Return the WPA IE we need for this driver.
  int (*get_wpa_ie)(context *, char *, int *);

  // Return the WPA2 IE we need for this driver.
  int (*get_wpa2_ie)(context *, char *, int *);

  // Disable encryption.
  int (*enc_disable)(context *);

  // Get the encryption capabilities of the card. (WEP, WPA, WPA2, TKIP, CCMP)
  void (*enc_capabilities)(context *);

  // Change the bssid that we are connected to.
  int (*setbssid)(context *, uint8_t *);

  // Notify the kernel (and any listeners) of the RFC2863 state of the 
  // interface.
  void (*set_operstate)(context *, uint8_t);

  // Notify the kernel that the link should start in dormant.
  void (*set_linkmode)(context *, uint8_t);

  // Get the percentage of the signal strength.
  int (*get_signal_percent)(context *);

  // Set the PMKID data on the interface.
  int (*apply_pmkid_data)(context *, pmksa_list *);
};

// Stuff needed by both wired, and wireless interfaces.

int cardif_init(context *, char);
int cardif_deinit(context *);
int cardif_get_socket(context *);
int cardif_sendframe(context *);
int cardif_getframe(context *);
void cardif_clock_tick(context *);
int cardif_get_if_state(context *);
int cardif_int_is_valid(char *);
int cardif_check_dest(context *);
int cardif_validate(char *);
char *cardif_get_search_ssid();
void cardif_set_search_ssid(char *);
void cardif_enum_ints();
char *cardif_get_ip(context *);
char *cardif_get_netmask(context *);
char *cardif_get_gw(context *);
char *cardif_get_dns1(context *);
char *cardif_get_dns2(context *);
char *cardif_get_dns3(context *);
char *cardif_find_description(char *);
char *cardif_get_mac_str(char *);
int cardif_is_wireless_by_name(char *);
void cardif_cancel_io(context *);
void cardif_restart_io(context *);

// Stuff needed by wireless interfaces.  (If wireless isn't supported they
// should either return XENOTWIRELSS, or just return (in the case of a void)

int cardif_enable_wpa(context *);
int cardif_do_wireless_scan(context *, char);
int cardif_set_wep_key(context *, uint8_t *, int, int);
int cardif_set_tkip_key(context *, char *, int, int, char *, 
			int);
int cardif_set_ccmp_key(context *, char *, int, int, char *, 
			int);
int cardif_delete_key(context *, int, int);
void cardif_associate(context *);
int cardif_disassociate(context *, int);
int cardif_GetSSID(context *, char *, unsigned int);
int cardif_check_ssid(context *);
int cardif_GetBSSID(context *, char *);
void cardif_setBSSID(context *, uint8_t *);
int cardif_int_is_wireless(context *);
int cardif_wep_associate(context *, int);
int cardif_disable_wpa_state(context *);
int cardif_enable_wpa_state(context *);
int cardif_drop_unencrypted(context *, char);
int cardif_countermeasures(context *, char);
int cardif_get_wpa_ie(context *, char *, int *);
int cardif_get_wpa2_ie(context *, uint8_t *, uint8_t *);
int cardif_clear_keys(context *);
int cardif_check_associated(context *);
void cardif_reassociate(context *, uint8_t);
void cardif_association_timeout_expired(context *);
int cardif_enc_disable(context *);
void cardif_get_abilities(context *);
void cardif_passive_scan_timeout(context *);
void cardif_operstate(context *, uint8_t);
void cardif_linkmode(context *, uint8_t);
int cardif_get_signal_strength_percent(context *);
int cardif_apply_pmkid_data(context *);

#endif
