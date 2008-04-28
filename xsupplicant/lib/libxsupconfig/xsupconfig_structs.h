/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_structs.h,v 1.7 2008/01/26 01:19:59 chessing Exp $
 * $Date: 2008/01/26 01:19:59 $
 **/

#ifndef __XSUPCONFIG_STRUCTS_H__
#define __XSUPCONFIG_STRUCTS_H__

#ifdef WINDOWS
#include "../../src/stdintwin.h"
#else
#include <stdint.h>
#endif

#ifndef BIT
/**
 * Set a bit based on it's bit number.
 **/
#define BIT(x)  (1 << x)
#endif

// if you change this, update the printing and parsing functions
// accordingly
#define CONFIG_MAC_LEN 6

/*** DEVELOPER CHECKLIST ****/
/* When adding a value to one of these structs you must
    1. update initialize_config_<struct>
    2. update delete_config_<struct>
    3. update dump_config_<struct> if it exists
    4. modify the grammar to account for the new fields (config_grammar.y)
    5. modify the lexicon for the new tokens (config_lexicon.l)
    6. add the code to have it written to a file in libxsupconfwrite.
    7. if it is a required piece to make an authentication work, add it to
        libxsupconfcheck.
	8. add password return to config_get_pwd_from_profile().
*/

typedef enum {RES_UNSET, RES_YES, RES_NO} sess_res;

#define CONFIG_IP_USE_DHCP      0    ///< Have the supplicant use DHCP
#define CONFIG_IP_USE_STATIC    1    ///< Have the supplicant use a static IP address
#define CONFIG_IP_USE_NONE      2    ///< Have the supplicant do nothing with IP addresses.

struct config_ip_data
{
	uint8_t type;             ///< One of the CONFIG_IP_USE_* defines above.
	uint8_t renew_on_reauth;  ///< TRUE/FALSE, should we do a DHCP renew on every reauth?
	char *ipaddr;             ///< The static IP address to use.
	char *netmask;            ///< The netmask to use with the static IP.
	char *gateway;            ///< The gateway to use with the static IP.
	char *dns1;               ///< The primary DNS to use with the static IP.
	char *dns2;               ///< The secondary DNS to use with the static IP.
	char *dns3;               ///< The third DNS to use with the static IP.
	char *search_domain;      ///< The search domain to use with DNS.
};

struct smartcard
{
  char *engine_id;
  char *opensc_so_path;
  char *key_id;
  //char *cert_id;
  //char *rootcert_id;
};

struct config_static_wep
{
  uint8_t *key[5];        // Index 0 should NEVER be used!
  uint8_t tx_key;
};

struct config_eap_tls 
{
  char * user_cert;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  sess_res session_resume;
  int chunk_size;
  char * random_file;
  char *trusted_server;
  struct smartcard sc;

};

struct config_eap_fast
{
  char *pac_location;
  sess_res provision;
  int chunk_size;
  char *innerid;

  struct config_eap_method *phase2; 
};

struct config_pwd_only
{
  char *password;
};

struct config_eap_tnc
{
  uint16_t frag_size;
};

typedef enum {TTLS_PHASE2_UNDEFINED,
	TTLS_PHASE2_PAP,
	TTLS_PHASE2_CHAP,
	TTLS_PHASE2_MSCHAP,
	TTLS_PHASE2_MSCHAPV2,
    TTLS_PHASE2_EAP } ttls_phase2_type;

// The items in this structure need to match those in config_eap_tls up to 
// the random_file item, or else things may have problems.
struct config_eap_ttls
{
  char * user_cert;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  sess_res session_resume;
  int  chunk_size;
  char *random_file;

  char *cncheck;                   // XXX Remove these!  They are part of trusted server now.
  int  cnexact;

  char *inner_id;
  char *trusted_server;
  uint8_t validate_cert;

  ttls_phase2_type phase2_type;      // the type to actually do
  void *phase2_data;                  // the data for that type
};

struct config_eap_mschapv2
{
  char *password;
  char *nthash;
  uint8_t ias_quirk;
};

// The items in this structure need to match those in config_eap_tls up to 
// the random_file item, or else things may have problems.
struct config_eap_peap
{
  char * user_cert;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  sess_res session_resume;
  int  chunk_size;
  char *random_file;

  char *cncheck;          // XXX Remove this.  It is part of trusted server now.
  char proper_peapv1;
  int cnexact;            // XXX Remove this.  It is part of trusted server now.

  char *identity; // phase2 identity
  uint8_t force_peap_version;
  char *trusted_server;
  uint8_t validate_cert;

  struct config_eap_method *phase2; 
};

struct config_eap_sim
{
  char *username;
  char *password;
  int auto_realm;
};

struct config_eap_aka
{
  char *username;
  char *password;
  int auto_realm;
};

/* A generic wrapper struct for above */
struct config_eap_method
{
  int method_num;
  void *method_data; // one of the structs above
  struct config_eap_method *next;
};

#define CONFIG_NET_DEST_MAC     BIT(0)    // indicates the variable below is set and should be used
#define CONFIG_NET_USE_OSC_TNC  BIT(1)    // indicates that we should, or shouldn't use TNC
#define CONFIG_NET_IS_HIDDEN    BIT(2)    // indicates that the SSID is hidden.

#define ASSOC_AUTO     0
#define ASSOC_OPEN     1
#define ASSOC_SHARED   2
#define ASSOC_LEAP     3
#define ASSOC_WPA      4
#define ASSOC_WPA2     5

// Different types of encryption that are allowed.
#define CRYPT_WEP40       1
#define CRYPT_TKIP        2
#define CRYPT_WRAP        3
#define CRYPT_CCMP        4
#define CRYPT_WEP104      5

// Different types of encryption that are allowed (as flags).
#define CRYPT_FLAGS_WEP40       BIT(0)
#define CRYPT_FLAGS_TKIP        BIT(1)
#define CRYPT_FLAGS_WRAP        BIT(2)
#define CRYPT_FLAGS_CCMP        BIT(3)
#define CRYPT_FLAGS_WEP104      BIT(4)

// Different types of authentication that are allowed.
#define AUTH_UNKNOWN               0
#define AUTH_NONE                  1
#define AUTH_PSK                   2
#define AUTH_EAP                   3

struct config_association
{
	uint8_t association_type;    ///<  Should be one of the ASSOC_* defines.
	uint8_t pairwise_keys;       ///<  Some combination of CRYPT_FLAGS_* defines.
	uint8_t group_keys;          ///<  One of the CRYPT_* defines.
	uint8_t auth_type;           ///<  One of the AUTH_* defines.

	uint8_t txkey;               ///<  The index of the WEP key that should be used to transmit data.  Must be 1..4.
	char *keys[5];               ///<  The static WEP keys that should be applied to the card.  Index 0 should not be used!
	char *psk;                   ///<  An ASCII string that will be used as the PreShared Key (PSK) for a WPA(2)-PSK connection.
	char *psk_hex;               ///<  An ASCII representation of a hex key that will be used as a PreShared Key.  (Note : The tools needed to generate this key are not currently included with Xsupplicant!)

	char *temp_psk;              ///<  Used to store a PSK entered with the UI, so that it doesn't show up in a UI's config later.  (ASCII PSK ONLY!)
};

struct config_connection
{
  char *name;
  char *ou;
  uint8_t flags;
  uint8_t priority;
  char *ssid;
  char *profile;
  char *device;
  struct config_association association;
  struct config_ip_data ip;                        ///< The IP address settings to use on this connection.
  uint8_t  dest_mac[CONFIG_MAC_LEN];
  uint8_t force_eapol_ver; 
  struct config_connection *next;
};

  // the following indicate the values below are set and should be used
#define CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS BIT(1)
#define CONFIG_GLOBALS_ALLMULTI             BIT(2)
#define CONFIG_GLOBALS_ASSOC_AUTO           BIT(3)
#define CONFIG_GLOBALS_FIRMWARE_ROAM        BIT(4)
#define CONFIG_GLOBALS_PASSIVE_SCAN         BIT(5)
#define CONFIG_GLOBALS_NO_EAP_HINTS         BIT(6)
#define CONFIG_GLOBALS_USE_SYSLOG           BIT(7)
#define CONFIG_GLOBALS_DETECT_ON_STARTUP    BIT(8)  // Should we detect other supplicants when the UI starts?  (This has no bearing on the operation of the engine.)
#define CONFIG_GLOBALS_ROLL_LOGS            BIT(9)  // Should we roll our log files?
#define CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF BIT(10) // When Windows sends a user logoff signal, should we disconnect all of our active connections?
#define CONFIG_GLOBALS_WIRELESS_ONLY        BIT(11) // Only manage wireless interfaces.

struct config_globals
{
  char *logpath;
  uint32_t loglevel;
  uint8_t logs_to_keep;          // Number of logs we should keep when rolling.
  uint16_t size_to_roll;         // The size (in MB) that we should roll the log at.

  char *log_facility;
  char *ipc_group_name;

  uint16_t flags;
  uint8_t  destination;
  uint16_t auth_period;
  uint16_t held_period;
  uint16_t max_starts;
  uint16_t stale_key_timeout;
  uint16_t assoc_timeout;
  uint16_t passive_timeout;      ///< The amount of time (in seconds) between each passive scan attempt.  (NOTE : If this value is greater than the value for pmksa_age_out, then your PMKSAs will *ALWAYS* age out the first time around!)
  uint16_t active_timeout;
  uint8_t  idleWhile_timeout;

  uint16_t pmksa_age_out;        ///< The amount of time to wait (in seconds) before we age out a PMKSA entry.  Maximum time is ((65535/60)/60) = 18.20 hours.  (Which would be a silly amount of time to really wait. ;)
  uint8_t  pmksa_cache_check;    ///< The frequency that we should do cache maintenance on the various interface caches.  This value is only used to age out cache entries.  The passive scan timer is used to keep them up to date.
};

struct config_profiles {
		char *name;
		char *identity;
		char *ou;
		uint32_t compliance;                   ///< A bit map of compliance enable/disable settings.  Look in tnc_compliance.h in the src/eap_types/tnc directory.

		char *temp_username;                   ///< A user provided username.  This value should *NEVER* be sent to a UI!
		char *temp_password;                   ///< A user provided password.  This value should *NEVER* be sent to a UI!

		struct config_eap_method *method;

		struct config_profiles *next;
};

struct config_trusted_server {
	char *name;
	char *store_type;
	char *location;
	char *common_name;
	char exact_common_name;

	struct config_trusted_server *next;
};

struct config_trusted_servers {
	struct config_trusted_server *servers;
};

#define CONFIG_INTERFACE_IS_WIRELESS  BIT(0)    ///< The interface is listed as wireless in the configuration.
#define CONFIG_INTERFACE_DONT_MANAGE  BIT(1)    ///< Don't manage this interface.

struct xsup_interfaces {
	char *description;
	uint8_t mac[6];
	char *driver_type;
	char *default_connection;
	uint8_t flags;

	struct xsup_interfaces *next;
};

/**
 * For now, the devices structure is only for interfaces, but that may change in the
 * future, so we define it as a structure.
 **/
struct xsup_devices {
	struct xsup_interfaces *interf;
};

struct config_managed_networks {
	char *ou;
	char *key;
	uint32_t serialid;
	char *update_url;
	uint8_t auto_update;
	uint16_t update_freq;
	char *last_update;

	struct config_managed_networks *next;
};

struct config_plugins {
  struct config_plugins *next;
  char *name;
  char *path;
  void *handle;
};

typedef struct config_globals config_globals;
typedef struct config_connection config_connection;
typedef struct config_profiles config_profiles;
typedef struct config_eap_method config_eap_method;
typedef struct config_trusted_servers config_trusted_servers;
typedef struct config_trusted_server config_trusted_server;
typedef struct xsup_devices config_devices;
typedef struct xsup_interfaces config_interfaces;
typedef struct config_managed_networks config_managed_networks;
typedef struct config_plugins config_plugins;

typedef struct config_eap_tls config_eap_tls;
typedef struct config_eap_ttls config_eap_ttls;
typedef struct config_eap_peap config_eap_peap ;
typedef struct config_eap_mschapv2 config_eap_mschapv2;
typedef struct config_pwd_only config_pwd_only;
typedef struct config_eap_sim config_eap_sim;
typedef struct config_eap_aka config_eap_aka;

#endif // __XSUPCONFIG_STRUCTS_H__
