/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
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
    4. modify libxsupconfig to understand new tags in the config file.
    5. add the code to have it written to a file in libxsupconfwrite.
    6. if it is a required piece to make an authentication work, add it to
        libxsupconfcheck.
	7. add password return to config_get_pwd_from_profile().
*/

typedef enum {RES_UNSET, RES_YES, RES_NO} sess_res;

// Values used for the 'type' member of the config_ip_data structure.
#define CONFIG_IP_USE_DHCP      0    ///< Have the supplicant use DHCP
#define CONFIG_IP_USE_STATIC    1    ///< Have the supplicant use a static IP address
#define CONFIG_IP_USE_NONE      2    ///< Have the supplicant do nothing with IP addresses.

// Used as part of the config_connection structure to store IP address related information.
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

// Used to store data to access TLS information on a smartcard when using EAP-TLS.  Part
// of the config_eap_tls structure.
struct smartcard
{
  char *engine_id;
  char *opensc_so_path;
  char *key_id;
  //char *cert_id;
  //char *rootcert_id;
};

// Used to store the 4 static WEP keys that may be used as part of a 
// config_connection structure.
struct config_static_wep
{
  uint8_t *key[5];        ///< An array to hold the 4 allowed static keys. Index 0 should NEVER be used!
  uint8_t tx_key;		  ///< The key index that should be used for the transmit key.
};

// All of the variables that are needed to successfully complete an
// EAP-TLS authentication.
struct config_eap_tls 
{
  char * user_cert;				///< The path to the user certificate.
  char *crl_dir;				///< The path to the OpenSSL directory that contains the CRL certificates.
  char * user_key;				///< The path to the user's private key file.  (Often the same as user_cert.)
  char * user_key_pass;			///< The password needed to decrypt the user's private key file.
  sess_res session_resume;		///< A tri-state value that identifies if we should use ression resumption.
  int chunk_size;				///< A.K.A. the TLS fragment size.  How much of a TLS certificate should be sent at a time.
  char * random_file;			///< Path to a file that contains random data.  (Not used on Windows.)
  char *trusted_server;			///< The name of a trusted server block that should be used to verify the server's certificate.
								//	   the name should be used to resolve the config_trusted_server block that contains
								//	   the data needed to validate the server certificate.
  char *store_type;				///< The type of cert store we need to look in for the certificate information.
  struct smartcard sc;			///< Stores information needed to read a certificate from a smart card.

};

#define EAP_FAST_PROVISION_ALLOWED			BIT(0)		// Should we allow the server to send us a new PAC?
#define EAP_FAST_PROVISION_ANONYMOUS		BIT(1)		// Should we allow anonymous provisioning?
#define EAP_FAST_PROVISION_AUTHENTICATED	BIT(2)		// Should we allow authenticted (certificate based) provisioning?
#define EAP_FAST_USE_LOGON_CREDS			BIT(3)		// Should we use the logon credentials when doing EAP-FAST?

// All of the variables that are needed to successfully complete an
// EAP-FAST authentication.
struct config_eap_fast
{
  char *pac_location;			///< The path to the file that contains the EAP-FAST PAC for this user.
  uint8_t flags;				///< A set of flags defined above.
  int chunk_size;				///< a.k.a. the TLS fragment size.  How big should TLS messages be when sent.
  char *innerid;				///< The username that will be used inside the tunnel that is created using the EAP-FAST PAC.
  char *trusted_server;			///< A trusted server to use with authenticated provisioning mode.
  char validate_cert;			///< A TRUE/FALSE value to determine if we should validate the certificate.

  struct config_eap_method *phase2; ///< A linked-list of valid inner (phase 2) configuration methods that can be used to authenticate an EAP-FAST connection.
};

#define CONFIG_PWD_ONLY_USE_LOGON_CREDS		BIT(0)

// A generic structure that can be used to store passwords for authentication
// methods that use only a password.
struct config_pwd_only
{
  char *password;				///< The clear text password that should be used for authentication.
  uint8_t flags;
};

// Configuration information for how EAP-TNC should be used.
// NOTE : EAP-TNC is a strange EAP method, and isn't used like other methods.
// Because of this, be *VERY* aware of what you are doing when modifying this
// structure!!!
struct config_eap_tnc
{
  uint16_t frag_size;			///< The fragment size that should be used for passing TNC data inside of a TLS tunnel.
								// NOTE : This size needs to be small enough that it fits inside the fragment size of the outer tunnel.
								// If it isn't, then you will end up getting really strange behavior.  Because of this, it is best not
								// to set this value, and let the supplicant figure it out for you!
};

// A list of authentication types that can be used inside of EAP-TTLS.  (With the exception
// of TTLS_PHASE2_UNDEFINED, which is there for detecting misconfigurations.)
typedef enum {TTLS_PHASE2_UNDEFINED,
	TTLS_PHASE2_PAP,					///< Authenticate using TTLS-PAP
	TTLS_PHASE2_CHAP,					///< Authenticate using TTLS-CHAP
	TTLS_PHASE2_MSCHAP,					///< Authenticate using TTLS-MSCHAP
	TTLS_PHASE2_MSCHAPV2,				///< Authenticate using TTLS-MSCHAPv2
    TTLS_PHASE2_EAP } ttls_phase2_type;	///< Authenticate using EAP inside of TTLS.

#define TTLS_FLAGS_USE_LOGON_CREDS		BIT(0)		///< Use logon credentials.

/// Configuration information for authenticating using EAP-TTLS.
//
// The items in this structure need to match those in config_eap_tls up to 
// the random_file item, because the TLS routines will type cast the data to
// a config_eap_tls structure for processing.  This makes the code easier to deal with,
// but has the side effect that the developer needs to be a bit more careful.
struct config_eap_ttls
{
  char * user_cert;					///< The path to the user certificate for the outer tunnel.  (Usually not used.)
  char *crl_dir;					///< The path to the OpenSSL directory that contains CRL certificates.
  char * user_key;					///< The path to the file that contains the user's private key.  (Usually not used.)
  char * user_key_pass;				///< The password needed to decrypt the user's private key.  (Usually not used.)
  sess_res session_resume;			///< A tri-state value that determines if session resumption should be used.
  int  chunk_size;					///< The size of the TLS fragments that should be sent.
  char *random_file;				///< The path to a file of random data used to seed OpenSSL.  (Not used with Windows.)

  char *inner_id;					///< The username to use inside the TTLS tunnel.
  char *trusted_server;				///< The name of the <Trusted_Server> block to be used to validate the server certificate.
  uint8_t validate_cert;			///< A TRUE/FALSE value that indicates if we should validate the server certificate or not.

  uint8_t flags;

  ttls_phase2_type phase2_type;      ///< One of the TTLS_PHASE2_* values.  Used to determine the inner method to use for authentication.
  void *phase2_data;                 ///< A pointer that should be type cast based on the TTLS_PHASE2_* values.  It will point to a configuration
									 //   structure that contains the information needed to complete the inner (phase 2) authentication.
};

#define FLAGS_EAP_MSCHAPV2_VOLATILE			BIT(0)   ///< This instance of the MSCHAPv2 configuration shouldn't be written to the config file.  (Mainly used with EAP-FAST for anonymous provisioning.)
#define FLAGS_EAP_MSCHAPV2_IAS_QUIRK		BIT(1)   ///< A TRUE/FALSE value to deal with a strange quirk with some IAS configurations.  (This is generally not used.)
#define FLAGS_EAP_MSCHAPV2_FAST_PROVISION	BIT(2)   ///< Is the purpose of this configuraion only for EAP-FAST provisioning?  (This option shouldn't be parsed in the parser, or written.)
#define FLAGS_EAP_MSCHAPV2_MACHINE_AUTH		BIT(3)	 ///< Should MS-CHAPv2 operate in machine authentication mode?
#define FLAGS_EAP_MSCHAPV2_USE_LOGON_CREDS	BIT(4)	 ///< Should MS-CHAPv2 use available logon credentials (if available)?

// Configuration information that is needed to authenticate using EAP-MSCHAPv2.
//  NOTE: This structure can show up as both an inner method to tunneled methods, or an outer method on it's own.
struct config_eap_mschapv2
{
  char *password;					///< The cleartext password to be used for EAP-MSCHAPv2.
  char *nthash;						///< An MS-CHAP hash of the password to be used to authenticate.  If this is provided, the password member above should be NULL.
  uint8_t flags;					///< Any set of the FLAGS_EAP_MSCHAPV2_* above.
};

/// Configuration information for authenticating using EAP-PEAP.
//
// The items in this structure need to match those in config_eap_tls up to 
// the random_file item, because the TLS routines will type cast the data to
// a config_eap_tls structure for processing.  This makes the code easier to deal with,
// but has the side effect that the developer needs to be a bit more careful.

#define FLAGS_PEAP_MACHINE_AUTH		BIT(0)			///< Should PEAP use machine authentication?
#define FLAGS_PEAP_USE_LOGON_CREDS  BIT(1)			///< Should we use logon credentials for authentication?

struct config_eap_peap
{
  char * user_cert;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  sess_res session_resume;
  int  chunk_size;
  char *random_file;

  char proper_peapv1;

  char *identity; // phase2 identity
  uint8_t force_peap_version;
  char *trusted_server;
  uint8_t validate_cert;
  uint8_t flags;

  struct config_eap_method *phase2; 
};

struct config_eap_sim
{
  char *password;
  char *reader;
  int auto_realm;
};

struct config_eap_aka
{
  char *password;
  char *reader;
  int auto_realm;
};

/* A generic wrapper struct for above */
struct config_eap_method
{
  int method_num;
  void *method_data; // one of the structs above
  struct config_eap_method *next;
};

// flags relevant to config_connection
#define CONFIG_NET_DEST_MAC     BIT(0)    // indicates the destination MAC is set and should be used

#define CONFIG_NET_IS_HIDDEN    BIT(2)    // indicates that the SSID is hidden.
#define CONFIG_VOLATILE_CONN    BIT(3)    // the connection is volatile and shouldn't be saved.

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
  uint8_t flags;
  uint8_t priority;
  char *ssid;
  char *profile;
  struct config_association association;
  struct config_ip_data ip;                        ///< The IP address settings to use on this connection.
  uint8_t  dest_mac[CONFIG_MAC_LEN];
  uint8_t force_eapol_ver; 
  struct config_connection *next;
};

  // the following indicate the values below are set and should be used
#define CONFIG_GLOBALS_FRIENDLY_WARNINGS BIT(1)
#define CONFIG_GLOBALS_ALLMULTI             BIT(2)
#define CONFIG_GLOBALS_ASSOC_AUTO           BIT(3)
#define CONFIG_GLOBALS_FIRMWARE_ROAM        BIT(4)
#define CONFIG_GLOBALS_PASSIVE_SCAN         BIT(5)
#define CONFIG_GLOBALS_EAP_HINTS         BIT(6)
//#define CONFIG_GLOBALS_USE_SYSLOG           BIT(7)
#define CONFIG_GLOBALS_DETECT_ON_STARTUP    BIT(8)  // Should we detect other supplicants when the UI starts?  (This has no bearing on the operation of the engine.)
#define CONFIG_GLOBALS_ROLL_LOGS            BIT(9)  // Should we roll our log files?
#define CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF BIT(10) // When Windows sends a user logoff signal, should we disconnect all of our active connections?
#define CONFIG_GLOBALS_WIRELESS_ONLY        BIT(11) // Only manage wireless interfaces.
#define CONFIG_GLOBALS_INT_CTRL          BIT(12) // Should we allow the underlying OS to control the interfaces?
#define CONFIG_GLOBALS_ALLOW_MA_REMAIN	    BIT(13) // Should we allow a machine authentication to remain connected even after a user has logged on?

#define LOGGING_NONE					0		// Don't log anything.
#define LOGGING_FILE					1		// Log to a file.  (Default)
#define LOGGING_SYSLOG					2		// Log to syslog.

struct config_globals
{
  char *logpath;
  uint32_t loglevel;
  uint8_t logs_to_keep;          // Number of logs we should keep when rolling.
  uint16_t size_to_roll;         // The size (in MB) that we should roll the log at.
  uint8_t logtype;				 // How should things be logged.  (Should be one of LOGGING_* from above.)

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
  uint8_t  dead_connection_timeout;  ///< The length of time we wait after a network has "disappeared" before we ask the user if we should try to select a different connection.

  char *wiredMachineAuthConnection;	///< The name of the connection we want to use for machine authentication on wired interfaces.  (This connection MUST be configured properly for machine authentication, and MUST exist in the global configuration.)
  char *wirelessMachineAuthConnection;	///< The name of the connection we want to use for machine authentication on wireless interfaces.  (This connection MUST be configured properly for machine authentication, and MUST exist in the global configuration.)
};

#define CONFIG_VOLATILE_PROFILE   BIT(0)

struct config_profiles {
		char *name;
		char *identity;
		uint8_t flags;
		uint32_t compliance;                   ///< A bit map of compliance enable/disable settings.  Look in tnc_compliance.h in the src/eap_types/tnc directory.

		char *temp_username;                   ///< A user provided username.  This value should *NEVER* be sent to a UI!
		char *temp_password;                   ///< A user provided password.  This value should *NEVER* be sent to a UI!

		struct config_eap_method *method;

		struct config_profiles *next;
};

#define CONFIG_VOLATILE_SERVER   BIT(0)

struct config_trusted_server {
	char *name;
	char *store_type;
	uint16_t num_locations;
	char **location;
	char *common_name;
	char exact_common_name;
	uint8_t flags;

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

struct config_plugins {
  struct config_plugins *next;
  char *name;
  char *path;
  uint8_t enabled;					// True if it is enabled, false if not.
  char *description;				// The description of this plugin.
  uint32_t plugin_type;				// Populated when the plugin is loaded, to speed searching for the plugin type.
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
typedef struct config_plugins config_plugins;

typedef struct config_eap_tls config_eap_tls;
typedef struct config_eap_ttls config_eap_ttls;
typedef struct config_eap_peap config_eap_peap ;
typedef struct config_eap_mschapv2 config_eap_mschapv2;
typedef struct config_pwd_only config_pwd_only;
typedef struct config_eap_sim config_eap_sim;
typedef struct config_eap_aka config_eap_aka;

#endif // __XSUPCONFIG_STRUCTS_H__
