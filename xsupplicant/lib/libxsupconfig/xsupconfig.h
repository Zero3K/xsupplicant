/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _XSUPCONFIG_H_
#define _XSUPCONFIG_H_

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "xsupconfig_structs.h"

#ifndef TRUE
#define TRUE          1
#endif

#ifndef FALSE
#define FALSE         0
#endif

#define OPTION_GLOBAL_CONFIG_ONLY	BIT(0)
#define OPTION_USER_CONFIG_ONLY		BIT(1)
#define OPTION_ANY_CONFIG			(BIT(0) | BIT(1))

#define CONFIG_LOAD_GLOBAL			OPTION_GLOBAL_CONFIG_ONLY
#define CONFIG_LOAD_USER			OPTION_USER_CONFIG_ONLY

#define SET_FLAG(var,flag)    (var |= flag)
#define UNSET_FLAG(var,flag)  (var &= ~flag)
#define TEST_FLAG(var,flag)   (var & flag)

#define DEST_AUTO      0
#define DEST_BSSID     1
#define DEST_MULTICAST 2
#define DEST_SOURCE    3

// The default network priority that is assigned to all networks that
// don't explicitly list a priority.
#define DEFAULT_PRIORITY  0xff

// The timer that we use to determine when we need to retransmit.  This 
// should probably be tied in to a lower layer timer, but for now, we
// will use a #define.
#define IDLE_WHILE_TIMER  32

// If a WEP key sits around for more than the timeout below, we should barf
// out a warning letting the user know that their data isn't as secure as
// it could be.
#define STALE_KEY_WARN_TIMEOUT 600   // 10 minutes.

// The amount of time we should wait before we assume an authentication will
// not be able to succeed.
#define AUTHENTICATION_TIMEOUT  32   // 32 seconds.

// The length of time to wait before we assume an assocation failed. (Defined
// by 802.11i section 8.1.3 as dot11RSNAConfigSA-Timeout.)  Default is 60, but
// we may want to provide the ability to change this in the future.
#define ASSOCIATION_TIMEOUT           60    // in seconds.

// The amount of time that needs to pass before we assume a connection is dead, and ask the user if we should
// roam to a new one.
#define DEAD_CONN_TIMEOUT			  15    // in seconds.

// The length of time to wait before we attempt another passive scan.
#define PASSIVE_TIMEOUT               30   // in seconds.

// The length of time to wait before we attempt another active scan.
#define RESCAN_TIMEOUT                30    // in seconds.

// The length of time to stay in HELD state.
#define HELD_STATE_TIMEOUT            60    // in seconds.

// The length of time before we assume a PSK connection will fail.
#define PSK_FAILURE_TIMEOUT			  10    // in seconds.

// The maximum number of starts to send before we assume that we are on a device that doesn't
// understand 802.1X, and switch to authenticated state.
#define MAX_STARTS                    3

// The default size (in MB) to roll the log file at.
#define LOG_SIZE_TO_ROLL              10    // MB
#define OLD_LOGS_TO_KEEP              3     // How many old log files should we keep around.

#define PMKSA_DEFAULT_AGEOUT_TIME     300   ///< The amount of time to keep a stale PMKSA around when the AP isn't visible anymore.
#define PMKSA_CACHE_REFRESH           10    ///< The amount of time between cache refresh/updates.

/*** EAP Type IDs (Only for EAP types that are implemented!!) ***/

// Bogus invalid EAP method # that indicates that we are talking about
// static WEP.
#define EAP_TYPE_MD5        4
#define EAP_TYPE_OTP        5
#define EAP_TYPE_GTC        6
#define EAP_TYPE_TLS        13
#define EAP_TYPE_LEAP       17
#define EAP_TYPE_SIM        18
#define EAP_TYPE_TTLS       21
#define EAP_TYPE_AKA        23
#define EAP_TYPE_PEAP       25
#define EAP_TYPE_MSCHAPV2   26
#define EAP_TYPE_TNC        38   /* tentative assignment per TNC_IFT_v1_0_r3 */
                                 /* (Section 7.1.3, page 27) */
#define EAP_TYPE_FAST       43
#define EAP_TYPE_PSK		47

// Phase 2 Types for TTLS
#define TTLS_PHASE2_PAP       1
#define TTLS_PHASE2_CHAP      2
#define TTLS_PHASE2_MSCHAP    3
#define TTLS_PHASE2_MSCHAPv2  4

int config_system_setup(char *);
int config_load_user_config(char *);					
void config_destroy();
struct config_connection *config_get_connections(uint8_t);
struct config_profiles *config_get_profiles(uint8_t);
int config_delete_connection(uint8_t, char *);
int config_delete_profile(uint8_t, char *);
int config_delete_trusted_server(uint8_t, char *);
int config_delete_interface(char *);
void config_create_new_config();
void config_terminate();
struct config_globals *config_get_globals();
struct config_plugins *config_get_plugins();
void reset_config_globals(struct config_globals *);
int add_change_config_connections(uint8_t, struct config_connection *);
int add_change_config_profiles(uint8_t, struct config_profiles *);
int add_change_config_trusted_server(uint8_t, struct config_trusted_server *);
int add_change_config_interface(struct xsup_interfaces *confif);
int add_change_config_plugins(struct config_plugins *confplug);
struct xsup_interfaces *config_get_config_ints();
struct xsup_interfaces *config_find_int(char *);
uint8_t config_get_network_priority(char *);
struct config_connection *config_find_connection_from_ssid(uint8_t, char *);
uint8_t config_get_friendly_warnings();
uint8_t config_get_idleWhile();
struct config_connection *config_find_connection(uint8_t, char *);
struct config_profiles *config_find_profile(uint8_t, char *);
char *config_get_pwd_from_profile(struct config_eap_method *);
struct config_trusted_servers *config_get_trusted_servers(uint8_t);
int config_set_new_globals(struct config_globals *);
char *config_get_inner_user_from_profile(struct config_eap_method *);

void delete_config_ip_data(struct config_connection *);
void delete_config_association(struct config_connection *);

// * private functions for config code
void delete_config_eap_tls(struct config_eap_tls **);
void dump_config_eap_tls(struct config_eap_tls *);

void delete_config_eap_fast(struct config_eap_fast **);
void dump_config_eap_fast(struct config_eap_fast *);

void delete_config_eap_tnc(struct config_eap_tnc **);
void dump_config_eap_tnc(struct config_eap_tnc *);

void delete_config_pwd_only(struct config_pwd_only **);
void dump_config_pwd_only(struct config_pwd_only *, char *, int);

void delete_config_ttls_phase2(struct config_eap_ttls *);
void delete_config_ttls_eap(struct config_eap_method **);
void dump_config_ttls_phase2(struct config_eap_ttls *);

void delete_config_eap_ttls(struct config_eap_ttls **);
void dump_config_eap_ttls(struct config_eap_ttls *);

void delete_config_eap_mschapv2(struct config_eap_mschapv2 **);
void dump_config_eap_mschapv2(struct config_eap_mschapv2 *, int);

void delete_config_eap_peap(struct config_eap_peap **);
void dump_config_eap_peap(struct config_eap_peap *);

void delete_config_eap_sim(struct config_eap_sim **);
void dump_config_eap_sim(struct config_eap_sim *, int);

void delete_config_eap_aka(struct config_eap_aka **);
void dump_config_eap_aka(struct config_eap_aka *, int);

void delete_config_eap_method(struct config_eap_method **);
void dump_config_eap_method(struct config_eap_method *, int);

void initialize_config_connections(struct config_connection **);
void delete_config_single_connection(struct config_connection **);
void delete_config_connections(struct config_connection **);
void dump_config_connections(struct config_connection *);

void initialize_config_globals(struct config_globals **);
void delete_config_globals(struct config_globals **);
void dump_config_globals(struct config_globals *);

void delete_config_profiles(struct config_profiles **);

void delete_config_data();
void dump_config_data();

int config_change_pwd(struct config_eap_method *, char *);
void delete_config_trusted_server(struct config_trusted_server **);
void delete_config_interface(struct xsup_interfaces **);


#endif
