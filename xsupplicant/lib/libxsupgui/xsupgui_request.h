/**
 * \file xsupgui_request.h
 *
 * \author chris@open1x.org
 *
 * Windows specific IPC implementation for Xsupplicant.
 *
 * \note This header file covers xsupgui_request.c, xsupgui_request2.c, etc.
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2006-2007 Chris Hessing
 * All Rights Reserved
 *
 * --- GPL Version 2 License ---
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * --- BSD License ---
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  - All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by the University of
 *       Maryland at College Park and its contributors.
 *  - Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _XSUPGUI_REQUEST_H_
#define _XSUPGUI_REQUEST_H_


#include "libxsupconfig/xsupconfig_structs.h"
#include <libxml/parser.h>

#ifndef TRUE
#define TRUE   1
#endif

#ifndef FALSE
#define FALSE  0
#endif

#define OPTION_GLOBAL_CONFIG_ONLY	BIT(0)
#define OPTION_USER_CONFIG_ONLY		BIT(1)
#define OPTION_ANY_CONFIG			(BIT(0) | BIT(1))

#define CONFIG_LOAD_GLOBAL			OPTION_GLOBAL_CONFIG_ONLY
#define CONFIG_LOAD_USER			OPTION_USER_CONFIG_ONLY

/**
 *  Result values.
 **/
#define REQUEST_TIMEOUT                   -1
#define REQUEST_FAILURE                   -2
#define REQUEST_SUCCESS                    0    // Anything >= this is a success.
#define REQUEST_NOT_IMPLEMENTED           -3

/**
 * Event classes that the supplicant might send us.
 **/
#define IPC_EVENT_LOG            1
#define IPC_EVENT_ERROR          2
#define IPC_EVENT_STATEMACHINE   3
#define IPC_EVENT_SCAN_COMPLETE  4
#define IPC_EVENT_REQUEST_PWD    5
#define IPC_EVENT_UI             6
#define IPC_EVENT_TNC_UI         7
#define IPC_EVENT_TNC_UI_REQUEST 8
#define IPC_EVENT_TNC_UI_BATCH_REQUEST 9
#define IPC_EVENT_COM_BROKEN     10  // The communication with the supplicant has been broken.  (The supplicant probably crashed.)

/**
 *  Error codes (and their meanings) that can be sent over the IPC channel.
 *
 *  Since these error codes will usually be used as a return value of a function,
 *  we want to start them at 100 to allow plenty of room for other error space.
 **/
#define IPC_ERROR_NONE                300   // No error.
#define IPC_ERROR_CANT_ALLOCATE_NODE  301   // Unable the allocate a node in the XML tree.
#define IPC_ERROR_UNKNOWN_REQUEST     302   // Requested information we know nothing about.
#define IPC_ERROR_CANT_LOCATE_NODE    303   // Couldn't find the node we needed in a request.
#define IPC_ERROR_INVALID_INTERFACE   304   // Couldn't locate the interface that was requested.
#define IPC_ERROR_INVALID_CONTEXT     305   // The context requested didn't contain all of the 
											//    information we needed.
#define IPC_ERROR_INVALID_BSSID       306   // We don't know a valid BSSID.  (The card is probably
											// not associated!)
#define IPC_ERROR_INVALID_SIGNAL_STRENGTH  307  // The signal strength value isn't available.
#define IPC_ERROR_INVALID_REQUEST     308   // The request didn't contain the information needed.
#define IPC_ERROR_INTERFACE_NOT_FOUND 310   // The interface requested was not found.
#define IPC_ERROR_COULDNT_CHANGE_UPW  311   // The username and/or password couldn't be changed.
#define IPC_ERROR_INVALID_ROOT_NODE   312   // The root node in the request was invalid.
#define IPC_ERROR_INVALID_CONN_NAME   313   // The connection name requested was invalid.
#define IPC_ERROR_INVALID_PROF_NAME   314   // The profile name requested was invalid.
#define IPC_ERROR_INT_NOT_WIRELESS    315   // The requested interface is not wireless.
#define IPC_ERROR_CANT_GET_IP         316   // Couldn't obtain the IP address for requested interface!
#define IPC_ERROR_CANT_GET_NETMASK    317   // Couldn't obtain the netmask for requested interface.
#define IPC_ERROR_CANT_GET_GATEWAY    318   // Couldn't obtain the default gateway for requested interface.
#define IPC_ERROR_CANT_FIND_SSID      319   // Couldn't locate the requested SSID in the SSID cache.
#define IPC_ERROR_NO_INTERFACES       320   // The supplicant is not currently managing any interfaces.
#define IPC_ERROR_INVALID_FILE        321   // The filename requested is invalid.
#define IPC_ERROR_CANT_WRITE_CONFIG   322   // Couldn't write the configuration file!
#define IPC_ERROR_INVALID_NODE        323   // Couldn't locate node %s!
#define IPC_ERROR_CANT_GET_CONFIG     324   // Couldn't get requested configuration information!
#define IPC_ERROR_CONFIG_CONFLICT     325   // Attempted to create a connection/profile/trusted server in a configuration, when the other configuration already has one by the same name.
#define IPC_ERROR_INVALID_TRUSTED_SVR 326   // Couldn't locate the requested trusted server.
#define IPC_ERROR_PARSING             327   // Attempt to parse requested configuration block failed.
#define IPC_ERROR_MALLOC              328   // Failed to allocate memory!
#define IPC_ERROR_CANT_CHANGE_CONFIG  329   // Failed to change requested configuration data.
#define IPC_ERROR_CANT_PASSIVE_SCAN   330   // The OS doesn't know how to passive scan, or the interface won't allow it.
#define IPC_ERROR_UNKNOWN_SCAN_ERROR  331   // An unhandled error occurred while attempting to scan.
#define IPC_ERROR_CERT_STORE_ERROR    332   // An error occurred obtaining access to the certificate store.
#define IPC_ERROR_CANT_GET_CERT_INFO  333   // Unable to locate the certificate information requested.
#define IPC_ERROR_BAD_TNC_UI_RESPONSE 334   // The attempt to trigger the response to a TNC UI request failed.
#define IPC_ERROR_INTERFACE_IN_USE    335   // The requested interface is already in use.
#define IPC_ERROR_NO_CONNECTION       336   // The interface doesn't have a connection assigned.
#define IPC_ERROR_NEW_ERRORS_IN_QUEUE 337   // There are errors to be read from the error queue.
#define IPC_ERROR_CANT_DEL_CONN_IN_USE 338  // Cannot delete the connection.  It is currently in use.
#define IPC_ERROR_CANT_GET_SYS_UPTIME 339   // Unable to determine the system uptime.
#define IPC_ERROR_NEED_USERNAME       340   // No username was provided for an EAP authentication.
#define IPC_ERROR_NEED_PASSWORD       341   // No password was provided for the authentication.
#define IPC_ERROR_CANT_RENAME         342   // Unable to rename connection/profile/trusted server.
#define IPC_ERROR_STILL_IN_USE        343   // The profile/trusted server is still in use and cannot be deleted.
#define IPC_ERROR_NAME_IN_USE         344   // The connection/profile/trusted server name is already in use.
#define IPC_ERROR_GEN_TROUBLE_TICKET  345   // An unrecoverable error occurred while generating trouble tickets.
#define IPC_ERROR_FILE_EXISTS         346   // A request was made to overwrite a file that already exists.
#define IPC_ERROR_NOT_SUPPORTED		  347   // The request is not supported.
#define IPC_ERROR_NOT_ALLOWED		  348   // The requested operation is not allowed while the supplicant is in its current state.
#define IPC_ERROR_SSID_NOT_FOUND      349   // The requested SSID is not found in the scan cache.
#define IPC_ERROR_REQUEST_FAILED	  350   // The operation requested failed.
#define IPC_ERROR_CONFIG_NOT_DEFINED  351	// The type of configuration was not defined.
#define IPC_ERROR_USER_NOT_ADMIN	  352	// The requested action can only be performed by an administrative user.
#define IPC_ERROR_INVALID_CONFIG	  353   // The configuration type (i.e. system level or user level) was invalid.

// Error messages that can be generated by xsupgui internal calls.
#define IPC_ERROR_CANT_FIND_RESPONSE  1000  // The required response header was not found in the response message.
#define IPC_ERROR_CANT_CREATE_REQUEST 1001  // The XML request document couldn't be created.
#define IPC_ERROR_CANT_CREATE_REQ_HDR 1002  // Unable to create the XML document framework.
#define IPC_ERROR_UNSPEC_REQ_FAILURE  1003  // The request failed for an unspecified reason.
#define IPC_ERROR_BAD_RESPONSE        1004  // The response XML document was invalid.
#define IPC_ERROR_CANT_FIND_REQ_ROOT_NODE 1005  // The root node in the request document couldn't be located.
#define IPC_ERROR_CANT_CREATE_INT_NODE 1006 // The <Interface> node couldn't be created for the request.
#define IPC_ERROR_CANT_FIND_RESP_ROOT_NODE 1007 // The root node in the response document couldn't be located.
#define IPC_ERROR_INVALID_PARAMETERS  1008  // The parameters passed in to the function were invalid.
#define IPC_ERROR_NULL_DOCUMENT       1009  // The document presented to the function is NULL.
#define IPC_ERROR_NO_ERROR_CODE       1010  // Got an error document that didn't contain an error code node.
#define IPC_ERROR_NULL_RESPONSE       1011  // The response document from the supplicant was NULL or didn't contain valid information.
#define IPC_ERROR_NULL_REQUEST        1012  // The request document was NULL or invalid after conversion.
#define IPC_ERROR_BAD_RESPONSE_DATA   1013  // The data included in the response document was invalid, or could not be parsed.
#define IPC_ERROR_CANT_ALLOCATE_MEMORY 1014  // Unable to allocate memory to store response data.
#define IPC_ERROR_NOT_ACK             1015  // The response was not the ACK that was expected.
#define IPC_ERROR_NOT_PONG            1016  // The response to a PING request was not a PONG.
#define IPC_ERROR_INVALID_RESP_DATA   1017  // The response data didn't pass validation tests.
#define IPC_ERROR_CANT_ADD_NODE       1018  // The function was unable to add the newly created node to the existing tree.
#define IPC_ERROR_INVALID_NUMBER_OF_EVENTS 1019 // The number of events specified in the return document was invalid.
#define IPC_ERROR_CANT_SEND_IPC_MSG   1020  // Unable to send IPC message to the supplicant.
#define IPC_ERROR_SEND_SIZE_MISMATCH  1021  // The data to send was a different size than the data that was sent.
#define IPC_ERROR_UNABLE_TO_READ      1022  // Data appeared to be ready, but couldn't be read.
#define IPC_ERROR_RECV_IPC_RUNT       1023  // Received an IPC runt fragment.
#define IPC_ERROR_CANT_MALLOC_LOCAL   1024  // Unable to malloc memory in the local process.
#define IPC_ERROR_NOT_INITIALIZED     1025  // A variable was not properly initialized.
#define IPC_ERROR_STALE_BUFFER_DATA   1026  // There was stale data in the event buffer.
#define IPC_ERROR_CTRL_ALREADY_CONNECTED 1027 // The IPC control channel was already connected.
#define IPC_ERROR_CTRL_NOT_CONNECTED  1028  // The IPC control channel is not connected.
#define IPC_ERROR_EVT_ALREADY_CONNECTED 1029 // The event channel was already connected.
#define IPC_ERROR_EVT_NOT_CONNECTED   1030  // The event channel is not connected.
#define IPC_ERROR_RUNT_RESPONSE       1031  // The response data was not large enough to be a valid response.
#define IPC_ERROR_READ_DEFAULT_FAILURE 1032 // There was an unknown reason that the overlapped I/O completed.

// State machines that we may get state machine events for. 
#define IPC_STATEMACHINE_PHYSICAL                              1   ///< Identify the physical state machine
#define IPC_STATEMACHINE_8021X                                 2   ///< Identify the 802.1X primary state machine
#define IPC_STATEMACHINE_8021X_BACKEND                         3   ///< Identify the 802.1X back end state machine
#define IPC_STATEMACHINE_EAP                                   4   ///< Identify the EAP state machine.

// Different types of authentication that are allowed.
#define AUTH_UNKNOWN               0
#define AUTH_NONE                  1
#define AUTH_PSK                   2
#define AUTH_EAP                   3

// Data type that will be returned for an enum_ints request.
typedef struct {
	char *name;
	char *desc;
	unsigned char is_wireless;
} int_enum;

typedef struct {
	char *mac;
	char *desc;
	unsigned char is_wireless;
	char *default_connection;
} int_config_enum;

typedef struct {
	char *name;
	char *desc;
} namedesc_enum;

typedef struct _cert_enum {
	char *storetype;
	char *certname;
	char *friendlyname;
	char *issuer;
	char *commonname;
	char *location;
	uint16_t month;
	uint16_t day;
	uint16_t year;
} cert_enum;

typedef struct {
	char *name;
	uint8_t config_type;
} profile_enum;

#define CONNECTION_ENC_NONE     1   ///< Configuration information says we will have no encryption enabled.
#define CONNECTION_ENC_ENABLED  2   ///< Configuration information says we will have encryption enabled.  (i.e. It is 802.1X with dynamic WEP, or some variation of WPA/WPA2)
#define CONNECTION_ENC_UNKNOWN  3   ///< We can't determine if encryption will be used or not from the information in the config file.

typedef struct {
	char *name;
	char *ssid;
	uint8_t config_type;		  ///< Which configuration did this entry come from.
	char *dev_desc;               // Device description.  You need to feed this in to 
								  // xsupgui_request_get_devname() to get the OS level device
	char encryption;              ///< Can be one of the CONNECTION_ENC_*.
	int priority;
	int auth_type;                ///< Will be one of the AUTH_* values above.
	int assoc_type;               ///< Will be one of the ASSOC_TYPE_* values below.
								
} conn_enum;

// Flags that indicate status for possible connections.
#define POSS_CONN_INT_AVAIL     0x01  ///< Set to 1 if the interface needed for a connection is available.
#define POSS_CONN_IS_WIRELESS   0x02  ///< Set to 1 if the interface is wireless
#define POSS_CONN_IS_HIDDEN     0x04  ///< Set to 1 if the SSID is configured as Hidden in the configuration.
#define POSS_CONN_SSID_KNOWN    0x08  ///< Set to 1 if the SSID was found in the scan cache.
#define POSS_CONN_INT_UNKNOWN   0x10  ///< Set to 1 if the interface isn't found in the live cache, or the configuration.  (Should almost NEVER happen!)
#define POSS_CONN_LINK_STATE    0x20  ///< Set to 1 if the link is up, set to 0 if it is down.
#define POSS_CONN_NO_PWD        0x40  ///< Set to 1 if the EAP method doesn't want a password to be set.

typedef struct {
	char *name;
	char *ssid;
	int   flags;                  ///< Flags for this connection as defined by POSS_CONN_* above.
								  ///<  *NOTE* : This will be set to 1 if the SSID is found in the SSID cache for the interface this connection is bound to.  It is possible, though unlikely, that the SSID may be seen by another interface.  In that case, this will still show 0!
	char *dev_desc;               // Device description.  You need to feed this in to 
								  // xsupgui_request_get_devname() to get the OS level device
	char encryption;              ///< Can be one of the CONNECTION_ENC_*.
	int priority;
	int auth_type;                ///< Will be one of the AUTH_* values above.
								
} poss_conn_enum;

typedef struct {
	char *name;
	uint8_t config_type;
} trusted_servers_enum;

typedef struct {
	char *name;
	unsigned char num;
} eap_enum;

typedef struct {
	char *ipaddr;
	char *gateway;
	char *netmask;
	char *dns1;
	char *dns2;
	char *dns3;
} ipinfo_type;

typedef struct {
	char *ssidname;
	uint16_t abil;       ///< A bitmap made up of ABILITY_* #define values.
	uint8_t percentage;
} ssid_info_enum;

typedef struct {
	char *errmsgs;
} error_messages;

typedef struct _cert_info {
	char *C;                   ///< The Country Field in the Certificate
	char *S;                   ///< The State Field in the Certificate
	char *L;                   ///< The Location Field in the Certificate
	char *O;                   ///< The Organization Field in the Certificate
	char *OU;                  ///< The Organizational Unit Field in the Certificate
	char *CN;                  ///< The Common Name Field in the Certificate
} cert_info;

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
typedef struct {
	uint8_t flag_byte;
	uint32_t length;
} ipc_header;
#else
struct _ipc_header {
  uint8_t flag_byte;
  uint32_t length;
} __attribute__((__packed__));

typedef struct _ipc_header ipc_header;
#endif

#ifdef WINDOWS
#pragma pack()
#endif

#define IPC_MSG_COMPLETE       0x00     ///< With this packet, the IPC message is complete.
#define IPC_MSG_TOTAL_SIZE     BIT(0)   ///< The four bytes in the header indicate the total size of the message.
#define IPC_MSG_MORE_FRAGS     BIT(1)   ///< There are additional fragments coming.
#define IPC_MSG_FRAG_SIZE      BIT(2)   ///< The four bytes in the header indicate the total size of this fragment.


/**
 *  Values for the 802.1X state machine states.
 **/
// This matches the order of states listed in IEEE 802.1X-2001, pg. 59,
// section 8.5.10.  (NOTE: These should match the values of the same name in
//                         statemachine.h!)
#define LOGOFF           1
#define DISCONNECTED     2
#define CONNECTING       3
#define ACQUIRED         4
#define AUTHENTICATING   5
#define HELD             6
#define AUTHENTICATED    7

// 802.1X-REV-d11 (2004) specifies a few additional states.  Also, in EAPoL
// v2, the ACQUIRED state no longer exists.
#define RESTART          8
#define S_FORCE_AUTH     9
#define S_FORCE_UNAUTH   10

/**
 * Values for the 802.1X backend state machine.  These MUST sync up with the 
 * values in backend_sm.h!
 **/
#define BACKEND_UNKNOWN     0
#define BACKEND_REQUEST     1
#define BACKEND_RESPONSE    2
#define BACKEND_SUCCESS     3
#define BACKEND_FAIL        4
#define BACKEND_TIMEOUT     5
#define BACKEND_IDLE        6
#define BACKEND_INITIALIZE  7
#define BACKEND_RECEIVE     8

/**
 * Values for the physical state machine.  (Only wireless for now.)
 **/
#define WIRELESS_UNKNOWN_STATE         0
#define WIRELESS_UNASSOCIATED          1
#define WIRELESS_ASSOCIATED            2
#define WIRELESS_ACTIVE_SCAN           3    // There may be a passive scan later.
#define WIRELESS_ASSOCIATING           4    // Attempting to associate
#define WIRELESS_ASSOCIATION_TIMEOUT_S 5
// State 6 has been removed.
#define WIRELESS_PORT_DOWN             7    // The interface is down state.
#define WIRELESS_NO_ENC_ASSOCIATION    8  
#define WIRELESS_INT_RESTART           9    // Restart everything.
#define WIRELESS_INT_STOPPED           10   // Stop answering requests.
#define WIRELESS_INT_HELD              11   // Hold the authentication, waiting for an event.

/**
 * Cipher types that can be used.  These defines need to
 * stay in sync with the values in wpa_common.h.
 **/
#define CIPHER_NONE         0x00
#define CIPHER_WEP40        0x01
#define CIPHER_TKIP         0x02
#define CIPHER_WRAP         0x03
#define CIPHER_CCMP         0x04
#define CIPHER_WEP104       0x05

/**
 * Values for the EAP state machine.  These MUST sync up with the values in
 * eap_sm.h of the same name!
 **/
#define EAP_UNKNOWN        0
#define EAP_DISABLED       1
#define EAP_INITIALIZE     2
#define EAP_IDLE           3
#define EAP_RECEIVED       4
#define EAP_GET_METHOD     5
#define EAP_METHOD         6
#define EAP_SEND_RESPONSE  7
#define EAP_DISCARD        8
#define EAP_IDENTITY       9
#define EAP_NOTIFICATION   10
#define EAP_RETRANSMIT     11
#define EAP_SUCCESS        12
#define EAP_FAILURE        13

/**
 * Different values for the type of association that was used to connect to a 
 *  wireless network.
 **/
#define ASSOC_TYPE_UNKNOWN      0
#define ASSOC_TYPE_OPEN         1
#define ASSOC_TYPE_SHARED       2
#define ASSOC_TYPE_LEAP         3
#define ASSOC_TYPE_WPA1         4
#define ASSOC_TYPE_WPA2         5

// Abilities that will be stored in the SSID cache, for a "quick look" at
// what the SSID supports.
#define ABILITY_ENC       0x0002
#define ABILITY_WPA_IE    0x0004
#define ABILITY_RSN_IE    0x0008
#define ABILITY_WPA_DOT1X 0x0010
#define ABILITY_WPA_PSK	  0x0020
#define ABILITY_RSN_DOT1X 0x0040
#define ABILITY_RSN_PSK   0x0080
#define ABILITY_DOT11_STD 0x0100		// Straight 802.11  (1 or 2 MBps, DSS or FH)
#define ABILITY_DOT11_A	  0x0200		// 802.11a (54Mbps (max) 5.8 Ghz, OFDM)
#define	ABILITY_DOT11_B	  0x0400		// 802.11b (11Mbps (max) 2.4 Ghz, DSS)
#define ABILITY_DOT11_G	  0x0800		// 802.11g (54Mbps (max) 2.4 Ghz, OFDM)
#define ABILITY_DOT11_N	  0x1000		// 802.11n (???Mbps (max) 2.4 or 5.8 Ghz, MIMO)
 
// Different encryption/authentication modes that are supported.  (Since
// any interface should be able to do 802.1X, we don't flag that here.)
// These are the capability values returned from xsupgui_request_get_interface_capabilities().
#define DOES_WPA                      0x00000001
#define DOES_WPA2                     0x00000002
#define DOES_WEP40                    0x00000004
#define DOES_WEP104                   0x00000008
#define DOES_TKIP                     0x00000010
#define DOES_CCMP                     0x00000020

/**
 * Calls that operate on things that are outside the configuration file.  (Live data,
 * calls to start and stop various things in the supplicant, etc.)
 */
int xsupgui_request_enum_eap_methods(eap_enum **eaptypes);
int xsupgui_request_get_1x_state(char *device, int *);
int xsupgui_request_get_eap_state(char *device, int *);
int xsupgui_request_get_backend_state(char *device, int *);
int xsupgui_request_get_physical_state(char *device, int *);
int xsupgui_request_get_pairwise_key_type(char *device, int *);
int xsupgui_request_get_group_key_type(char *device, int *);
int xsupgui_request_get_eap_type_in_use(char *device, int *);
int xsupgui_request_get_ip_info(char *device, ipinfo_type **info);
int xsupgui_request_set_connection(char *device, char *conn_name);
int xsupgui_request_get_connection_upw(char *conn_name, char **username, char **password, int *authtype);
int xsupgui_request_set_connection_upw(char *conn_name, char *username, char *password);
int xsupgui_request_set_connection_pw(char *conn_name, char *password);
int xsupgui_request_set_disassociate(char *device, unsigned char reason);
int xsupgui_request_get_signal_strength_percent(char *device, int *strength);
int xsupgui_request_get_seconds_authenticated(char *device, long int *seconds);
int xsupgui_request_get_association_type(char *device, int *assoctype);
int xsupgui_request_ping();
int xsupgui_request_terminate();
int xsupgui_request_stop(char *device);
int xsupgui_request_logoff(char *device);
int xsupgui_request_get_devname(char *dev_desc, char **device);
int xsupgui_request_get_devdesc(char *device, char **dev_desc);
int xsupgui_request_enum_live_ints(int_enum **retints);
int xsupgui_request_enum_ssids(char *device, ssid_info_enum **ssids);
int xsupgui_request_wireless_scan(char *, uint8_t);
int xsupgui_request_version_string(char **);
int xsupgui_request_enum_root_ca_certs(cert_enum **);
int xsupgui_request_ca_certificate_info(char *, char *, cert_info **);
int xsupgui_request_answer_tnc_ui_request(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
int xsupgui_request_get_os_specific_int_data(char *, char **, char **, int *);
int xsupgui_request_get_ssid(char *device, char **ssid);
int xsupgui_request_get_bssid(char *device, char **bssid);
int xsupgui_request_get_conn_name_from_int(char *intname, char **connname);
int xsupgui_request_get_error_msgs(error_messages **);
int xsupgui_request_enum_possible_connections(poss_conn_enum **connections);
int xsupgui_request_unbind_connection(char *device);
int xsupgui_request_create_trouble_ticket_file(char *filename, char *scratchdir, int overwrite);
int xsupgui_request_get_interface_capabilities(char *device, int *capabilities);
int xsupgui_request_get_link_state_from_int(char *intname, int *state);
int xsupgui_request_add_root_ca_certificate(char *filename);
int xsupgui_request_get_tnc_conn_id(char *device, unsigned int *tnc_conn_id);
int xsupgui_request_set_connection_lock(char *intname, int endis);
int xsupgui_request_intname_from_tnc_conn_id(unsigned int tnc_conn_id, char **intname);
int xsupgui_request_dhcp_release_renew(char *intname);
int xsupgui_request_get_freq(char *device, unsigned int *freq);
int xsupgui_request_disconnect_connection(char *device);
int xsupgui_request_get_are_doing_psk(char *device, int *state);
int xsupgui_request_get_is_connection_in_use(char *conname, int *intuse);
int xsupgui_request_get_is_profile_in_use(char *profname, int *inuse);
int xsupgui_request_get_is_trusted_server_in_use(char *tsname, int *inuse);
int xsupgui_request_get_are_administrator(int *admin);
int xsupgui_request_enum_smartcard_readers(char ***readers);

/** 
 * Calls that operate on the configuration file structures.  (Things that will become
 * part of the configuration file once a write request is executed.)
 */
int xsupgui_request_enum_ints_config(int_config_enum **retints);
int xsupgui_request_enum_profiles(uint8_t config_type, profile_enum **profs);
int xsupgui_request_enum_connections(uint8_t, conn_enum **);
int xsupgui_request_reload_config();
int xsupgui_request_get_globals_config(config_globals **globals);
int xsupgui_request_get_profile_config(uint8_t config_type, char *prof_name, config_profiles **prof_config);
int xsupgui_request_get_connection_config(uint8_t config_type, char *conn_name, config_connection **conn_config);
int xsupgui_request_get_interface_config(char *intdesc, config_interfaces **int_config);
int xsupgui_request_get_trusted_server_config(uint8_t config_type, char *servname, config_trusted_server **ts_config);
int xsupgui_request_set_trusted_server_config(uint8_t config_type, config_trusted_server *);
int xsupgui_request_set_connection_config(uint8_t config_type, config_connection *conn_config);
int xsupgui_request_set_profile_config(uint8_t config_type, config_profiles *prof_config);
int xsupgui_request_set_interface_config(config_interfaces *int_config);
int xsupgui_request_set_globals_config(config_globals *globals);
int xsupgui_request_delete_profile_config(uint8_t config_type, char *prof_name, int force);
int xsupgui_request_delete_connection_config(uint8_t config_type, char *conn_name);
int xsupgui_request_delete_interface_config(char *intdesc);
int xsupgui_request_delete_trusted_server_config(uint8_t config_type, char *servname, int force);
int xsupgui_request_delete_some_conf(char *deletefrom, char *searchtag, char *searchitem, uint8_t config_type, int force);
int xsupgui_request_enum_trusted_servers(uint8_t, trusted_servers_enum **);
int xsupgui_request_write_config(uint8_t, char *);
int xsupgui_request_rename_connection(uint8_t, char *, char *);
int xsupgui_request_rename_trusted_server(uint8_t, char *, char *);
int xsupgui_request_rename_profile(uint8_t, char *, char *);

/**
 * Calls to free the values returned from "live" data calls
 */
int xsupgui_request_free_eap_enum(eap_enum **);
int xsupgui_request_free_ip_info(ipinfo_type **);
int xsupgui_request_free_int_enum(int_enum **);
int xsupgui_request_free_ssid_enum(ssid_info_enum **);
void xsupgui_request_free_cert_enum(cert_enum **);
void xsupgui_request_free_cert_info(cert_info **);
void xsupgui_request_free_error_msgs(error_messages **);
int xsupgui_request_free_poss_conn_enum(poss_conn_enum **);
int xsupgui_request_free_enum_smartcard_readers(char ***);

/**
 * Calls to free the values returned from the configuration file calls.
 */
int xsupgui_request_free_int_config_enum(int_config_enum **);
int xsupgui_request_free_namedesc_enum(namedesc_enum **);
int xsupgui_request_free_profile_enum(profile_enum **);
int xsupgui_request_free_conn_enum(conn_enum **);
int xsupgui_request_free_trusted_servers_enum(trusted_servers_enum **);
int xsupgui_request_free_config_globals(config_globals **);
int xsupgui_request_free_profile_config(config_profiles **);
int xsupgui_request_free_connection_config(config_connection **);
int xsupgui_request_free_interface_config(config_interfaces **);
int xsupgui_request_free_trusted_server_config(config_trusted_server **);


/**
 * Calls to free generic data types.
 */
int xsupgui_request_free_str(char **);


/**
 * Utility calls for functions in the library.  (A UI normally won't use these.)
 */
int xsupgui_request_is_ack(xmlDocPtr);   
int xsupgui_request_set_as_event(char **, int *);
xmlNodePtr xsupgui_request_find_node(xmlNodePtr, char *);

int xsupgui_request_send(xmlDocPtr indoc, xmlDocPtr *outdoc);
int xsupgui_request_check_exceptions(xmlDocPtr indoc);

int xsupgui_request_get_some_value(char *device, char *state_request, char *state_response, char *response_key, int *result);
int xsupgui_request_get_byte_string(char *device, char *request, char *response,char *response_key, char **result);
int xsupgui_request_get_long_int(char *device, char *request, char *response, char *response_key, long int *result);
     
#endif // _XSUPGUI_REQUEST_H_
