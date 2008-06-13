/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file ipc_callout.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _IPC_CALLOUT_H_
#define _IPC_CALLOUT_H_

#ifndef WINDOWS
#include <sys/socket.h>
#endif
#include <libxml/parser.h>

/**
 *  Error/warning/deprecated codes (and their meanings) that can be sent over the IPC channel.
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
#define IPC_ERROR_CANT_LOGOFF         309   // Attempt to change to logoff state failed.
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
#define IPC_ERROR_INVALID_OU_NAME     325   // Couldn't locate the requested OU.
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
#define IPC_ERROR_SSID_NOT_FOUND      348   // The requested SSID is not found in the scan cache.

/**
 *  Result values.
 **/
#define IPC_TIMEOUT                   -1
#define IPC_FAILURE                   -2
#define IPC_SUCCESS                    0    // Anything >= this is a success.
#define IPC_FUNCTION_NOT_FOUND        -3
#define IPC_CHANGE_TO_EVENT_ONLY     100    // Convert this socket to an event only socket.
#define IPC_CHANGE_TO_SYNC_ONLY      110    // Convert this socket to request/response only.

#define AUTH_STATE_STOPPED    1
#define AUTH_STATE_RESTART    2
#define AUTH_STATE_START      3
#define AUTH_STATE_RUNNING    4

// Define if the configuration file tells us that a connection will be encrypted or not.
#define CONNECTION_ENC_NONE     1   ///< Configuration information says we will have no encryption enabled.
#define CONNECTION_ENC_ENABLED  2   ///< Configuration information says we will have encryption enabled.  (i.e. It is 802.1X with dynamic WEP, or some variation of WPA/WPA2)
#define CONNECTION_ENC_UNKNOWN  3   ///< We can't determine if encryption will be used or not from the information in the config file.

// Flags that indicate status for possible connections.
#define POSS_CONN_INT_AVAIL     0x01  ///< Set to 1 if the interface needed for a connection is available.
#define POSS_CONN_IS_WIRELESS   0x02  ///< Set to 1 if the interface is wireless
#define POSS_CONN_IS_HIDDEN     0x04  ///< Set to 1 if the SSID is configured as Hidden in the configuration.
#define POSS_CONN_SSID_KNOWN    0x08  ///< Set to 1 if the SSID was found in the scan cache.
#define POSS_CONN_INT_UNKNOWN   0x10  ///< Set to 1 if the interface isn't found in the live cache, or the configuration.  (Should almost NEVER happen!)
#define POSS_CONN_LINK_STATE    0x20  ///< Set to 1 if the link is up, set to 0 if it is down.
#define POSS_CONN_NO_PWD        0x40  ///< Set to 1 if the EAP method doesn't want a password to be set.

void ipc_callout_init();
void ipc_callout_deinit();

uint8_t ipc_callout_process(uint8_t *, int, uint8_t **, int *);
int ipc_callout_convert_amp(char *, char **);

xmlDocPtr ipc_callout_build_doc();

/**
 *  Functions that handle IPC commands.
 *
 *  All functions should be of the format :
 *    int ipc_callout_XXX(xmlNodePtr innode, xmlNodePtr *outnode);
 *
 *  Functions should return 0 if there are no errors, and -1 if there are.
 *
 **/
int ipc_callout_ping(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_live_interfaces(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_eap_methods(xmlNodePtr, xmlNodePtr *);
// ipc_callout_enum_sc_readers() is not implemented yet!
int ipc_callout_reload_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_terminate(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_1x_state(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_eap_state(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_backend_state(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_physical_state(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_pairwise_key_type(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_group_key_type(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_eap_type_in_use(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_ssid(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_bssid(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_seconds_authenticated(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_signal_strength_percent(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_connections(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_connection_upw(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_association_type(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_logoff(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_device_name(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_connection_upw(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_connection_pw(xmlNodePtr, xmlNodePtr *);
int ipc_callout_change_socket_type(xmlNodePtr, xmlNodePtr *);
int ipc_callout_change_connection(xmlNodePtr, xmlNodePtr *);
int ipc_callout_disassociate(xmlNodePtr, xmlNodePtr *);
int ipc_callout_stop(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_ip_data(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_profiles(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_trusted_servers(xmlNodePtr, xmlNodePtr *);
int ipc_callout_write_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_globals(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_profile(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_connection(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_trusted_server_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_interface_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_managed_network_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_managed_networks(xmlNodePtr, xmlNodePtr *);
int ipc_callout_delete_managed_network(xmlNodePtr, xmlNodePtr *);
int ipc_callout_delete_connection_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_delete_profile_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_delete_trusted_server_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_delete_interface_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_globals_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_connection_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_profile_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_trusted_server_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_managed_network_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_config_interfaces(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_known_ssids(xmlNodePtr, xmlNodePtr *);
int ipc_callout_wireless_scan(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_version_string(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_root_ca_certs(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_cert_info(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_tnc_request_response(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_os_specific_int_data(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_conn_from_int(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_interface_config(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_error_queue(xmlNodePtr, xmlNodePtr *);
int ipc_callout_enum_possible_connections(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_unbind_connection(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_rename_connection(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_rename_profile(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_rename_trusted_server(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_device_desc(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_link_state_for_int(xmlNodePtr, xmlNodePtr *);
int ipc_callout_request_create_trouble_ticket(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_interface_capabilities(xmlNodePtr, xmlNodePtr *);
int ipc_callout_add_cert_to_store(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_tnc_conn_id(xmlNodePtr, xmlNodePtr *);
int ipc_callout_set_conn_lock(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_interface_from_tnc_connid(xmlNodePtr, xmlNodePtr *);
int ipc_callout_dhcp_release_renew(xmlNodePtr, xmlNodePtr *);
int ipc_callout_get_frequency(xmlNodePtr, xmlNodePtr *);

#endif  // _IPC_CALLOUT_H_
