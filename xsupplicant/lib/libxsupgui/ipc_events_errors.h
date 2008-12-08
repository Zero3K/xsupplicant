/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_events_errors.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __IPC_EVENTS_ERRORS_H__
#define __IPC_EVENTS_ERRORS_H__

// Error Events (Be sure to update the switch statement in xsupgui_events.c if you add anything!
#define IPC_EVENT_ERROR_CANT_START_SCAN_STR                    "The supplicant failed to start a scan.  Error was : %s."
#define IPC_EVENT_ERROR_TIMEOUT_WAITING_FOR_ID_STR             "The supplicant timed out waiting for the authentication to start.  It is likely that the authentication server has failed."
#define IPC_EVENT_ERROR_TIMEOUT_DURING_AUTH_STR                "The supplicant timed out during the authentication.  (See log for more details.)"
#define IPC_EVENT_ERROR_MALLOC_STR                             "Failed to allocate memory in function %s."
#define IPC_EVENT_ERROR_GET_MAC_STR                            "Failed to get the MAC address of interface %s."
#define IPC_EVENT_ERROR_CANT_CREATE_WIRELESS_CTX_STR           "Failed to create wireless context for interface %s."
#define IPC_EVENT_ERROR_SEND_FAILED_STR                        "Failed to send frame on interface %s.  (See log for more details.)"
#define IPC_EVENT_ERROR_GETTING_INT_INFO_STR                   "Failed to get interface information for interface %s."
#define IPC_EVENT_ERROR_GETTING_SCAN_DATA_STR                  "Failed to get scan data for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_802_11_AUTH_MODE_STR    "Failed to set the 802.11 authentication mode for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_802_11_ENC_MODE_STR     "Failed to set the 802.11 encryption mode for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_802_11_INFRA_MODE_STR   "Failed to set the 802.11 infrastructure mode for interface %s.   Please be sure that your wireless card drivers are current."
#define IPC_EVENT_ERROR_FAILED_SETTING_SSID_STR                "Failed to set the SSID for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_BSSID_STR               "Failed to set the BSSID (MAC address) for interface %s."
#define IPC_EVENT_ERROR_FAILED_GETTING_BSSID_STR               "Failed to get the BSSID (MAC address) for interface %s."
#define IPC_EVENT_ERROR_FAILED_GETTING_SSID_STR                "Failed to get the SSID for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_WEP_KEY_STR             "Failed to set WEP key for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_TKIP_KEY_STR            "Failed to set TKIP key for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_CCMP_KEY_STR            "Failed to set CCMP key for interface %s."
#define IPC_EVENT_ERROR_FAILED_SETTING_UNKNOWN_KEY_STR         "Failed to set unknown key type for interface %s."
#define IPC_EVENT_ERROR_OVERFLOW_ATTEMPTED_STR                 "There was an attempt to overflow a buffer in %s()."
#define IPC_EVENT_ERROR_INVALID_KEY_REQUEST_STR                "The authenticator requested encryption keys from %s which doesn't support it!"
#define IPC_EVENT_ERROR_RESTRICTED_HOURS_STR                   "The account you are attempting to use is restricted to specific hours.  (Please see your system administrator.)"
#define IPC_EVENT_ERROR_ACCT_DISABLED_STR                      "Your user account has been disabled.  (Please see your system administrator.)"
#define IPC_EVENT_ERROR_PASSWD_EXPIRED_STR                     "Your password has expired.  Please see your system administrator to reset it."
#define IPC_EVENT_ERROR_NO_PERMS_STR                           "Your account does not have permission to use this network."
#define IPC_EVENT_ERROR_CHANGING_PASSWD_STR                    "There was an error changing your password."
#define IPC_EVENT_ERROR_TEXT_STR                               "The following error has occurred : %s"
#define IPC_EVENT_ERROR_FAILED_AES_UNWRAP_STR                  "Failed AES key unwrap on interface %s."
#define IPC_EVENT_ERROR_UNKNOWN_KEY_REQUEST_STR                "An unknown WPA/WPA2 key type was requested on interface %s."
#define IPC_EVENT_ERROR_INVALID_PTK_STR                        "The attempt to generate the PTK failed for interface %s."
#define IPC_EVENT_ERROR_IES_DONT_MATCH_STR                     "The information element provided during association and the one during the handshake don't match for interface %s!"
#define IPC_EVENT_ERROR_PMK_UNAVAILABLE_STR                    "The Premaster Key was unavailable on interface %s."
#define IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD_STR                "The root CA certificate couldn't be loaded."
#define IPC_EVENT_ERROR_TLS_DECRYPTION_FAILED_STR              "TLS decryption failed."
#define IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN_STR                "The supplicant has terminated operation."
#define IPC_EVENT_ERROR_NO_IPC_SLOTS_STR                       "Insufficient IPC slots to connect a new IPC client."
#define IPC_EVENT_ERROR_UNKNOWN_EAPOL_KEY_TYPE_STR             "The AP has requested the use of an encryption method we don't understand."
#define IPC_EVENT_ERROR_INVALID_MIC_VERSION_STR                "The AP requested the use of a MIC type we don't understand."
#define IPC_EVENT_ERROR_UNKNOWN_PEAP_VERSION_STR               "The server attempted to use an unknown PEAP version."
#define IPC_EVENT_ERROR_NO_WCTX_STR                            "Interface %s doesn't have a valid wireless context!  Flagging it as invalid!"
#define IPC_EVENT_ERROR_CANT_RENEW_DHCP_STR                    "Unable to renew IP address via DHCP.  Some network functionality may be limited."
#define IPC_EVENT_ERROR_CANT_ADD_CERT_TO_STORE_STR             "Unable to add the certificate to the certificate store."
#define IPC_EVENT_ERROR_CANT_READ_FILE_STR                     "Unable to read the requested file."
#define IPC_EVENT_ERROR_CERT_CHAIN_IS_INVALID_STR              "The certificate chain requested is invalid.  (See logs for more details.)"
#define IPC_EVENT_ERROR_NOT_SUPPORTED_STR                      "You attempted to use %s, which your card reports it doesn't support."
#define IPC_EVENT_ERROR_SIM_READER_NOT_FOUND_STR			   "SIM card reader '%s' isn't currently available.  Please connect it and try again."
#define IPC_EVENT_ERROR_SIM_CANT_CONNECT_STR				   "Error connecting to smart card reader '%s'!"
#define IPC_EVENT_ERROR_SIM_CARD_NOT_READY_STR				   "The SIM card or reader is not ready."
#define IPC_EVENT_ERROR_NO_SIM_READERS_STR					   "There were no SIM card readers found on this machine."
#define IPC_EVENT_ERROR_NO_PIN_STR							   "No PIN was provided to be used for authentication."
#define IPC_EVENT_ERROR_BAD_PIN_MORE_ATTEMPTS_STR			   "Invalid PIN.  At least one more attempt remains."
#define IPC_EVENT_ERROR_BAD_PIN_CARD_BLOCKED_STR			   "Invalid PIN.  Your card is now blocked."
#define IPC_EVENT_ERROR_3G_NOT_SUPPORTED_STR				   "Inserted SIM doesn't support 3G mode."
#define IPC_EVENT_ERROR_UNKNOWN_SIM_ERROR_STR				   "An unknown SIM error occurred."
#define IPC_EVENT_ERROR_SIM_NOTIFICATION_STR				   "A SIM notification was generated, the number is provided in the parameter field."

// Windows Specific Error Events 
#define IPC_EVENT_ERROR_FAILED_TO_BIND_STR                     "Failed to bind interface %s to device handle."
#define IPC_EVENT_ERROR_FAILED_TO_GET_HANDLE_STR               "Failed to get handle for device %s."
#define IPC_EVENT_ERROR_EVENT_HANDLE_FAILED_STR                "Failed to get event handle for interface %s."
#define IPC_EVENT_ERROR_WMI_ATTACH_FAILED_STR                  "Failed to connection to the WMI handler."
#define IPC_EVENT_ERROR_WMI_ASYNC_FAILED_STR                   "Failed to execute async method '%s'."
#define IPC_EVENT_ERROR_WZC_ATTACH_FAILED_STR				   "Failed to connect to the WZC control channel."

#endif // __IPC_EVENTS_ERRORS_H__
