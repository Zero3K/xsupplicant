/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_events_index.h
 *
 * \author chris@open1x.org
 *
 **/
#ifndef __IPC_EVENTS_INDEX_H__
#define __IPC_EVENTS_INDEX_H__

// Error Events
#define IPC_EVENT_ERROR_CANT_START_SCAN                        1   ///< The supplicant failed to start a scan.  Error was : %s.
#define IPC_EVENT_ERROR_TIMEOUT_WAITING_FOR_ID                 2   ///< The supplicant timed out waiting for the authentication to start.  It is likely that the authentication server has failed.
#define IPC_EVENT_ERROR_TIMEOUT_DURING_AUTH                    3   ///< The supplicant timed out during the authentication.  (See log for more details.)
#define IPC_EVENT_ERROR_MALLOC                                 4   ///< Failed to allocate memory in function %s.
#define IPC_EVENT_ERROR_GET_MAC                                5   ///< Failed to get the MAC address of interface %s.
#define IPC_EVENT_ERROR_CANT_CREATE_WIRELESS_CTX               6   ///< Failed to create wireless context for interface %s.
#define IPC_EVENT_ERROR_SEND_FAILED                            7   ///< Failed to send frame on interface %s.  (See log for more details.)
#define IPC_EVENT_ERROR_GETTING_INT_INFO                       8   ///< Failed to get interface information for interface %s.
#define IPC_EVENT_ERROR_GETTING_SCAN_DATA                      9   ///< Failed to get scan data for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_802_11_AUTH_MODE        10  ///< Failed to set the 802.11 authentication mode for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_802_11_ENC_MODE         11  ///< Failed to set the 802.11 encryption mode for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_802_11_INFRA_MODE       12  ///< Failed to set the 802.11 infrastructure mode for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_SSID                    13  ///< Failed to set the SSID for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_BSSID                   14  ///< Failed to set the BSSID (MAC address) for interface %s.
#define IPC_EVENT_ERROR_FAILED_GETTING_BSSID                   15  ///< Failed to get the BSSID (MAC address) for interface %s.
#define IPC_EVENT_ERROR_FAILED_GETTING_SSID                    16  ///< Failed to get the SSID for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_WEP_KEY                 17  ///< Failed to set WEP key for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_TKIP_KEY                18  ///< Failed to set TKIP key for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_CCMP_KEY                19  ///< Failed to set CCMP key for interface %s.
#define IPC_EVENT_ERROR_FAILED_SETTING_UNKNOWN_KEY             20  ///< Failed to set unknown key type for interface %s.
#define IPC_EVENT_ERROR_OVERFLOW_ATTEMPTED                     21  ///< There was an attempt to overflow a buffer in %s().
#define IPC_EVENT_ERROR_INVALID_KEY_REQUEST                    22  ///< The authenticator requested encryption keys from %s which doesn't support it! 
#define IPC_EVENT_ERROR_RESTRICTED_HOURS                       23  ///< The account you are attempting to use is restricted to specific hours.  (Please see your system administrator.)
#define IPC_EVENT_ERROR_ACCT_DISABLED                          24  ///< Your user account has been disabled.  (Please see your system administrator.)
#define IPC_EVENT_ERROR_PASSWD_EXPIRED                         25  ///< Your password has expired.  Please see your system administrator to reset it.
#define IPC_EVENT_ERROR_NO_PERMS                               26  ///< Your account does not have permission to use this network.
#define IPC_EVENT_ERROR_CHANGING_PASSWD                        27  ///< There was an error changing your password.
#define IPC_EVENT_ERROR_TEXT                                   28  ///< The following error has occurred : %s
#define IPC_EVENT_ERROR_FAILED_AES_UNWRAP                      29  ///< Failed AES key unwrap on interface %s.
#define IPC_EVENT_ERROR_UNKNOWN_KEY_REQUEST                    30  ///< An unknown WPA/WPA2 key type was requested on interface %s.
#define IPC_EVENT_ERROR_INVALID_PTK                            31  ///< The attempt to generate the PTK failed for interface %s.
#define IPC_EVENT_ERROR_IES_DONT_MATCH                         32  ///< The information element provided during association and the one during the handshake don't match for interface %s!
#define IPC_EVENT_ERROR_PMK_UNAVAILABLE                        33  ///< The Premaster Key was unavailable on interface %s.
#define IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD                    34  ///< The root CA certificate couldn't be loaded.
#define IPC_EVENT_ERROR_TLS_DECRYPTION_FAILED                  35  ///< TLS decryption failed.
#define IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN                    36  ///< The supplicant has terminated operation.
#define IPC_EVENT_ERROR_NO_IPC_SLOTS                           37  ///< Insufficient IPC slots to connect a new IPC client.
#define IPC_EVENT_ERROR_UNKNOWN_EAPOL_KEY_TYPE                 38  ///< The AP has requested the use of an encryption method we don't understand.
#define IPC_EVENT_ERROR_INVALID_MIC_VERSION                    39  ///< The AP requested the use of a MIC type we don't understand.
#define IPC_EVENT_ERROR_UNKNOWN_PEAP_VERSION                   40  ///< The server attempted to use an unknown PEAP version.
#define IPC_EVENT_ERROR_NO_WCTX                                41  ///< Interface %s doesn't have a valid wireless context!  Flagging it as invalid!
#define IPC_EVENT_ERROR_CANT_RENEW_DHCP                        42  ///< Unable to renew IP address via DHCP.  Some network functionality may be limited.
#define IPC_EVENT_ERROR_CANT_ADD_CERT_TO_STORE                 43  ///< Unable to add the certificate to the certificate store.
#define IPC_EVENT_ERROR_CANT_READ_FILE                         44  ///< Unable to read the requested file.
#define IPC_EVENT_ERROR_CERT_CHAIN_IS_INVALID                  45  ///< The certificate chain requested is invalid.  (See logs for more details.)
#define IPC_EVENT_ERROR_NOT_SUPPORTED                          46  ///< You attempted to use %s, which your card reports it doesn't support.
#define IPC_EVENT_ERROR_SIM_READER_NOT_FOUND				   47  ///< The requested SIM reader was not found.
#define IPC_EVENT_ERROR_SIM_CANT_CONNECT					   48  ///< Unable to connect to the requested SIM card reader.
#define IPC_EVENT_ERROR_SIM_CARD_NOT_READY					   49  ///< The SIM card or reader is not ready.
#define IPC_EVENT_ERROR_NO_SIM_READERS						   50  ///< There were no SIM card readers found on this machine.
#define IPC_EVENT_ERROR_NO_PIN								   51  ///< No PIN was provided to be used to authentication.
#define IPC_EVENT_ERROR_BAD_PIN_MORE_ATTEMPTS				   52  ///< Invalid PIN.  At least one more attempt remains.
#define IPC_EVENT_ERROR_BAD_PIN_CARD_BLOCKED				   53  ///< Invalid PIN.  Your card is now blocked.
#define IPC_EVENT_ERROR_3G_NOT_SUPPORTED					   54  ///< Inserted SIM doesn't support 3G mode.
#define IPC_EVENT_ERROR_UNKNOWN_SIM_ERROR					   55  ///< An unknown SIM error occurred.
#define IPC_EVENT_ERROR_SIM_NOTIFICATION					   56  ///< A SIM notification was generated, the number is provided in the parameter field.
#define IPC_EVENT_ERROR_TLS_HANDSHAKE_FAILED				   57  ///< Authentication failed.  (Reason : %s)

// Windows Specific Error Events 
#define IPC_EVENT_ERROR_FAILED_TO_BIND                         1000 ///< Failed to bind interface %s to device handle.
#define IPC_EVENT_ERROR_FAILED_TO_GET_HANDLE                   1001 ///< Failed to get handle for device %s.
#define IPC_EVENT_ERROR_EVENT_HANDLE_FAILED                    1002 ///< Failed to get event handle for interface %s.
#define IPC_EVENT_ERROR_WMI_ATTACH_FAILED                      1003 ///< Failed to connection to the WMI handler.
#define IPC_EVENT_ERROR_WMI_ASYNC_FAILED                       1004 ///< Failed to execute async method '%s'.
#define IPC_EVENT_ERROR_WZC_ATTACH_FAILED                      1005 ///< Failed to connect to the WZC control channel.

// Events that may indicate that a UI should do something.
#define IPC_EVENT_UI_IP_ADDRESS_SET                            1   ///< An interface has had it's IP address set.
#define IPC_EVENT_INTERFACE_INSERTED                           2   ///< An interface has been inserted.
#define IPC_EVENT_INTERFACE_REMOVED                            3   ///< An interface has been removed.
#define IPC_EVENT_SIGNAL_STRENGTH                              4   ///< An interface's signal strength is being updated.
#define IPC_EVENT_BAD_PSK                                      5   ///< An interface appears to have a bad WPA(2)-PSK value set.
#define IPC_EVENT_UI_AUTH_TIMEOUT							   6   ///< There was a timeout during the authentication.
#define IPC_EVENT_UI_GOING_TO_SLEEP                            7   ///< The system is entering a sleep mode.
#define IPC_EVENT_UI_SLEEP_CANCELLED                           8   ///< Another process cancelled the sleep attempt.
#define IPC_EVENT_UI_WAKING_UP                                 9   ///< The system is coming out of sleep mode.
#define IPC_EVENT_UI_LINK_UP								   10  ///< The interface's link came up.
#define IPC_EVENT_UI_LINK_DOWN								   11  ///< The interface's link went down.
#define IPC_EVENT_UI_INT_CTRL_CHANGED						   12  ///< The supplicant changed it's control posture.
#define IPC_EVENT_UI_TROUBLETICKET_DONE						   13  ///< The requested trouble ticket has been created successfully.
#define IPC_EVENT_UI_TROUBLETICKET_ERROR					   14  ///< The requested trouble ticket couldn't be created.
#define IPC_EVENT_UI_NEED_UPW								   15  ///< The supplicant needs a username and password to be able to complete this connection.
#define IPC_EVENT_UI_POST_CONNECT_TIMEOUT					   16  ///< The supplicant has been disconnect for some period of time.  So prompt the user to see if they want to try to connect to something else.
#define IPC_EVENT_UI_CONNECTION_DISCONNECT					   17  ///< The supplicant has disconnected the connection for interface %s.
#define IPC_EVENT_PSK_SUCCESS								   18  ///< The PSK connection completed successfully.
#define IPC_EVENT_8021X_FAILED								   19  ///< The 802.1X connection failed due to invalid credentials.
#define IPC_EVENT_PSK_TIMEOUT								   20  ///< The PSK connection attempt timed out.
#define IPC_EVENT_CONNECTION_UNBOUND						   21  ///< The connection was unbound from interface %s.
#define IPC_EVENT_AUTO_SELECTED_CONNECTION					   22  ///< A connection was automagically selected based on prioritization information.
#define IPC_EVENT_OTHER_SUPPLICANT_POSSIBLE					   23  ///< Another supplicant may be operating on this system.

// State machines that we may get state machine events for. 
#define IPC_STATEMACHINE_PHYSICAL                              1   ///< Identify the physical state machine
#define IPC_STATEMACHINE_8021X                                 2   ///< Identify the 802.1X primary state machine
#define IPC_STATEMACHINE_8021X_BACKEND                         3   ///< Identify the 802.1X back end state machine
#define IPC_STATEMACHINE_EAP                                   4   ///< Identify the EAP state machine.

#endif // __IPC_EVENTS_INDEX_H__



