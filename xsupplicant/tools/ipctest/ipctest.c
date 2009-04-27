/**
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipctest.c
 *
 * \author chris@open1x.org
 *
 **/

#ifndef WINDOWS
#include <unistd.h>
#endif

#include <string.h>

#include <libxml/parser.h>

#include "libxsupgui/xsupgui.h"
#include "libxsupgui/xsupgui_xml_common.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupgui/xsupgui_request.h"

#ifdef WINDOWS
#include "src/stdintwin.h"
#else
#define _strdup strdup
#endif

#include "src/getopts.h"

// Terminate the IPC test program.
void die()
{
	printf("Disconnecting.\n");
	xsupgui_disconnect();
	_exit(1);
}

/**
 * \brief Issue a ping request to the supplicant, and display the result from that
 *        request.
 **/
void doping()
{
	int err = 0;

	printf("Sending a ping..\n\n");
	err = xsupgui_request_ping();

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Ping success!\n");
		break;

	case REQUEST_TIMEOUT:
		printf("Ping timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Got error %d!\n", err);
		die();
		break;
	}
}

void build_tt()
{
	int err = 0;

	printf("Requesting a trouble ticket be built...\n");
	err =
	    xsupgui_request_create_trouble_ticket_file("c:\\tt.zip", "c:\\", 1);
	switch (err) {
	case REQUEST_SUCCESS:
		printf("Success!\n");
		break;

	case REQUEST_TIMEOUT:
		printf("timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Got error %d!\n", err);
		die();
		break;
	}
	printf("\n");
}

void add_cert()
{
	int err = 0;

	printf("Requesting a new root CA cert be added...\n");
	err = xsupgui_request_add_root_ca_certificate("c:\\root.der");
	switch (err) {
	case REQUEST_SUCCESS:
		printf("Success!\n");
		break;

	case REQUEST_TIMEOUT:
		printf("timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Got error %d!\n", err);
		die();
		break;
	}
	printf("\n");
}

/**
 * \brief Issue a request to reload the configuration file.
 **/
void doreload()
{
	int err = 0;

	printf("Requesting a config reload...");
	err = xsupgui_request_reload_config();

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Success!\n");
		break;

	case REQUEST_TIMEOUT:
		printf("timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Got error %d!\n", err);
		die();
		break;
	}
	printf("\n");
}

/**
 *  \brief Ask the supplicant to terminate itself.
 **/
void doterminate()
{
	int err = 0;

	printf("Requesting the supplicant terminate...");
	err = xsupgui_request_terminate();

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Success!\n");
		break;

	case REQUEST_TIMEOUT:
		printf("timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Got error %d!\n", err);
		die();
		break;
	}

	printf("\n");
}

/**
 * \brief Display all of the fields that are returned for each trusted server.
 **/
void docerts_list(trusted_servers_enum * data)
{
	int i = 0;

	if (data == NULL) {
		printf("NONE!\n");
		return;
	}

	while (data[i].name != NULL) {
		printf("%s\n", data[i].name);
		i++;
	}
	printf("\n");
}

/**
 * \brief Request that we enumerate all of the trusted servers that are currently in the
 *        supplicant's memory.
 **/
void docerts_enum_helper(uint8_t config_type)
{
	trusted_servers_enum *mydata = NULL;
	int err = 0;

	printf("Requesting a list of trusted servers..\n\n");
	err = xsupgui_request_enum_trusted_servers(config_type, &mydata);

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Trusted Server(s) are :\n");
		docerts_list(mydata);
		xsupgui_request_free_trusted_servers_enum(&mydata);
		break;

	case REQUEST_TIMEOUT:
		printf("Trusted Servers enum request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error getting trusted servers list!\n");
		die();
		break;

	default:
		printf("Error : %d\n", err);
		//die();
		break;
	}
}

void docerts_enum()
{
	printf(" ----- System Level Trusted Servers ------\n");
	docerts_enum_helper(CONFIG_LOAD_GLOBAL);
	printf(" ----- User Level Trusted Servers -----\n");
	docerts_enum_helper(CONFIG_LOAD_USER);
	printf(" ----- All Trusted Servers -----\n");
	docerts_enum_helper((CONFIG_LOAD_USER | CONFIG_LOAD_GLOBAL));
}

/**
 * \brief Display all of the fields that are returned for each interface
 *        when we enumerate all interfaces.
 **/
void doint_list(int_enum * data)
{
	int i = 0;

	if (data == NULL) {
		printf("NONE!\n");
		return;
	}

	while (data[i].name != NULL) {
		printf("(%d) %s\n\t%s\n\t%s\n", i + 1, data[i].desc, data[i].name, data[i].friendlyName);
		if (data[i].is_wireless == 1) {
			printf("\t\tInterface is Wireless!\n");
		} else {
			printf("\t\tInterface is NOT wireless!\n");
		}
		i++;
	}
	printf("\n");
}

/**
 * \brief Request that we enumerate all of the interfaces that the supplicant
 *        currently knows about.
 **/
void doint_enum()
{
	int_enum *mydata = NULL;
	int err = 0;

	printf("Requesting a list of interfaces..\n\n");
	err = xsupgui_request_enum_live_ints(&mydata);

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Interfaces are :\n");
		doint_list(mydata);
		break;

	case REQUEST_TIMEOUT:
		printf("Interface list request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error getting interface list!\n");
		die();
		break;

	default:
		printf("Error : %d\n", err);
		die();
		break;
	}

	xsupgui_request_free_int_enum(&mydata);
}

/**
 * \brief Display all of the fields that are returned for each interface
 *        when we enumerate all interfaces.
 **/
void doint_conf_list(int_config_enum * data)
{
	int i = 0;

	if (data == NULL) {
		printf("NONE!\n");
		return;
	}

	while (data[i].desc != NULL) {
		printf("(%d) %s -- %s\n", i + 1, data[i].desc, data[i].mac);
		i++;
	}
	printf("\n");
}

/**
 * \brief Request that we enumerate all of the interfaces that the supplicant
 *        configuration file currently knows about.
 **/
void doint_conf_enum()
{
	int_config_enum *mydata = NULL;
	int err = 0;

	printf
	    ("Requesting a list of interfaces (from the configuration)..\n\n");
	err = xsupgui_request_enum_ints_config(&mydata);

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Interfaces are :\n");
		doint_conf_list(mydata);
		break;

	case REQUEST_TIMEOUT:
		printf("Interface list request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error getting interface list!\n");
		die();
		break;

	default:
		printf("Error : %d\n", err);
		die();
		break;
	}

	xsupgui_request_free_int_config_enum(&mydata);
}

void doprof_list(profile_enum * profs)
{
	int i = 0;

	while (profs[i].name != NULL) {
		printf("\tProfile : %s\n", profs[i].name);
		i++;
	}
	printf("\n");
}

/**
 * \brief Request that we enumerate all of the profiles that are currently in the
 *        supplicant's memory.
 **/
void doprof_enum_helper(uint8_t config_type)
{
	profile_enum *mydata = NULL;
	int err = 0;

	printf("Requesting a list of profiles..\n\n");
	err = xsupgui_request_enum_profiles(config_type, &mydata);

	switch (err) {
	case REQUEST_SUCCESS:
		printf("Profiles are :\n");
		doprof_list(mydata);
		break;

	case REQUEST_TIMEOUT:
		printf("Profile enum request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error getting interface list!\n");
		die();
		break;

	default:
		printf("Error : %d\n", err);
		die();
		break;
	}

	xsupgui_request_free_profile_enum(&mydata);
}

void doprof_enum()
{
	printf("  ----- Listing System Level Profiles -----\n");
	doprof_enum_helper(CONFIG_LOAD_GLOBAL);

	printf("  ----- Listing User Level Profiles -----\n");
	doprof_enum_helper(CONFIG_LOAD_USER);

	printf("  ----- Listing All Profiles -----\n");
	doprof_enum_helper((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER));
}

/**
 * \brief  Display information about each EAP type that came from the request to
 *         enumerate known EAP types.
 **/
void doeap_list(eap_enum * data)
{
	int i = 0;

	if (data == NULL) {
		printf("NONE!\n");
		return;
	}

	while (data[i].name != NULL) {
		printf("(%d) %s - Type %d\n", i + 1, data[i].name, data[i].num);
		i++;
	}
	printf("\n");
}

/**
 * \brief Request that the supplicant enumerate all of the EAP methods that it was
 *        built with.
 **/
void doeap_enum()
{
	eap_enum *mydata = NULL;
	int err = 0;

	printf("Requesting a list of EAP methods..\n\n");
	err = xsupgui_request_enum_eap_methods(&mydata);

	switch (err) {
	case REQUEST_SUCCESS:
		printf("EAP methods are :\n");
		doeap_list(mydata);
		break;

	case REQUEST_TIMEOUT:
		printf("EAP method list request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error getting EAP method list!\n");
		die();
		break;

	default:
		printf("Error : %d\n", err);
		die();
		break;
	}

	xsupgui_request_free_eap_enum(&mydata);
}

/**
 *  \brief Request the state of the 802.1X state machine, and display display
 *         a string that identifies the state.
 *
 *  @param[in] intname   The OS specific interface name.
 **/
void doget1xstate(char *intname)
{
	int result;

	printf("802.1X state for test interface : ");
	if (xsupgui_request_get_1x_state(intname, &result) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	switch (result) {
	case LOGOFF:
		printf("LOGOFF\n");
		break;

	case DISCONNECTED:
		printf("DISCONNECTED\n");
		break;

	case CONNECTING:
		printf("CONNECTING\n");
		break;

	case ACQUIRED:
		printf("ACQUIRED\n");
		break;

	case AUTHENTICATING:
		printf("AUTHENTICATING\n");
		break;

	case HELD:
		printf("HELD\n");
		break;

	case AUTHENTICATED:
		printf("AUTHENTICATED\n");
		break;

	case RESTART:
		printf("RESTART\n");
		break;

	case S_FORCE_AUTH:
		printf("S_FORCE_AUTH\n");
		break;

	case S_FORCE_UNAUTH:
		printf("S_FORCE_UNAUTH\n");
		break;

	default:
		printf("Unknown value %d!\n", result);
		break;
	}
	printf("\n");
}

/**
 *  \brief  Request that the supplicant tell us what state the EAP state machine
 *          is currently in.
 **/
void dogeteapstate(char *device)
{
	int retval = 0;

	printf("EAP state for test interface : ");
	if (xsupgui_request_get_eap_state(device, &retval) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	switch (retval) {
	case EAP_UNKNOWN:
		printf("UNKNOWN\n");
		break;

	case EAP_DISABLED:
		printf("DISABLED\n");
		break;

	case EAP_INITIALIZE:
		printf("INITIALIZE\n");
		break;

	case EAP_IDLE:
		printf("IDLE\n");
		break;

	case EAP_RECEIVED:
		printf("RECEIVED\n");
		break;

	case EAP_GET_METHOD:
		printf("GET_METHOD\n");
		break;

	case EAP_METHOD:
		printf("METHOD\n");
		break;

	case EAP_SEND_RESPONSE:
		printf("SEND_RESPONSE\n");
		break;

	case EAP_DISCARD:
		printf("DISCARD\n");
		break;

	case EAP_IDENTITY:
		printf("IDENTITY\n");
		break;

	case EAP_NOTIFICATION:
		printf("NOTIFICATION\n");
		break;

	case EAP_RETRANSMIT:
		printf("RETRANSMIT\n");
		break;

	case EAP_SUCCESS:
		printf("SUCCESS\n");
		break;

	case EAP_FAILURE:
		printf("FAILURE\n");
		break;

	default:
		printf("Got unknown state %d.\n", retval);
		break;
	}
	printf("\n");
}

/**
 *  \brief  Request that the supplicant give us the state that the backend state
 *          machine is currently in.  Then, display it in a human readable format.
 *
 *  @param[in] device   The OS specific name for the device to query.
 **/
void dogetbackendstate(char *device)
{
	int retval = 0;

	printf("802.1X backend state for test interface : ");
	if (xsupgui_request_get_backend_state(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed\n");
		die();
	}

	switch (retval) {
	case 255:
		printf("Hasn't run!\n");
		break;

	case BACKEND_UNKNOWN:
		printf("UNKNOWN\n");
		break;

	case BACKEND_REQUEST:
		printf("REQUEST\n");
		break;

	case BACKEND_RESPONSE:
		printf("RESPONSE\n");
		break;

	case BACKEND_SUCCESS:
		printf("SUCCESS\n");
		break;

	case BACKEND_FAIL:
		printf("FAIL\n");
		break;

	case BACKEND_TIMEOUT:
		printf("TIMEOUT\n");
		break;

	case BACKEND_IDLE:
		printf("IDLE\n");
		break;

	case BACKEND_INITIALIZE:
		printf("INITIALIZE\n");
		break;

	case BACKEND_RECEIVE:
		printf("RECEIVE\n");
		break;

	default:
		printf("Got error %d.\n", retval);
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request that the supplicant tell us the state that the physical state
 *          machine is currently in.
 *
 *  @param[in] device   The OS specific name for the device we want to know about.
 *
 *  \note The physical device state machine doesn't map to any IEEE or IETF standard.
 *        It is internal to the supplicant.
 **/
void dogetphysicalstate(char *device)
{
	int retval = 0;

	printf("Physical state for test interface : ");
	if (xsupgui_request_get_physical_state(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	switch (retval) {
	case WIRELESS_UNKNOWN_STATE:
		printf("UNKNOWN_STATE\n");
		break;

	case WIRELESS_UNASSOCIATED:
		printf("UNASSOCIATED\n");
		break;

	case WIRELESS_ASSOCIATED:
		printf("ASSOCIATED\n");
		break;

	case WIRELESS_ACTIVE_SCAN:
		printf("ACTIVE_SCAN\n");
		break;

	case WIRELESS_ASSOCIATING:
		printf("ASSOCIATING\n");
		break;

	case WIRELESS_ASSOCIATION_TIMEOUT_S:
		printf("WIRELESS_ASSOCIATION_TIMEOUT_S\n");
		break;

	case WIRELESS_PORT_DOWN:
		printf("PORT_DOWN\n");
		break;

	case WIRELESS_NO_ENC_ASSOCIATION:
		printf("NO_ENC_ASSOCIATION\n");
		break;

	case WIRELESS_INT_RESTART:
		printf("INT_RESTART\n");
		break;

	case WIRELESS_INT_STOPPED:
		printf("INT_STOPPED\n");
		break;

	case WIRELESS_INT_HELD:
		printf("INT_HELD\n");
		break;

	case 255:
		printf("Hasn't run!\n");
		break;

	default:
		printf("Unknown state %d.\n", retval);
		break;
	}

	printf("\n");
}

/**
 *  \brief  Determine the pairwise (unicast) encryption method being used on a 
 *          specific interface.
 *
 *  @param[in] device   The OS specific device name to get the pairwise encryption
 *                      method for.
 **/
void dogetpairwisetype(char *device)
{
	int retval = 0;

	printf("Pairwise Key Type for test interface : ");
	if (xsupgui_request_get_pairwise_key_type(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed\n");
		die();
		return;
	}

	switch (retval) {
	case CIPHER_NONE:
		printf("NONE\n");
		break;

	case CIPHER_WEP40:
		printf("WEP40\n");
		break;

	case CIPHER_TKIP:
		printf("TKIP\n");
		break;

	case CIPHER_WRAP:
		// Shouldn't ever get this!
		printf("WRAP\n");
		break;

	case CIPHER_CCMP:
		printf("CCMP\n");
		break;

	case CIPHER_WEP104:
		printf("WEP104\n");
		break;

	default:
		printf("Unknown cipher : %d\n", retval);
		die();
		break;
	}

	printf("\n");
}

/**
 *  \brief Ask the supplicant what group (multicast/broadcast) encryption method is
 *         currently in use.
 *
 *  @param[in] device   The OS specific device name for the device that we want to know
 *                      the encryption type for.
 **/
void dogetgrouptype(char *device)
{
	int retval = 0;

	printf("Group Key Type for test interface : ");
	if (xsupgui_request_get_group_key_type(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed\n");
		die();
		return;
	}

	switch (retval) {
	case CIPHER_NONE:
		printf("NONE\n");
		break;

	case CIPHER_WEP40:
		printf("WEP40\n");
		break;

	case CIPHER_TKIP:
		printf("TKIP\n");
		break;

	case CIPHER_WRAP:
		// Shouldn't ever get this!
		printf("WRAP\n");
		break;

	case CIPHER_CCMP:
		printf("CCMP\n");
		break;

	case CIPHER_WEP104:
		printf("WEP104\n");
		break;

	default:
		printf("Unknown value : %d\n", retval);
		die();
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request, and display, the SSID that the supplicant is attempting to connect
 *          to on a specific interface.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 *
 *  \note Even if the interface isn't associated to the SSID, it may still return a value.
 *        This call should not be used to determine if an interface is associated or not.
 **/
void dogetssid(char *device)
{
	int retval = 0;
	char *ssid = NULL;

	printf("SSID : ");
	retval = xsupgui_request_get_ssid(device, &ssid);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("Request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Request failed!\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("%s\n", ssid);
		break;

	default:
		printf("Error : %d\n", retval);
		die();
		break;
	}
	printf("\n");

	xsupgui_request_free_str(&ssid);
}

/**
 *  \brief  Request, and display, the BSSID that the supplicant is attempting to connect
 *          to on a specific interface.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void dogetbssid(char *device)
{
	int retval = 0;
	char *bssid = NULL;

	printf("BSSID : ");
	retval = xsupgui_request_get_bssid(device, &bssid);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("Request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Request failed!\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("%s\n", bssid);
		break;

	default:
		printf("Error : %d\n", retval);
		if (retval != IPC_ERROR_INVALID_BSSID)
			die();	// Invalid BSSID probably means we aren't associated.
		break;
	}
	printf("\n");

	xsupgui_request_free_str(&bssid);
}

/**
 *  \brief  Request, and display, the number of seconds that the supplicant has been
 *          in authenticated state.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void dogettimeauthed(char *device)
{
	int retval = 0;
	long int timeauthed = 0;

	printf("Time authenticated : ");
	retval = xsupgui_request_get_seconds_authenticated(device, &timeauthed);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("Request timed out!\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Request failed!\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("%ld second(s)\n", timeauthed);
		break;

	default:
		printf("Error : %d\n", retval);
		die();
		break;
	}
	printf("\n");
}

/**
 *  \brief  Request, and display, the current signal strength for the requested device.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void dogetsignal(char *device)
{
	int retval = 0;

	printf("Signal Strength : ");
	if (xsupgui_request_get_signal_strength_percent(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	if (retval > 100) {
		printf("Error : %d\n", retval);
		die();
	} else {
		printf("%d percent\n", retval);
	}
	printf("\n");
}

/**
 *  \brief  Request, and display, the EAP type that was used for the authentication
 *          on a given device.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void dogeteaptype(char *device)
{
	int retval = 0;

	printf("EAP Type for test interface : ");
	if (xsupgui_request_get_eap_type_in_use(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	switch (retval) {
	case 0:
		printf("EAP hasn't started yet!\n");
		break;

	default:
		printf("Type %d.\n", retval);
		break;
	}

	printf("\n");
}

/**
 * \brief Display information about possible connections to use.
 **/
void show_poss_conns(poss_conn_enum * conn)
{
	int i = 0;

	printf("\n");
	while (conn[i].name != NULL) {
		printf("Connection : %s\n", conn[i].name);
		printf("\tPriority : %d\n", conn[i].priority);
		printf("\tSSID: %s\n", conn[i].ssid);
		printf("\tFlags : %04X\n", conn[i].flags);
		printf("\tAuth  : %d\n", conn[i].auth_type);
		printf("\tEncryption Enabled : ");
		switch (conn[i].encryption) {
		case CONNECTION_ENC_NONE:
			printf("NONE\n");
			break;

		case CONNECTION_ENC_ENABLED:
			printf("Enabled\n");
			break;

		case CONNECTION_ENC_UNKNOWN:
			// Allow this to fall through to the default case.
		default:
			printf("Unknown\n");
			break;
		}

		i++;
	}
}

/**
 * \brief Display information about all of the connections in use.
 **/
void show_conns(conn_enum * conn)
{
	int i = 0;

	printf("\n");
	while (conn[i].name != NULL) {
		printf("Connection : %s\n", conn[i].name);
		printf("\tPriority : %d\n", conn[i].priority);
		printf("\tSSID: %s\n", conn[i].ssid);
		printf("\tEncryption Enabled : ");
		switch (conn[i].encryption) {
		case CONNECTION_ENC_NONE:
			printf("NONE\n");
			break;

		case CONNECTION_ENC_ENABLED:
			printf("Enabled\n");
			break;

		case CONNECTION_ENC_UNKNOWN:
			// Allow this to fall through to the default case.
		default:
			printf("Unknown\n");
			break;
		}

		i++;
	}
}

/**
 *  \brief  Request, and display, the connections that are currently in the supplicant's
 *          memory.
 **/
void dogetconnections_help(uint8_t config_type)
{
	int retval = 0;
	conn_enum *connections = NULL;

	printf("Known connections : ");
	retval = xsupgui_request_enum_connections(config_type, &connections);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("timed out.\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	case REQUEST_SUCCESS:
		show_conns(connections);
		break;

	default:
		printf("Got error %d.\n", retval);
		die();
		break;
	}

	xsupgui_request_free_conn_enum(&connections);
	printf("\n");
}

void dogetconnections()
{
	printf("  ----- System Level Connections -----\n");
	dogetconnections_help(CONFIG_LOAD_GLOBAL);

	printf("  ----- User Level Connections -----\n");
	dogetconnections_help(CONFIG_LOAD_USER);

	printf("  ----- Combined Connections -----\n");
	dogetconnections_help((CONFIG_LOAD_USER | CONFIG_LOAD_GLOBAL));
}

/**
 *  \brief  Request, and display, the username/password for the given connection name.
 *
 *  @param[in] conn_name   The connection name that we want to get the username/password
 *                         from.
 **/
void getupwd(char *conn_name)
{
	int retval = 0;
	char *username = NULL, *password = NULL;
	int err = 0;

	printf("Requested credentials for connection '%s'...", conn_name);
	err =
	    xsupgui_request_get_connection_upw(conn_name, &username, &password,
					       &retval);
	if (err != REQUEST_SUCCESS) {
		printf("Failed   (Error : %d)\n", err);
		die();
		return;
	}

	switch (retval) {
	case AUTH_NONE:
	case AUTH_EAP:
		printf("\n\n Authentication Type : EAP\n");
		printf("Username = %s    Password = %s\n", username, password);
		break;

	case AUTH_PSK:
		printf("\n\n Authentication Type : PSK\n");
		printf("Password = %s\n", password);
		break;

	default:
		printf("Unknown type %d.\n", retval);
		break;
	}

	xsupgui_request_free_str(&username);
	xsupgui_request_free_str(&password);
	printf("\n");
}

void getcapabilities(char *device)
{
	int retval = 0;

	printf("Capabilities : ");
	if (xsupgui_request_get_interface_capabilities(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}
	printf("%04x\n", retval);
}

/**
 *  \brief  Request, and display, the method of association that the supplicant is
 *          attempting to use on this connection.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void getassoctype(char *device)
{
	int retval = 0;

	printf("Association Type : ");
	if (xsupgui_request_get_association_type(device, &retval) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	switch (retval) {
	case ASSOC_TYPE_UNKNOWN:
		printf("Unknown\n");
		break;

	case ASSOC_TYPE_OPEN:
		printf("Open\n");
		break;

	case ASSOC_TYPE_SHARED:
		printf("Shared\n");
		break;

	case ASSOC_TYPE_LEAP:
		printf("LEAP\n");
		break;

	case ASSOC_TYPE_WPA1:
		printf("WPA\n");
		break;

	case ASSOC_TYPE_WPA2:
		printf("WPA2\n");
		break;

	default:
		printf("Unknown type %d.\n", retval);
		die();
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request that the username and password for the specified connection be changed
 *          to a new value.
 *
 *  @param[in] conn_name   The name of the connection to set the username/password for.
 *  @param[in] username   The new username for this connection.
 *  @param[in] password   The new password for this connection.
 **/
void setupwd(char *conn_name, char *username, char *password)
{
	int retval = 0;

	printf("Setting username/password...");
	retval =
	    xsupgui_request_set_connection_upw(conn_name, username, password);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("timed out.\n");
		die();
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("OK\n");
		break;

	default:
		printf("Got error %d.\n", retval);
		die();
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request, that the supplicant change to a new connection.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void dochangeconn(char *device, char *conn)
{
	int retval = 0;

	printf("Requesting connection change to '%s'...", conn);
	retval = xsupgui_request_set_connection(device, conn);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("timed out.\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("OK!\n");
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Error %d.\n", retval);
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request that the supplicant disassociate from the currently associated
 *          network.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void setdisassoc(char *device)
{
	int retval = 0;

	printf("Disassociating....");
	retval = xsupgui_request_set_disassociate(device, 0);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("timed out.\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("OK!\n");
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Error %d.\n", retval);
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request that an interface no longer process events, or frames on a given
 *          interface.  This will cause authentication attempts to be ignored.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 **/
void setpause(char *device)
{
	int retval = 0;

	printf("Pausing....");
	retval = xsupgui_request_stop(device);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("timed out.\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("OK!\n");
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Error %d.\n", retval);
		break;
	}

	printf("\n");
}

/**
 *  \brief  Request, and display, the IP address information for the currently active
 *          connection.
 *
 *  @param[in] device   The OS specific device name that the request is for.
 *
 *  \note It is possible for this request to return success but for any, or all, results
 *        to be NULL.
 **/
void getipaddr(char *device)
{
	int retval = 0;
	ipinfo_type *ipi = NULL;

	printf("Requesting IP information.\n\n");
	retval = xsupgui_request_get_ip_info(device, &ipi);
	switch (retval) {
	case REQUEST_TIMEOUT:
		printf("timed out.\n");
		die();
		break;

	case REQUEST_SUCCESS:
		printf("\tIP Address : %s\n", ipi->ipaddr);
		printf("\tNetmask    : %s\n", ipi->netmask);
		printf("\tGateway    : %s\n", ipi->gateway);
		printf("\tDNS 1      : %s\n", ipi->dns1);
		printf("\tDNS 2      : %s\n", ipi->dns2);
		printf("\tDNS 3      : %s\n", ipi->dns3);
		break;

	case REQUEST_FAILURE:
		printf("Error!\n");
		die();
		break;

	default:
		printf("Error %d.\n", retval);
		die();
		break;
	}

	printf("\n");

	xsupgui_request_free_ip_info(&ipi);
}

/**
 * \brief Ask the supplicant to write it's configuration file to 'test.out'.
 **/
void dowrite_conf(char *filename)
{
	printf("Writing configuration file....");

	if (xsupgui_request_write_config(CONFIG_LOAD_GLOBAL, filename) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
	} else {
		printf("Success.\n");
	}
}

/**
 * \brief Ask the supplicant for the current global settings.
 **/
void doget_globals()
{
	struct config_globals *myglobs;

	printf("Getting global settings...");

	if (xsupgui_request_get_globals_config(&myglobs) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	printf("Success...\n\n");

	printf("Setting for logging is : %s\n", myglobs->logpath);
	printf("Max Starts : %d\n", myglobs->max_starts);
	printf("Auth Period : %d\n", myglobs->auth_period);
	printf("Held Period : %d\n", myglobs->held_period);
}

/**
 * \brief Ask the supplicant for the configuration for a named profile.
 **/
void doget_profile()
{
	struct config_profiles *myprof;

	printf("Getting profile settings...");

	if (xsupgui_request_get_profile_config
	    (CONFIG_LOAD_GLOBAL, "House_TTLS", &myprof) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	printf("Success...\n\n");

	printf("Identity = %s\n", myprof->identity);
}

/**
 * \brief Ask the supplicant for the configuration for a named connection.
 **/
void doget_connection()
{
	struct config_connection *mycon;

	printf("Getting connection settings...");

	if (xsupgui_request_get_connection_config
	    (CONFIG_LOAD_GLOBAL, "Home WPA 2 PSK Network",
	     &mycon) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	printf("Success...\n\n");

	xsupgui_request_free_connection_config(&mycon);
}

/**
 * \brief Ask the supplicant for the trusted server configuration for the named server.
 **/
void doget_ts()
{
	struct config_trusted_server *ts = NULL;
	int i = 0;

	printf("Getting trusted server settings...");

	if (xsupgui_request_get_trusted_server_config
	    (CONFIG_LOAD_GLOBAL, "Equifax Cert Test", &ts) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		//die();
		return;
	}

	printf("Success... (Found %d locations.)\n\n", ts->num_locations);

	for (i = 0; i < ts->num_locations; i++) {
		printf("Location %d = %s\n", i, ts->location[i]);
	}
}

/**
 * \brief Ask the supplicant for configuration information about a specific interface.
 **/
void doget_int()
{
	config_interfaces *ints;

	printf("Getting interface settings...");

	if (xsupgui_request_get_interface_config("Intel IPW3945", &ints) !=
	    REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	printf("Success...\n\n");

	printf("Description = %s\n", ints->description);
}

/**
 * \brief Ask the supplicant to delete a profile from memory.
 **/
void del_profile()
{
	if (xsupgui_request_delete_profile_config
	    (CONFIG_LOAD_GLOBAL, "Beat me!", TRUE) != REQUEST_SUCCESS) {
		printf("Couldn't delete 'Beat me!' from the profiles list!\n");
		die();
		return;
	} else {
		printf("Delete 'Beat me!' from the profiles list.\n");
	}
}

/**
 * \brief Ask the supplicant to delete a connection from memory.
 **/
void del_connection()
{
	if (xsupgui_request_delete_connection_config
	    (CONFIG_LOAD_GLOBAL, "RSA Test") != REQUEST_SUCCESS) {
		printf
		    ("Couldn't delete 'RSA Test' from the connections list!\n");
		die();
		return;
	} else {
		printf("Delete 'RSA Test' from the connections list.\n");
	}
}

/**
 * \brief Ask the supplicant to delete an interface from memory.
 **/
void del_interface()
{
	if (xsupgui_request_delete_interface_config("Intel IPW3945") !=
	    REQUEST_SUCCESS) {
		printf
		    ("Couldn't delete 'Intel IPW3945' from the interfaces list!\n");
		die();
		return;
	} else {
		printf("Delete 'Intel IPW3945' from the interfaces list.\n");
	}
}

/**
 * \brief Ask the supplicant to delete a trusted server from memory.
 **/
void del_trusted_server()
{
	if (xsupgui_request_delete_trusted_server_config
	    (CONFIG_LOAD_GLOBAL, "Test Server 1", TRUE) != REQUEST_SUCCESS) {
		printf
		    ("Couldn't delete 'Test Server 1' from the trusted servers list!\n");
		die();
		return;
	} else {
		printf
		    ("Delete 'Test Server 1' from the trusted servers list.\n");
	}
}

/**
 * \brief Change a value in the globals settings.
 **/
void change_globals()
{
	struct config_globals *globs = NULL;
	char *val = NULL;

	if (xsupgui_request_get_globals_config(&globs) != REQUEST_SUCCESS) {
		printf("Couldn't get global settings.\n");
		die();
		return;
	}

	val = globs->logpath;
	globs->logpath = "c:\\newpath\\";
	printf("Globals->flags = %x\n", globs->flags);

	if ((globs->flags & CONFIG_GLOBALS_ASSOC_AUTO) ==
	    CONFIG_GLOBALS_ASSOC_AUTO)
		globs->flags &= (~CONFIG_GLOBALS_ASSOC_AUTO);
	else
		globs->flags |= CONFIG_GLOBALS_ASSOC_AUTO;

	if (xsupgui_request_set_globals_config(globs) != REQUEST_SUCCESS) {
		printf("Couldn't set global settings.\n");
		die();
		return;
	}

	if (xsupgui_request_get_globals_config(&globs) != REQUEST_SUCCESS) {
		printf("Couldn't get global settings the second time!\n");
		die();
		return;
	}

	printf("Logpath is now set to '%s'.\n", globs->logpath);
	printf("Globals->flags = %x\n", globs->flags);
}

void create_conn()
{
	struct config_connection *conn = NULL;
	int result = 0;

	conn =
	    (struct config_connection *)
	    malloc(sizeof(struct config_connection));

	conn->name = _strdup("Test User Connection");
	conn->profile = _strdup("Test Profile");

	if ((result =
	     xsupgui_request_set_connection_config(CONFIG_LOAD_USER,
						   conn)) != REQUEST_SUCCESS) {
		printf("Couldn't set connection settings.  (Error : %d)\n",
		       result);
		die();
		return;
	}

	printf("Wrote a user config to memory.\n");

	printf("Writing user configuration file....");

	if ((result =
	     xsupgui_request_write_config(CONFIG_LOAD_USER,
					  NULL)) != REQUEST_SUCCESS) {
		printf("Failed!  (Error : %d)\n", result);
		die();
	} else {
		printf("Success.\n");
	}
}

/**
 * \brief Change a value in the connection settings.
 **/
void change_conn()
{
	struct config_connection *conn = NULL;

	if (xsupgui_request_get_connection_config
	    (CONFIG_LOAD_GLOBAL, "Ignition Test", &conn) != REQUEST_SUCCESS) {
		printf("Couldn't get connection settings.\n");
		die();
		return;
	}

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, conn) !=
	    REQUEST_SUCCESS) {
		printf("Couldn't set connection settings.\n");
		die();
		return;
	}

	if (xsupgui_request_get_connection_config
	    (CONFIG_LOAD_GLOBAL, "Ignition Test", &conn) != REQUEST_SUCCESS) {
		printf("Couldn't get connection settings the second time!\n");
		die();
		return;
	}
}

/**
 * \brief Change a value in the profile settings.
 **/
void change_prof()
{
	struct config_profiles *prof = NULL;
	char *val = NULL;

	if (xsupgui_request_get_profile_config
	    (CONFIG_LOAD_GLOBAL, "House_TTLS", &prof) != REQUEST_SUCCESS) {
		printf("Couldn't get profile settings.\n");
		die();
		return;
	}

	val = prof->identity;
	free(prof->identity);
	prof->identity = _strdup("some id");

	if (xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof) !=
	    REQUEST_SUCCESS) {
		printf("Couldn't set profile settings.\n");
		die();
		return;
	}

	if (xsupgui_request_get_profile_config
	    (CONFIG_LOAD_GLOBAL, "House_TTLS", &prof) != REQUEST_SUCCESS) {
		printf("Couldn't get profile settings the second time!\n");
		die();
		return;
	}

	printf("Identity is now set to '%s'.\n", prof->identity);
}

/**
 * \brief Change a value in the trusted server settings.
 **/
void change_ts()
{
	struct config_trusted_server *ts = NULL;
	char *val = NULL;

	if (xsupgui_request_get_trusted_server_config
	    (CONFIG_LOAD_GLOBAL, "Equifax Cert Test", &ts) != REQUEST_SUCCESS) {
		printf("Couldn't get trusted server settings.\n");
		die();
		return;
	}

	val = ts->store_type;
	free(ts->store_type);
	ts->store_type = _strdup("Mac OS X Store");

	ts->num_locations++;
	ts->location =
	    realloc(ts->location, ts->num_locations * (sizeof(ts->location)));
	ts->location[ts->num_locations - 1] =
	    _strdup("This won't work!  (But is an okay test. ;)");

	if (xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts) !=
	    REQUEST_SUCCESS) {
		printf("Couldn't set trusted server settings.\n");
		die();
		return;
	}

	if (xsupgui_request_get_trusted_server_config
	    (CONFIG_LOAD_GLOBAL, "Equifax Cert Test", &ts) != REQUEST_SUCCESS) {
		printf
		    ("Couldn't get trusted server settings the second time!\n");
		die();
		return;
	}

	printf("Store type is now set to '%s'.\n", ts->store_type);
}

/**
 * \brief Get the SSID cache from the supplicant.
 **/
void doget_ssids(char *devname)
{
	ssid_info_enum *ssids = NULL;
	int i = 0;

	if (xsupgui_request_enum_ssids(devname, &ssids) != REQUEST_SUCCESS) {
		printf("Couldn't get supplicant's SSID cache!\n");
		die();
		return;
	}

	while (ssids[i].ssidname != NULL) {
		printf("SSID : %s\t", ssids[i].ssidname);
		if (ssids[i].abil & ABILITY_ENC)
			printf("Encrypted ");
		if (ssids[i].abil & ABILITY_WPA_IE)
			printf("WPA1 ");
		if (ssids[i].abil & ABILITY_RSN_IE)
			printf("WPA2 ");
		if (ssids[i].abil & ABILITY_WPA_DOT1X)
			printf("WPA1-Enterprise ");
		if (ssids[i].abil & ABILITY_WPA_PSK)
			printf("WPA1-PSK ");
		if (ssids[i].abil & ABILITY_RSN_DOT1X)
			printf("WPA2-Enterprise ");
		if (ssids[i].abil & ABILITY_RSN_PSK)
			printf("WPA2-PSK ");
		if (ssids[i].abil & ABILITY_DOT11_STD)
			printf("802.11std ");
		if (ssids[i].abil & ABILITY_DOT11_A)
			printf("802.11a ");
		if (ssids[i].abil & ABILITY_DOT11_B)
			printf("802.11b ");
		if (ssids[i].abil & ABILITY_DOT11_G)
			printf("802.11g ");
		if (ssids[i].abil & ABILITY_DOT11_N)
			printf("802.11n ");
		printf("\n");

		i++;
	}

	xsupgui_request_free_ssid_enum(&ssids);
}

/**
 * \brief Request that the supplicant start a passive scan, if it can't, then 
 *        ask for an active scan.
 **/
void doscan(char *devname)
{
	if (xsupgui_request_wireless_scan(devname, TRUE) != REQUEST_SUCCESS) {
		printf("Failed passive scan... trying an active one..\n");
		if (xsupgui_request_wireless_scan(devname, FALSE) !=
		    REQUEST_SUCCESS) {
			printf("Failed active scan!\n");
			die();
			return;
		} else {
			printf("Requested active scan.\n");
			return;
		}
	}

	printf("Requested passive scan.\n");
}

void getvername()
{
	char *version;

	if (xsupgui_request_version_string(&version) != REQUEST_SUCCESS) {
		printf("Failed to get version string!\n");
		die();
	} else {
		printf("Version : %s\n", version);
		free(version);
	}
}

void getrootcacerts()
{
	cert_enum *casa;
	int i = 0;

	if (xsupgui_request_enum_root_ca_certs(&casa) != REQUEST_SUCCESS) {
		printf("Failed to get root CA certificates.\n");
		die();
	} else {
		while (casa[i].certname != NULL) {
			printf("Certificate : %s\n", casa[i].certname);
			printf("\tStore Type    : %s\n", casa[i].storetype);
			printf("\tFriendly Name : %s\n", casa[i].friendlyname);
			printf("\tIssuer        : %s\n", casa[i].issuer);
			printf("\tExpires       : %d/%d/%d\n", casa[i].month,
			       casa[i].day, casa[i].year);
			printf("\tCommon Name   : %s\n", casa[i].commonname);
			printf("\tLocation      : %s\n", casa[i].location);
			printf("\n");
			i++;
		}
	}
	printf("\n");

	xsupgui_request_free_cert_enum(&casa);
}

void getusercerts()
{
	cert_enum *casa;
	int i = 0;

	if (xsupgui_request_enum_user_certs(&casa) != REQUEST_SUCCESS) {
		printf("Failed to get user certificates.\n");
		die();
	} else {
		printf("Certs found :\n");
		while (casa[i].certname != NULL) {
			printf("Certificate : %s\n", casa[i].certname);
			printf("\tStore Type    : %s\n", casa[i].storetype);
			printf("\tFriendly Name : %s\n", casa[i].friendlyname);
			printf("\tIssuer        : %s\n", casa[i].issuer);
			printf("\tExpires       : %d/%d/%d\n", casa[i].month,
			       casa[i].day, casa[i].year);
			printf("\tCommon Name   : %s\n", casa[i].commonname);
			printf("\tLocation      : %s\n", casa[i].location);
			printf("\n");
			i++;
		}
	}
	printf("\n");

	xsupgui_request_free_cert_enum(&casa);
}

void getrootcainfo()
{
	cert_info *cinfo = NULL;

	if (xsupgui_request_ca_certificate_info
	    ("WINDOWS", "0048F8D37B153F6EA2798C323EF4F318A5624A9E",
	     &cinfo) != REQUEST_SUCCESS) {
		printf("Couldn't get certificate information!\n");
		die();
		return;
	}

	printf("C = %s\n", cinfo->C);
	printf("S = %s\n", cinfo->S);
	printf("L = %s\n", cinfo->L);
	printf("O = %s\n", cinfo->O);
	printf("OU = %s\n", cinfo->OU);
	printf("CN = %s\n", cinfo->CN);

	xsupgui_request_free_cert_info(&cinfo);
}

void getintdata(char *intname)
{
	char *desc = NULL;
	char *mac = NULL;
	int wireless = 0;
	int result;

	if ((result =
	     xsupgui_request_get_os_specific_int_data(intname, &desc, &mac,
						      &wireless)) !=
	    REQUEST_SUCCESS) {
		printf
		    ("Couldn't get interface information for interface '%s'.  (Reason : %d)\n",
		     intname, result);
		die();
		return;
	}

	printf("Description = %s\n", desc);
	printf("MAC Address = %s\n", mac);
	printf("Wireless    = %d\n", wireless);

	free(desc);
	free(mac);
}

void getconn_name(char *intname)
{
	char *name = NULL;

	if (xsupgui_request_get_conn_name_from_int(intname, &name) !=
	    REQUEST_SUCCESS) {
		printf("Couldn't get connection information for interface!\n");
		return;
	}

	printf("Using connection : %s\n", name);
	free(name);
}

void getqueuederrors()
{
	error_messages *msgs = NULL;
	int i = 0;

	if (xsupgui_request_get_error_msgs(&msgs) != REQUEST_SUCCESS) {
		printf
		    ("Couldn't get queued errors.  (Perhaps there were none?)\n");
		return;
	}

	while (msgs[i].errmsgs != NULL) {
		printf("Error : %s\n", msgs[i].errmsgs);
		i++;
	}

	xsupgui_request_free_error_msgs(&msgs);
}

void renameconnection(char *oldname, char *newname)
{
	if (xsupgui_request_rename_connection
	    (CONFIG_LOAD_GLOBAL, oldname, newname) != REQUEST_SUCCESS) {
		printf("Failed to rename the connection!\n");
		return;
	}
}

void renameprofile(char *oldname, char *newname)
{
	if (xsupgui_request_rename_profile(CONFIG_LOAD_GLOBAL, oldname, newname)
	    != REQUEST_SUCCESS) {
		printf("Failed to rename the profile!\n");
		return;
	}
}

void renametrusted_server(char *oldname, char *newname)
{
	int retval = 0;
	retval =
	    xsupgui_request_rename_trusted_server(CONFIG_LOAD_GLOBAL, oldname,
						  newname);
	if (retval != REQUEST_SUCCESS) {
		printf("Failed to rename the trusted server!  (Error : %d)\n",
		       retval);
		return;
	}
}

/**
 * \brief Ask the supplicant for the current global settings.
 **/
void dochange_logpath()
{
	struct config_globals *myglobs;

	printf("Getting global settings...");

	if (xsupgui_request_get_globals_config(&myglobs) != REQUEST_SUCCESS) {
		printf("Failed!\n");
		die();
		return;
	}

	printf("Success...\n\n");

	printf("Setting for logging is : %s\n", myglobs->logpath);

	free(myglobs->logpath);

	myglobs->logpath = _strdup("c:\\xsup_dev");

	printf("New setting for logging is : %s\n", myglobs->logpath);

	if (xsupgui_request_set_globals_config(myglobs) != REQUEST_SUCCESS) {
		printf("failed!\n");
		die();
		return;
	}

	printf("Success...\n\n");
}

void doget_freq(char *intname)
{
	uint32_t freq;

	if (xsupgui_request_get_freq(intname, &freq) == REQUEST_SUCCESS) {
		printf("Frequency : %d\n", freq);
	}
}

void do_disconnect_connection(char *intname)
{
	if (xsupgui_request_disconnect_connection(intname) == REQUEST_SUCCESS) {
		printf("Disconnected successfully!\n");
	} else {
		printf("FAILED to disconnect!\n");
	}
}

void do_get_user_is_admin()
{
	int admin = 0;
	int retval = 0;

	retval = xsupgui_request_get_are_administrator(&admin);
	if (retval == REQUEST_SUCCESS) {
		if (admin == TRUE) {
			printf("User *IS* an administrator\n");
		} else {
			printf("User *IS NOT* an administrator\n");
		}
	} else {
		printf
		    ("Get admin state request failed or timed out. (Error : %d)\n",
		     retval);
	}
}

void enum_sc_readers()
{
	int retval = 0;
	char **list = NULL;
	int count = 0;

	retval = xsupgui_request_enum_smartcard_readers(&list);
	if (retval != REQUEST_SUCCESS) {
		printf("Failed to enumerate smart cards!  (Error : %d)\n",
		       retval);
		return;
	}

	while (list[count] != NULL) {
		printf("Reader : %s\n", list[count]);
		count++;
	}
}

/**
 *  \brief  Display a header that indicates the test that is about to be run.
 *
 *  @param[in] test   The name of the test being run.
 **/
void nt(char *test)
{
	if (test != NULL) {
		printf("-----------------(%s)--------------------\n", test);
	} else {
		printf("----------------------------------------\n");
	}
}

int main(int argc, char *argv[])
{
	/*
	struct options opts[] = {
		{1, "connection", "Force the connection to use", "C", 1},
		{2, "interface", "Use this interface", "i", 1}
	};

	int op = 0;
	char *args = NULL;
	char *conn = NULL;
	char *intface = NULL;

	while ((op = getopts(argc, argv, opts, &args)) != 0) {
		switch (op) {
		case 1:
			{
				printf("Connection: %s\n", args);
				conn = args;
			}
		case 2:
			{
				printf("Interface: %s\n", args);
				intface = args;
			}
		}
	}

	if (argc < 2) {
		printf("ipctest  <OS Device Name>\n");
		printf("\n");
		return 1;
	}
*/
	printf("Connecting to xsupplicant..\n");
	if (xsupgui_connect() != 0) {
		printf("Error connecting socket/pipe!\n");
		return 1;
	}
#if 0
	doget_ssids("\\DEVICE\\{10F7F3B7-3D0D-47A4-B765-DB8795551F97}");
	return 0;
#endif

#if 1
      do_get_user_is_admin();
//      enum_sc_readers();
//      create_conn();
	nt("Enumerate Interfaces");
	doint_enum();
	nt("Get User Certs");
	getusercerts();
	nt("Terminate Supplicant");
	doterminate();

	return 0;
#endif

#if 0
//      dochangeconn("\\DEVICE\\{4DACA2DF-2701-4B9A-81EC-27FA9EADF721}", "New Connection");
//      change_globals();
//      dowrite_conf(NULL);

	do_disconnect_connection
	    ("\\DEVICE\\{10F7F3B7-3D0D-47A4-B765-DB8795551F97}");
	return 0;
#endif

#if 0
	doget_freq("\\DEVICE\\{10F7F3B7-3D0D-47A4-B765-DB8795551F97}");
	doget_ts();
	change_ts();
	doget_ts();
	return 0;
#endif

#if 0
	getcapabilities(intface);
	return 0;
#endif

#if 0
	nt("Terminate Supplicant");
	doterminate();
	exit(1);
#endif

#if 0
	add_cert();
#endif

#if 0
	build_tt();
	return 0;
#endif

#if 0
	dochangeconn(intface, conn);

	return 0;
#endif

#if 0
	nt("Renaming a trusted server");
	renametrusted_server("OSC Root CA", "My Root & CA");
	nt("Renaming a profile");
	renameprofile("Radiator Profile", "My Radiator & Profile");
	nt("Renaming the connection");
	renameconnection("Radiator Connection", "My & Radiator & Connection");
	nt("Writing the config to 'test.out'.");
	dowrite_conf("test.out");
	return 0;
#endif

#if 0
	nt("Enumerating possible connections");
	doget_possible_connections();

	nt("Getting connections");
	dogetconnections();

	nt("Getting a connection config");
	doget_connection();
#endif

#if 1
	nt("Requesting Version String");
	getvername();
#endif

#if 1
	nt("Enumerating Certificates");
	getrootcacerts();

	nt("Getting data on one Root CA");
	getrootcainfo();
#endif

#if 1
	nt("Enumerate Certificates...");
	docerts_enum();
#endif

#if 0
	nt("Changing log path");
	dochange_logpath();
#endif

#if 1
	nt("Get Physical State");
	dogetphysicalstate(argv[1]);
#endif

#if 0
	getupwd("Home WPA 2 PSK Network");
	xsupgui_disconnect();
	return 0;
#endif

#if 0
	nt("Getting interface data");
	getintdata(argv[1]);
#endif

#if 0
	nt("Changing Connection");
	dochangeconn(argv[1], "Office Wired Test");
	xsupgui_disconnect();
	return 0;
#endif

#if 0
	nt("Writing configuration to 'test.out'...");
	dowrite_conf("test.out");
#endif

#if 0
	nt("Writing config.\n");
	dowrite_conf(NULL);
	exit(1);
#endif

#if 0
	nt("Terminate Supplicant");
	doterminate();
#endif

	nt("Ping Test");
	doping();

	nt("Get Time Authenticated");
	dogettimeauthed(argv[1]);

	nt("Getting queued errors");
	getqueuederrors();
	exit(1);
	nt("Enumerate Interfaces");
	doint_enum();
	nt("Enumerate EAP Methods");
	doeap_enum();
//      nt("Reload Config Test");     // Need to fix this on the supplicant side! (The contexts need to be updated following the reload.)
//      doreload();
	nt("Get 802.1X state");
	doget1xstate(argv[1]);
	nt("Get EAP state");
	dogeteapstate(argv[1]);
	nt("Get Backend State");
	dogetbackendstate(argv[1]);
	nt("Get Physical State");
	dogetphysicalstate(argv[1]);
	nt("Get Pairwise Key Type");
	dogetpairwisetype(argv[1]);
	nt("Get Group Key Type");
	dogetgrouptype(argv[1]);
	nt("Get EAP Type");
	dogeteaptype(argv[1]);
	nt("Get SSID");
	dogetssid(argv[1]);
	nt("Get BSSID");
	dogetbssid(argv[1]);
	nt("Get Time Authenticated");
	dogettimeauthed(argv[1]);
	nt("Get Signal");
	dogetsignal(argv[1]);
	nt("Get Connections");
	dogetconnections(argv[1]);
	nt("Get Credentials from 'Home WPA 2 PSK Network'");
	getupwd("Home WPA 2 PSK Network");
	nt("Get Credentials from 'Home WPA EAP-TTLS Network'");
	getupwd("Home WPA EAP-TTLS Network");
	nt("Get Association Type for test interface");
	getassoctype(argv[1]);
	nt("Changing Username/Password for 'Home WPA 2 PSK Network'");
	setupwd("Home WPA 2 PSK Network", NULL, "newpassword");
	/*
	   nt("Changing Username/Password for 'Home WPA EAP-TTLS Network'");
	   setupwd("Home WPA EAP-TTLS Network", "foo", "bar");
	 */
	nt("Get Credentials from 'Home WPA 2 PSK Network'");
	getupwd("Home WPA 2 PSK Network");

	nt("Get Credentials from 'Home WPA EAP-TTLS Network'");
	getupwd("Home WPA EAP-TTLS Network");

	/*
	   nt("Force Changing the Connection on an Interface");
	   dochangeconn(argv[1], "Office Wired Test");

	   nt("Disassociating...");
	   setdisassoc("\\DEVICE\\{57FB2BD9-E1F7-47EE-813A-64FF1B4B65F0}");
	   nt("Pausing...");
	   setpause("\\DEVICE\\{57FB2BD9-E1F7-47EE-813A-64FF1B4B65F0}");
	 */

	nt("Get IP Address information...");
	getipaddr(argv[1]);

	nt("Enumerate Profiles...");
	doprof_enum();

	nt("Enumerate Certificates...");
	docerts_enum();

	nt("Writing configuration to 'test.out'...");
	dowrite_conf("test.out");

	nt("Getting Global Settings...");
	doget_globals();

	nt("Getting Profile Settings...");
	doget_profile();

	nt("Getting Connection Settings...");
	doget_connection();

	nt("Getting Trusted Server...");
	doget_ts();

	nt("Getting interface information...");
	doget_int();

	nt("Getting interfaces defined in the configuration file.");
	doint_conf_enum();

	nt("Deleting 'Beat me!' profile");
	del_profile();

	nt("Deleting 'RSA Test' connection");
	del_connection();

	nt("Deleting interface 'Intel IPW3945'");
	del_interface();

#if 0
	nt("Deleting trusted server 'Test Server 1'");
	del_trusted_server();

	nt("Changing logpath in global settings.");
	change_globals();

	nt("Changing connection settings.");
	change_conn();

	nt("Changing profile settings.");
	change_prof();

	nt("Changing trusted server settings");
	change_ts();
#endif

	nt("Writing config to 'test2.out'...");
	dowrite_conf("test2.out");

	nt("Getting list of known SSIDs...");
	doget_ssids(argv[1]);

	nt("Requesting a scan");
	doscan(argv[1]);

	nt("Requesting Version String");
	getvername();

	nt("Getting connection name");
	getconn_name(argv[1]);

	nt("Getting root CA information");
	getrootcainfo();

	nt("Getting interface data");
	getintdata(argv[1]);

	// You may want to comment this one out! ;)
#if 0
	nt("Terminate Supplicant");
	doterminate();
#endif

	nt(NULL);

	printf("Disconnecting.\n");
	xsupgui_disconnect();

	return 0;
}
