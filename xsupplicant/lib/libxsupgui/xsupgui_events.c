/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_events.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupgui_events.c,v 1.6 2008/01/26 01:19:59 chessing Exp $
 * $Date: 2008/01/26 01:19:59 $
 **/

#include <string.h>
#include <libxml/parser.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "src/ipc_events_index.h"
#include "src/ipc_events_catalog.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "ipc_events_errors.h"
#include "xsupgui_events.h"
#include "xsupgui.h"
#include "xsupgui_request.h"

/**
 * \brief When an event is generated that is a log event, call this function
 *        to generate a displayable string. 
 *
 * \todo This will need to be internationalized!
 *
 * @param[out] ints   The OS name of the interface that generated the event.
 * @param[out] logline   A return value that contains a printable string that 
 *                       is contained in the IPC event. 
 *
 * \retval  -1 on error  ('logline' will be invalid, 'ints' may not!)
 * \retval   0 unknown  ('logline' *MAY* be valid.  Check before using it.)
 * \retval  >=1 success, with 'logline' being at the log level defined by
 *              \ref xsupgui_events.h
 *
 * \warning  The caller is expected to free the memory that is allocated
 *           for 'logline'.
 **/
int xsupgui_events_generate_log_string(char **ints, char **logline)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL;
	xmlNodePtr log = NULL;
	xmlNodePtr msg = NULL;
	xmlNodePtr t = NULL;
	int retval = REQUEST_SUCCESS;

	(*ints) = NULL;
	(*logline) = NULL;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
		return IPC_ERROR_NULL_DOCUMENT;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = IPC_ERROR_BAD_RESPONSE;
		goto gen_log_done;
	}

	log = xsupgui_request_find_node(root->children, "Log");
	if (log == NULL) 
	{
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto gen_log_done;
	}

	t = xsupgui_request_find_node(log->children, "Interface");
	if (t == NULL)
	{
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto gen_log_done;
	}

	(*ints) = (char *)xmlNodeGetContent(t);

	msg = xsupgui_request_find_node(log->children, "Message");
	if (msg == NULL)
	{
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto gen_log_done;
	}

	(*logline) = (char *)xmlNodeGetContent(msg);

gen_log_done:

	return retval;
}

/**
 * \brief Go through an event document that has been identified as being
 *        from a state machine, and return the values it stores.
 *
 * @param[out] intf   The name of the interface that generated the event.
 * @param[out] sm   An integer that identifies the type of state machine
 *                  that generated the event.
 * @param[out] oldstate   The state that the state machine was in before
 *                        it changed to the new state.
 * @param[out] newstate   The state that the state machine is in now.
 * 
 * @param[out] tncconnectionid The TNC Connection ID corresponding to this 
 *
 * \retval  -1 on error  (all data will be invalid)
 * \retval   0 on success
 **/
int xsupgui_events_get_state_change(char **intf, int *sm, int *oldstate, int *newstate, uint32_t *tncconnectionid)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL;
	int retval = 0;
	char *value = NULL;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto state_change_done;
	}

	t = xsupgui_request_find_node(root->children, "State_Transition");
	if (t == NULL) 
	{
		retval = -1;
		goto state_change_done;
	}

	t = t->children;

	t = xsupgui_request_find_node(t, "Interface");
	if (t == NULL)
	{
		retval = -1;
		goto state_change_done;
	}

	(*intf) = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(t, "Statemachine");
	if (t == NULL)
	{
		retval = -1;
		goto state_change_done;
	}

	value = (char *)xmlNodeGetContent(t);

	(*sm) = atoi(value);

	free(value);
	value = NULL;

	t = xsupgui_request_find_node(t, "Old_State");
	if (t == NULL)
	{
		retval = -1;
		goto state_change_done;
	}

	value = (char *)xmlNodeGetContent(t);

	(*oldstate) = atoi(value);

	free(value);
	value = NULL;

	t = xsupgui_request_find_node(t, "New_State");
	if (t == NULL)
	{
		retval = -1;
		goto state_change_done;
	}

	value = (char *)xmlNodeGetContent(t);

	(*newstate) = atoi(value);

	free(value);
	value = NULL;

    // Note that if this tag doesn't exist, we still need to return
    // a value, otherwise non-tnc builds will fail here.
    t = xsupgui_request_find_node(t, "TNC_Connection_ID");
    if (t == NULL)
    {
        // For non-tnc versions of XSupplicant.
        (*tncconnectionid) = 0xFFFFFFFF;
    }
    else
    {
        value = xmlNodeGetContent(t);

        (*tncconnectionid) = atoi(value);
    }

    free(value);
    value = NULL;

state_change_done:
	//xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Given an event document, parse it, and determine the event ID, so that 
 *        the caller can make the proper request.
 *
 * @param[in] doc   The XML document that was returned from the backend supplicant.
 *
 * \retval -1   couldn't determine the ID from the document
 * \retval >0   the ID value for the message
 **/
long int xsupgui_events_get_event_num(xmlDocPtr doc)
{
	xmlNodePtr n, t;
	long int retval = 0;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) return -1;

	/**
	 *  All event checks below should be checked from most likely to
	 *  least likely in an effort to reduce the work needed to 
	 *  process them!
	 **/

	t = xsupgui_request_find_node(n->children, "State_Transition");
	if (t != NULL)
	{
		retval = IPC_EVENT_STATEMACHINE;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "Log");
	if (t != NULL) 
	{
		retval = IPC_EVENT_LOG;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "UI_Event");
	if (t != NULL)
	{
		retval = IPC_EVENT_UI;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "Wireless_Scan_Complete");
	if (t != NULL)
	{
		retval = IPC_EVENT_SCAN_COMPLETE;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "TNC_Event");
	if (t != NULL)
	{
		retval = IPC_EVENT_TNC_UI;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "TNC_Request_Event");
	if (t != NULL)
	{
		retval = IPC_EVENT_TNC_UI_REQUEST;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "TNC_Request_Batch_Event");
	if (t != NULL)
	{
		retval = IPC_EVENT_TNC_UI_BATCH_REQUEST;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "Error_Event");
	if (t != NULL)
	{
		retval = IPC_EVENT_ERROR;
		goto event_num_done;
	}

	t = xsupgui_request_find_node(n->children, "EAP_Password_Request");
	if (t != NULL)
	{
		retval = IPC_EVENT_REQUEST_PWD;
		goto event_num_done;
	}

event_num_done:
	return retval;
}

/**
 * \brief Go through an event document that has been identified as being
 *        a scan complete, and find the interface name that generated the
 *        event.
 *
 * @param[out] intf   The name of the interface that generated the event.
 *
 * \retval  -1 on error  (all data will be invalid)
 * \retval   0 unknown  (all data should be considered invalid)
 * \retval  >=1 success
 **/
int xsupgui_events_get_scan_complete_interface(char **intf)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL;
	int retval = 0;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
//		xsupgui_free_event_doc();
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "Wireless_Scan_Complete");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	t = xsupgui_request_find_node(t, "Interface");
	if (t == NULL)
	{
		retval = -1;
		goto done;
	}

	(*intf) = (char *)xmlNodeGetContent(t);

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Parse a "get password" event, and return the data to the
 *        caller.
 *
 * @param[in,out] conn_name   The connection that is requesting this information.
 * @param[in,out] eapmethod   A string that identifies the EAP method that is requesting
 *                            the authentication method.
 * @param[in,out] chalstr    The challenge string to display to the user.
 *
 * \retval  -1 on error  (all data will be invalid)
 * \retval   0 unknown  (all data should be considered invalid)
 * \retval  >=1 success
 **/
int xsupgui_events_get_passwd_challenge(char **conn_name, char **eapmethod, char **chalstr)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL;
	int retval = 0;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
//		xsupgui_free_event_doc();
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "EAP_Password_Request");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	t = xsupgui_request_find_node(t, "Connection_Name");
	if (t == NULL)
	{
		retval = -1;
		goto done;
	}

	(*conn_name) = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(t, "EAP_Method");
	if (t == NULL)
	{
		retval = -1;
		goto done;
	}

	(*eapmethod) = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(t, "Challenge_String");
	if (t == NULL)
	{
		retval = -1;
		goto done;
	}

	(*chalstr) = (char *)xmlNodeGetContent(t);

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Allocate enough memory to safely return an error string, and
 *        assemble the string from the master string, and the argument
 *        that came across IPC.
 *
 * @param[in,out] errstr   The resulting error string.
 * @param[in] instr   The "master" string from ipc_events_errors.h
 * @param[in] arg   The argument that was sent from the supplicant.
 **/
void xsupgui_events_build_error(char **errstr, char *instr, char *arg)
{
	char *mystr = NULL;

	if (instr == NULL) (*errstr) = NULL;  // Nothing to do.

	if (arg == NULL)
	{
		(*errstr) = strdup(instr);
		return;
	}

	// This malloc() will result in a buffer that is at least 2 bytes larger than
	// what we really need.  So, we should be safe from overflows.
	mystr = malloc(strlen(instr) + strlen(arg) + 10);
	if (mystr == NULL)
	{
		(*errstr) = NULL;
		return;
	}

	memset(mystr, 0x00, (sizeof(instr) + strlen(arg)));

	sprintf(mystr, instr, arg);

	(*errstr) = mystr;
}

/**
 * \brief Parse an error condition event, and return the data to the
 *        caller.
 *
 * @param[in,out] errstr   The reconstructed error string.
 *
 * \retval  -1 on error  (all data will be invalid)
 * \retval   0 unknown  (all data should be considered invalid)
 * \retval  >=1 success
 **/
int xsupgui_events_get_error(int *errnum, char **errstr)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL, n = NULL;
	char *value = NULL;
	int code = 0;
	int retval = 0;

	if (errnum == NULL) return -1;
	if (errstr == NULL) return -1;

	(*errnum) = 0;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "Error_Event");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	n = xsupgui_request_find_node(t, "Error_Code");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	code = atoi(value);

	(*errnum) = code;

	free(value);

	n = xsupgui_request_find_node(n, "Argument");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	// Now, build the string.
	switch (code)
	{
	case IPC_EVENT_ERROR_CANT_START_SCAN:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CANT_START_SCAN_STR, value);
		break;

	case IPC_EVENT_ERROR_TIMEOUT_WAITING_FOR_ID:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_TIMEOUT_WAITING_FOR_ID_STR, value);
		break;

	case IPC_EVENT_ERROR_TIMEOUT_DURING_AUTH:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_TIMEOUT_DURING_AUTH_STR, value);
		break;

	case IPC_EVENT_ERROR_MALLOC:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_MALLOC_STR, value);
		break;

	case IPC_EVENT_ERROR_GET_MAC:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_GET_MAC_STR, value);
		break;

	case IPC_EVENT_ERROR_CANT_CREATE_WIRELESS_CTX:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CANT_CREATE_WIRELESS_CTX_STR, value);
		break;

	case IPC_EVENT_ERROR_SEND_FAILED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_SEND_FAILED_STR, value);
		break;

	case IPC_EVENT_ERROR_GETTING_INT_INFO:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_GETTING_INT_INFO_STR, value);
		break;

	case IPC_EVENT_ERROR_GETTING_SCAN_DATA:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_GETTING_SCAN_DATA_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_802_11_AUTH_MODE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_802_11_AUTH_MODE_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_802_11_ENC_MODE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_802_11_ENC_MODE_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_802_11_INFRA_MODE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_802_11_INFRA_MODE_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_SSID:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_SSID_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_BSSID:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_BSSID_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_GETTING_BSSID:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_GETTING_BSSID_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_GETTING_SSID:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_GETTING_SSID_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_WEP_KEY:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_WEP_KEY_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_TKIP_KEY:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_TKIP_KEY_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_CCMP_KEY:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_CCMP_KEY_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_SETTING_UNKNOWN_KEY:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_SETTING_UNKNOWN_KEY_STR, value);
		break;

	case IPC_EVENT_ERROR_OVERFLOW_ATTEMPTED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_OVERFLOW_ATTEMPTED_STR, value);
		break;

	case IPC_EVENT_ERROR_INVALID_KEY_REQUEST:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_INVALID_KEY_REQUEST_STR, value);
		break;

	case IPC_EVENT_ERROR_RESTRICTED_HOURS:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_RESTRICTED_HOURS_STR, value);
		break;

	case IPC_EVENT_ERROR_ACCT_DISABLED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_ACCT_DISABLED_STR, value);
		break;

	case IPC_EVENT_ERROR_PASSWD_EXPIRED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_PASSWD_EXPIRED_STR, value);
		break;

	case IPC_EVENT_ERROR_NO_PERMS:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_NO_PERMS_STR, value);
		break;

	case IPC_EVENT_ERROR_CHANGING_PASSWD:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CHANGING_PASSWD_STR, value);
		break;

	case IPC_EVENT_ERROR_TEXT:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_TEXT_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_AES_UNWRAP:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_AES_UNWRAP_STR, value);
		break;

	case IPC_EVENT_ERROR_UNKNOWN_KEY_REQUEST:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_UNKNOWN_KEY_REQUEST_STR, value);
		break;

	case IPC_EVENT_ERROR_INVALID_PTK:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_INVALID_PTK_STR, value);
		break;

	case IPC_EVENT_ERROR_IES_DONT_MATCH:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_IES_DONT_MATCH_STR, value);
		break;

	case IPC_EVENT_ERROR_PMK_UNAVAILABLE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_PMK_UNAVAILABLE_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD_STR, value);
		break;

	case IPC_EVENT_ERROR_TLS_DECRYPTION_FAILED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_TLS_DECRYPTION_FAILED_STR, value);
		break;

	case IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN_STR, value);
		break;

	case IPC_EVENT_ERROR_NO_IPC_SLOTS:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_NO_IPC_SLOTS_STR, value);
		break;

	case IPC_EVENT_ERROR_UNKNOWN_EAPOL_KEY_TYPE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_UNKNOWN_EAPOL_KEY_TYPE_STR, value);
		break;

	case IPC_EVENT_ERROR_INVALID_MIC_VERSION:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_INVALID_MIC_VERSION_STR, value);
		break;

	case IPC_EVENT_ERROR_UNKNOWN_PEAP_VERSION:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_UNKNOWN_PEAP_VERSION_STR, value);
		break;

	case IPC_EVENT_ERROR_NO_WCTX:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_NO_WCTX_STR, value);
		break;

	case IPC_EVENT_ERROR_CANT_RENEW_DHCP:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CANT_RENEW_DHCP_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_TO_BIND:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_TO_BIND_STR, value);
		break;

	case IPC_EVENT_ERROR_FAILED_TO_GET_HANDLE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_FAILED_TO_GET_HANDLE_STR, value);
		break;

	case IPC_EVENT_ERROR_EVENT_HANDLE_FAILED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_EVENT_HANDLE_FAILED_STR, value);
		break;

	case IPC_EVENT_ERROR_WMI_ATTACH_FAILED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_WMI_ATTACH_FAILED_STR, value);
		break;

	case IPC_EVENT_ERROR_WMI_ASYNC_FAILED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_WMI_ASYNC_FAILED_STR, value);
		break;

	case IPC_EVENT_ERROR_CANT_ADD_CERT_TO_STORE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CANT_ADD_CERT_TO_STORE_STR, value);
		break;
		
	case IPC_EVENT_ERROR_CANT_READ_FILE:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CANT_READ_FILE_STR, value);
		break;

	case IPC_EVENT_ERROR_CERT_CHAIN_IS_INVALID:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_CERT_CHAIN_IS_INVALID, value);
		break;

	case IPC_EVENT_ERROR_NOT_SUPPORTED:
		xsupgui_events_build_error(errstr, IPC_EVENT_ERROR_NOT_SUPPORTED_STR, value);
		break;

	default:
		xsupgui_events_build_error(errstr, "Unknown error event!", NULL);
		break;
	}

	free(value);

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Catch a UI event and return it's event number, and the interface (if any)
 *        that caused the event generation.
 *
 * @param[out] evtnum   The event number that was triggered.
 * @param[out] intname   The OS specific interface name that generated the event.
 * @param[out] param   The parameter value that came with this UI event.  (May return NULL!)
 *
 * \retval 0 on success
 * \retval <0 on failure
 **/
int xsupgui_events_get_ui_event(int *evtnum, char **intname, char **param)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL, n = NULL;
	char *value = NULL;
	int retval  = 0;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
//		xsupgui_free_event_doc();
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "UI_Event");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	n = xsupgui_request_find_node(t, "Event_Code");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*evtnum) = atoi(value);

	free(value);

	(*intname) = NULL;

	n = xsupgui_request_find_node(t, "Interface");
	if (n != NULL)
	{
		(*intname) = (char *)xmlNodeGetContent(n);
	}
	
	n = xsupgui_request_find_node(t, "Parameter");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	(*param) = (char *)xmlNodeGetContent(n);

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Catch a TNC UI event, and return it's IANA OUI, and event number.
 *
 * @param[out] oui   The IANA OUI that generated this event.
 * @param[out] notification   The index in to the message catalog that identifies
 *                            what the UI should display.
 *
 * \retval 0 on success
 * \retval <0 on failure
 **/
int xsupgui_events_get_tnc_ui_event(uint32_t *oui, uint32_t *notification)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL, n = NULL;
	char *value = NULL;
	int retval = 0;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
//		xsupgui_free_event_doc();
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "TNC_Event");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	n = xsupgui_request_find_node(t, "OUI");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*oui) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "Notification");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*notification) = atoi(value);
	free(value);

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Catch a TNC UI event that needs an action, and return it's IANA OUI, 
 *        and request number.
 *
 * @param[out] imcID   The ID of the IMC that generated this event.
 * @param[out] connID   The connection ID the IMC uses to identify this connection.
 * @param[out] oui   The IANA OUI that generated this event.
 * @param[out] request   The index in to the message catalog that identifies
 *                       which request the UI should display.
 *
 * \retval 0 on success
 * \retval <0 on failure
 **/
int xsupgui_events_get_tnc_ui_request_event(uint32_t *imcID, uint32_t *connID, 
											uint32_t *oui, uint32_t *request)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL, n = NULL;
	char *value = NULL;
	int retval = 0;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
//		xsupgui_free_event_doc();
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "TNC_Request_Event");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	n = xsupgui_request_find_node(t, "imcID");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*imcID) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "connID");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*connID) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "OUI");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*oui) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "Request");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*request) = atoi(value);
	free(value);

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Following an IPC_EVENT_TNC_UI_BATCH_REQUEST event, gather all of the data about the
 *        event.
 *
 * @param[out] oui   The vendor specific OUI that triggered the batch.
 * @param[out] msgid   The vendor specific message ID that triggered the batch.
 * @param[out] batch   A NULL terminated array of messages in the batch.
 *
 * \retval 0 on success
 * \retval <0 on failure.
 **/
int xsupgui_events_get_tnc_ui_batch_request_event(uint32_t *imcID, uint32_t *connID, uint32_t *oui, uint32_t *msgid, tnc_msg_batch **batch)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL, t = NULL, n = NULL, item = NULL;
	char *value;
	int items = 0;
	int retval = 0;
	int i = 0;
	tnc_msg_batch *data = NULL;

	doc = xsupgui_get_event_doc();
	if (doc == NULL) 
	{
//		xsupgui_free_event_doc();
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = xsupgui_request_find_node(root->children, "TNC_Request_Batch_Event");
	if (t == NULL) 
	{
		retval = -1;
		goto done;
	}

	t = t->children;

	n = xsupgui_request_find_node(t, "imcID");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*imcID) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "connID");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*connID) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "OUI");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*oui) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "MsgID");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	(*msgid) = atoi(value);
	free(value);

	n = xsupgui_request_find_node(t, "Items");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	value = (char *)xmlNodeGetContent(n);

	items = atoi(value);
	free(value);

	// "items" contains the number of items that are in the batch.  So
	// allocate some memory to store the items.
	data = malloc(((items+1) * sizeof(tnc_msg_batch)));
	if (data == NULL)
	{
		retval = -1;
		goto done;
	}

	memset(data, 0x00, ((items+1) * sizeof(tnc_msg_batch)));

	n = xsupgui_request_find_node(t, "Batch");
	if (n == NULL)
	{
		retval = -1;
		goto done;
	}

	n = n->children;

	for (i = 0; i < items; i++)
	{
		// Now, parse each item in the batch.
		t = xsupgui_request_find_node(n, "Item");
		if (t == NULL)
		{
			retval = -1;
			goto done;
		}

		item = xsupgui_request_find_node(t->children, "imcID");
		if (item == NULL)
		{
			retval = -1;
			goto done;
		}

		value = (char *)xmlNodeGetContent(item);
		data[i].imcID = atoi(value);
		free(value);

		item = xsupgui_request_find_node(t->children, "connectionID");
		if (item == NULL)
		{
			retval = -1;
			goto done;
		}

		value = (char *)xmlNodeGetContent(item);
		data[i].connectionID = atoi(value);
		free(value);

		item = xsupgui_request_find_node(t->children, "OUI");
		if (item == NULL)
		{
			retval = -1;
			goto done;
		}

		value = (char *)xmlNodeGetContent(item);
		data[i].oui = atoi(value);
		free(value);

		item = xsupgui_request_find_node(t->children, "MsgID");
		if (item == NULL)
		{
			retval = -1;
			goto done;
		}

		value = (char *)xmlNodeGetContent(item);
		data[i].msgid = atoi(value);
		free(value);

		item = xsupgui_request_find_node(t->children, "Parameter");
		if (item == NULL)
		{
			retval = -1;
			goto done;
		}

		value = (char *)xmlNodeGetContent(item);

		if ((value != NULL) || (strlen(value) != 0))
		{
			data[i].parameter = value;
		}
		else
		{
			free(value);
		}

		n = n->next;
	}

	(*batch) = data;

done:
//	xsupgui_free_event_doc();

	return retval;
}

/**
 * \brief Free the memory that was used in the TNC message batch.
 *
 * @param[in] data   The TNC message batch that we want to free the members of.
 **/
void xsupgui_events_free_tnc_msg_batch_data(tnc_msg_batch **data)
{
	int i = 0;
	tnc_msg_batch *batch = NULL;

	batch = (*data);

	while (batch[i].oui != 0)
	{
		free(batch[i].parameter);
		batch[i].parameter = 0;

		i++;
	}

	free((*data));

	(*data) = NULL;
}

