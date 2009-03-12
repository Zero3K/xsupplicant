/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request2.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <libxml/parser.h>

#include "xsupgui.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"

/**
 *  \brief Request that the supplicant reload it's configuration file.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_reload_config()
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL;
	int done = REQUEST_SUCCESS, err = 0;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto reload_config_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "Reload_Configuration", NULL) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto reload_config_done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto reload_config_done;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto reload_config_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto reload_config_done;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "ACK") != NULL) {
		done = REQUEST_SUCCESS;
	} else {
		done = IPC_ERROR_NOT_ACK;
	}

 reload_config_done:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Request that the supplicant terminate itself.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_terminate()
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL;
	int done = 0, err = 0;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto terminate_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "Terminate", NULL) == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto terminate_done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto terminate_done;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto terminate_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto terminate_done;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "ACK") != NULL) {
		done = REQUEST_SUCCESS;
	} else {
		done = IPC_ERROR_NOT_ACK;
	}

 terminate_done:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Tell Xsupplicant to pause an interface. 
 *
 *  This will kick the statemachine in to a "STOPPED" state.  When
 *  the statemachine is stopped, any connection that is currently in
 *  use will continue to exist.  If the authenticator asks the 
 *  supplicant to reauthenticate, or rekey, the supplicant will ignore it.
 *  So, in general, you should send a logoff and/or disassociate before
 *  pausing the interface.
 *
 * @param[in] device  The OS specific name of the device to pause.
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_stop(char *device)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char *temp = NULL;

	if (device == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_stop;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Request_Stop", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_stop;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_stop;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_stop;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_stop;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_stop;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "ACK") != NULL) {
		done = REQUEST_SUCCESS;
	} else {
		done = IPC_ERROR_NOT_ACK;
	}

 request_stop:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Request that the supplicant send a LOGOFF.
 *
 *  @param[in] device  The OS specific name of the device that we want to have send a 
 *                     LOGOFF.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 *
 *  \warning Sending a LOGOFF message will not cause all authentications to stop.  It will
 *           only terminate the currently authenticated session.  In general, the 
 *           authenticator will attempt to start another authentication shortly after 
 *           getting a LOGOFF message.  If it is the intent to stop future authentications,
 *           you should request that the interface go in to a "stopped" state.
 **/
int xsupgui_request_logoff(char *device)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char *temp = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_logoff;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Request_Logoff", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_logoff;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_INVALID_PARAMETERS;
		free(temp);
		goto request_logoff;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_logoff;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_logoff;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_logoff;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "ACK") != NULL) {
		done = REQUEST_SUCCESS;
	} else {
		done = IPC_ERROR_NOT_ACK;
	}

 request_logoff:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Request the state of the 802.1X state machine on a given interface.
 *
 *  @param[in] device   The OS specific device name that we want to know the 802.1X state
 *                      machine state for.
 *  @param[out] state   The current state of the 802.1X state machine.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_1x_state(char *device, int *state)
{
	return xsupgui_request_get_some_value(device, "Get_1X_State",
					      "dot1X_State", "State", state);
}

/**
 *  \brief Request the state of the EAP state machine on a given interface.
 *
 *  @param[in] device   The OS specific name of the device to get the EAP state machine
 *                      state from.
 *  @param[out] state   The current state of the EAP state machine.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_eap_state(char *device, int *state)
{
	return xsupgui_request_get_some_value(device, "Get_EAP_State",
					      "EAP_State", "State", state);
}

/**
 *  \brief Request the state of the 802.1X backend state machine on a given interface.
 *
 *  @param[in] device   The OS specific name of the device to get the 802.1X backend state
 *                      machine state from.
 *  @param[out] state   The current state of the 802.1X backend state machine.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_backend_state(char *device, int *state)
{
	return xsupgui_request_get_some_value(device, "Get_Backend_State",
					      "Backend_State", "State", state);
}

/**
 *  \brief Request the state of the physical interface state machine on a given interface.
 *
 *  @param[in] device   The OS specific device name to get the physical state machine state
 *                      from.
 *  @param[out] state   The current state of the physical interface state machine.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_physical_state(char *device, int *state)
{
	return xsupgui_request_get_some_value(device, "Get_Physical_State",
					      "Physical_State", "State", state);
}

/**
 *  \brief Request the pairwise key type in use on a given interface.
 *
 *  @param[in] device   The OS specific device name that we want to know the pairwise key 
 *                      type for.
 *  @param[out] keytype   The pairwise key type that is in use.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_pairwise_key_type(char *device, int *keytype)
{
	return xsupgui_request_get_some_value(device, "Get_Pairwise_Key_Type",
					      "Pairwise_Key_Type", "Key_Type",
					      keytype);
}

/**
 *  \brief Request the group key type in use on a given interface.
 *
 *  @param[in] device   The OS specific device name that we want to know the group key
 *                      type for.
 *  @param[out] keytype   The group key type that is in use.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_group_key_type(char *device, int *keytype)
{
	return xsupgui_request_get_some_value(device, "Get_Group_Key_Type",
					      "Group_Key_Type", "Key_Type",
					      keytype);
}

/**
 * \brief Request EAP type in use on a given interface.
 *
 * @param[in] device   The OS specific device name that we want to know the EAP type that
 *                     was used to authenticate.
 * @param[out] eaptype   The EAP method that is in use on the requested interface.
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_get_eap_type_in_use(char *device, int *eaptype)
{
	return xsupgui_request_get_some_value(device, "Get_EAP_Type_In_Use",
					      "EAP_Type_In_Use", "EAP_Type",
					      eaptype);
}

/**
 *  \brief Request IP information in use on a given interface.
 *
 *  @param[in] device   The OS specific device name to get the IP address information for.
 *  @param[out] info   A structure that contains the IP address, netmask, gateway, and
 *                     other IP information for the interface.
 *
 *  \retval REQUEST_SUCCESS on success
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_get_ip_info(char *device, ipinfo_type ** info)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS, err = 0;
	ipinfo_type *inf = NULL;
	char *temp = NULL;

	if (info == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	(*info) = NULL;

	if (device == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_get_ipinfo;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_IP_Data", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_get_ipinfo;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_get_ipinfo;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_get_ipinfo;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_get_ipinfo;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_get_ipinfo;
	}

	inf = malloc(sizeof(ipinfo_type));
	if (inf == NULL) {
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto request_get_ipinfo;
	}

	memset(inf, 0x00, sizeof(ipinfo_type));

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "IP_Data");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		free(inf);
		goto request_get_ipinfo;
	}
	// We don't care about the interface result for now.
	t = xsupgui_request_find_node(n->children, "IP_Address");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		free(inf);
		goto request_get_ipinfo;
	}

	inf->ipaddr = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n->children, "Netmask");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		free(inf);
		goto request_get_ipinfo;
	}

	inf->netmask = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n->children, "Gateway");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		free(inf);
		goto request_get_ipinfo;
	}

	inf->gateway = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n->children, "DNS1");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		free(inf);
		goto request_get_ipinfo;
	}

	inf->dns1 = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n->children, "DNS2");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		free(inf);
		goto request_get_ipinfo;
	}

	inf->dns2 = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n->children, "DNS3");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		free(inf);
		goto request_get_ipinfo;
	}

	inf->dns3 = (char *)xmlNodeGetContent(t);

	done = REQUEST_SUCCESS;

 request_get_ipinfo:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	(*info) = inf;

	return done;
}

/**
 *  \brief Request that we change to a new connection.
 *
 *  Request that the supplicant switch to a new connection.  This will
 *  cause the supplicant to disassociate from any currently associated network
 *  and attempt to associate to the network specified by the new connection
 *  block.
 *
 *  \retval REQUEST_SUCCESS on success
 *	\retval REQUEST_TIMEOUT on timeout.
 *	\retval >299 on other error.
 **/
int xsupgui_request_set_connection(char *device, char *conn_name)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char *temp = NULL;

	if ((device == NULL) || (conn_name == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_set_conn;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Request_Connection_Change", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_set_conn;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_set_conn;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(conn_name, &temp);
	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Connection_Name",
	     (xmlChar *) temp) == NULL) {
		done = IPC_ERROR_UNSPEC_REQ_FAILURE;
		free(temp);
		goto request_set_conn;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_set_conn;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_set_conn;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_set_conn;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "ACK") != NULL) {
		done = REQUEST_SUCCESS;
	} else {
		done = IPC_ERROR_NOT_ACK;
	}

 request_set_conn:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request the connections available in the configuration file.
 *
 * @param[in] config_type   Which configuration to enumerate.  (This is a bit value, and can be ORed.)
 * @param[out] connections   A structure that contains a list of connections, and information
 *                           about each one.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout.
 * \retval >299 on other error.
 *
 **/
int xsupgui_request_enum_connections(uint8_t config_type,
				     conn_enum ** connections)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numints = 0, i = 0, err = 0;
	conn_enum *myconns = NULL;
	char tempnum[5];

	if (connections == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	(*connections) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_connections;
	}

	if ((t =
	     xmlNewChild(n, NULL, (xmlChar *) "Enum_Connections",
			 NULL)) == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_connections;
	}

	sprintf((char *)&tempnum, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *) "Config_Type", (xmlChar *) tempnum)
	    == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_connections;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_enum_connections;
	}
	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto finish_enum_connections;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_enum_connections;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Connections");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_connections;
	}

	t = xsupgui_request_find_node(n->children, "Number_Of_Connections");
	if (t == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_connections;
	}

	content = xmlNodeGetContent(t);
	if ((content == NULL) || (strlen((char *)content) == 0)) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_connections;
	}
#ifdef REQUEST_DEBUG
	printf("%s connection(s) found!\n", content);
#endif
	numints = atoi((char *)content);
	xmlFree(content);

	// Allocate memory for our return structure.
	myconns = malloc(sizeof(conn_enum) * (numints + 1));
	if (myconns == NULL) {
#ifdef REQUEST_DEBUG
		printf("Couldn't allocate memory to return interface data!\n");
#endif
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_connections;
	}
	// Clear the memory.
	memset(myconns, 0x00, (sizeof(conn_enum) * (numints + 1)));

	n = n->children;
	for (i = 0; i < numints; i++) {
		n = xsupgui_request_find_node(n, "Connection");
		if (n == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		t = xsupgui_request_find_node(n->children, "Connection_Name");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		myconns[i].name = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Config_Type");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		content = xmlNodeGetContent(t);
		myconns[i].config_type = atoi((char *)content);
		xmlFree(content);

		t = xsupgui_request_find_node(n->children, "SSID_Name");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		myconns[i].ssid = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Priority");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		content = xmlNodeGetContent(t);
		if (content != NULL) {
			myconns[i].priority = atoi((char *)content);
			xmlFree(content);
		}

		t = xsupgui_request_find_node(n->children, "Encryption");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		content = xmlNodeGetContent(t);
		if (content != NULL) {
			myconns[i].encryption = atoi((char *)content);
			xmlFree(content);
		}

		t = xsupgui_request_find_node(n->children, "Authentication");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		content = xmlNodeGetContent(t);
		if ((content != NULL) && (strlen((char *)content) > 0)) {
			myconns[i].auth_type = atoi((char *)content);
			xmlFree(content);
		}

		t = xsupgui_request_find_node(n->children, "Association_Type");
		if (t == NULL) {
			if (myconns != NULL)
				free(myconns);
			done = IPC_ERROR_BAD_RESPONSE;
			goto finish_enum_connections;
		}

		content = xmlNodeGetContent(t);
		if ((content != NULL) && (strlen((char *)content) > 0)) {
			myconns[i].assoc_type = atoi((char *)content);
			xmlFree(content);
		}

		n = n->next;
	}

	(*connections) = myconns;
	done = REQUEST_SUCCESS;

 finish_enum_connections:
	if (doc)
		xmlFreeDoc(doc);
	if (retdoc)
		xmlFreeDoc(retdoc);

	return done;
}
