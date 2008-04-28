/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request3.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupgui_request3.c,v 1.4 2007/10/20 06:14:53 galimorerpg Exp $
 * $Date: 2007/10/20 06:14:53 $
 **/

#include <string.h>
#include <libxml/parser.h>

#ifdef WINDOWS
#include "src/stdintwin.h"
#endif

#include "xsupgui.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"

/**
 * \brief Request the SSID in use for a given interface.
 *
 * @param[in] device   The OS specific device name for the device we want to get the SSID
 *                     for.
 * @param[out] ssid   The SSID that this interface is attempting to use.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout.
 * \retval >299 on other error.
 *
 * \note This call returns the SSID that the interface is attempting to use.  The caller
 *       shouldn't assume that because there is an SSID value returned that the interface
 *       is actually associated to the network.
 **/
int xsupgui_request_get_ssid(char *device, char **ssid)
{
	return xsupgui_request_get_byte_string(device, "Get_SSID", "SSID", "SSID_Name", ssid);
}

/**
 * \brief Request the BSSID (MAC address of the AP) in use for a given interface.
 *
 * @param[in] device   The OS specific device name that we want to get the BSSID for.
 * @param[out] bssid   An ASCII printable string that identifies the BSSID that this
 *                     interface is associated to.
 *
 * \brief REQUEST_SUCCESS on success
 * \brief REQUEST_TIMEOUT on timeout
 * \brief >299 on other error.
 *
 * \note bssid will be returned as a printable string.  If you want the hex version,
 *        you will need to convert it yourself.
 **/
int xsupgui_request_get_bssid(char *device, char **bssid)
{
	return xsupgui_request_get_byte_string(device, "Get_BSSID", "BSSID", "BSSID_Value", bssid);
}

/**
 *  \brief Request that the supplicant disassociate an interface.
 *
 *  @param[in] device   The OS specific device name that caller would like to send a
 *                      disassociate for.
 *  @param[in] reason   The reason code to return in the disassocate request.  (Reason 
 *                      codes are defined by the IEEE 802.11 standard.)
 *
 *  \retval REQUEST_SUCCESS on success
 *	\retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error.
 **/
int xsupgui_request_set_disassociate(char *device, unsigned char reason)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char strreason[50];
	char *temp = NULL;

	if (device == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_disassoc;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Request_Disassociate", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_disassoc;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_disassoc;
	}
	free(temp);

	sprintf((char *)&strreason, "%d", reason);
	if (xmlNewChild(t, NULL, (xmlChar *)"Reason", (xmlChar *)strreason) == NULL)
	{
		done = IPC_ERROR_UNSPEC_REQ_FAILURE;
		goto request_disassoc;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto request_disassoc;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto request_disassoc;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_disassoc;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "ACK") != NULL)
	{
		done = REQUEST_SUCCESS;
	}
	else
	{
		done = IPC_ERROR_NOT_ACK;
	}

request_disassoc:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request the signal strength of an interface, as a percentage.
 *
 * @param[in] device   The OS specific device name that we wish to get the signal 
 *                     strength from.
 * @param[out] strength   A signal strength as a percentage.
 *
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQEUST_SUCCESS on success
 * \retval >299 on other error.
 *
 **/
int xsupgui_request_get_signal_strength_percent(char *device, int *strength)
{
	return xsupgui_request_get_some_value(device, "Get_Signal_Strength_Percent", "Signal_Strength", "Percent", strength);
}

/**
 * \brief Request the length of time a given interface has been in authenticated state.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 *
 * \note If you call this function while the interface is not in authenticated state,
 *       you will always get 0!  ("Authenticated" state includes S_FORCE_AUTH state!)
 **/
int xsupgui_request_get_seconds_authenticated(char *device, long int *seconds)
{
	return xsupgui_request_get_long_int(device, "Get_Seconds_Authenticated", "Seconds_Authenticated", 
								 "Seconds", seconds);
}

/**
 * \brief Request the association type that is currently in use.
 *
 * @param[in] device   The OS specific device name that we want to get the association type
 *                     from.
 * @param[out] assoctype   The association type that is in use.
 *
 * \retval REQUEST_FAILURE on failure
 * \retval REQUEST_SUCCESS on success
 * \retval >299 on other error.
 **/
int xsupgui_request_get_association_type(char *device, int *assoctype)
{
	return xsupgui_request_get_some_value(device, "Get_Association_Type", "Association_Type", "Association", assoctype);
}

/**
 * \brief Verify that the supplicant is still alive and kicking.
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_ping()
{
	xmlDocPtr doc = NULL, retdoc = NULL;
	xmlNodePtr n = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_ping_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *)"Ping", NULL) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_ping_done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto request_ping_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto request_ping_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_ping_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	if (xsupgui_request_find_node(n, "Pong") != NULL)
	{
		done = REQUEST_SUCCESS;
	}
	else
	{
		done = IPC_ERROR_NOT_PONG;
	}

request_ping_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request the username and password for a given connection.
 *
 * @param[in] conn_name   The name of the connection we would like to get the username
 *                        and password for.
 * @param[out] username   The username that is associated with this connection.
 * @param[out] password   The password that is associated with this connection.
 * @param[out] authtype   The authentication type that will be used with this connection.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 **/
int xsupgui_request_get_connection_upw(char *conn_name, char **username, char **password, int *authtype)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int err = 0;
	char *temp = NULL;

	if (conn_name == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_connection_upw;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Get_Connection_UPW", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_connection_upw;
	}

	xsupgui_xml_common_convert_amp(conn_name, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Connection", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_UNSPEC_REQ_FAILURE;
		free(temp);
		goto finish_connection_upw;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_connection_upw;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_connection_upw;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_connection_upw;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Connection_UPW");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_connection_upw;
	}

	t = xsupgui_request_find_node(n->children, "Username");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_connection_upw;
	}

	(*username) = (char *)xmlNodeGetContent(t);   // It is perfectly reasonable to have a NULL username.  (In the case of a WPA(2)-PSK network.) So don't check it!

	t = xsupgui_request_find_node(n->children, "Password");
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_connection_upw;
	}
	(*password) = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n->children, "Authentication");
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_connection_upw;
	}

	content = xmlNodeGetContent(t);
	(*authtype) = AUTH_NONE;
	if (strcmp((char *)content, "PSK") == 0) (*authtype) = AUTH_PSK;
	if (strcmp((char *)content, "EAP") == 0) (*authtype) = AUTH_EAP;
	if (content != NULL) free(content);

finish_connection_upw:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;  
}

/**
 * \brief Request the OS specific device name given a device description from the configuration
 *        file.
 *
 * @param[in] dev_desc   The description that is from the configuration file.
 * @param[out] device   The OS specific device name that maps to the description from
 *                      the configuration file.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 **/
int xsupgui_request_get_devname(char *dev_desc, char **device)
{
	xmlDocPtr doc = NULL, retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;
	char *temp = NULL;

	if ((dev_desc == NULL) || (device == NULL)) return IPC_ERROR_INVALID_PARAMETERS;

	(*device) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_get_devname_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Get_Device_Name", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_get_devname_done;
	}

	xsupgui_xml_common_convert_amp(dev_desc, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Device_Description", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_UNSPEC_REQ_FAILURE;
		free(temp);
		goto request_get_devname_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto request_get_devname_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto request_get_devname_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_get_devname_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	t = xsupgui_request_find_node(n, "Device_Name");
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto request_get_devname_done;
	}

	t = xsupgui_request_find_node(t->children, "Interface");
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto request_get_devname_done;
	}

	(*device) = (char *)xmlNodeGetContent(t);

	done = REQUEST_SUCCESS;

request_get_devname_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Set the username and password for a given connection.
 *
 * @param[in] conn_name   The name of the connection that we want to set the username and
 *                        password for.
 * @param[in] username    The new username that will be applied to this connection. (May
 *                        be NULL if the connection is a WPA-PSK connection.)
 * @param[in] password    The new password that will be applied to this connection.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 **/
int xsupgui_request_set_connection_upw(char *conn_name, char *username, char *password)
{
	xmlDocPtr doc = NULL, retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;
	char *temp = NULL;

	if (conn_name == NULL)  
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_set_upw_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Set_Connection_UPW", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_set_upw_done;
	}

	xsupgui_xml_common_convert_amp(conn_name, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Connection_Name", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_upw_done;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(username, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Username", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_upw_done;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(password, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Password", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_upw_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto request_set_upw_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto request_set_upw_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_set_upw_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	n = xsupgui_request_find_node(n, "Set_Connection_UPW_Result");
	if (n != NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto request_set_upw_done;
	}

	t = xsupgui_request_find_node(n, "ACK");
	if (t != NULL)
	{
		done = IPC_ERROR_NOT_ACK;
		goto request_set_upw_done;
	}

	done = REQUEST_SUCCESS;

request_set_upw_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Set the password for a given connection.
 *
 * @param[in] conn_name   The name of the connection that we want to set the username and
 *                        password for.
 * @param[in] password    The new password that will be applied to this connection.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 **/
int xsupgui_request_set_connection_pw(char *conn_name, char *password)
{
	xmlDocPtr doc = NULL, retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;
	char *temp = NULL;

	if (conn_name == NULL)  
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_set_pw_done;
	}

	t = xmlNewChild(n, NULL, "Set_Connection_PW", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_set_pw_done;
	}

	xsupgui_xml_common_convert_amp(conn_name, &temp);
	if (xmlNewChild(t, NULL, "Connection_Name", temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_pw_done;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(password, &temp);
	if (xmlNewChild(t, NULL, "Password", temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_pw_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto request_set_pw_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto request_set_pw_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_set_pw_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	n = xsupgui_request_find_node(n, "Set_Connection_PW_Result");
	if (n != NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto request_set_pw_done;
	}

	t = xsupgui_request_find_node(n, "ACK");
	if (t != NULL)
	{
		done = IPC_ERROR_NOT_ACK;
		goto request_set_pw_done;
	}

	done = REQUEST_SUCCESS;

request_set_pw_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request that the supplicant return it's currently known profiles.
 *
 * @param[out] profs   An array of data containing the name and type of each
 *                     profile that is currently in memory.  This list will be
 *                     terminated by all members being NULL, or 0.
 *
 * \retval REQUEST_SUCCESS   The supplicant's response contains a valid set of profiles,
 *                           and the data in "profs" is valid.
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299   An error occurred.
 **/
int xsupgui_request_enum_profiles(profile_enum **profs)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numprofs = 0, i = 0, err = 0;
	profile_enum *myprofs = NULL;

	if (profs == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	(*profs) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_profiles;
	}

	if (xmlNewChild(n, NULL, (xmlChar *)"Enum_Profiles", NULL) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_profiles;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_enum_profiles;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_enum_profiles;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_enum_profiles;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Profiles_List");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_profiles;
	}

	t = xsupgui_request_find_node(n->children, "Number_Of_Profiles");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_profiles;
	}

	content = xmlNodeGetContent(t);
	if ((content == NULL) || (strlen((char *)content) == 0))
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_profiles;
	}

	numprofs = atoi((char *)content);

	if (content != NULL) free(content);

	// Allocate memory for our return structure.
	myprofs = malloc(sizeof(profile_enum)*(numprofs+1));
	if (myprofs == NULL) 
	{
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_profiles;
	}

	// Clear the memory.
	memset(myprofs, 0x00, (sizeof(profile_enum)*(numprofs+1)));

	n = n->children;
	for (i=0; i <numprofs; i++)
	{
		n = xsupgui_request_find_node(n, "Profile");
		if (n == NULL) 
		{
			if (myprofs != NULL) free(myprofs);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_profiles;
		}

		t = xsupgui_request_find_node(n->children, "Profile_Name");
		if (t == NULL) 
		{
			if (myprofs != NULL) free(myprofs);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_profiles;
		}

		myprofs[i].name = (char *)xmlNodeGetContent(t);
	
		n = n->next;
	}

	(*profs) = myprofs;
	done = REQUEST_SUCCESS;

finish_enum_profiles:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;  
}

/**
 * \brief See if the character array passed in is a valid XML ACK document.
 *
 * @param[in] indoc   The character array that makes up an XML document to 
 *                    check for an ACK message.
 * @param[in] insize   The size of the character array that makes up the
 *                     XML document.
 *
 * \retval REQUEST_SUCCESS   The XML document contains an ACK.
 * \retval REQUEST_FAILURE   The XML document does not contain an ACK.
 * \retval >299   An error occurred trying to check the document.
 **/
int xsupgui_request_is_ack(xmlDocPtr indoc)
{
	xmlNodePtr t;
	int retval = REQUEST_SUCCESS;

	if (indoc == NULL) return IPC_ERROR_NULL_DOCUMENT;

	t = xmlDocGetRootElement(indoc);
	if (t == NULL) 
	{
		retval = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto is_ack_done;
	}

	t = xsupgui_request_find_node(t->children, "ACK");
	if (t == NULL) 
	{
		retval = REQUEST_FAILURE;
		goto is_ack_done;
	}

is_ack_done:

	return retval;
}

/**
 * \brief Build the XML document that requests that a socket be turned in 
 *        to an event only socket.
 *
 * @param[out] request   A character array that contains a text representation
 *                       of the XML document to send to the backend supplicant.
 *                       It is up to the caller to free the memory when the 
 *                       they are finished with the request.
 * @param[out] requestsize   The length of the character array that makes up
 *                           the request.
 *
 * \retval REQUEST_SUCCESS   The data in request, and requestsize are valid, and 
 *                           can be used to request the socket change.
 * \retval REQUEST_FAILURE   An error occurred creating the XML document.
 * \retval >299   An error occurred attempting to set the connection type.
 **/
int xsupgui_request_set_as_event(char **request, int *requestsize)
{
	xmlDocPtr outdoc;
	xmlNodePtr n;
	int done = REQUEST_SUCCESS;

	if ((request == NULL) || (requestsize == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	outdoc = xsupgui_xml_common_build_msg();
	if (outdoc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(outdoc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto set_as_event_done;
	}

	n = xmlNewChild(n, NULL, (xmlChar *)"Change_Socket_Type", NULL);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto set_as_event_done;
	}

	n = xmlNewChild(n, NULL, (xmlChar *)"Socket_Event_Only", NULL);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto set_as_event_done;
	}

	xmlDocDumpFormatMemory(outdoc, (xmlChar **)request, requestsize, 0);

set_as_event_done:
	if (outdoc != NULL) xmlFreeDoc(outdoc);

	return done;
}

/**
 * \brief Request the OS specific device description given a device name from the configuration
 *        file.
 *
 * @param[in] device   The OS specific device name that maps to the description from
 *                      the configuration file.
 * @param[out] dev_desc   The description that is from the configuration file.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 **/
int xsupgui_request_get_devdesc(char *device, char **dev_desc)
{
	xmlDocPtr doc = NULL, retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;
	char *temp = NULL;

	if ((dev_desc == NULL) || (device == NULL)) return IPC_ERROR_INVALID_PARAMETERS;

	(*dev_desc) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_get_devname_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Get_Device_Description", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_get_devname_done;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_UNSPEC_REQ_FAILURE;
		free(temp);
		goto request_get_devname_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto request_get_devname_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto request_get_devname_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_get_devname_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	t = xsupgui_request_find_node(n, "Device_Description");
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto request_get_devname_done;
	}

	t = xsupgui_request_find_node(t->children, "Description");
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto request_get_devname_done;
	}

	(*dev_desc) = (char *)xmlNodeGetContent(t);

	done = REQUEST_SUCCESS;

request_get_devname_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);

	return done;
}
