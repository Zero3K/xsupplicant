/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request7.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <libxml/parser.h>

#ifdef WINDOWS
#include "src/stdintwin.h"
#else
#include <stdint.h>
#endif

#include "src/xsup_common.h"

#include "xsupgui.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"

/**
 * \brief Answer a yes/no TNC UI request.
 *
 * @param[in] imcID   The ID of the IMC that generated the request that we are answering.
 * @param[in] connID   The connection ID that the IMC is using to track this connection.
 * @param[in] oui   The OUI of the IMC that generated the request.
 * @param[in] response   The response (TRUE/FALSE) to send to the IMC.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_answer_tnc_ui_request(uint32_t imcID, uint32_t connID,
					  uint32_t oui, uint32_t notification,
					  uint32_t response)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char tempstatic[100];
	int retval = REQUEST_SUCCESS;
	int err = 0;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "TNC_Request_Event_Response",
			NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	sprintf((char *)&tempstatic, "%d", imcID);
	if (xmlNewChild(t, NULL, (xmlChar *) "imcID", (xmlChar *) tempstatic) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	sprintf((char *)&tempstatic, "%d", connID);
	if (xmlNewChild(t, NULL, (xmlChar *) "connID", (xmlChar *) tempstatic)
	    == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	sprintf((char *)&tempstatic, "%d", oui);
	if (xmlNewChild(t, NULL, (xmlChar *) "OUI", (xmlChar *) tempstatic) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	sprintf((char *)&tempstatic, "%d", response);
	if (xmlNewChild(t, NULL, (xmlChar *) "Response", (xmlChar *) tempstatic)
	    == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	sprintf((char *)&tempstatic, "%d", notification);
	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Notification",
	     (xmlChar *) tempstatic) == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}
	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		retval = err;
		goto done;
	}

	retval = xsupgui_request_is_ack(retdoc);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Given an OS specific interface name, get the information about it.
 *
 * @param[in] intname   The OS specific interface name that we need to get information
 *                      for.
 * @param[out] intdesc   The interface description tied to the OS specific interface name.
 * @param[out] mac   The string representation of the MAC address for the interface.
 *                   (Suitable for inclusion in the configuration file structures.)
 * @param[out] iswireless   TRUE or FALSE indicating if the interface named is wireless.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_get_os_specific_int_data(char *intname, char **intdesc,
					     char **mac, int *iswireless)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;
	char *temp = NULL;

	if ((intname == NULL) || (intdesc == NULL) || (mac == NULL)
	    || (iswireless == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*intdesc) = NULL;
	(*mac) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_OS_Specific_Int_Data", NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	xsupgui_xml_common_convert_amp(intname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, "OS_Specific_Int_Data");
	if (n == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	n = n->children;
	t = xsupgui_request_find_node(n, "Description");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	(*intdesc) = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n, "MAC");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	(*mac) = (char *)xmlNodeGetContent(t);

	t = xsupgui_request_find_node(n, "Wireless");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	value = (char *)xmlNodeGetContent(t);

	(*iswireless) = atoi(value);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Given an interface name, get it's connection name back.
 *
 * @param[in] intname   The OS specific interface name that we need to get information
 *                      for.
 * @param[out] connname   The interface connection name.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_get_conn_name_from_int(char *intname, char **connname)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;
	char *temp = NULL;

	if ((intname == NULL) || (connname == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*connname) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Connection_From_Interface",
			NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	xsupgui_xml_common_convert_amp(intname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, "Connection_From_Interface");
	if (n == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	n = n->children;

	t = xsupgui_request_find_node(n, "Connection");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	(*connname) = (char *)xmlNodeGetContent(t);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Request that the supplicant return any error messages that might be in the queue.
 *
 * \note If the return value is IPC_ERROR_NO_ERRORS_IN_QUEUE, then there is nothing wrong with the
 *       supplicant.  It just means that there is nothing to show.
 *
 * @param[in] emsg_enum   The resulting array of error message strings.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_get_error_msgs(error_messages ** emsg_enum)
{
	int retval = REQUEST_SUCCESS;
	int err = 0, numevents = 0, i = 0;
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	error_messages *msgs = NULL;

	if (emsg_enum == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	(*emsg_enum) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Error_Queue", NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, "Error_Queue");
	if (n == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	t = xsupgui_request_find_node(n->children, "Number_Of_Events");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	value = (char *)xmlNodeGetContent(t);

	if ((value == NULL) || (strlen(value) == 0)) {
		retval = IPC_ERROR_INVALID_NUMBER_OF_EVENTS;
		goto done;
	}

	numevents = atoi(value);
	free(value);
	value = NULL;

	t = xsupgui_request_find_node(n->children, "Errors");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	msgs =
	    (error_messages *)
	    Malloc((sizeof(error_messages) * (numevents + 1)));
	if (msgs == NULL) {
		retval = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto done;
	}

	t = t->children;

	for (i = 0; i < numevents; i++) {
		t = xsupgui_request_find_node(t, "Message");
		if (t == NULL) {
			retval = IPC_ERROR_BAD_RESPONSE;
			free(msgs);
			goto done;
		}

		msgs[i].errmsgs = (char *)xmlNodeGetContent(t);

		t = t->next;
	}

	(*emsg_enum) = msgs;

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Clean up all of the memory that was used by the error message enum.
 *
 * @param[in] errmsg_enum   The error message enum that was returned from xsupgui_request_get_error_msgs().
 **/
void xsupgui_request_free_error_msgs(error_messages ** errmsg_enum)
{
	error_messages *cur = NULL;
	int i = 0;

	if (errmsg_enum == NULL)
		return;		// Nothing to free.

	cur = (*errmsg_enum);

	if (cur != NULL) {
		while (cur[i].errmsgs != NULL) {
			free(cur[i].errmsgs);
			i++;
		}
	}

	free((*errmsg_enum));
	(*errmsg_enum) = NULL;
}

/**
 * \brief Free a poss_conn_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_poss_conn_enum(poss_conn_enum ** data)
{
	int i = 0;
	poss_conn_enum *cenum = NULL;

	cenum = (*data);
	if (cenum == NULL)
		return REQUEST_SUCCESS;

	i = 0;

	while (cenum[i].name != NULL) {
		if (cenum[i].name != NULL)
			free(cenum[i].name);
		if (cenum[i].ssid != NULL)
			free(cenum[i].ssid);
		i++;
	}

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 *  \brief Request that the supplicant unbind a profile and connection from the context.
 *
 *  @param[in] device  The OS specific name of the device that we want to unbind profile/connection data.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 *
 *  \warning Unbinding a connection without sending a disassociate and/or logoff will leave
 *           your connection in a limbo state.  It shouldn't have any bad side effects, but may
 *           have some strange error messages as a result.
 **/
int xsupgui_request_unbind_connection(char *device)
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
		goto cdone;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Unbind_Connection", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto cdone;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_INVALID_PARAMETERS;
		free(temp);
		goto cdone;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto cdone;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto cdone;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto cdone;
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

 cdone:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Request that the supplicant rename a configuration item.  (Connection/Profile/Trusted Server)
 *
 * @param[in] itemtype  The IPC command for the change.
 * @param[in] oldname   The current name of item.
 * @param[in] newname   The name the item should be changed to.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_rename_something(char *itemtype, uint8_t config_type,
				     char *oldname, char *newname)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char *temp = NULL;
	char res[5];

	if ((itemtype == NULL) || (oldname == NULL) || (newname == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto cdone;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) itemtype, NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto cdone;
	}

	sprintf(res, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *) "Config_Type", (xmlChar *) res) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto cdone;
	}

	xsupgui_xml_common_convert_amp(oldname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Old_Name", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_INVALID_PARAMETERS;
		free(temp);
		goto cdone;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(newname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "New_Name", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_INVALID_PARAMETERS;
		free(temp);
		goto cdone;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto cdone;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto cdone;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto cdone;
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

 cdone:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request that we change the name of a connection.
 *
 * @param[in] config_type   The type of configuration we want to look in for this name.
 * @param[in] oldname   The current name of the connection.
 * @param[in] newname   The name that we want the connection to be changed to.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_rename_connection(uint8_t config_type, char *oldname,
				      char *newname)
{
	return xsupgui_request_rename_something("Rename_Connection",
						config_type, oldname, newname);
}

/**
 * \brief Request that we change the name of a profile.
 *
 * @param[in] oldname   The current name of the profile.
 * @param[in] newname   The name that we want the profile to be changed to.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_rename_profile(uint8_t config_type, char *oldname,
				   char *newname)
{
	return xsupgui_request_rename_something("Rename_Profile", config_type,
						oldname, newname);
}

/**
 * \brief Request that we change the name of a trusted server.
 *
 * @param[in] oldname   The current name of the trusted server.
 * @param[in] newname   The name that we want the trusted server to be changed to.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error
 **/
int xsupgui_request_rename_trusted_server(uint8_t config_type, char *oldname,
					  char *newname)
{
	return xsupgui_request_rename_something("Rename_Trusted_Server",
						config_type, oldname, newname);
}

/**
 * \brief Given an interface name, get it's link state.
 *
 * @param[in] intname   The OS specific interface name that we need to get information
 *                      for.
 * @param[out] connname   The interface connection name.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_get_link_state_from_int(char *intname, int *state)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;
	char *temp = NULL;

	if ((intname == NULL) || (state == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*state) = 0;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Link_State_From_Interface",
			NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	xsupgui_xml_common_convert_amp(intname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, "Link_State_From_Interface");
	if (n == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	n = n->children;

	t = xsupgui_request_find_node(n, "Link_State");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	value = (char *)xmlNodeGetContent(t);

	(*state) = atoi(value);

	xmlFree(value);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Request that the engine create a trouble ticket dump.
 *
 * @param[in] filename   The file name (ending in .zip) that should be created.
 * @param[in] scratchdir   A scratch directory that should be used for plug-ins to create dump data.
 * @param[in] overwrite   If we should overwrite the .zip file if it exists, or return an error.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_create_trouble_ticket_file(char *filename, char *scratchdir,
					       int overwrite)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char tempstatic[100];
	char *temp = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Create_Trouble_Ticket", NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	xsupgui_xml_common_convert_amp(scratchdir, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Temp_Data_Path", (xmlChar *) temp)
	    == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto done;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(filename, &temp);
	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Trouble_Ticket_File",
	     (xmlChar *) temp) == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto done;
	}
	free(temp);

	sprintf((char *)&tempstatic, "%d", overwrite);
	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Overwrite",
	     (xmlChar *) tempstatic) == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}
	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		retval = err;
		goto done;
	}

	retval = xsupgui_request_is_ack(retdoc);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Request the association type that is currently in use.
 *
 * @param[in] device   The OS specific device name that we want to get the association type
 *                     from.
 * @param[out] capabilities   A bitmap that contains information about the capabilities of an interface.
 *
 * \retval REQUEST_FAILURE on failure
 * \retval REQUEST_SUCCESS on success
 * \retval >299 on other error.
 **/
int xsupgui_request_get_interface_capabilities(char *device, int *capabilities)
{
	return xsupgui_request_get_some_value(device,
					      "Get_Interface_Capabilities",
					      "Interface_Capabilities",
					      "Capabilities", capabilities);
}

/**
 * \brief Request that the engine install a new root CA certificate to the certificate store.
 *
 * @param[in] filename   The file name (ending in .zip) that should be created.
 *
 * \retval >299 the request to the supplicant failed.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_add_root_ca_certificate(char *filename)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char *temp = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Add_Cert_to_Store", NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	xsupgui_xml_common_convert_amp(filename, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Cert_Path", (xmlChar *) temp) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}
	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		retval = err;
		goto done;
	}

	retval = xsupgui_request_is_ack(retdoc);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Request the TNC connection ID for an interface.
 *
 * @param[in] device   The OS specific device name that we want to get the association type
 *                     from.
 * @param[out] tnc_conn_id   The TNC connection ID for the interface.
 *
 * \retval REQUEST_FAILURE on failure
 * \retval REQUEST_SUCCESS on success
 * \retval >299 on other error.
 **/
int xsupgui_request_get_tnc_conn_id(char *device, unsigned int *tnc_conn_id)
{
	return xsupgui_request_get_some_value(device, "Get_TNC_Conn_ID",
					      "TNC_Conn_ID", "Conn_ID",
					      (int *)tnc_conn_id);
}

/**
 *  \brief Tell XSupplicant to lock or unlock the connection in use on an interface.
 *
 *  This call will basically control if an interface should be allowed to automatically decide
 *  which network it should be connected to.  
 *
 * @param[in] intname  The OS specific name of the device to pause.
 * @param[in] endis    Set to TRUE to lock the connection, FALSE to unlock it.
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_set_connection_lock(char *intname, int endis)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char *temp = NULL;
	char temp_static[10];

	if (intname == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_lock;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Set_Connection_Lock", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_lock;
	}

	xsupgui_xml_common_convert_amp(intname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_lock;
	}
	free(temp);

	memset(&temp_static, 0x00, sizeof(temp_static));
	sprintf((char *)&temp_static, "%d", endis);

	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Connection_Lock",
	     (xmlChar *) & temp_static) == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_lock;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_lock;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_lock;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_lock;
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

 request_lock:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request the interface name from the supplicant given the TNC connection ID.
 *
 * @param[in] tnc_conn_id   The TNC connection ID that we want to determine the interface
 *							binding for.
 * @param[out] intname   The OS specific interface name that is bound to the TNC connection
 *                       ID.
 *
 * \note This function will return IPC_ERROR_NOT_SUPPORTED if the engine is built without
 *       TNC support!
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_intname_from_tnc_conn_id(unsigned int tnc_conn_id,
					     char **intname)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;
	char tempint[10];

	if (intname == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	*intname = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Interface_From_TNC_Conn_ID",
			NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	memset(&tempint, 0x00, sizeof(tempint));
	sprintf((char *)&tempint, "%d", tnc_conn_id);
	if (xmlNewChild
	    (t, NULL, (xmlChar *) "Connection_ID",
	     (xmlChar *) tempint) == NULL) {
		retval = IPC_ERROR_CANT_CREATE_INT_NODE;
		goto done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children,
				      "Interface_From_TNC_Conn_ID");
	if (n == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	n = n->children;

	t = xsupgui_request_find_node(n, "Interface_Name");
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	value = (char *)xmlNodeGetContent(t);

	(*intname) = _strdup(value);

	xmlFree(value);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 *  \brief Tell XSupplicant to do a DHCP release/renew on an interface.
 *
 * @param[in] intname  The OS specific name of the device to pause.
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_dhcp_release_renew(char *intname)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err = 0;
	char *temp = NULL;

	if (intname == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "DHCP_Release_Renew", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_done;
	}

	xsupgui_xml_common_convert_amp(intname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_done;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_done;
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

 request_done:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request the frequency an interface is using.
 *
 * @param[in] device   The OS specific device name that we want to get the association type
 *                     from.
 * @param[out] freq   The frequency in use.
 *
 * \retval REQUEST_FAILURE on failure
 * \retval REQUEST_SUCCESS on success
 * \retval >299 on other error.
 **/
int xsupgui_request_get_freq(char *device, unsigned int *freq)
{
	return xsupgui_request_get_some_value(device, "Get_Frequency",
					      "Frequency", "Freq", (int *)freq);
}

/**
 *  \brief Tell XSupplicant to disconnect a connection bound to an interface.
 *
 * @param[in] intname  The OS specific name of the device to disconnect.
 *
 * \retval REQUEST_SUCCESS on success 
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error
 **/
int xsupgui_request_disconnect_connection(char *device)
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
		goto request_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Disconnect_Connection", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_done;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto request_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_done;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_done;
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

 request_done:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Ask if the interface is doing PSK.
 *
 *  @param[in] device   The OS specific name of the device to get the EAP state machine
 *                      state from.
 *  @param[out] state   TRUE if PSK is in progress.  FALSE otherwise.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  (usually indicates the interface isn't wireless.)
 **/
int xsupgui_request_get_are_doing_psk(char *device, int *state)
{
	return xsupgui_request_get_some_value(device, "Get_Are_Doing_PSK",
					      "Are_Doing_PSK", "Doing_PSK",
					      state);
}

/**
 * \brief Get the 'in use' state for a connection/profile/trusted server.
 *
 * @param[in] root_cmd   The text for the root command name that will be sent to the engine.
 * @param[in] child_cmd   The text for the child tag that will identify the connection/profile/trusted server.
 * @param[in] value   The name of the connection/profile/trusted server we want to query.
 * @param[in] resp_root   The expected root response name from the engine.
 * @param[in] resp_child   The child name that contains the answer from the command
 * @param[out] state   The 'in use' state of the requested connection/profile/trusted server.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  
 **/
int xsupgui_request_get_in_use_state(char *root_cmd, char *child_cmd,
				     char *value, char *resp_root,
				     char *resp_child, int *state)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int retval = REQUEST_SUCCESS;
	int err = 0;

	if ((root_cmd == NULL) || (child_cmd == NULL) || (value == NULL)
	    || (state == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*state) = FALSE;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) root_cmd, NULL);
	if (t == NULL) {
		retval = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	if (xmlNewChild(t, NULL, (xmlChar *) child_cmd, (xmlChar *) value) ==
	    NULL) {
		retval = IPC_ERROR_CANT_CREATE_INT_NODE;
		goto done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		retval = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		retval = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, resp_root);
	if (n == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	n = n->children;

	t = xsupgui_request_find_node(n, resp_child);
	if (t == NULL) {
		retval = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	content = xmlNodeGetContent(t);
	(*state) = atoi((char *)content);
	xmlFree(content);

 done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return retval;
}

/**
 * \brief Ask the engine if the named connection is currently active on 
 *		any interfaces.
 *
 * @param[in] profname   The name of the connection that we want to check on.
 * @param[out] inuse	 TRUE if it is in use, FALSE if it isn't.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  
 **/
int xsupgui_request_get_is_connection_in_use(char *conname, int *inuse)
{
	return xsupgui_request_get_in_use_state("Get_Is_Connection_In_Use",
						"Connection_Name", conname,
						"Is_Connection_In_Use",
						"Use_State", inuse);
}

/**
 * \brief Ask the engine if the named profile is currently active on 
 *		any interfaces.
 *
 * @param[in] profname   The name of the profile that we want to check on.
 * @param[out] inuse	 TRUE if it is in use, FALSE if it isn't.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  
 **/
int xsupgui_request_get_is_profile_in_use(char *profname, int *inuse)
{
	return xsupgui_request_get_in_use_state("Get_Is_Profile_In_Use",
						"Profile_Name", profname,
						"Is_Profile_In_Use",
						"Use_State", inuse);
}

/**
 * \brief Ask the engine if the named trusted server is currently active on 
 *		any interfaces.
 *
 * @param[in] tsname   The name of the profile that we want to check on.
 * @param[out] inuse	 TRUE if it is in use, FALSE if it isn't.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  
 **/
int xsupgui_request_get_is_trusted_server_in_use(char *tsname, int *inuse)
{
	return xsupgui_request_get_in_use_state("Get_Is_Trusted_Server_In_Use",
						"Trusted_Server_Name", tsname,
						"Is_Trusted_Server_In_Use",
						"Use_State", inuse);
}

/**
 *  \brief Ask if the console user is an administrator/root user.
 *
 *  @param[out] admin   TRUE if console user is an admin.  FALSE otherwise.
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  (usually indicates the interface isn't wireless.)
 **/
int xsupgui_request_get_are_administrator(int *admin)
{
	return xsupgui_request_get_some_value(NULL, "Get_Are_Administrator",
					      "Are_Administrator",
					      "Administrator", admin);
}

/**
 * \brief Request a list of available smart card readers.
 *
 * @param[out] readers  A NULL terminated array of smart card readers.
 *
 *  \note This call will return IPC_ERROR_NOT_SUPPORTED if SIM card support isn't
 *		  enabled in the engine!
 *
 *  \retval REQUEST_SUCCESS on success 
 *  \retval REQUEST_TIMEOUT on timeout
 *  \retval >299 on other error  
 **/
int xsupgui_request_enum_smartcard_readers(char ***readers)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	char **readerlist = NULL;
	int done = 0, err = 0;
	int count = 0;

	if (readers == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Enum_Smartcard_Readers", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_done;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_done;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_done;
	}

	n = xsupgui_request_find_node(n->children, "Smartcard_Readers");
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_done;
	}
	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	t = n->children;

	while (t != NULL) {
		t = xsupgui_request_find_node(t, "Reader");

		if (t != NULL) {
			count++;

			readerlist =
			    realloc(readerlist, count * (sizeof(char *)));
			if (readerlist == NULL) {
				done = IPC_ERROR_REQUEST_FAILED;
				goto request_done;
			}

			value = (char *)xmlNodeGetContent(t);

			readerlist[(count - 1)] = _strdup(value);
			xmlFree(value);
			t = t->next;
		}
	}

	count++;
	readerlist = realloc(readerlist, count * (sizeof(char *)));
	readerlist[(count - 1)] = NULL;	// Our terminator.

	(*readers) = readerlist;

 request_done:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}

int xsupgui_request_free_enum_smartcard_readers(char ***readers)
{
	char **readerlist = NULL;
	int i = 0;

	readerlist = (*readers);

	while (readerlist[i] != NULL) {
		free(readerlist[i]);
		i++;
	}

	free(readerlist);
	readers = NULL;

	return 0;
}

/**
 * \brief Store the logon username and password.  (Usually used with something like GINA or PAM.)
 *
 * @param[in] username    The new username to be stored (and used in profiles that request it)
 * @param[in] password    The new password to be stored
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on other error.
 **/
int xsupgui_request_set_logon_upw(char *username, char *password)
{
	xmlDocPtr doc = NULL, retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;
	char *temp = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto request_set_upw_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Store_Logon_Creds", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto request_set_upw_done;
	}

	xsupgui_xml_common_convert_amp(username, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Username", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_upw_done;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(password, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Password", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto request_set_upw_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto request_set_upw_done;
	}
	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto request_set_upw_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto request_set_upw_done;
	}

	done = xsupgui_request_is_ack(retdoc);

 request_set_upw_done:
	if (doc != NULL)
		xmlFreeDoc(doc);
	if (retdoc != NULL)
		xmlFreeDoc(retdoc);

	return done;
}
