/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_callout.c
 *
 * \author chris@open1x.org, terry.simons@gmail.com
 *
 * \note  There is no reason to generate error events on anything in this file.  If 
 *        a call in this file fails it is an indication that  we won't be able to 
 *        send it out anyway. ;)
 *
 **/
#ifndef WINDOWS
#include <netinet/in.h>
#include <strings.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "libxsupconfwrite/xsupconfwrite.h"
#include "libxsupconfwrite/xsupconfwrite_globals.h"
#include "libxsupconfwrite/xsupconfwrite_profiles.h"
#include "libxsupconfwrite/xsupconfwrite_connection.h"
#include "libxsupconfwrite/xsupconfwrite_interface.h"
#include "libxsupconfwrite/xsupconfwrite_trusted_server.h"
#include "libxsupconfig/xsupconfig_parse.h"
#include "libxsupconfig/xsupconfig_parse_globals.h"
#include "libxsupconfig/xsupconfig_parse_connection.h"
#include "libxsupconfig/xsupconfig_parse_profile.h"
#include "libxsupconfig/xsupconfig_parse_trusted_server.h"
#include "libxsupconfig/xsupconfig_parse_interface.h"
#include "libxsupconfcheck/xsupconfcheck.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_ipc.h"
#include "interfaces.h"
#include "eap_sm.h"
#include "statemachine.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "platform/cert_handler.h"
#include "platform/platform.h"
#include "error_prequeue.h"
#include "timer.h"
#include "version.h"
#include "wpa_common.h"
#include "ipc_events_index.h"
#include "logon_creds.h"
#include "liblist/liblist.h"
#include "ipc_callout_helper.h"
#include "ipc_events.h"

#ifdef EAP_SIM_ENABLE
#include <winscard.h>
#include "eap_types/sim/sm_handler.h"
#include "eap_types/sim/eapsim.h"
#include "eap_types/aka/eapaka.h"
#endif

#ifdef WINDOWS
#include "platform/windows/tthandler.h"
#include "platform/windows/wzc_ctrl.h"
#include "platform/windows/wlanapi_interface.h"
#elif LINUX
#include "platform/linux/tthandler.h"
#endif

// XXX These can be removed once ipc_callout_eap_cert_state() has moved to the proper location.
#include "eap_types/tls/eaptls.h"
#include "eap_types/tls/tls_funcs.h"
// XXX (End)

#ifdef USE_TNC
#include "eap_types/tnc/tnc_compliance_callbacks.h"
#endif

#ifdef WINDOWS
#include <windows.h>
#include "event_core_win.h"
#include "platform/windows/cardif_windows_wmi.h"
#else
#include "event_core.h"
#endif

#include "ipc_callout.h"
#include "config_ssid.h"
#include "wireless_sm.h"
#include "xsup_err.h"
#include "libxsupconfig/xsupconfig_devices.h"

#include "buildnum.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

void global_config_reload();	// Defined in xsup_driver.c (ICK!)

extern struct rfc4137_eap_handler eaphandlers[];	// Defined in eap_sm.c (ICK!)

struct ipc_calls {
	char *name;
	int (*ipc_call) (xmlNodePtr, xmlNodePtr *);
};

struct ipc_calls my_ipc_calls[] = {
	{"Ping", ipc_callout_ping},
	{"Enum_Live_Interfaces", ipc_callout_enum_live_interfaces},
	{"Enum_EAP_Methods", ipc_callout_enum_eap_methods},
	{"Reload_Configuration", ipc_callout_reload_config},
	{"Terminate", ipc_callout_terminate},
	{"Get_1X_State", ipc_callout_get_1x_state},
	{"Get_EAP_State", ipc_callout_get_eap_state},
	{"Get_Backend_State", ipc_callout_get_backend_state},
	{"Get_Physical_State", ipc_callout_get_physical_state},
	{"Get_Pairwise_Key_Type", ipc_callout_get_pairwise_key_type},
	{"Get_Group_Key_Type", ipc_callout_get_group_key_type},
	{"Get_EAP_Type_In_Use", ipc_callout_get_eap_type_in_use},
	{"Get_SSID", ipc_callout_get_ssid},
	{"Get_BSSID", ipc_callout_get_bssid},
	{"Get_Seconds_Authenticated", ipc_callout_get_seconds_authenticated},
	{"Get_Signal_Strength_Percent",
	 ipc_callout_get_signal_strength_percent},
	{"Enum_Connections", ipc_callout_enum_connections},
	{"Get_Connection_UPW", ipc_callout_get_connection_upw},
	{"Get_Association_Type", ipc_callout_get_association_type},
	{"Request_Logoff", ipc_callout_request_logoff},
	{"Get_Device_Name", ipc_callout_request_device_name},
	{"Get_Device_Description", ipc_callout_request_device_desc},
	{"Set_Connection_UPW", ipc_callout_set_connection_upw},
	{"Set_Connection_PW", ipc_callout_set_connection_pw},
	{"Change_Socket_Type", ipc_callout_change_socket_type},
	{"Request_Connection_Change", ipc_callout_change_connection},
	{"Request_Disassociate", ipc_callout_disassociate},
	{"Request_Stop", ipc_callout_stop},
	{"Get_IP_Data", ipc_callout_get_ip_data},
	{"Enum_Profiles", ipc_callout_enum_profiles},
	{"Enum_Trusted_Servers", ipc_callout_enum_trusted_servers},
	{"Write_Config", ipc_callout_write_config},
	{"Get_Globals_Config", ipc_callout_get_globals},
	{"Get_Profile_Config", ipc_callout_get_profile},
	{"Get_Connection_Config", ipc_callout_get_connection},
	{"Get_Trusted_Server_Config", ipc_callout_get_trusted_server_config},
	{"Get_Interface_Config", ipc_callout_get_interface_config},
	{"Delete_Connection_Config", ipc_callout_delete_connection_config},
	{"Delete_Profile_Config", ipc_callout_delete_profile_config},
	{"Delete_Trusted_Server_Config",
	 ipc_callout_delete_trusted_server_config},
	{"Delete_Interface_Config", ipc_callout_delete_interface_config},
	{"Set_Globals_Config", ipc_callout_set_globals_config},
	{"Set_Connection_Config", ipc_callout_set_connection_config},
	{"Set_Profile_Config", ipc_callout_set_profile_config},
	{"Set_Trusted_Server_Config", ipc_callout_set_trusted_server_config},
	{"Enum_Config_Interfaces", ipc_callout_enum_config_interfaces},
	{"Enum_Known_SSIDs", ipc_callout_enum_known_ssids},
	{"Wireless_Scan", ipc_callout_wireless_scan},
	{"Get_Version_String", ipc_callout_get_version_string},
	{"Enum_Root_CA_Certs", ipc_callout_enum_root_ca_certs},
	{"Get_Certificate_Info", ipc_callout_get_cert_info},
	{"TNC_Request_Event_Response", ipc_callout_get_tnc_request_response},
	{"Get_OS_Specific_Int_Data", ipc_callout_get_os_specific_int_data},
	{"Get_Connection_From_Interface", ipc_callout_get_conn_from_int},
	{"Set_Interface_Config", ipc_callout_set_interface_config},
	{"Get_Error_Queue", ipc_callout_get_error_queue},
	{"Unbind_Connection", ipc_callout_request_unbind_connection},
	{"Rename_Connection", ipc_callout_request_rename_connection},
	{"Rename_Profile", ipc_callout_request_rename_profile},
	{"Rename_Trusted_Server", ipc_callout_request_rename_trusted_server},
	{"Get_Link_State_From_Interface", ipc_callout_get_link_state_for_int},
	{"Create_Trouble_Ticket", ipc_callout_request_create_trouble_ticket},
	{"Get_Interface_Capabilities", ipc_callout_get_interface_capabilities},
	{"Add_Cert_to_Store", ipc_callout_add_cert_to_store},
	{"Get_TNC_Conn_ID", ipc_callout_get_tnc_conn_id},
	{"Set_Connection_Lock", ipc_callout_set_conn_lock},
	{"Get_Interface_From_TNC_Conn_ID",
	 ipc_callout_get_interface_from_tnc_connid},
	{"Get_Frequency", ipc_callout_get_frequency},
	{"DHCP_Release_Renew", ipc_callout_dhcp_release_renew},
	{"Disconnect_Connection", ipc_callout_disconnect_connection},
	{"Get_Are_Doing_PSK", ipc_callout_get_doing_psk},
	{"Get_Is_Connection_In_Use", ipc_callout_get_is_connection_in_use},
	{"Get_Is_Profile_In_Use", ipc_callout_get_is_profile_in_use},
	{"Get_Is_Trusted_Server_In_Use",
	 ipc_callout_get_is_trusted_server_in_use},
	{"Get_Are_Administrator", ipc_callout_get_are_administrator},
	{"Enum_Smartcard_Readers", ipc_callout_enum_smartcard_readers},
	{"Enum_User_Certs", ipc_callout_enum_user_certs},
	{"Store_Logon_Creds", ipc_callout_store_logon_creds},
	{NULL, NULL}
};

// XXX ICK..  Do this better.
extern void (*imc_disconnect_callback) (uint32_t connectionID);

/**
 *  \brief Take a character array that contains an XML document, parse it, and make sure
 *			it is something we understand.
 *
 *  \param[in] xmlbuf   A pointer to a memory buffer containing a properly formed XML
 *                      document.
 *
 *  \param[in] buffersize   The size of the buffer that xmlbuf points to.
 *
 *  \retval xmlDocPtr   An xmlDocPtr containing the libxml2 parsed version of the
 *                      document.
 **/
xmlDocPtr ipc_callout_validate_msg(xmlChar * xmlbuf, int buffersize)
{
	xmlDocPtr doc;
	xmlNodePtr n;
	xmlChar *prop;

	if (!xsup_assert((xmlbuf != NULL), "xmlbuf != NULL", FALSE))
		return NULL;

	if (!xsup_assert((buffersize > 0), "buffersize > 0", FALSE))
		return NULL;

	doc = xmlReadMemory((char *)xmlbuf, buffersize, "ipc.xml", NULL, 0);
	if (doc == NULL)
		return NULL;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}

	prop = xmlGetProp(n, (xmlChar *) "Version");
	if (prop == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}

	if (strcmp((char *)prop, CMD_VERSION) != 0) {
		xmlFreeDoc(doc);
		xmlFree(prop);
		return NULL;
	}

	if (prop != NULL)
		xmlFree(prop);

	return doc;
}

/**
 * \brief Create the XML message structure that we will use to pass a log 
 *        message to the IPC event listener.
 *
 * \retval NULL on failure
 * \retval xmlDocPtr a document that is built to be an event.  The caller should
 *         get the root node of the document, and append children to fill out the
 *         message.
 **/
xmlDocPtr ipc_callout_build_doc()
{
	xmlDocPtr doc;
	xmlNodePtr n;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc == NULL)
		return NULL;

	n = xmlNewNode(NULL, BAD_CAST "xsup_ipc");
	if (n == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}

	if (xmlNewProp(n, (xmlChar *) "Version", (xmlChar *) CMD_VERSION) ==
	    NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't set version attribute on XML document!\n");
		xmlFreeNode(n);
		return NULL;
	}

	xmlDocSetRootElement(doc, n);

	return doc;
}

/**
 * \brief Create an error message to send back to an IPC client.
 *
 *  Generate an error message that will contain the interface name that generated it,
 *  the command name that it was generated during, and a 32 bit id number (see ipc_callout.h 
 *  for ids and descriptions).
 *
 *  \param[in] intname   The interface name that caused the error.  (May be NULL.)
 *  \param[in] cmdname   The command name that caused the error.
 *  \param[in] idnum   The error ID code.  (See \ref ipc_callout.h)
 *  \param[out] outnode   The XML document that identifies the error.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on error
 *
 *  \warning If this function returns success, the caller should also return success so
 *           that the message is sent.  If the caller returns an error, the message is
 *           discarded!
 *
 *  \warning The value for intname can be NULL, in this case, an empty node is created,
 *               the processor on the other end of the pipe should handle this case.  If
 *               intname is NULL, then it means the error was something that wasn't
 *               interface specific.
 **/
int ipc_callout_create_error(char *intname, char *cmdname, int idnum,
			     xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	char numstr[6];
	char *temp = NULL;

	if (cmdname == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Attempt to create an error document with a "
			     "NULL command name!\n");
		return IPC_FAILURE;
	}

	debug_printf(DEBUG_IPC, "Creating an error response!\n");

	n = xmlNewNode(NULL, (xmlChar *) "Error");
	if (n == NULL)
		return IPC_FAILURE;

	ipc_callout_convert_amp(intname, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface_Name", (xmlChar *) temp)
	    == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Interface_Name> node in error "
			     "document!\n");
		xmlFreeNode(n);
		free(temp);
		return IPC_FAILURE;
	}
	free(temp);

	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Command_Name",
	     (xmlChar *) cmdname) == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Command_Name> node in error "
			     "document!\n");
		xmlFreeNode(n);
		return IPC_FAILURE;
	}

	sprintf((char *)&numstr, "%d", idnum);
	if (xmlNewChild(n, NULL, (xmlChar *) "Error_Code", (xmlChar *) numstr)
	    == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Error_Code> node in error "
			     "document!\n");
		xmlFreeNode(n);
		return IPC_FAILURE;
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Generate an ACK to a request specified by 'cmdname'.
 *
 *  \param[in] intname   The OS name of the interface this ACK is in response to. (May be NULL)
 *  \param[in] cmdname   The IPC command that the ACK is for.
 *  \param[out] outnode   The XML document that should be sent to the client.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on error
 *
 *  \warning    The value for intname can be NULL, in this case, an empty node is created,
 *               the processor on the other end of the pipe should handle this case.  If
 *               intname is NULL, then it means the ACK was something that wasn't
 *               interface specific.
 **/
int ipc_callout_create_ack(char *intname, char *cmdname, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	char *temp = NULL;

	if (cmdname == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Attempt to create an ACK document with a NULL "
			     "command name!\n");
		return IPC_FAILURE;
	}

	debug_printf(DEBUG_IPC, "Creating an ACK response!\n");

	n = xmlNewNode(NULL, (xmlChar *) "ACK");
	if (n == NULL)
		return IPC_FAILURE;

	ipc_callout_convert_amp(intname, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface_Name", (xmlChar *) temp)
	    == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Failed to create <Interface_Name> in XML ACK document!\n");
		xmlFreeNode(n);
		FREE(temp);
		return IPC_FAILURE;
	}
	FREE(temp);

	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Command_Name",
	     (xmlChar *) cmdname) == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Failed to create <Command_Name> in XML ACK document!\n");
		xmlFreeNode(n);
		return IPC_FAILURE;
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 *  \brief Given the IPC command name, locate the function that should be called to handle it, and
 *         call it.
 *
 *  \param[in] name   The IPC command name to execute.
 *  \param[in] cur_node   A pointer to the node for the command.
 *  \param[out] respNode   A pointer to a node suitable for inclusion in a libxml2
 *                         result document.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on error, 
 *  \retval IPC_FUNCTION_NOT_FOUND on function not found.
 **/
int ipc_callout_call_request(char *name, xmlNodePtr cur_node,
			     xmlNodePtr * respNode)
{
	int i = 0;

	if (!xsup_assert((name != NULL), "name != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((cur_node != NULL), "cur_node != NULL", FALSE))
		return IPC_FAILURE;

	while ((my_ipc_calls[i].name != NULL)
	       && (strcmp(my_ipc_calls[i].name, name) != 0))
		i++;

	if (my_ipc_calls[i].name == NULL)
		return IPC_FUNCTION_NOT_FOUND;

	debug_printf(DEBUG_IPC, "IPC Function Index: '%d'\n", i);
	debug_printf(DEBUG_IPC, "IPC Function Name: '%s' @ address (0x%08X)\n",
		     my_ipc_calls[i].name, my_ipc_calls[i].ipc_call);

	// Otherwise, call the function and return the value.
	return my_ipc_calls[i].ipc_call(cur_node, respNode);
}

/**
 *  \brief Search through the node list, and find the node called 'nodename'.
 *
 *  \param[in] head   A pointer to the head of a linked node list that may contain
 *                    the node we are looking for.
 *  \param[in] nodename   The tag name of the node we are looking for.  (i.e. If
 *                        you are looking for <foo/>, this value should be set to
 *                        "foo".)
 *
 *  \retval NULL   on failure
 *  \retval xmlNodePtr   if the node was found in the list.
 *
 *  \warning This function will *NOT* check child nodes!
 **/
xmlNodePtr ipc_callout_find_node(xmlNodePtr head, char *nodename)
{
	xmlNodePtr cur_node;

	if (!xsup_assert((head != NULL), "head != NULL", FALSE))
		return NULL;

	if (!xsup_assert((nodename != NULL), "nodename != NULL", FALSE))
		return NULL;

	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if ((cur_node->type == XML_ELEMENT_NODE)
		    && (strcmp((char *)cur_node->name, nodename) == 0)) {
			return cur_node;
		}
	}

	return NULL;
}

/**
 * \brief Process an IPC message.
 *
 * \param[in] buffer   A memory buffer that points to the text representation of
 *                     an XML document to be processed.
 * \param[in] size     The size of 'buffer'.
 * \param[out] retbuf   A memory buffer that points to the text representation of
 *                      an XML document to send to the client.
 * \param[out] retsize  The size of 'retbuf'.
 *
 * \todo Revisit the result values for this function!
 **/
uint8_t ipc_callout_process(uint8_t * buffer, int size, uint8_t ** retbuf,
			    int *retsize)
{
	xmlDocPtr doc = NULL, outdoc = NULL;
	xmlNodePtr cur_node = NULL, n = NULL, newChild = NULL, newRoot = NULL;
	unsigned int valid_count = 0;
	uint8_t retval = 0;

	(*retbuf) = NULL;
	(*retsize) = 0;

	if (!xsup_assert((buffer != NULL), "buffer != NULL", FALSE))
		return 0;

	if (!xsup_assert((size > 0), "size > 0", FALSE))
		return 0;

	doc = ipc_callout_validate_msg(buffer, size);
	if (doc == NULL) {
		debug_printf(DEBUG_IPC, "Failed Message (%d) :\n", size);
		debug_hex_dump(DEBUG_IPC, buffer, size);
		// If we get an error here, silently discard the request.
		debug_printf(DEBUG_NORMAL,
			     "Error parsing/validating IPC request document!\n");
		xmlFreeDoc(doc);
		return 0;
	}

	outdoc = ipc_callout_build_doc();
	if (outdoc == NULL) {
		// If we can't build a response, then we discard the request.
		debug_printf(DEBUG_NORMAL,
			     "Error creating new IPC response document!\n");
		xmlFreeDoc(doc);
		return 0;
	}

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't get root node in request document!\n");
		xmlFreeDoc(doc);
		xmlFreeDoc(outdoc);
		return 0;
	}

	newRoot = xmlDocGetRootElement(outdoc);
	if (newRoot == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't get root node from response document!\n");
		xmlFreeDoc(doc);
		xmlFreeDoc(outdoc);
		return 0;
	}
	// Parse all of our nodes, and call the functions for them.
	for (cur_node = n->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			switch (ipc_callout_call_request
				((char *)cur_node->name, cur_node, &newChild)) {
			case IPC_SUCCESS:
				// Attach this node to the root set of nodes.
				if (xmlAddChild(newRoot, newChild) == NULL) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't add child node to response document!\n");
					xmlFreeNode(newChild);
				} else {
					valid_count++;
				}
				break;

			case IPC_FAILURE:
				debug_printf(DEBUG_NORMAL,
					     "There was an error building a response to the '%s' request!\n",
					     cur_node->name);
				if (newChild != NULL)
					xmlFreeNode(newChild);
				break;

			case IPC_FUNCTION_NOT_FOUND:
				debug_printf(DEBUG_NORMAL,
					     "Couldn't locate a handler for request '%s'!\n",
					     cur_node->name);
				if (ipc_callout_create_error(NULL, (char *)cur_node->name,
				     IPC_ERROR_UNKNOWN_REQUEST,
				     &newChild) == 0) {
					if (xmlAddChild(newRoot, newChild) == NULL) {
						debug_printf(DEBUG_NORMAL,
							     "Couldn't add child node to response document!\n");
						xmlFreeNode(newChild);
					} else {
						valid_count++;
					}
				} else {
					xmlFreeNode(newChild);
				}
				break;

			case IPC_CHANGE_TO_EVENT_ONLY:
				retval = IPC_CHANGE_TO_EVENT_ONLY;
				// Attach this node to the root set of nodes.
				if (xmlAddChild(newRoot, newChild) == NULL) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't add child node to response document!\n");
					xmlFreeNode(newChild);
				} else {
					valid_count++;
				}
				break;

			case IPC_CHANGE_TO_SYNC_ONLY:
				retval = IPC_CHANGE_TO_SYNC_ONLY;
				// Attach this node to the root set of nodes.
				if (xmlAddChild(newRoot, newChild) == NULL) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't add child node to response document!\n");
					xmlFreeNode(newChild);
				} else {
					valid_count++;
				}
				break;

			default:
				debug_printf(DEBUG_NORMAL,
					     "Unknown return value from ipc_callout_request()!\n");
				
				if(newChild != NULL)
				{
					xmlFreeNode(newChild);
				}
				
				break;
			}
		}
	}

	if (valid_count == 0) {
		// Nothing to return!
		(*retbuf) = NULL;
		(*retsize) = 0;
	} else {
		// Then, put the document back in to a format to be sent.
		xmlDocDumpFormatMemory(outdoc, retbuf, retsize, 0);
	}

	xmlFreeDoc(outdoc);
	xmlFreeDoc(doc);

	return retval;
}

/**
 * \brief Process a "Ping" message, and return a "Pong".
 *
 * \param[in] innode     The XML node containing the "Ping" request.
 * \param[out] outnode   The XML node holding the result of processing the "Ping"
 *                       request.
 *
 * \retval IPC_FAILURE on failure
 * \retval IPC_SUCCESS on success
 **/
int ipc_callout_ping(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n;

	(*outnode) = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC PING request!\n");

	// If we got here, then we know this is a PING request, so we really don't need any
	// information from indoc.  We just need to build a response, and send it off.

	n = xmlNewNode(NULL, (xmlChar *) "Pong");	// No content for a ping response.
	if (n == NULL) {
		// If we get here, then we probably are out of memory.  But, we should attempt to
		// build an error packet anyway.
		return ipc_callout_create_error(NULL, "Ping",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 *  \brief Handle an Interfaces request by dumpping the interface cache, and sending it.
 *
 *  \param[in] innode   A pointer to the node that contains the enum interfaces 
 *                      request.
 *  \param[out] outnode   The node(s) that result from processing innode.
 *
 *  \retval IPC_FAILURE on failure
 *  \retval IPC_SUCCESS on success
 **/
int ipc_callout_enum_live_interfaces(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	struct interfaces *intcache = NULL;
	unsigned int count;
	char res[100];
	char *temp = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC Interfaces request!\n");

	// If we got here, then we know this is a Interface request, so we really don't need any
	// information from indoc.  We just need to build a response, and send it off.
	intcache = interfaces_get_cache_head();
	if (intcache == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No interfaces found to enumerate!\n");
		return ipc_callout_create_error(NULL, "Interface_Live_List",
						IPC_ERROR_NO_INTERFACES,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Interface_Live_List");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Interface_Live_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	count = liblist_num_nodes((genlist *) intcache);

	sprintf((char *)&res, "%d", count);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface_Count", (xmlChar *) res)
	    == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Interface_Live_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	while (intcache != NULL) {
		t = xmlNewChild(n, NULL, (xmlChar *) "Interface", NULL);
		if (t == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Interface_Live_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		ipc_callout_convert_amp(intcache->intname, &temp);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface_Name",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			free(temp);
			return ipc_callout_create_error(NULL,
							"Interface_Live_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		free(temp);

		ipc_callout_convert_amp(intcache->desc, &temp);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface_Description",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			free(temp);
			return ipc_callout_create_error(NULL,
							"Interface_Live_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		free(temp);

		if (xmlNewChild(t, NULL, (xmlChar *)"Interface_Friendly_Name",
			(xmlChar *)intcache->friendlyName) == NULL) {
				xmlFreeNode(n);
				free(temp);
				return ipc_callout_create_error(NULL, "Interface_Live_List",
					IPC_ERROR_CANT_ALLOCATE_NODE, outnode);
		}

		sprintf((char *)&res, "%d", intcache->is_wireless);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface_Is_Wireless",
		     (xmlChar *) res) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Interface_Live_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		intcache = intcache->next;
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 *  \brief Got a request to enumerate the EAP methods that we know about.
 *
 *  \param[in] innode   A pointer to the node that contains the enumerate EAP
 *                      methods request.
 *  \param[out] outnode   The resulting XML node(s) from the enumerate EAP
 *                        methods request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_enum_eap_methods(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n, t;
	unsigned int count, i;
	char res[100];

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC Enum EAP Methods request!\n");

	// If we got here, then we know this is a Interface request, so we really don't need any
	// information from indoc.  We just need to build a response, and send it off.
	n = xmlNewNode(NULL, (xmlChar *) "EAP_Methods_List");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "EAP_Methods_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	count = 0;

	while (eaphandlers[count].eap_type_handler != NO_EAP_AUTH) {
		count++;
	}
	sprintf((char *)&res, "%d", count);
	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Number_Of_Methods",
	     (xmlChar *) res) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "EAP_Methods_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	i = 0;

	while (eaphandlers[i].eap_type_handler != NO_EAP_AUTH) {
		t = xmlNewChild(n, NULL, (xmlChar *) "EAP_Method", NULL);
		if (t == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"EAP_Methods_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Method_Name",
		     (xmlChar *) eaphandlers[i].eapname) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"EAP_Methods_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&res, "%d", eaphandlers[i].eap_type_handler);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Method_Number",
		     (xmlChar *) res) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"EAP_Methods_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		i++;
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Got a request to reload our configuration.
 *
 * \param[in] innode   A pointer to the XML node that contains the configuration
 *                     reload request.
 * \param[out] outnode   The XML node(s) that indicate the result of processing the
 *                       configuration reload request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_reload_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC reload config request!\n");

	global_config_reload();

	return ipc_callout_create_ack(NULL, "Reload_Config", outnode);
}

/**
 * \brief Got a request for us to terminate ourselves.
 *
 * \param[in] innode    A pointer to the XML node that contains the request to
 *                      terminate ourselves.
 * \param[out] outnode  XML node(s) that contain the result of our attempt to
 *                      terminate ourselves.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_terminate(xmlNodePtr innode, xmlNodePtr * outnode)
{
	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC terminate request!\n");

	event_core_terminate();

	return ipc_callout_create_ack(NULL, "Terminate", outnode);
}

/**
 * \brief Get the context data from a request containing the Interface value.
 * 
 * \param[in] innode   The XML node(s) that contain the OS name for the Interface
 *                     we are looking for.
 *
 * \retval NULL on failure, or interface not found.
 * \retval context A pointer to the context that is for the interface specified in 
 *                 "innode".
 **/
context *ipc_callout_get_context_from_int(xmlNodePtr innode)
{
	xmlNodePtr n = NULL;
	xmlChar *content = NULL;
	context *ctx = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return NULL;

	if (innode->children == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Input XML node doesn't have any children to check!\n");
		return NULL;
	}

	n = ipc_callout_find_node(innode->children, "Interface");
	if (n == NULL) {
		return NULL;
	}

	content = xmlNodeGetContent(n);
	if (content == NULL) {
		debug_printf(DEBUG_IPC,
			     "IPC nodes did not contain a name for the Interface!\n");
		return NULL;
	}

	ctx = event_core_locate((char *)content);
	if (ctx == NULL) {
		xmlFree(content);
		return NULL;
	}

	xmlFree(content);
	return ctx;
}

/**
 * \brief Get name of an interface from a request containing the interface description.
 *
 *  \param[in] innode  The node that contains at least one child node that is a
 *                     <Device_Description>.  The <Device_Description> is used to
 *                     determine the proper context to work with.
 *
 *  \retval NULL on failure
 *  \retval ptr A pointer to the OS specific name of the interface. (On success)
 *
 *  \note The caller is expected to free the memory returned.
 **/
char *ipc_callout_get_context_from_desc(xmlNodePtr innode)
{
	xmlNodePtr n;
	xmlChar *content;
	struct xsup_interfaces *ints;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return NULL;

	n = ipc_callout_find_node(innode->children, "Device_Description");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't located <Device_Description> node!\n");
		return NULL;
	}

	content = xmlNodeGetContent(n);

	ints = config_get_config_ints();
	if (ints == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No interfaces were defined in the configuration file!\n",
			     content);
		free(content);
		return NULL;
	}

	while ((ints != NULL)
	       && (strcmp(ints->description, (char *)content) != 0))
		ints = ints->next;

	if (ints == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Got a request for non-existant interface named '%s'!\n",
			     content);
		free(content);
		return NULL;
	}

	free(content);

	content = (xmlChar *) interfaces_get_name_from_mac((char *)ints->mac);

	return (char *)content;
}

/**
 * \brief Build a generic response to some state request.
 *
 *  In general, all of the state XML responses look very similar.  There is basically
 *  only a couple of small differences.  The differences are passed in as parameters 
 *  to this function, so that a single function that be used for multiple state machine
 *  responses.
 *
 *  \param[in] request_state   The text of the tag that was used to request the state
 *                             information.  (This value is used in the event that an 
 *                             error message needs to be returned.)
 *  \param[in] response_state   The text for the tag that will be used to carry the
 *                              response message.
 *  \param[in] state_value   The numeric value that represents the state that the requested
 *                           state machine is in.
 *  \param[in] response_key   The text for the tag that will carry the response value.
 *  \param[in] device   The OS specific name for the device that the state machine value is 
 *                      for.
 *  \param[out] outnode   The XML node tree that contains the response.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_some_state_response(char *request_state, char *response_state,
				    int state_value, char *response_key,
				    char *device, xmlNodePtr * outnode)
{
	char resultstr[10];
	xmlNodePtr n = NULL;
	char *temp = NULL;

	if (!xsup_assert
	    ((request_state != NULL), "request_state != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert
	    ((response_state != NULL), "response_state != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((response_key != NULL), "response_key != NULL", FALSE))
		return IPC_FAILURE;

	/*  -- Some callers use this function with a NULL device, which is allowable.
	if (!xsup_assert((device != NULL), "device != NULL", FALSE))
		return IPC_FAILURE;
*/
	sprintf((char *)&resultstr, "%d", state_value);

	n = xmlNewNode(NULL, (xmlChar *) response_state);
	if (n == NULL)
		return ipc_callout_create_error(device, request_state,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);

	if (xmlNewChild
	    (n, NULL, (xmlChar *) response_key,
	     (xmlChar *) resultstr) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(device, request_state,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(device, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		xmlFreeNode(n);
		free(temp);
		return ipc_callout_create_error(device, request_state,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;

	return IPC_SUCCESS;
}

/**
 * \brief Build a response to some string based request.
 *
 * \param[in] request   The text of the tag that was used to request the state
 *                      information.  (This value is used in the event that an 
 *                      error message needs to be returned.)
 * \param[in] response  The text for the tag that will be used to carry the
 *                      response message.
 * \param[in] value     The string that is sent in response to the request.
 * \param[in] response_key   The text for the tag that will carry the response value.
 * \param[in] device    The OS specific name for the device that the state
 *                      machine value is for.
 * \param[out] outnode  The XML node tree that contains the response.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_some_response_str(char *request, char *response, char *value,
				  char *response_key, char *device,
				  xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	char *temp = NULL;

	if (!xsup_assert((request != NULL), "request != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((response != NULL), "response != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((response_key != NULL), "response_key != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((device != NULL), "device != NULL", FALSE))
		return IPC_FAILURE;

	// We have the data we need, so create the response.
	n = xmlNewNode(NULL, (xmlChar *) response);
	if (n == NULL)
		return ipc_callout_create_error(device, request,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);

	if (xmlNewChild(n, NULL, (xmlChar *) response_key, (xmlChar *) value) ==
	    NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(device, request,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(device, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		xmlFreeNode(n);
		free(temp);
		return ipc_callout_create_error(device, request,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;

	return IPC_SUCCESS;
}

/**
 * \brief Build a 32 bit (signed) value response to some state request.
 *
 * \param[in] request   The text of the tag that was used to request the state
 *                      information.  (This value is used in the event that an 
 *                      error message needs to be returned.)
 * \param[in] response  The text for the tag that will be used to carry the
 *                      response message.
 * \param[in] value   The 32 bit (signed) int that is sent in response to the request.
 * \param[in] response_key   The text for the tag that will carry the response value.
 * \param[in] device         The OS specific name for the device that the
 *                           state machine value is for.
 * \param[out] outnode       The XML node tree that contains the response.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_response_int32(char *request, char *response, long int value,
			       char *response_key, char *device,
			       xmlNodePtr * outnode)
{
	char resultstr[12];
	xmlNodePtr n = NULL;
	char *temp = NULL;

	if (!xsup_assert((request != NULL), "request != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((response != NULL), "response != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((response_key != NULL), "response_key != NULL", FALSE))
		return IPC_FAILURE;

	if (!xsup_assert((device != NULL), "device != NULL", FALSE))
		return IPC_FAILURE;

	sprintf((char *)&resultstr, "%ld", value);

	n = xmlNewNode(NULL, (xmlChar *) response);
	if (n == NULL)
		return ipc_callout_create_error(device, request,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);

	if (xmlNewChild
	    (n, NULL, (xmlChar *) response_key,
	     (xmlChar *) resultstr) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(device, request,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(device, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		xmlFreeNode(n);
		free(temp);
		return ipc_callout_create_error(device, request,
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;

	return IPC_SUCCESS;
}

/**
 * \brief Return the current state of the 802.1X state machine for a given interface.
 *
 * \param[in] innode     The XML node tree that contains the request to get the
 *                       current state of the 802.1X state machine.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_1x_state(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_1X_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->statemachine == NULL)
		return ipc_callout_create_error(ctx->intName, "Get_1X_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_state_response("Get_1X_State", "dot1X_State",
					       ctx->statemachine->curState,
					       "State", ctx->intName, outnode);
}

/**
 *  \brief Return the current state of the EAP state machine for a given interface.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     current state of the EAP state machine.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_eap_state(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_EAP_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->eap_state == NULL)
		return ipc_callout_create_error(ctx->intName, "Get_EAP_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_state_response("Get_EAP_State", "EAP_State",
					       ctx->eap_state->eap_sm_state,
					       "State", ctx->intName, outnode);
}

/**
 *  \brief Return the current state of the 802.1X backend state machine for a given interface.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     current state of the 802.1X backend state machine.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_backend_state(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_Backend_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->statemachine == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Backend_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_state_response("Get_Backend_State",
					       "Backend_State",
					       ctx->statemachine->curState,
					       "State", ctx->intName, outnode);
}

/**
 *  \brief Return the current state of the physical state machine for a given interface.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     current state of the physical state machine.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_physical_state(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_Physical_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intTypeData == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Physical_State",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intType == ETH_802_11_INT) {
		wctx = (wireless_ctx *) ctx->intTypeData;

		return ipc_callout_some_state_response("Get_Physical_State",
						       "Physical_State",
						       wctx->state, "State",
						       ctx->intName, outnode);
	}
	// Need to add support for wired state.
	return IPC_FAILURE;
}

/**
 *  \brief Return the pairwise key for a given interface.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     pairwise key type.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_pairwise_key_type(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_Pairwise_Key_Type",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intTypeData == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Pairwise_Key_Type",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intType == ETH_802_11_INT) {
		wctx = ctx->intTypeData;

		if ((wctx == NULL) || (wctx->state != ASSOCIATED)) {
			return
			    ipc_callout_some_state_response
			    ("Get_Pairwise_Key_Type", "Pairwise_Key_Type",
			     CIPHER_NONE, "Key_Type", ctx->intName, outnode);
		} else {
			return
			    ipc_callout_some_state_response
			    ("Get_Pairwise_Key_Type", "Pairwise_Key_Type",
			     wctx->pairwiseKeyType, "Key_Type", ctx->intName,
			     outnode);
		}
	}
	// Need to add support for wired state.
	return IPC_FAILURE;
}

/**
 *  \brief Return the group key type for a given interface.
 * 
 *  \param innode   A pointer to the XML node that contains the group
 *                  key request.
 *  \param outnode   The resulting XML nodes.  It will either contain the
 *                   group key type, or an error message.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_group_key_type(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_Group_Key_Type",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intTypeData == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Group_Key_Type",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intType == ETH_802_11_INT) {
		wctx = ctx->intTypeData;

		if ((wctx == NULL) || (wctx->state != ASSOCIATED)) {
			return
			    ipc_callout_some_state_response
			    ("Get_Group_Key_Type", "Group_Key_Type",
			     CIPHER_NONE, "Key_Type", ctx->intName, outnode);
		} else {
			return
			    ipc_callout_some_state_response
			    ("Get_Group_Key_Type", "Group_Key_Type",
			     wctx->groupKeyType, "Key_Type", ctx->intName,
			     outnode);
		}
	}
	// Need to add support for wired state.
	return IPC_FAILURE;
}

/**
 *  \brief Return the EAP type in use for a given interface.  (May be 0, if
 *         authentication is not complete yet.
 *
 *  \param innode   A pointer to the XML nodes that contain the request to get the
 *                  EAP type in use.
 *  \param outnode   A pointer to the XML nodes that contain the EAP type for an
 *                   interface, or an error message.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_eap_type_in_use(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_EAP_Type_In_Use",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->eap_state == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_EAP_Type_In_Use",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_state_response("Get_EAP_Type_In_Use",
					       "EAP_Type_In_Use",
					       ctx->eap_state->selectedMethod,
					       "EAP_Type", ctx->intName,
					       outnode);
}

/**
 *  \brief Return the SSID in use for a given interface. 
 *
 *  \param innode   A pointer to the nodes that contain the request to get the
 *                  SSID that an interface is attempting to associate to.
 *
 *  \param outnode   A pointer to the nodes that contain the SSID information.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \note   This call will return a value even if the interface isn't actually 
 *          associated to the network.  As such, this call should not be used to
 *          determine the association state of an interface!  (A better choice would
 *          be to use the "get BSSID" call.)
 **/
int ipc_callout_get_ssid(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_SSID",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intTypeData == NULL)
		return ipc_callout_create_error(ctx->intName, "Get_SSID",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_response_str("Get_SSID", "SSID",
					     ((wireless_ctx
					       *)
					      (ctx->intTypeData))->cur_essid,
					     "SSID_Name", ctx->intName,
					     outnode);
}

/**
 *  \brief Return the BSSID in use for a given interface. 
 *
 *  \param innode   A pointer to the nodes that contain the request to get
 *                  the BSSID.
 *  \param outnode   A pointer to the nodes that contain either the BSSID of
 *                   the AP that we are connected to, or an error.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \note  This function can be used to determine if the AP is associated.  However,
 *         depending on the OS in use, it will return different values.  On Windows,
 *         if the interface isn't associated it will return an error.  On Linux, it is
 *         likely that a BSSID of 44:44:44:44:44:44 will be returned.  (All 0s and all Fs 
 *         is also possible, but unusual.)  Calls to this function for the purposes of
 *         determining the association state should keep this in mind.
 **/
int ipc_callout_get_bssid(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	unsigned char addr[50], mac[6];

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_BSSID",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (cardif_GetBSSID(ctx, (char *)&mac) != XENONE)
		return ipc_callout_create_error(ctx->intName, "Get_BSSID",
						IPC_ERROR_INVALID_BSSID,
						outnode);

	sprintf((char *)&addr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
		mac[2], mac[3], mac[4], mac[5]);
	return ipc_callout_some_response_str("Get_BSSID", "BSSID", (char *)addr,
					     "BSSID_Value", ctx->intName,
					     outnode);
}

/**
 *  \brief Return the length of time (in seconds) that we have been in authenticated state.
 *
 *  \param[in] innode   A pointer to the nodes that contain the request to determine the
 *                      number of seconds that the connection has been in AUTHENTICATED
 *                      state.
 *  \param[out] outnode   A pointer to the nodes that contain the number of seconds that
 *                        an interface has been in AUTHENTICATED state.  It may also contain
 *                        an error, but that is unusual.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \note   If the interface isn't currently in authenticated state, this function will
 *          not return a useful value.  As such, it should not be used to determine if an
 *          authentication has been successful.  You should query the 802.1X state machine
 *          instead.
 **/
int ipc_callout_get_seconds_authenticated(xmlNodePtr innode,
					  xmlNodePtr * outnode)
{
	context *ctx = NULL;
	uint64_t curuptime = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL,
						"Get_Seconds_Authenticated",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->statemachine == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Seconds_Authenticated",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if ((ctx->statemachine->curState != AUTHENTICATED) &&
	    (ctx->statemachine->curState != S_FORCE_AUTH) &&
	    (ctx->statemachine->curState != S_FORCE_UNAUTH)) {
		return ipc_callout_response_int32("Get_Seconds_Authenticated",
						  "Seconds_Authenticated", 0,
						  "Seconds", ctx->intName,
						  outnode);
	}
#ifdef WINDOWS
	if (cardif_windows_get_uptime(&curuptime) != 0) {
		return ipc_callout_create_error(ctx->intName,
						"Get_Seconds_Authenticated",
						IPC_ERROR_CANT_GET_SYS_UPTIME,
						outnode);
	}
#else
	if (cardif_get_uptime(&curuptime) != 0) {
		return ipc_callout_create_error(ctx->intName,
						"Get_Seconds_Authenticated",
						IPC_ERROR_CANT_GET_SYS_UPTIME,
						outnode);
	}
	if ((ctx->statemachine->portEnabled == FALSE)
	    && (ctx->statemachine->to_authenticated == 0))
		curuptime = 0;
#endif				/* WINDOWS */

	// ipc_callout_response_int32 should handle a 64 bit number properly as well.
	return ipc_callout_response_int32("Get_Seconds_Authenticated",
					  "Seconds_Authenticated",
					  (curuptime -
					   ctx->statemachine->to_authenticated),
					  "Seconds", ctx->intName, outnode);
}

/**
 *  \brief Return the signal strength as a percentage.
 *
 *  \param[in] innode   A pointer to the nodes that contain the request to get the
 *                      signal strength.
 *
 *  \param[out] outnode   A pointer to the result nodes that contain the signal strength.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \warning If an interface is not associated, the resulting value is undefined.  
 *
 *  \note  If the interface is not associated, different OSes will present different things, 
 *          from an error condition, to a value that appears perfectly reasonable.  As such,
 *          this value should not be used unless the interface is in ASSOCIATED state.
 *
 *  \note  Because different OSes will return signal strength in different ways, the percentage
 *         value returned should not be considered accurate.  Instead, it is a rough
 *         estimate that should be used to provide the user with eye candy, and nothing more.
 *         It is also possible that in certain circumstances the resulting value may be
 *         greater that 100%.  In these cases, the UI should display the value as 100%.
 **/
int ipc_callout_get_signal_strength_percent(xmlNodePtr innode,
					    xmlNodePtr * outnode)
{
	context *ctx;
	int strength;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL,
						"Get_Signal_Strength_Percent",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intType != ETH_802_11_INT)
		return ipc_callout_create_error(ctx->intName,
						"Get_Signal_Strength_Percent",
						IPC_ERROR_INT_NOT_WIRELESS,
						outnode);

	strength = cardif_get_signal_strength_percent(ctx);
	if (strength < 0)
		return ipc_callout_create_error(ctx->intName,
						"Get_Signal_Strength_Percent",
						IPC_ERROR_INVALID_SIGNAL_STRENGTH,
						outnode);

	return ipc_callout_some_state_response("Get_Signal_Strength_Percent",
					       "Signal_Strength", strength,
					       "Percent", ctx->intName,
					       outnode);
}

/**
 *  \brief Handle a request for all connections defined in a configuration file.
 *
 *  \param[in] innode   A pointer to the nodes that contain a request to determine all of 
 *                      the available connections.
 *
 *  \param[out] outnode   A pointer to the resulting nodes that contain various information
 *                        about the available connection.  (The connection name, the device
 *                        description for the interface that a connection is bound to, the 
 *                        SSID name (if it is wireless), and the priority value for the 
 *                        connection.)
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 **/
int ipc_callout_enum_connections(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	unsigned int count = 0, result = 0;
	uint8_t config_type = 0;
	xmlChar *ttype = NULL;
	char res[100];

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC enum connections request!\n");

	n = ipc_callout_find_node(innode, "Enum_Connections");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid request to enumerate connections!\n");
		return ipc_callout_create_error(NULL, "Enum_Connections",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No <Config_Type> node found in the <Enum_Connections> request!  Not sure what to do.\n");
		return ipc_callout_create_error(NULL, "Enum_Connections",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	ttype = xmlNodeGetContent(t);
	config_type = atoi((char *)ttype);
	xmlFree(ttype);

	count = 0;
	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		count =
		    ipc_callout_helper_count_connections(config_get_connections
							 (CONFIG_LOAD_GLOBAL));
	}

	if ((config_type & CONFIG_LOAD_USER) == CONFIG_LOAD_USER) {
		count +=
		    ipc_callout_helper_count_connections(config_get_connections
							 (CONFIG_LOAD_USER));
	}

	n = xmlNewNode(NULL, (xmlChar *) "Connections");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Enum_Connections",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	sprintf((char *)&res, "%d", count);
	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Number_Of_Connections",
	     (xmlChar *) res) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Connections",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		result =
		    ipc_callout_helper_build_connection_list(CONFIG_LOAD_GLOBAL,
							     n);
		if (result != XENONE)
			return ipc_callout_create_error(NULL,
							"Enum_Connections",
							result, outnode);
	}

	if ((config_type & CONFIG_LOAD_USER) == CONFIG_LOAD_USER) {
		result =
		    ipc_callout_helper_build_connection_list(CONFIG_LOAD_USER,
							     n);
		if (result != XENONE)
			return ipc_callout_create_error(NULL,
							"Enum_Connections",
							result, outnode);
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Given a connection name, get the username and password that are currently defined
 *        for this connection.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to get the
 *                     username and password for a connection.
 * \param[out] outnode   A pointer to the nodes that contain the username and password for
 *                       the desired connection.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \note  This returns the active username/password in memory.  It may not match the values
 *        that are in the configuration file if the UI has pushed a new username and/or
 *        password to the supplicant.
 **/
int ipc_callout_get_connection_upw(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n;
	struct config_connection *conn = NULL;
	struct config_profiles *prof = NULL;
	char *request = NULL;
	int authtype = 0;
	char *username = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return -1;

	debug_printf(DEBUG_IPC, "Got an IPC connection u/pw request!\n");

	n = ipc_callout_find_node(innode, "Get_Connection_UPW");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get first UPW node.\n");
		return IPC_FAILURE;
	}

	n = ipc_callout_find_node(n->children, "Connection");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Connection' node.\n");
		return ipc_callout_create_error(NULL, "Get_Connection_UPW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	request = (char *)xmlNodeGetContent(n);
	if (request == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get data from the 'Connection' node.\n");
		return ipc_callout_create_error(NULL, "Get_Connection_UPW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for connection : %s\n", request);
	conn = config_find_connection(CONFIG_LOAD_GLOBAL, request);
	if (conn == NULL) {
		// Didn't find it in the global, so look in the user specific.
		conn = config_find_connection(CONFIG_LOAD_USER, request);
		if (conn == NULL) {
			debug_printf(DEBUG_NORMAL, "Connection not found!\n");
			free(request);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_INVALID_CONN_NAME,
							outnode);
		}
	}

	free(request);

	// Aside from doing our best to locate the named profile, we shouldn't check that
	// prof has a value here.  Those checks are done later.
	prof = config_find_profile(CONFIG_LOAD_GLOBAL, conn->profile);
	if (prof == NULL) {
		prof = config_find_profile(CONFIG_LOAD_USER, conn->profile);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Connection_UPW");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Get_Connection_UPW",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	authtype = conn->association.auth_type;

	// If we don't know what authtype is in use, try to figure it out.
	if (authtype == 0) {
		// We don't explicitly have an auth type, so try to figure it out.
		if (conn->profile != NULL) {
			// We have a profile, so we should be doing 802.1X.
			authtype = AUTH_EAP;
		} else if ((conn->association.psk != NULL)
			   || (conn->association.psk_hex != NULL)) {
			// We have a PSK, so we are probably doing WPA-PSK.
			authtype = AUTH_PSK;
		}
		// If we don't know, then leave it how it was.
	}

	switch (authtype) {
	case AUTH_PSK:
		if (xmlNewChild(n, NULL, (xmlChar *) "Authentication",
		     (xmlChar *) "PSK") == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		break;

	case AUTH_EAP:
		if (xmlNewChild(n, NULL, (xmlChar *) "Authentication",
		     (xmlChar *) "EAP") == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		break;

	case AUTH_NONE:
	default:
		if (xmlNewChild(n, NULL, (xmlChar *) "Authentication",
		     (xmlChar *) "NONE") == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		break;
	}

	if (prof == NULL) {
		if (xmlNewChild(n, NULL, (xmlChar *) "Username", NULL) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (conn == NULL) {
			if (xmlNewChild(n, NULL, (xmlChar *) "Password", NULL)
			    == NULL) {
				xmlFreeNode(n);
				return ipc_callout_create_error(NULL,
								"Get_Connection_UPW",
								IPC_ERROR_CANT_ALLOCATE_NODE,
								outnode);
			}
		} else if ((conn != NULL) && (conn->association.psk == NULL)) {
			if (xmlNewChild(n, NULL, (xmlChar *) "Password",
			     (xmlChar *) conn->association.psk_hex) == NULL) {
				xmlFreeNode(n);
				return ipc_callout_create_error(NULL,
								"Get_Connection_UPW",
								IPC_ERROR_CANT_ALLOCATE_NODE,
								outnode);
			}
		} else {
			if (xmlNewChild(n, NULL, (xmlChar *) "Password",
			     (xmlChar *) conn->association.psk) == NULL) {
				xmlFreeNode(n);
				return ipc_callout_create_error(NULL,
								"Get_Connection_UPW",
								IPC_ERROR_CANT_ALLOCATE_NODE,
								outnode);
			}
		}
	} else {
		username = config_get_inner_user_from_profile(prof->method);
		if (username == NULL) {
		  if (prof->identity != NULL)
		    {
			username = _strdup(prof->identity);
			if (username != NULL) {
				xsup_common_upcase(username);

				// If the outer name starts with anonymous, leave the username field blank.
				if (strncmp(username, "ANONYMOUS", 9) == 0) {
					FREE(username);
				} else {
					FREE(username);
					username = prof->identity;
				}
			}
		    }
		}

		if (xmlNewChild(n, NULL, (xmlChar *) "Username",
		     (xmlChar *) username) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(n, NULL, (xmlChar *) "Password",
		     (xmlChar *) config_get_pwd_from_profile(prof->method)) ==
		    NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Get_Connection_UPW",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Request the association type in use for a given interface.  (i.e. Open, Shared,
 *        LEAP, WPA, WPA2.)
 *
 * \param[in] innode   A pointer to the nodes that contain the request to get the
 *                     association type for an interface.
 * \param[out] outnode   A pointer to the nodes that contain a numeric representation of
 *                       the association type.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \note This will return the association type that the supplicant is attempting to use
 *       to create an association.  It does not actually represent the association method
 *       that an AP wants to use.  It also does not represent the actually state of an
 *       association on an interface.
 **/
int ipc_callout_get_association_type(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_Association_Type",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	wctx = (wireless_ctx *) ctx->intTypeData;
	if (wctx == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Association_Type",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_state_response("Get_Association_Type",
					       "Association_Type",
					       wctx->assoc_type, "Association",
					       ctx->intName, outnode);
}

/**
 * \brief Request that an interface send a logoff message.
 *
 * \param[in] innode   A pointer to the nodes that contain the request for an interface
 *                     to send a logoff message.
 *
 * \param[out] outnode   A pointer to the nodes that contain an ACK on success, or an
 *                       error on failure.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \note This function will only send a logoff message.  It does not stop the interface
 *       from attempting another authentication.  In most cases, when a logoff is sent,
 *       the authenticator will reset it's state machine, and attempt to authenticate the
 *       connection again.  Because of this, the logoff is usually not useful by itself.
 *
 **/
int ipc_callout_request_logoff(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Request_Logoff",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (statemachine_change_state(ctx, LOGOFF) == 0) {
		ctx->conn = NULL;
		FREE(ctx->conn_name);
		eap_sm_deinit(&ctx->eap_state);
		eap_sm_init(&ctx->eap_state);
		ctx->auths = 0;	// So that we renew DHCP on the next authentication.

		txLogoff(ctx);

#ifdef WINDOWS
		cardif_windows_release_ip(ctx);
#else
#warning Fill this in for your OS!
#endif

		return ipc_callout_create_ack(ctx->intName, "Request_Logoff",
					      outnode);
	} else {
		return ipc_callout_create_error(NULL, "Request_Logoff",
						IPC_ERROR_CANT_LOGOFF, outnode);
	}
}

/**
 * \brief Given a device name from the configuration file, determine what the OS 
 *        specific name for the device is.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to get the OS
 *                     specific name from the configuration file device name.
 *
 * \param[out] outnode   A pointer to the nodes that contain the OS specific device name
 *                       for a device name specified in the configuration file.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 **/
int ipc_callout_request_device_name(xmlNodePtr innode, xmlNodePtr * outnode)
{
	char *intname = NULL;
	xmlNodePtr n = NULL;
	char *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	intname = ipc_callout_get_context_from_desc(innode);
	if (intname == NULL) {
		return ipc_callout_create_error(NULL, "Get_Device_Name",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}
	// We have the data we need, so create the response.
	n = xmlNewNode(NULL, (xmlChar *) "Device_Name");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Device_Name> tag!\n");
		return ipc_callout_create_error(intname, "Get_Device_Name",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(intname, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		xmlFreeNode(n);
		free(temp);
		return ipc_callout_create_error(intname, "Get_Device_Name",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Given an OS specific device name, determine what the OS 
 *        specific description for the device is.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to get the OS
 *                     device description from the configuration file device name.
 *
 * \param[out] outnode   A pointer to the nodes that contain the OS device description
 *                       for a device name specified in the configuration file.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 **/
int ipc_callout_request_device_desc(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	xmlNodePtr n = NULL;
	char *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		return ipc_callout_create_error(NULL, "Get_Device_Description",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}
	// We have the data we need, so create the response.
	n = xmlNewNode(NULL, (xmlChar *) "Device_Description");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Device_Description> tag!\n");
		return ipc_callout_create_error(ctx->intName,
						"Get_Device_Description",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(ctx->desc, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Description", (xmlChar *) temp) ==
	    NULL) {
		xmlFreeNode(n);
		free(temp);
		return ipc_callout_create_error(ctx->intName,
						"Get_Device_Description",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 *  \brief Change the username and password in use for a given profile.
 *
 *  \param[in] prof   A pointer to the config_profiles struct that identifies the profile
 *                    to change the username/password for.
 *  \param[in] username   A pointer to the new username to be used for this profile.
 *  \param[in] password   A pointer to the new password to be used for this profile.
 *
 *  \retval 0 on success
 *	\retval nonzero on failure.
 *
 *  \note This function only changes the username and password that is currently stored in
 *        memory.  It does not change the values stored in the configuration file.
 **/
int ipc_callout_set_profile_upw(struct config_profiles *prof, char *username,
				char *password)
{
	// It is perfectly legal to have the username and/or password be NULL.
	if (!xsup_assert((prof != NULL), "prof != NULL", FALSE))
		return -1;

	if (username != NULL) {
		FREE(prof->temp_username);
		prof->temp_username = _strdup(username);
	}

	if (password != NULL) {
		FREE(prof->temp_password);
		prof->temp_password = _strdup(password);
	}

	return 0;
}

/**
 *  \brief Change the value of the PSK used for WPA/WPA2 PSK.
 *
 *  \param[in] conn   A pointer to the config_connection struct that contains the 
 *                    configuration that we want to change the PSK for.
 *  \param[in] password   A pointer to the new PSK that will be used to authenticate on
 *                        this connection.
 *
 *  \retval 0 on success
 *  \retval nonzero on failure.
 *
 *  \note  This function only changes the PSK in memory.  It does not update the configuration
 *         file!
 **/
int ipc_callout_set_connection_psk(struct config_connection *conn,
				   char *password)
{
	if (conn == NULL)
		return -1;

	// Free the password if we already had one.
	FREE(conn->association.temp_psk);

	// Then, set the new one.
	conn->association.temp_psk = _strdup(password);

	return 0;
}

/**
 *  \brief This function will go through all available contexts and make sure that the
 *         proper username and password combinations are up to date.  This should be called
 *         after a username and/or password is updated via IPC, to make sure that the
 *         context structures are still valid.
 *
 *  \warning Failure to use this call after a username and/or password change will result 
 *           in the supplicant crashing!!!!!!
 **/
void ipc_callout_rebind_upw_all()
{
	context *ctx = NULL;

	// Reset the locator to the event indicies.
	event_core_reset_locator();

	ctx = event_core_get_next_context();
	while (ctx != NULL) {
		if ((ctx->eap_state != NULL) && (ctx->prof != NULL)) {
			// Rebind everything....
			ctx->eap_state->ident = ctx->prof->identity;
		}

		ctx = event_core_get_next_context();
	}
}

/**
 * \brief Determine the requirements for the authentication method in use.  In general, we will
 *        require a username and password before we can allow an authentication to begin.  But, some
 *        methods (such as GTC) may require a password be provided in-line to the auth.
 *
 * \note This function returns flags for what the connection needs to proceed.  It doesn't take in
 *       to account what the connection already knows.
 *
 * @param[in] cur   The connection we want to get information on.
 * 
 * \retval uint8_t  A byte that contains flag settings the UI can use to determine what to ask for.
 **/
uint8_t ipc_callout_auth_needs(struct config_connection *cur)
{
	struct config_profiles *profile = NULL;
	struct config_eap_peap *peap = NULL;

	if (!xsup_assert((cur != NULL), "cur != NULL", FALSE))
		return 0;

	profile = config_find_profile(CONFIG_LOAD_GLOBAL, cur->profile);
	if (profile == NULL) {
		profile = config_find_profile(CONFIG_LOAD_USER, cur->profile);
		if (profile == NULL)
			return 0;
	}

	if (profile->method->method_num == EAP_TYPE_PEAP) {
		peap = profile->method->method_data;

		if (peap->phase2->method_num == EAP_TYPE_GTC) {
			return POSS_CONN_NO_PWD;
		}
	}
#ifdef WINDOWS
	if (profile->method->method_num == EAP_TYPE_TLS)
		return POSS_CONN_NO_PWD;
#endif				// WINDOWS

	return 0;
}

/**
 *  \brief Change the username and password in use for a specific connection.
 *
 *  \param[in] innode   A pointer to the node tree that contains the request to change
 *                      the username and password for a connection.
 *  \param[out] outnode   A pointer to the node tree that contains either an ACK for
 *                        success, or an error code for failure.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \warning  If a connection points to something that isn't a WPA(2)-PSK network, then
 *            this call will actually change the username/password on the profile that this
 *            connection points to.  If more than one connection points to the same profile,
 *            this can have undesired results!
 *
 *  \note This call only changes the username and/or password that is stored in memory.  It
 *        does not change the values stored in the configuration file!
 **/
int ipc_callout_set_connection_upw(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	struct config_connection *conn = NULL;
	struct config_profiles *prof = NULL;
	char *request = NULL, *username = NULL, *password = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC connection *SET* u/pw request!\n");

	n = ipc_callout_find_node(innode, "Set_Connection_UPW");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get first UPW node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Connection_Name");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Connection_Name' node.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_UPW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	request = (char *)xmlNodeGetContent(t);
	if (request == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get data from the 'Connection_Name' node.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_UPW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for connection : %s\n", request);
	conn = config_find_connection(CONFIG_LOAD_GLOBAL, request);
	if (conn == NULL) {
		conn = config_find_connection(CONFIG_LOAD_USER, request);
		if (conn == NULL) {
			debug_printf(DEBUG_IPC,
				     "Couldn't locate connection '%s'!\n",
				     request);
			FREE(request);
			return ipc_callout_create_error(NULL,
							"Set_Connection_UPW",
							IPC_ERROR_INVALID_CONN_NAME,
							outnode);
		}
	}
	// Done with 'request'.
	FREE(request);

	if (conn->association.auth_type != AUTH_PSK) {
		prof = config_find_profile(CONFIG_LOAD_GLOBAL, conn->profile);
		if (prof == NULL) {
			prof =
			    config_find_profile(CONFIG_LOAD_USER,
						conn->profile);
			if (prof == NULL) {
				debug_printf(DEBUG_IPC,
					     "Couldn't locate profile '%s'!\n",
					     conn->profile);
				return ipc_callout_create_error(NULL,
								"Set_Connection_UPW",
								IPC_ERROR_INVALID_PROF_NAME,
								outnode);
			}
		}
	}

	t = ipc_callout_find_node(n, "Username");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Username' node.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_UPW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	username = (char *)xmlNodeGetContent(t);
	if ((username != NULL) && (strlen(username) == 0)) {
		xmlFree(username);
		username = NULL;
	}

	if (ipc_callout_auth_needs(conn) == 0) {
		t = ipc_callout_find_node(n, "Password");
		if (t == NULL) {
			debug_printf(DEBUG_IPC,
				     "Couldn't get 'Password' node!\n");
			xmlFree(username);
			return ipc_callout_create_error(NULL,
							"Set_Connection_UPW",
							IPC_ERROR_INVALID_REQUEST,
							outnode);
		}

		password = (char *)xmlNodeGetContent(t);
		if ((password != NULL) && (strlen(password) == 0)) {
			xmlFree(password);
			xmlFree(username);
			password = NULL;
			return ipc_callout_create_error(NULL,
							"Set_Connection_UPW",
							IPC_ERROR_NEED_PASSWORD,
							outnode);
		}
	} else {
		password = NULL;
	}

	if (conn->association.auth_type != AUTH_PSK) {
		if (ipc_callout_set_profile_upw(prof, username, password) != 0) {
			debug_printf(DEBUG_IPC,
				     "Couldn't change username/password!\n");
			xmlFree(username);
			if (password != NULL)
				xmlFree(password);
			return ipc_callout_create_error(NULL,
							"Set_Connection_UPW",
							IPC_ERROR_COULDNT_CHANGE_UPW,
							outnode);
		}
	} else {
		if (ipc_callout_set_connection_psk(conn, password) != 0) {
			debug_printf(DEBUG_IPC, "Couldn't change password!\n");
			if (password != NULL)
				xmlFree(password);
			// Username should already be NULL.  But make sure it is.
			if (username != NULL)
				xmlFree(username);
			return ipc_callout_create_error(NULL,
							"Set_Connection_UPW",
							IPC_ERROR_COULDNT_CHANGE_UPW,
							outnode);
		}
	}

	if (username != NULL)
		xmlFree(username);
	if (password != NULL)
		xmlFree(password);

	ipc_callout_rebind_upw_all();

	return ipc_callout_create_ack(NULL, "Set_Connection_UPW", outnode);
}

/**
 *  \brief Change the password in use for a specific connection.
 *
 *  \param[in] innode   A pointer to the node tree that contains the request to change
 *                      the password for a connection.
 *  \param[out] outnode   A pointer to the node tree that contains either an ACK for
 *                        success, or an error code for failure.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \warning  If a connection points to something that isn't a WPA(2)-PSK network, then
 *            this call will actually change the username/password on the profile that this
 *            connection points to.  If more than one connection points to the same profile,
 *            this can have undesired results!
 *
 *  \note This call only changes the password that is stored in memory.  It
 *        does not change the values stored in the configuration file!
 **/
int ipc_callout_set_connection_pw(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	struct config_connection *conn = NULL;
	struct config_profiles *prof = NULL;
	char *request = NULL, *username = NULL, *password = NULL;
	int retval = 0;
	context *ctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC connection *SET* pw request!\n");

	n = ipc_callout_find_node(innode, "Set_Connection_PW");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get first PW node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Connection_Name");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Connection_PW' node.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_PW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	request = (char *)xmlNodeGetContent(t);
	if (request == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get data from the 'Set_Connection_PW' node.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_PW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for connection : %s\n", request);
	conn = config_find_connection(CONFIG_LOAD_GLOBAL, request);
	if (conn == NULL) {
		conn = config_find_connection(CONFIG_LOAD_USER, request);
		if (conn == NULL) {
			debug_printf(DEBUG_IPC,
				     "Couldn't locate connection '%s'!\n",
				     request);
			xmlFree(request);
			return ipc_callout_create_error(NULL,
							"Set_Connection_PW",
							IPC_ERROR_INVALID_CONN_NAME,
							outnode);
		}
	}
	// Done with 'request'.
	xmlFree(request);

	// If we don't know the auth type, try to reason it out.
	if (conn->association.auth_type == AUTH_UNKNOWN) {
		// See if we can figure it out.
		if (conn->profile != NULL) {
			// We are probably using EAP.
			conn->association.auth_type = AUTH_EAP;
		} else if ((conn->profile == NULL)
			   && ((conn->association.association_type == ASSOC_WPA)
			       || (conn->association.association_type ==
				   ASSOC_WPA2))) {
			// We are probably doing PSK.
			conn->association.auth_type = AUTH_PSK;
		} else if ((conn->profile == NULL)
			   &&
			   ((conn->association.association_type == ASSOC_OPEN)
			    || (conn->association.association_type ==
				ASSOC_SHARED))) {
			// We are probably doing static WEP.
			conn->association.auth_type = AUTH_NONE;
		}
	}

	if (conn->association.auth_type == AUTH_EAP) {
		prof = config_find_profile(CONFIG_LOAD_GLOBAL, conn->profile);
		if (prof == NULL) {
			prof =
			    config_find_profile(CONFIG_LOAD_USER,
						conn->profile);
			if (prof == NULL) {
				debug_printf(DEBUG_IPC,
					     "Couldn't locate profile '%s'!\n",
					     conn->profile);
				return ipc_callout_create_error(NULL,
								"Set_Connection_PW",
								IPC_ERROR_INVALID_PROF_NAME,
								outnode);
			}
		}
	}

	t = ipc_callout_find_node(n, "Password");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Password' node!\n");
		FREE(username);
		return ipc_callout_create_error(NULL, "Set_Connection_PW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	password = (char *)xmlNodeGetContent(t);
	if ((password != NULL) && (strlen(password) == 0)) {
		xmlFree(password);
		password = NULL;
		return ipc_callout_create_error(NULL, "Set_Connection_PW",
						IPC_ERROR_NEED_PASSWORD,
						outnode);
	}

	if (conn->association.auth_type == AUTH_EAP) {
		if (ipc_callout_set_profile_upw(prof, username, password) != 0) {
			debug_printf(DEBUG_IPC,
				     "Couldn't change username/password!\n");
			FREE(username);
			FREE(password);
			return ipc_callout_create_error(NULL,
							"Set_Connection_PW",
							IPC_ERROR_COULDNT_CHANGE_UPW,
							outnode);
		}
	} else if (conn->association.auth_type == AUTH_PSK) {
		if (ipc_callout_set_connection_psk(conn, password) != 0) {
			debug_printf(DEBUG_IPC, "Couldn't change password!\n");
			FREE(password);
			// Username should already be NULL.  But make sure it is.
			FREE(username);
			return ipc_callout_create_error(NULL,
							"Set_Connection_UPW",
							IPC_ERROR_COULDNT_CHANGE_UPW,
							outnode);
		}
	} else if (conn->association.auth_type == AUTH_NONE) {
		// Set our static WEP key.
		conn->association.keys[1] = _strdup(password);
		conn->association.txkey = 1;
	} else {
		debug_printf(DEBUG_IPC,
			     "The UI sent us an invalid request.!\n");
		FREE(password);
		// Username should already be NULL.  But make sure it is.
		FREE(username);
		return ipc_callout_create_error(NULL, "Set_Connection_UPW",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	FREE(username);
	FREE(password);

	ipc_callout_rebind_upw_all();

	retval = ipc_callout_create_ack(NULL, "Set_Connection_PW", outnode);

	ctx = event_core_locate_by_connection(conn->name);

	if (ctx == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Unable to restart authentication after the password was provided!\n");
		return retval;
	}

	if (ctx->pwd_callback != NULL) {
		(*ctx->pwd_callback) (ctx);	// Kick restart the authentication.
	}

	return retval;
}

/**
 *  \brief Request that a socket be changed to either an events only socket, or a 
 *         query/response socket.  (In the case of Windows, "socket" = "pipe".)
 *
 *  \param[in] innode   A pointer to the node tree that contains the request to change the
 *                      socket type.
 *  \param[out] outnode   A pointer to a node tree that either contains an ACK, or an error
 *                        code.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 *
 *  \note  This call doesn't change any attributes on the socket, as far as the OS is 
 *         concerned.  It simply sets (or unsets) a flag that indicates that only events
 *         should be sent down this channel.  This allows the supplicant to know if it 
 *         should expect to get any requests on this channel, or not.
 **/
int ipc_callout_change_socket_type(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS, retval2 = IPC_SUCCESS;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC connection change connection type request!\n");

	n = ipc_callout_find_node(innode, "Change_Socket_Type");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'change socket type' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Socket_Event_Only");
	if (t == NULL) {
		t = ipc_callout_find_node(n, "Socket_Sync_Only");
		if (t == NULL) {
			debug_printf(DEBUG_IPC,
				     "No valid socket type found!\n");
			return ipc_callout_create_error(NULL, NULL,
							IPC_ERROR_INVALID_ROOT_NODE,
							outnode);
		} else {
			retval = IPC_CHANGE_TO_SYNC_ONLY;
		}
	} else {
		retval = IPC_CHANGE_TO_EVENT_ONLY;
	}

	retval2 = ipc_callout_create_ack(NULL, "Change_Socket_Type", outnode);
	if (retval2 == IPC_SUCCESS)
		return retval;

	return retval;
}

/**
 * \brief Catch an IPC request to change the connection.
 *
 * This function should update the context, disassociate (if the interface is 
 * wireless), and reinit all of the state machines in order to force them to 
 * reconnect.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 **/
int ipc_callout_change_connection(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS, retval2 = IPC_SUCCESS;
	char *iface = NULL;
	char *conn_name = NULL;
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	struct found_ssids *ssid = NULL;
	xmlChar *content = NULL;
	struct config_profiles *myprof = NULL;
	struct config_connection *mycon = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC change connection request!\n");

	n = ipc_callout_find_node(innode, "Request_Connection_Change");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Request_Connection_Change' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Interface");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Interface> node in the request!\n");
		return ipc_callout_create_error(NULL,
						"Request_Connection_Change",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	content = xmlNodeGetContent(t);
	iface = _strdup((char *)content);
	xmlFree(content);

	if ((iface == NULL) || (strlen(iface) <= 0)) {
		debug_printf(DEBUG_IPC,
			     "An invalid interface was found in the request event!\n");
		return ipc_callout_create_error(NULL,
						"Request_Connection_Change",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	t = ipc_callout_find_node(n, "Connection_Name");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Connection_Name> node in the request!\n");
		return ipc_callout_create_error(NULL,
						"Request_Connection_Change",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	content = xmlNodeGetContent(t);
	conn_name = _strdup((char *)content);
	xmlFree(content);

	if ((conn_name == NULL) || (strlen(conn_name) <= 0)) {
		debug_printf(DEBUG_IPC,
			     "An invalid connection name was found in the request event!\n");
		return ipc_callout_create_error(NULL,
						"Request_Connection_Change",
						IPC_ERROR_INVALID_CONN_NAME,
						outnode);
	}

	debug_printf(DEBUG_IPC,
		     "Changing to connection '%s' on interface '%s'.\n",
		     conn_name, iface);

	ctx = event_core_locate(iface);
	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate the interface requested over IPC!\n");
		free(conn_name);
		return ipc_callout_create_error(iface,
						"Request_Connection_Change",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	switch (xsupconfcheck_check_connection(ctx, conn_name, TRUE)) {
	case CONNECTION_NEED_PIN:
		mycon = config_find_connection(CONFIG_LOAD_USER, conn_name);
		if (mycon == NULL)
			mycon =
			    config_find_connection(CONFIG_LOAD_GLOBAL,
						   conn_name);

		if (mycon != NULL) {
			myprof =
			    config_find_profile(CONFIG_LOAD_USER,
						mycon->profile);
			if (myprof == NULL)
				myprof =
				    config_find_profile(CONFIG_LOAD_GLOBAL,
							mycon->profile);

#ifdef EAP_SIM_ENABLE
			if (myprof != NULL) {
				if (myprof->method->method_num == EAP_TYPE_AKA) {
					if (eapaka_is_pin_needed
					    (ctx,
					     myprof->method->method_data) ==
					    FALSE)
						break;
				} else if (myprof->method->method_num ==
					   EAP_TYPE_SIM) {
					if (eapsim_is_pin_needed
					    (ctx,
					     myprof->method->method_data) ==
					    FALSE)
						break;
				}
			}
#endif
		}
		// Fall through.

	case CONNECTION_NEED_UPW:
	case CONNECTION_NEED_PSK:
		// If the EAP method is using logon creds and we have some, move along.
		if (ipc_callout_helper_can_use_logon_creds(ctx, conn_name) ==
		    TRUE)
			break;

		// We need to ask the user for information.
		ipc_events_ui(ctx, IPC_EVENT_UI_NEED_UPW, conn_name);

		free(conn_name);

		// We return an ACK in this case because technically we are doing what was asked.  We
		// notifed the UI that we need more data, so the call was a success.
		retval2 =
		    ipc_callout_create_ack(NULL, "Request_Connection_Change",
					   outnode);
		return retval2;
		break;

	case 0:
		// Do nothing.
		break;

	default:
		free(conn_name);
		FREE(ctx->conn_name);
		debug_printf(DEBUG_NORMAL,
			     "A configuration issue was discovered.  Notifying the UI.\n");
		return ipc_callout_create_error(ctx->intName,
						"Request_Connection_Change",
						IPC_ERROR_NEW_ERRORS_IN_QUEUE,
						outnode);
		break;
	}

	// If we currently have a forced connection, then we will do a forced unbind.
	if ((TEST_FLAG(ctx->flags, FORCED_CONN)) && (ctx->conn != NULL)) {
		ipc_events_ui(NULL, IPC_EVENT_CONNECTION_UNBOUND,
			      ctx->conn->name);
	}

	SET_FLAG(ctx->flags, FORCED_CONN);
	SET_FLAG(ctx->flags, DHCP_RELEASE_RENEW);	// Force a release/renew on this auth.
	ctx->conn = config_find_connection(CONFIG_LOAD_GLOBAL, conn_name);
	if (ctx->conn == NULL) {
		ctx->conn = config_find_connection(CONFIG_LOAD_USER, conn_name);
		if (ctx->conn == NULL) {
			debug_printf(DEBUG_IPC,
				     "Couldn't find connection '%s'!\n",
				     conn_name);
			free(conn_name);
			return ipc_callout_create_error(iface,
							"Request_Connection_Change",
							IPC_ERROR_INVALID_CONN_NAME,
							outnode);
		}
	}

	if (ctx->intType == ETH_802_11_INT) {
		// Check if the SSID is a static WEP SSID.
		ssid =
		    config_ssid_find_by_name(ctx->intTypeData, ctx->conn->ssid);
		if (ssid == NULL) {
			debug_printf(DEBUG_IPC,
				     "Unable to find the desired SSID in the scan cache!\n");
			free(conn_name);
			return ipc_callout_create_error(iface,
							"Request_Connection_Change",
							IPC_ERROR_SSID_NOT_FOUND,
							outnode);
		}
	}
	// Validate and update the connection name.
	FREE(ctx->conn_name);

	ctx->conn_name = _strdup(conn_name);

	if ((ctx->conn->association.auth_type == AUTH_PSK)
	    || (ctx->conn->association.auth_type == AUTH_NONE)) {
		ctx->prof = NULL;
	} else {
		ctx->prof =
		    config_find_profile(CONFIG_LOAD_GLOBAL, ctx->conn->profile);
		if (ctx->prof == NULL) {
			ctx->prof =
			    config_find_profile(CONFIG_LOAD_USER,
						ctx->conn->profile);
		}
		// We only care that there is a profile if we are using wireless.  On wired, it is
		// okay not to have one as that would be a case where we only want to set IP information.
		if ((ctx->prof == NULL) && (ctx->intType == ETH_802_11_INT)) {
			debug_printf(DEBUG_IPC, "Couldn't find profile '%s'!\n",
				     ctx->conn->profile);
			free(conn_name);
			return ipc_callout_create_error(iface,
							"Request_Connection_Change",
							IPC_ERROR_INVALID_PROF_NAME,
							outnode);
		}
		// We found our profile, so we need to clear the EAP state machine, and let it rebuild itself.
		eap_sm_deinit(&ctx->eap_state);
		eap_sm_init(&ctx->eap_state);
	}

	if (ctx->intType == ETH_802_11_INT) {
		wctx = ctx->intTypeData;
		if (wctx == NULL) {
			free(conn_name);
			return ipc_callout_create_error(iface,
							"Request_Connection_Change",
							IPC_ERROR_INVALID_CONTEXT,
							outnode);
		}
		// Make sure we weren't doing PSK before.  If we were, then we could get bogus error messages.
		UNSET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
			   WIRELESS_SM_DOING_PSK);
		timer_cancel(ctx, PSK_DEATH_TIMER);

		FREE(wctx->cur_essid);
		wctx->cur_essid = _strdup(ctx->conn->ssid);

		// Clear out the key type currently in use.
		wctx->pairwiseKeyType = 0;
		wctx->groupKeyType = 0;

		// If it is wireless, disassociating should reset all of the state machines
		// that need to be reset.
		statemachine_reinit(ctx);
		wireless_sm_change_state(ASSOCIATING, ctx);
	} else {
		// Wired.

		// If we don't have a profile defined, then we want to jump to force authed state so
		// that IP address information still gets set.
		if (ctx->prof == NULL) {
			debug_printf(DEBUG_IPC,
				     "Wired interface that doesn't do 802.1X.\n");
			statemachine_change_state(ctx, S_FORCE_AUTH);
		} else {
			// Otherwise, if we want to do 802.1X, send a logoff. (Which will implicitly be followed
			// by a start.)
			statemachine_change_state(ctx, LOGOFF);
		}
	}

	ctx->auths = 0;

	free(conn_name);
	free(iface);

	retval2 =
	    ipc_callout_create_ack(NULL, "Request_Connection_Change", outnode);
	if (retval2 == IPC_SUCCESS) {
		return retval;
	}

	return retval;
}

/**
 * \brief Catch an IPC request to disassociate.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \warning  This will request that the supplicant send a disassociate message to the
 *           AP that it is connected to.  In most cases, the wireless driver will attempt
 *           a new association to the AP directly following the disassociate.  So, if you
 *           do not wish to have a new association attempted, you should take steps to ask
 *           the supplicant to pause an interface.
 **/
int ipc_callout_disassociate(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS, retval2 = IPC_SUCCESS;
	char *iface = NULL;
	char *strreason = NULL;
	int reason = 0;
	context *ctx;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC disassociate request!\n");

	n = ipc_callout_find_node(innode, "Request_Disassociate");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Request_Disassociate' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Interface");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Interface> node in the request!\n");
		return ipc_callout_create_error(NULL, "Request_Disassociate",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	iface = (char *)xmlNodeGetContent(t);
	if (iface == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Not interface specified to execute a disassociation on!\n");
		return ipc_callout_create_error(NULL, "Request_Disassociate",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	t = ipc_callout_find_node(n, "Reason");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Connection_Name> node in the request!\n");
		retval =
		    ipc_callout_create_error(NULL, "Request_Connection_Change",
					     IPC_ERROR_INTERFACE_NOT_FOUND,
					     outnode);
		goto disassoc_done;
	}

	strreason = (char *)xmlNodeGetContent(t);
	if (strreason == NULL) {
		reason = 0;	// Unspecified reason.
	} else {
		reason = atoi(strreason);
		free(strreason);
	}

	debug_printf(DEBUG_IPC,
		     "Sending disassociate on interface %s.  (Reason %d)\n",
		     iface, reason);

	ctx = event_core_locate(iface);
	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate the interface requested over IPC!\n");
		retval =
		    ipc_callout_create_error(iface, "Request_Disassociate",
					     IPC_ERROR_INTERFACE_NOT_FOUND,
					     outnode);
		goto disassoc_done;
	}

	if (ctx->intType != ETH_802_11_INT) {
		debug_printf(DEBUG_IPC,
			     "Request to disassociate on a wired interface! The IPC client needs to be fixed!\n");
		retval =
		    ipc_callout_create_error(iface, "Request_Disassociate",
					     IPC_ERROR_INT_NOT_WIRELESS,
					     outnode);
		goto disassoc_done;
	}

	cardif_disassociate(ctx, reason);

	// Make sure this flag is cleared so that we don't get any absurd screaming with PSK when the users hits
	// connect/disconnect over and over again. ;)
	UNSET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
		   WIRELESS_SM_DOING_PSK);

	// Let ourselves know that a UI requested this disconnect.
	SET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
		 WIRELESS_SM_DISCONNECT_REQ);

	// Force a state machine reinit.
	eap_sm_force_init(ctx->eap_state);

	retval2 =
	    ipc_callout_create_ack(iface, "Request_Disassociate", outnode);

 disassoc_done:
	FREE(iface);

	return retval;
}

/**
 * \brief Catch an IPC request to pause an interface.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \warning This function will cause the supplicant to stop processing 802.1X messages
 *          on a specific interface.  It will not terminate an authentications that already
 *          exist.  In general, you will want this call to be used in conjunction with a 
 *          logoff, or disassociate request.
 **/
int ipc_callout_stop(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS;
	char *iface = NULL;
	context *ctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC pause request!\n");

	n = ipc_callout_find_node(innode, "Request_Stop");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Request_Stop' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Interface");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Interface> node in the request!\n");
		return ipc_callout_create_error(NULL, "Request_Stop",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	iface = (char *)xmlNodeGetContent(t);
	if (iface == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No interface specified to execute a stop on!\n");
		return ipc_callout_create_error(NULL, "Request_Stop",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Sending pause on interface %s.\n", iface);

	ctx = event_core_locate(iface);
	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate the interface requested over IPC!\n");
		retval =
		    ipc_callout_create_error(iface, "Request_Stop",
					     IPC_ERROR_INTERFACE_NOT_FOUND,
					     outnode);
		goto stop_done;
	}

	if (ctx->intType == ETH_802_11_INT) {
		wireless_sm_change_state(INT_STOPPED, ctx);
	} else {
		debug_printf(DEBUG_IPC,
			     "Request to stop a wired interface! (Not implemented!)\n");
		retval =
		    ipc_callout_create_error(iface, "Request_Stop",
					     IPC_ERROR_INVALID_INTERFACE,
					     outnode);
		goto stop_done;
	}

	retval = ipc_callout_create_ack(iface, "Request_Stop", outnode);

 stop_done:
	free(iface);

	return retval;
}

/**
 * \brief Catch an IPC request to get IP address information from an interface.
 *
 * \todo Add DNS information
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \note It is perfectly acceptible for any, or all, of the resulting settings to be
 *       NULL.  The client should check for this case!
 **/
int ipc_callout_get_ip_data(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS;
	char *iface = NULL;
	context *ctx = NULL;
	char *ipaddr = NULL;
	char *netmask = NULL;
	char *gateway = NULL;
	char *dns1 = NULL, *dns2 = NULL, *dns3 = NULL;
	char *temp = NULL;

	(*outnode) = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC get IP data request!\n");

	n = ipc_callout_find_node(innode, "Get_IP_Data");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Get_IP_Data' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Interface");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Interface> node in the request!\n");
		return ipc_callout_create_error(NULL, "Get_IP_Data",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	iface = (char *)xmlNodeGetContent(t);

	debug_printf(DEBUG_IPC, "Looking for interface %s.\n", iface);

	ctx = event_core_locate(iface);
	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate the interface requested over IPC!\n");
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_INTERFACE_NOT_FOUND,
					     outnode);
		goto get_ip_done;
	}

	ipaddr = cardif_get_ip(ctx);
	if (ipaddr != NULL)
		debug_printf(DEBUG_IPC, "IP Address : %s\n", ipaddr);

	netmask = cardif_get_netmask(ctx);
	if (netmask != NULL)
		debug_printf(DEBUG_IPC, "Net Mask : %s\n", netmask);

	gateway = cardif_get_gw(ctx);
	if (gateway != NULL)
		debug_printf(DEBUG_IPC, "Default GW : %s\n", gateway);

	dns1 = cardif_get_dns1(ctx);
	if (dns1 != NULL)
		debug_printf(DEBUG_IPC, "DNS 1 : %s\n", dns1);

	dns2 = cardif_get_dns2(ctx);
	if (dns2 != NULL)
		debug_printf(DEBUG_IPC, "DNS 2 : %s\n", dns2);

	dns3 = cardif_get_dns3(ctx);
	if (dns3 != NULL)
		debug_printf(DEBUG_IPC, "DNS 3 : %s\n", dns3);

	// We have the data we need, so create the response.
	n = xmlNewNode(NULL, (xmlChar *) "IP_Data");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL, "Couldn't create <IP_Data> tag!\n");
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	ipc_callout_convert_amp(iface, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		xmlFreeNode(n);
		free(temp);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}
	free(temp);

	if (xmlNewChild(n, NULL, (xmlChar *) "IP_Address", (xmlChar *) ipaddr)
	    == NULL) {
		xmlFreeNode(n);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "Netmask", (xmlChar *) netmask) ==
	    NULL) {
		xmlFreeNode(n);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "Gateway", (xmlChar *) gateway) ==
	    NULL) {
		xmlFreeNode(n);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "DNS1", (xmlChar *) dns1) == NULL) {
		xmlFreeNode(n);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "DNS2", (xmlChar *) dns2) == NULL) {
		xmlFreeNode(n);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "DNS3", (xmlChar *) dns3) == NULL) {
		xmlFreeNode(n);
		retval =
		    ipc_callout_create_error(iface, "Get_IP_Data",
					     IPC_ERROR_CANT_ALLOCATE_NODE,
					     outnode);
		goto get_ip_done;
	}

	(*outnode) = n;

 get_ip_done:
	FREE(iface);
	FREE(dns1);
	FREE(dns2);
	FREE(dns3);
	FREE(ipaddr);
	FREE(netmask);
	FREE(gateway);

	return retval;
}

/**
 *  \brief Got a request to enumerate the profiles that we know about.
 *
 *  @param[in] innode   A pointer to the node that contains the enumerate profiles
 *                      request.
 *  @param[out] outnode   The resulting XML node(s) from the enumerate profiles
 *                        request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_enum_profiles(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	unsigned int count;
	char res[100];
	uint8_t config_type = 0;
	xmlChar *ttype = NULL;
	int result = 0;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC Enum profiles request!\n");

	n = xmlNewNode(NULL, (xmlChar *) "Profiles_List");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Profiles_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	t = ipc_callout_find_node(innode, "Enum_Profiles");
	if (t == NULL) {
		return ipc_callout_create_error(NULL, "Enum_Profiles",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(t->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No <Config_Type> node found in the <Enum_Profiles> request!  Not sure what to do.\n");
		return ipc_callout_create_error(NULL, "Enum_Profiles",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	ttype = xmlNodeGetContent(t);
	config_type = atoi((char *)ttype);
	xmlFree(ttype);

	count = 0;
	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		count += liblist_num_nodes((genlist *)
					   config_get_profiles
					   (CONFIG_LOAD_GLOBAL));
	}

	if ((config_type & CONFIG_LOAD_USER) == CONFIG_LOAD_USER) {
		count += liblist_num_nodes((genlist *)
					   config_get_profiles
					   (CONFIG_LOAD_USER));
	}

	sprintf((char *)&res, "%d", count);
	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Number_Of_Profiles",
	     (xmlChar *) res) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Profiles_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		result =
		    ipc_callout_helper_build_profile_list(CONFIG_LOAD_GLOBAL,
							  n);
		if (result != XENONE)
			return ipc_callout_create_error(NULL, "Profiles_List",
							result, outnode);
	}

	if ((config_type & CONFIG_LOAD_USER) == CONFIG_LOAD_USER) {
		result =
		    ipc_callout_helper_build_profile_list(CONFIG_LOAD_USER, n);
		if (result != XENONE)
			return ipc_callout_create_error(NULL, "Profiles_List",
							result, outnode);
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 *  \brief Got a request to enumerate the trusted servers that we know about.
 *
 *  @param[in] innode   A pointer to the node that contains the enumerate trusted
 *                      servers request.
 *  @param[out] outnode   The resulting XML node(s) from the enumerate trusted
 *                        servers request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_enum_trusted_servers(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	unsigned int count;
	char res[100];
	struct config_trusted_servers *svrs = NULL;
	uint8_t config_type = 0;
	xmlChar *ttype = NULL;
	int result = 0;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC Enum trusted servers request!\n");

	n = xmlNewNode(NULL, (xmlChar *) "Trusted_Servers_List");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Enum_Trusted_Servers",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	t = ipc_callout_find_node(innode, "Enum_Trusted_Servers");
	if (t == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Request didn't appear to be a valid Enum_Trusted_Servers request!\n");
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Trusted_Servers",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(t->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No <Config_Type> node found in the <Get_Connections> request!  Not sure what to do.\n");
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Trusted_Servers",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	ttype = xmlNodeGetContent(t);
	config_type = atoi((char *)ttype);
	xmlFree(ttype);

	count = 0;

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		svrs = config_get_trusted_servers(CONFIG_LOAD_GLOBAL);
		if (svrs != NULL)
			count += liblist_num_nodes((genlist *) svrs->servers);
	}

	if ((config_type & CONFIG_LOAD_USER) == CONFIG_LOAD_USER) {
		svrs = config_get_trusted_servers(CONFIG_LOAD_USER);
		if (svrs != NULL)
			count += liblist_num_nodes((genlist *) svrs->servers);
	}

	sprintf((char *)&res, "%d", count);
	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Trusted_Servers_Count",
	     (xmlChar *) res) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Trusted_Servers",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		svrs = config_get_trusted_servers(CONFIG_LOAD_GLOBAL);
		if (svrs != NULL) {
			result =
			    ipc_callout_helper_build_trusted_server_list
			    (CONFIG_LOAD_GLOBAL, n);
			if (result != XENONE) {
				xmlFreeNode(n);
				return ipc_callout_create_error(NULL,
								"Enum_Trusted_Servers",
								result,
								outnode);
			}
		}
	}

	if ((config_type & CONFIG_LOAD_USER) == CONFIG_LOAD_USER) {
		svrs = config_get_trusted_servers(CONFIG_LOAD_USER);
		if (svrs != NULL) {
			result =
			    ipc_callout_helper_build_trusted_server_list
			    (CONFIG_LOAD_USER, n);
			if (result != XENONE) {
				xmlFreeNode(n);
				return ipc_callout_create_error(NULL,
								"Enum_Trusted_Servers",
								result,
								outnode);
			}
		}
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to write out our configuration file.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_write_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *filename = NULL;
	xmlChar *temp = NULL;
	uint8_t conf_type = 0;
	char *temp_filename = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC write configuration request!\n");

	n = ipc_callout_find_node(innode, "Write_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Write_Config' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Filename");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Filename> node in the request!\n");
		return ipc_callout_create_error(NULL, "Write_Config",
						IPC_ERROR_INVALID_FILE,
						outnode);
	}

	filename = (char *)xmlNodeGetContent(t);

	if ((filename != NULL) && (strlen(filename) < 1)) {
		xmlFree(filename);
		filename = NULL;
	}

	t = ipc_callout_find_node(n, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Config_Type> node in the request!\n");
		return ipc_callout_create_error(NULL, "Write_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	temp = xmlNodeGetContent(t);
	conf_type = atoi((char *)temp);
	xmlFree(temp);

	if ((conf_type == CONFIG_LOAD_USER) && (filename == NULL)) {
		// We need to determine the path to store the user's config.
		temp_filename = platform_get_users_data_store_path();
		if (temp_filename == NULL)
			return -1;

		filename = Malloc(strlen(temp_filename) + 50);
		if (filename == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Unable to create the path to store the current user's configuration!\n");
			FREE(temp_filename);
			return -1;
		}

		strcpy(filename, temp_filename);
#ifdef WINDOWS
		strcat(filename, "\\xsupplicant.user.conf");
#else
		strcat(filename, "/xsupplicant.user.conf");
#endif
		FREE(temp_filename);

		if (xsupconfwrite_write_user_config(filename) !=
		    XSUPCONFWRITE_ERRNONE) {
			FREE(filename);
			return ipc_callout_create_error(NULL, "Write_Config",
							IPC_ERROR_CANT_WRITE_CONFIG,
							outnode);
		}
	} else {
		// Write the system level config.
		if (xsupconfwrite_write_config(filename) !=
		    XSUPCONFWRITE_ERRNONE) {
			FREE(filename);
			return ipc_callout_create_error(NULL, "Write_Config",
							IPC_ERROR_CANT_WRITE_CONFIG,
							outnode);
		}
	}

	FREE(filename);
	return ipc_callout_create_ack(NULL, "Write_Config", outnode);
}

/**
 * \brief Catch an IPC request to get global settings out of our configuration file.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_globals(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	struct config_globals *globs = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get global settings configuration request!\n");

	n = ipc_callout_find_node(innode, "Get_Globals_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Globals_Config' node.\n");
		return ipc_callout_create_error(NULL, "Get_Globals_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Globals_Config");
	if (n == NULL)
		return ipc_callout_create_error(NULL, "Get_Globals_Config",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);

	globs = config_get_globals();

	// Write out ALL settings, so there is no confusion on the other end.
	t = xsupconfwrite_globals_create_tree(globs, TRUE);
	if (t == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Globals_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (xmlAddChild(n, t) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Globals_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to get profile settings out of our configuration file.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_profile(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *profname = NULL;
	struct config_profiles *profs = NULL;
	uint8_t config_type = 0;
	xmlChar *content = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get profile settings configuration request!\n");

	n = ipc_callout_find_node(innode, "Get_Profile_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Profile_Config' node.\n");
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Name");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Name' node from 'Get_Profile_Config'!\n");
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	profname = _strdup((char *)content);
	xmlFree(content);

	if ((profname == NULL) || (strlen(profname) == 0)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the name of the profile we want to get!\n");
		FREE(profname);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for profile '%s'.\n", profname);

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Config_Type' node from 'Get_Profile_Config'!\n");
		FREE(profname);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	config_type = atoi((char *)content);
	xmlFree(content);

	if ((config_type != CONFIG_LOAD_GLOBAL)
	    && (config_type != CONFIG_LOAD_USER)) {
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_INVALID_CONFIG,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Profile_Config");
	if (n == NULL) {
		FREE(profname);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	profs = config_get_profiles(config_type);

	while ((profs != NULL) && (strcmp(profs->name, profname) != 0)) {
		profs = profs->next;
	}

	if (profs == NULL) {
		FREE(profname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (strcmp(profs->name, profname) != 0) {
		FREE(profname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}
	// Write out ALL settings, so there is no confusion on the other end.
	t = xsupconfwrite_profile_create_tree(profs, config_type, TRUE);
	if (t == NULL) {
		xmlFreeNode(n);
		FREE(profname);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (xmlAddChild(n, t) == NULL) {
		xmlFreeNode(n);
		FREE(profname);
		return ipc_callout_create_error(NULL, "Get_Profile_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	FREE(profname);
	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to get connection settings out of our configuration file.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_connection(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *connname = NULL;
	struct config_connection *conns = NULL;
	uint8_t config_type = 0;
	xmlChar *content = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get connection settings configuration request!\n");

	n = ipc_callout_find_node(innode, "Get_Connection_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Connection_Config' node.\n");
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Name");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Name' node from 'Get_Connection_Config'!\n");
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	connname = _strdup((char *)content);
	xmlFree(content);

	if ((connname == NULL) || (strlen(connname) == 0)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the name of the connection we want to get!\n");
		FREE(connname);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for connection '%s'.\n", connname);

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Config_Type' node from 'Get_Connection_Config'!\n");
		FREE(connname);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	config_type = atoi((char *)content);
	xmlFree(content);

	if ((config_type != CONFIG_LOAD_GLOBAL)
	    && (config_type != CONFIG_LOAD_USER)) {
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_INVALID_CONFIG,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Connection_Config");
	if (n == NULL) {
		FREE(connname);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	conns = config_get_connections(config_type);

	while ((conns != NULL) && (conns->name != NULL) && (strcmp(conns->name, connname) != 0)) {
		conns = conns->next;
	}

	if (conns == NULL) {
		FREE(connname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (strcmp(conns->name, connname) != 0) {
		FREE(connname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}
	// Write out ALL settings, so there is no confusion on the other end.
	t = xsupconfwrite_connection_create_tree(conns, config_type, TRUE);
	if (t == NULL) {
		xmlFreeNode(n);
		FREE(connname);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (xmlAddChild(n, t) == NULL) {
		xmlFreeNode(n);
		FREE(connname);
		return ipc_callout_create_error(NULL, "Get_Connection_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	FREE(connname);
	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to get trusted server settings out of our configuration file.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_trusted_server_config(xmlNodePtr innode,
					  xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *tsname = NULL;
	struct config_trusted_server *ts = NULL;
	struct config_trusted_servers *tss = NULL;
	uint8_t config_type = 0;
	xmlChar *content = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get trusted server configuration request!\n");

	n = ipc_callout_find_node(innode, "Get_Trusted_Server_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Trusted_Server_Config' node.\n");
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Name");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Name' node from 'Get_Trusted_Server_Config'!\n");
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	tsname = _strdup((char *)content);
	xmlFree(content);

	if ((tsname == NULL) || (strlen(tsname) == 0)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the name of the trusted server we want to get!\n");
		FREE(tsname);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for connection '%s'.\n", tsname);

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Config_Type' node from 'Get_Trusted_Server_Config'!\n");
		FREE(tsname);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	config_type = atoi((char *)content);
	xmlFree(content);

	if ((config_type != CONFIG_LOAD_GLOBAL)
	    && (config_type != CONFIG_LOAD_USER)) {
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_INVALID_CONFIG,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Trusted_Server_Config");
	if (n == NULL) {
		FREE(tsname);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	tss = config_get_trusted_servers(config_type);

	if (tss == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate a <Trusted_Servers> block!\n");
		FREE(tsname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	ts = tss->servers;

	while ((ts != NULL) && (strcmp(ts->name, tsname) != 0)) {
		ts = ts->next;
	}

	if (ts == NULL) {
		FREE(tsname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (strcmp(ts->name, tsname) != 0) {
		FREE(tsname);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}
	FREE(tsname);

	// Write out ALL settings, so there is no confusion on the other end.
	t = xsupconfwrite_trusted_server_create_tree(ts, TRUE);
	if (t == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (xmlAddChild(n, t) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Trusted_Server_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to get interface configuration settings out of our configuration file.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_interface_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *intname = NULL;
	struct xsup_interfaces *ints = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get interface configuration request!\n");

	n = ipc_callout_find_node(innode, "Get_Interface_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Interface_Config' node.\n");
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Description");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Description' node from 'Get_Interface_Config'!\n");
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	intname = (char *)xmlNodeGetContent(t);

	if (intname == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the name of the interface we want to get!\n");
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Looking for interface '%s'.\n", intname);

	n = xmlNewNode(NULL, (xmlChar *) "Interface_Config");
	if (n == NULL) {
		free(intname);
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ints = config_get_config_ints();

	while ((ints != NULL) && (strcmp(ints->description, intname) != 0)) {
		ints = ints->next;
	}

	if (ints == NULL) {
		free(intname);
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (strcmp(ints->description, intname) != 0) {
		free(intname);
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	free(intname);

	// Write out ALL settings, so there is no confusion on the other end.
	t = xsupconfwrite_interface_create_tree(ints, TRUE);
	if (t == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	if (xmlAddChild(n, t) == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Interface_Config",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Process the headers for a delete command.
 *
 * @param[in] innode   The root node from the XML document that was sent over.
 * @param[in] cmdname   The command name that generated this call. (Such as 
 *                      Delete_Managed_Network_Config)
 * @param[in] findtag   The XML tag name that will contain the search value.
 * @param[out] searchval   The value that the caller should be looking for.  The
 *                         caller is expected to free this memory when it is done
 *                         using it.
 *
 * \retval IPC_SUCCESS on success
 * \retval !IPC_SUCCESS on failure (this value should be fed in to 
 *         ipc_callout_create_error() to create an error document to return
 *         to the IPC caller.
 **/
int ipc_callout_get_delete_name(xmlNodePtr innode, char *cmdname, char *findtag,
				char **searchval, uint8_t * config_type)
{
	xmlNodePtr n = NULL, t = NULL;
	char *resval = NULL;
	xmlChar *content = NULL;

	if (innode == NULL)
		return IPC_ERROR_INVALID_NODE;

	n = ipc_callout_find_node(innode, cmdname);
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get '%s' node.\n", cmdname);
		return IPC_ERROR_INVALID_NODE;
	}

	t = ipc_callout_find_node(n->children, findtag);
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get '%s' node from "
			     "'%s'!\n", findtag, cmdname);
		return IPC_ERROR_CANT_LOCATE_NODE;
	}

	content = xmlNodeGetContent(t);
	resval = _strdup((char *)content);
	xmlFree(content);

	if ((resval == NULL) || (strlen(resval) == 0)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the name of the %s we want "
			     "to delete!\n", findtag);
		FREE(resval);
		return IPC_ERROR_CANT_GET_CONFIG;
	}

	debug_printf(DEBUG_IPC, "Looking for '%s'\n", resval);

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		FREE(resval);
		return IPC_ERROR_INVALID_NODE;
	}

	content = xmlNodeGetContent(t);
	(*config_type) = (uint8_t) atoi((char *)content);
	xmlFree(content);

	(*searchval) = resval;

	return IPC_SUCCESS;
}

/**
 * \brief Process the headers for a delete command.
 *
 * @param[in] innode   The root node from the XML document that was sent over.
 * @param[in] cmdname   The command name that generated this call. (Such as 
 *                      Delete_Managed_Network_Config)
 * @param[in] findtag   The XML tag name that will contain the search value.
 * @param[out] searchval   The value that the caller should be looking for.  The
 *                         caller is expected to free this memory when it is done
 *                         using it.
 * @param[out] config_type   The type of configuration we want to look at.
 * @param[out] force   Should we force the deletion of this item.
 *
 * \retval IPC_SUCCESS on success
 * \retval !IPC_SUCCESS on failure (this value should be fed in to 
 *         ipc_callout_create_error() to create an error document to return
 *         to the IPC caller.
 **/
int ipc_callout_get_delete_name_and_force(xmlNodePtr innode, char *cmdname,
					  char *findtag, char **searchval,
					  uint8_t * config_type, int *force)
{
	xmlNodePtr n = NULL, t = NULL;
	char *resval = NULL;
	xmlChar *content = NULL;

	if (innode == NULL)
		return IPC_ERROR_INVALID_NODE;

	n = ipc_callout_find_node(innode, cmdname);
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get '%s' node.\n", cmdname);
		return IPC_ERROR_INVALID_NODE;
	}

	t = ipc_callout_find_node(n->children, findtag);
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get '%s' node from "
			     "'%s'!\n", findtag, cmdname);
		return IPC_ERROR_CANT_LOCATE_NODE;
	}

	resval = (char *)xmlNodeGetContent(t);

	if ((resval == NULL) || (strlen(resval) == 0)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the name of the %s we want "
			     "to delete!\n", findtag);
		return IPC_ERROR_CANT_GET_CONFIG;
	}

	debug_printf(DEBUG_IPC, "Looking for '%s'\n", resval);
	(*searchval) = resval;

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		return IPC_ERROR_INVALID_NODE;
	}

	content = xmlNodeGetContent(t);
	(*config_type) = (uint8_t) atoi((char *)content);
	xmlFree(content);

	t = ipc_callout_find_node(n->children, "Force");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Force' node from "
			     "'%s'!\n", cmdname);
		return IPC_ERROR_CANT_LOCATE_NODE;
	}

	resval = (char *)xmlNodeGetContent(t);

	if ((resval == NULL) || (strlen(resval) == 0)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't determine the 'force' value of the %s we want "
			     "to delete!\n", findtag);
		return IPC_ERROR_CANT_GET_CONFIG;
	}

	(*force) = atoi(resval);
	FREE(resval);

	return IPC_SUCCESS;
}

/**
 * \brief Search through all of the active contexts looking to see if the
 *		named connection is in use.
 * 
 * @param[in] conname   The name of the connection we are looking for.
 *
 * \retval TRUE if it is in use.
 * \retval FALSE if it is not in use.
 **/
int ipc_callout_is_connection_in_use(char *conname)
{
	context *ctx = NULL;

	if (conname == NULL)
		return FALSE;

	// Iterate through all of the contexts to be sure we aren't using this connection.
	event_core_reset_locator();

	ctx = event_core_get_next_context();
	while (ctx != NULL) {
		if ((ctx->conn != NULL) && (ctx->conn->name != NULL)) {
			if (strcmp(ctx->conn->name, conname) == 0) {
				return TRUE;	// It is in use.
			}
		}

		ctx = event_core_get_next_context();
	}

	return FALSE;
}

/**
 *  \brief Got a request to delete a connection that we know about.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      delete a connection from memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the delete connection 
 *                        request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_delete_connection_config(xmlNodePtr innode,
					 xmlNodePtr * outnode)
{
	char *name = NULL;
	int retval;
	context *ctx = NULL;
	uint8_t config_type = 0;

	retval = ipc_callout_get_delete_name(innode, "Delete_Connection_Config",
					     "Name", &name, &config_type);
	if (retval != IPC_SUCCESS) {
		FREE(name);
		return ipc_callout_create_error(NULL,
						"Delete_Connection_Config",
						retval, outnode);
	}

	if (ipc_callout_is_connection_in_use(name) == TRUE) {
		// ACK!  We can't delete a connection that is in use!
		return ipc_callout_create_error(ctx->intName,
						"Delete_Connection_Config",
						IPC_ERROR_CANT_DEL_CONN_IN_USE,
						outnode);
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			// User can't delete this one.
			return ipc_callout_create_error(ctx->intName,
							"Delete_Connection_Config",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}

	if (config_delete_connection(config_type, name) != XENONE) {
		debug_printf(DEBUG_NORMAL,
			     "Request to delete a connection that "
			     "was not found!\n");
		FREE(name);
		return ipc_callout_create_error(NULL,
						"Delete_Connection_Config",
						IPC_ERROR_INVALID_CONN_NAME,
						outnode);
	}

	FREE(name);
	return ipc_callout_create_ack(NULL, "Delete_Connection_Config",
				      outnode);
}

/**
 * \brief Determine if the named profile is in use.
 *
 * @param[in] profname   The name of the profile we want to check.
 *
 * \retval TRUE if it is currently in use.
 * \retval FALSE if it isn't.
 **/
int ipc_callout_is_profile_in_use(char *name)
{
	context *ctx = NULL;

	if (name == NULL)
		return FALSE;

	// Iterate through all of the contexts to be sure we aren't using this trusted server.
	event_core_reset_locator();

	ctx = event_core_get_next_context();
	while (ctx != NULL) {
		if ((ctx->conn != NULL) && (ctx->prof != NULL)) {
			if (strcmp(ctx->prof->name, name) == 0) {
				return TRUE;
			}
		}

		ctx = event_core_get_next_context();
	}

	return FALSE;
}

/**
 *  \brief Got a request to delete a profile that we know about.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      delete a profile from memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the delete profile
 *                        request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_delete_profile_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	char *name = NULL;
	int retval = 0;
	int forced = 0;

	uint8_t config_type = 0;

	retval =
	    ipc_callout_get_delete_name_and_force(innode,
						  "Delete_Profile_Config",
						  "Name", &name, &config_type,
						  &forced);
	if (retval != IPC_SUCCESS) {
		free(name);
		return ipc_callout_create_error(NULL, "Delete_Profile_Config",
						retval, outnode);
	}

	if (forced == FALSE) {
		if ((ipc_callout_helper_is_profile_in_use
		     (CONFIG_LOAD_GLOBAL, name) == TRUE)
		    ||
		    (ipc_callout_helper_is_profile_in_use
		     (CONFIG_LOAD_USER, name) == TRUE)) {
			// We found something.
			free(name);
			return ipc_callout_create_error(NULL,
							"Delete_Profile_Config",
							IPC_ERROR_STILL_IN_USE,
							outnode);

		}
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			// User can't delete this one.
			free(name);
			return ipc_callout_create_error(NULL,
							"Delete_Profile_Config",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}

	if (config_delete_profile(config_type, name) != XENONE) {
		debug_printf(DEBUG_NORMAL, "Request to delete a profile that "
			     "was not found!\n");
		free(name);
		return ipc_callout_create_error(NULL, "Delete_Profile_Config",
						IPC_ERROR_INVALID_PROF_NAME,
						outnode);
	}

	free(name);

	return ipc_callout_create_ack(NULL, "Delete_Profile_Config", outnode);
}

/**
 *  \brief Got a request to delete an interface that we know about.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      delete an interface from memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the delete interface
 *                        request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_delete_interface_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	char *name = NULL;
	int retval = 0;
	uint8_t config_type = 0;	// Ignored since interface configs can only be global.

	retval = ipc_callout_get_delete_name(innode, "Delete_Interface_Config",
					     "Description", &name,
					     &config_type);
	if (retval != IPC_SUCCESS) {
		return ipc_callout_create_error(NULL, "Delete_Interface_Config",
						retval, outnode);
	}

	if (config_delete_interface(name) != XENONE) {
		debug_printf(DEBUG_NORMAL,
			     "Request to delete an interface that "
			     "was not found!\n");
		return ipc_callout_create_error(NULL, "Delete_Interface_Config",
						IPC_ERROR_INVALID_INTERFACE,
						outnode);
	}

	return ipc_callout_create_ack(NULL, "Delete_Interface_Config", outnode);
}

/**
 * \brief Search through the active contexts looking to see if a named
 *		trusted server is in use.
 *
 * @param[in] name   The name of the trusted server to look for.
 *
 * \retval TRUE if it is found.
 * \retval FALSE if it is not found.
 **/
int ipc_callout_is_trusted_server_in_use(char *name)
{
	context *ctx = NULL;
	char *tsname = NULL;

	if (name == NULL)
		return FALSE;

	// Iterate through all of the contexts to be sure we aren't using this trusted server.
	event_core_reset_locator();

	ctx = event_core_get_next_context();
	while (ctx != NULL) {
		if ((ctx->conn != NULL) && (ctx->prof != NULL)) {
			tsname =
			    ipc_callout_helper_get_tsname_from_profile
			    (ctx->prof);
			if ((tsname != NULL) && (strcmp(tsname, name) == 0)) {
				return TRUE;
			}
		}

		ctx = event_core_get_next_context();
	}

	return FALSE;
}

/**
 *  \brief Got a request to delete a trusted server that we know about.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      delete a trusted server from memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the delete trusted
 *                        server request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_delete_trusted_server_config(xmlNodePtr innode,
					     xmlNodePtr * outnode)
{
	char *name = NULL;
	int retval = 0;
	uint8_t config_type = 0;

	retval =
	    ipc_callout_get_delete_name(innode, "Delete_Trusted_Server_Config",
					"Name", &name, &config_type);
	if (retval != IPC_SUCCESS) {
		return ipc_callout_create_error(NULL,
						"Delete_Trusted_Server_Config",
						retval, outnode);
	}

	if ((ipc_callout_helper_is_trusted_server_in_use
	     (CONFIG_LOAD_GLOBAL, name) == TRUE)
	    ||
	    (ipc_callout_helper_is_trusted_server_in_use(CONFIG_LOAD_USER, name)
	     == TRUE)) {
		free(name);
		return ipc_callout_create_error(NULL,
						"Delete_Trusted_Server_Config",
						IPC_ERROR_STILL_IN_USE,
						outnode);
	}

	if (platform_user_is_admin() != TRUE) {
		free(name);
		return ipc_callout_create_error(NULL,
						"Delete_Trusted_Server_Config",
						IPC_ERROR_USER_NOT_ADMIN,
						outnode);
	}

	if (config_delete_trusted_server(config_type, name) != XENONE) {
		debug_printf(DEBUG_NORMAL,
			     "Request to delete a trusted server that "
			     "was not found!\n");
		return ipc_callout_create_error(NULL,
						"Delete_Trusted_Server_Config",
						IPC_ERROR_INVALID_TRUSTED_SVR,
						outnode);
	}

	return ipc_callout_create_ack(NULL, "Delete_Trusted_Server_Config",
				      outnode);
}

/**
 *  \brief Got a request to set new values to the globals.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      set new globals to memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the set new globals
 *                        request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_set_globals_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	struct config_globals *newg = NULL;
	struct config_globals *oldg = NULL;
	xmlNodePtr n = NULL;
	int change = FALSE;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC set globals configuration request!\n");

	n = ipc_callout_find_node(innode, "Set_Globals_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Globals_Config' node.\n");
		return ipc_callout_create_error(NULL, "Set_Globals_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}
	// Set up the new ones.
	newg = Malloc(sizeof(struct config_globals));
	if (newg == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't allocate memory to store new config globals structure.\n");
		return ipc_callout_create_error(NULL, "Set_Globals_Config",
						IPC_ERROR_MALLOC, outnode);
	}

	xsupconfig_parse(n->children->children, globals, CONFIG_LOAD_GLOBAL,
			 (void **)&newg);
	if (newg == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't parse config global information!\n");
		return ipc_callout_create_error(NULL, "Set_Globals_Config",
						IPC_ERROR_PARSING, outnode);
	}

	oldg = config_get_globals();

#ifdef WINDOWS
	windows_int_ctrl_change(newg);
#endif

	event_core_change_wireless(newg);

	if ((oldg == NULL) || (newg->logtype != oldg->logtype)
	    || (logpath_changed(newg->logpath) == TRUE)) {
		debug_printf(DEBUG_NORMAL,
			     "Log file settings have changed.  The new log file (if any) will be located in '%s'.\n",
			     newg->logpath);
		change = TRUE;
		logfile_cleanup();
	}

	reset_config_globals(newg);

	xsup_debug_clear_level();
	xsup_debug_set_level(newg->loglevel);

	if (change == TRUE) {
		logfile_setup();
	}

	return ipc_callout_create_ack(NULL, "Set_Globals_Config", outnode);
}

/**
 *  \brief Got a request to set new values to the connection.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      set/change new connection to memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the set/change 
 *                        connection request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_set_connection_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	struct config_connection *newc = NULL;
	struct config_connection *tempc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int config_type = 0;
	xmlChar *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC set connection configuration request!\n");

	n = ipc_callout_find_node(innode, "Set_Connection_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Connection_Config' node.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Config_Type' node.\n");
		return ipc_callout_create_error(NULL, "Config_Type",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	temp = xmlNodeGetContent(t);
	config_type = atoi((char *)temp);
	xmlFree(temp);
	debug_printf(DEBUG_IPC, "Setting connection for config type %d.\n",
		     config_type);

	// Set up the new ones.
	newc = Malloc(sizeof(struct config_connection));
	if (newc == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't allocate memory to store new config connection structure.\n");
		return ipc_callout_create_error(NULL, "Set_Connection_Config",
						IPC_ERROR_MALLOC, outnode);
	}

	xsupconfig_parse(n->children->children, connection, config_type,
			 (void **)&newc);
	if (newc == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't parse connection config information!\n");
		return ipc_callout_create_error(NULL, "Set_Connection_Config",
						IPC_ERROR_PARSING, outnode);
	}
	// XXX TODO: Add this code back in.  But, we need to first provide a way to change priorities without
	// editing the entire configuration block.
/*
	if (ipc_callout_is_connection_in_use(newc->name) == TRUE)
	{
		debug_printf(DEBUG_IPC, "Attempted to change a configuration that is already in use.\n");

		// Free the memory used to parse the command.
		delete_config_single_connection(&newc);

		return ipc_callout_create_error(NULL, "Set_Connection_Config", IPC_ERROR_NOT_ALLOWED, outnode);
	}
*/

	if ((config_type != CONFIG_LOAD_GLOBAL)
	    && (config_type != CONFIG_LOAD_USER)) {
		return ipc_callout_create_error(NULL, "Set_Connection_Config",
						IPC_ERROR_INVALID_CONFIG,
						outnode);
	}

	if (config_type == CONFIG_LOAD_GLOBAL) {
		// Only administrative users can do this.
		if (platform_user_is_admin() != TRUE) {
			debug_printf(DEBUG_NORMAL,
				     "You cannot change the connection settings for this connection.  Only an administrative user can do this.\n");
			return ipc_callout_create_error(NULL,
							"Set_Connection_Config",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}
	// XXX Band-aid to make the UI work correctly.  If the connection
	// is in use we will only update the priority.  Updating everything
	// could cause a crash.
	if (ipc_callout_is_connection_in_use(newc->name) != TRUE) {
		// Verify that if the connection exists it is in the configuration that the UI instructed us to update.
		if (config_type == CONFIG_LOAD_GLOBAL) {
			// See if it exists in user space.
			if (config_find_connection(CONFIG_LOAD_USER, newc->name)
			    != NULL) {
				// The request asked us to create a connection in the wrong config.  Scream.
				delete_config_single_connection((void **)&newc);
				return ipc_callout_create_error(NULL,
								"Set_Connection_Config",
								IPC_ERROR_CONFIG_CONFLICT,
								outnode);
			}
		} else {
			if (config_find_connection
			    (CONFIG_LOAD_GLOBAL, newc->name) != NULL) {
				// The request asked us to create a connection in the wrong config.  Scream.
				delete_config_single_connection((void **)&newc);
				return ipc_callout_create_error(NULL,
								"Set_Connection_Config",
								IPC_ERROR_CONFIG_CONFLICT,
								outnode);
			}
		}

		if (add_change_config_connections(config_type, newc) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't change connection data!\n");
			return ipc_callout_create_error(NULL,
							"Set_Connection_Config",
							IPC_ERROR_CANT_CHANGE_CONFIG,
							outnode);
		}
	} else {
		tempc = config_find_connection(config_type, newc->name);
		if (tempc != NULL) {
			tempc->priority = newc->priority;

			// XXX ICK!  Need to clean up the behavior of updating configurations while they are in use.  This is getting
			// silly!
			if (newc->association.psk != NULL) {
				FREE(tempc->association.psk);
				tempc->association.psk =
				    _strdup(newc->association.psk);
			}
		}
		// Free the memory used to parse the command.
		delete_config_single_connection((void **)&newc);
	}

	return ipc_callout_create_ack(NULL, "Set_Connection_Config", outnode);
}

/**
 *  \brief Got a request to set new values to the profile.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      set/change new profile to memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the set/change 
 *                        profile request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_set_profile_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	struct config_profiles *newp = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	uint8_t config_type = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC set profile configuration request!\n");

	n = ipc_callout_find_node(innode, "Set_Profile_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Profile_Config' node.\n");
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Config_Type' node.\n");
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	config_type = (uint8_t) atoi((char *)content);
	xmlFree(content);

	if ((config_type != CONFIG_LOAD_GLOBAL)
	    && (config_type != CONFIG_LOAD_USER)) {
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_INVALID_CONFIG,
						outnode);
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			return ipc_callout_create_error(NULL,
							"Set_Profile_Config",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}
	// Set up the new ones.
	newp = Malloc(sizeof(struct config_profiles));
	if (newp == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't allocate memory to store new config profile structure.\n");
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_MALLOC, outnode);
	}

	t = ipc_callout_find_node(n->children, "Profile");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Profile' node.\n");
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	xsupconfig_parse(t->children, profile, config_type, (void **)&newp);
	if (newp == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't parse profile config information!\n");
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_PARSING, outnode);
	}
	// XXX Revisit this.  If we prevent writing of the config, then a UI can't save the user's
	// credentials.  This check isn't a big deal right now because the UI is doing similar checks,
	// but we should probably add a derivation of this fix in an upcoming version.
	/*
	   if (ipc_callout_is_profile_in_use(newp->name) == TRUE)
	   {
	   debug_printf(DEBUG_IPC, "Attempted to change the configuration of a profile already in use.\n");

	   // Free the memory used to parse the command.
	   delete_config_single_profile(&newp);

	   return ipc_callout_create_error(NULL, "Set_Profile_Config", IPC_ERROR_NOT_ALLOWED, outnode);
	   }
	 */

	if (add_change_config_profiles(config_type, newp) != XENONE) {
		debug_printf(DEBUG_IPC, "Couldn't change profile data!\n");
		return ipc_callout_create_error(NULL, "Set_Profile_Config",
						IPC_ERROR_CANT_CHANGE_CONFIG,
						outnode);
	}

	return ipc_callout_create_ack(NULL, "Set_Profile_Config", outnode);
}

/**
 * \brief Reset the certificate state on all certificate using EAP methods that
 *        are currently bound to active contexts.
 *
 * \todo This probably belongs as a function pointer in the eap_sm.c file.
 **/
// XXX Move this to the proper place as defined by the TODO above!
void ipc_callout_reset_eap_cert_state()
{
	context *ctx = NULL;
	struct tls_vars *mytls_vars;

	event_core_reset_locator();

	ctx = event_core_get_next_context();

	while (ctx != NULL) {
		if ((ctx->eap_state->selectedMethod == EAP_TYPE_PEAP) ||
		    (ctx->eap_state->selectedMethod == EAP_TYPE_TTLS)) {
			mytls_vars = ctx->eap_state->active->eap_data;
			mytls_vars->certs_loaded &= (~ROOT_CERTS_LOADED);	// Clear the certs loaded bit.
		}

		ctx = event_core_get_next_context();
	}
}

/**
 *  \brief Got a request to set/change trusted server data.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      set/change trusted server data in memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the set/change 
 *                        trusted server data request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_set_trusted_server_config(xmlNodePtr innode,
					  xmlNodePtr * outnode)
{
	struct config_trusted_server *newts = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	uint8_t config_type = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC set trusted server configuration request!\n");

	n = ipc_callout_find_node(innode, "Set_Trusted_Server_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Trusted_Server_Config' node.\n");
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	t = ipc_callout_find_node(n->children, "Config_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Config_Type' node.\n");
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	content = xmlNodeGetContent(t);
	config_type = (uint8_t) atoi((char *)content);
	xmlFree(content);

	if ((config_type != CONFIG_LOAD_GLOBAL)
	    && (config_type != CONFIG_LOAD_USER)) {
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_INVALID_CONFIG,
						outnode);
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			return ipc_callout_create_error(NULL,
							"Set_Trusted_Server_Config",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}
	// Set up the new ones.
	newts = Malloc(sizeof(struct config_trusted_server));
	if (newts == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't allocate memory to store new config trusted server structure.\n");
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_MALLOC, outnode);
	}

	t = ipc_callout_find_node(n->children, "Trusted_Server");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find trusted server config information!\n");
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_PARSING, outnode);
	}

	xsupconfig_parse(t->children, trusted_server, config_type,
			 (void **)&newts);
	if (newts == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't parse trusted server config information!\n");
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_PARSING, outnode);
	}

	if (ipc_callout_is_trusted_server_in_use(newts->name) == TRUE) {
		debug_printf(DEBUG_IPC,
			     "Attempted to change the configuration on a trusted server that is already in use.\n");

		// Free the memory used to parse the command.
		delete_config_trusted_server((void **)&newts);

		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_NOT_ALLOWED, outnode);
	}

	if (add_change_config_trusted_server(config_type, newts) != XENONE) {
		debug_printf(DEBUG_IPC,
			     "Couldn't add/change trusted server data in memory!\n");
		return ipc_callout_create_error(NULL,
						"Set_Trusted_Server_Config",
						IPC_ERROR_CANT_CHANGE_CONFIG,
						outnode);
	}

	ipc_callout_reset_eap_cert_state();

	return ipc_callout_create_ack(NULL, "Set_Trusted_Server_Config",
				      outnode);
}

/**
 *  \brief Got a request to set/change interface data.
 *
 *  @param[in] innode   A pointer to the node that contains the request to 
 *                      set/change interface data in memory.
 *                      
 *  @param[out] outnode   The resulting XML node(s) from the set/change 
 *                        interface data request.
 *
 *  \retval IPC_SUCCESS   on success
 *  \retval IPC_FAILURE   on failure
 **/
int ipc_callout_set_interface_config(xmlNodePtr innode, xmlNodePtr * outnode)
{
	struct xsup_interfaces *newif = NULL;
	xmlNodePtr n = NULL;
	context *ctx = NULL;
	char *intname = NULL;
	int status = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC set interface configuration request!\n");

	n = ipc_callout_find_node(innode, "Set_Interface_Config");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Interface_Config' node.\n");
		return ipc_callout_create_error(NULL, "Set_Interface_Config",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}
	// Set up the new ones.
	newif = Malloc(sizeof(struct xsup_interfaces));
	if (newif == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't allocate memory to store new interface structure.\n");
		return ipc_callout_create_error(NULL, "Set_Interface_Config",
						IPC_ERROR_MALLOC, outnode);
	}

	xsupconfig_parse(n->children->children, interf, CONFIG_LOAD_GLOBAL,
			 (void **)&newif);
	if (newif == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't parse interface information!\n");
		return ipc_callout_create_error(NULL, "Set_Interface_Config",
						IPC_ERROR_PARSING, outnode);
	}

	status = add_change_config_interface(newif);
	if ((status != XENONE) && (status != XDATACHANGED)) {
		debug_printf(DEBUG_IPC,
			     "Couldn't add/change interface data in memory!\n");
		return ipc_callout_create_error(NULL, "Set_Interface_Config",
						IPC_ERROR_CANT_CHANGE_CONFIG,
						outnode);
	}

	if (status == XENONE) {
		// This is a new interface, so bind it.
		intname = interfaces_get_name_from_mac((char *)newif->mac);
		if (intname != NULL) {
			if (context_init_interface
			    (&ctx, newif->description, intname, NULL, 0) != 0) {
				debug_printf(DEBUG_NORMAL,
					     "Couldn't initialize interface '%s'!\n",
					     newif->description);
			}
		}
	} else {
		// This isn't a new interface, so we only want to do something if no connection is
		// active on it.
		intname = interfaces_get_name_from_mac((char *)newif->mac);
		if (intname != NULL) {
			event_core_reset_locator();
			ctx = event_core_get_next_context();
			status = 0;

			while ((ctx != NULL) && (status == 0)) {
				if ((ctx->intName != NULL)
				    && (strcmp(ctx->intName, intname) == 0)) {
					// We found the context we want to work with.
					status = 1;	// Break out of the loop.

					if (ctx->conn != NULL) {
						config_build(ctx, NULL);	// Build the default configuration.
					}
				}

				if (status == 0)
					ctx = event_core_get_next_context();
			}

			if (status == 0)	// No context was found.  Let's see if the interface is alive.
			{
				intname =
				    interfaces_get_name_from_mac((char *)
								 newif->mac);
				if (intname != NULL) {
					// But the interface is alive, so we need to bind it.
					// This is usually a case where a second interface of the same hardware
					// is plugged in, and Windows calls it the same thing.  (This could potentially be a problem
					// on non-Windows platforms as well.)
					if (context_init_interface
					    (&ctx, newif->description, intname,
					     NULL, 0) != 0) {
						debug_printf(DEBUG_NORMAL,
							     "Couldn't initialize interface '%s'!\n",
							     newif->description);
					}
				}
			}
		}
	}

	return ipc_callout_create_ack(NULL, "Set_Interface_Config", outnode);
}

/**
 *  \brief Handle an Interfaces request by dumpping the interfaces in the configuration, 
 *         and sending it.
 *
 *  \param[in] innode   A pointer to the node that contains the enum interfaces 
 *                      request.
 *  \param[out] outnode   The node(s) that result from processing innode.
 *
 *  \retval IPC_FAILURE on failure
 *  \retval IPC_SUCCESS on success
 **/
int ipc_callout_enum_config_interfaces(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	config_interfaces *ints = NULL;
	unsigned int count;
	char res[100];
	char addr[50];
	char *temp = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC Config Interfaces request!\n");

	// If we got here, then we know this is a Interface request, so we really don't need any
	// information from indoc.  We just need to build a response, and send it off.
	ints = config_get_config_ints();

	n = xmlNewNode(NULL, (xmlChar *) "Interface_Config_List");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Interface_Config_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	count = liblist_num_nodes((genlist *) ints);

	sprintf((char *)&res, "%d", count);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface_Count", (xmlChar *) res)
	    == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Interface_Config_List",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	while (ints != NULL) {
		t = xmlNewChild(n, NULL, (xmlChar *) "Interface", NULL);
		if (t == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Interface_Config_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&addr, "%02X:%02X:%02X:%02X:%02X:%02X",
			ints->mac[0], ints->mac[1], ints->mac[2], ints->mac[3],
			ints->mac[4], ints->mac[5]);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface_MAC",
		     (xmlChar *) addr) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Interface_Config_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		ipc_callout_convert_amp(ints->description, &temp);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Interface_Description",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			free(temp);
			return ipc_callout_create_error(NULL,
							"Interface_Config_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		free(temp);

		memset(&res, 0x00, sizeof(res));

		if (TEST_FLAG(ints->flags, CONFIG_INTERFACE_IS_WIRELESS)) {
			strcpy((char *)&res, "YES");
		} else {
			strcpy((char *)&res, "NO");
		}

		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Is_Wireless",
		     (xmlChar *) res) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Interface_Config_List",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		ints = ints->next;
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 *  \brief Return the current SSID cache to the IPC caller.
 *
 *  \param[in] innode   A pointer to the node that contains the enum SSIDs 
 *                      request.
 *  \param[out] outnode   The node(s) that result from processing innode.
 *
 *  \retval IPC_FAILURE on failure
 *  \retval IPC_SUCCESS on success
 **/
int ipc_callout_enum_known_ssids(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n, t;
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	struct found_ssids *cur = NULL;
	unsigned int count = 0;
	char res[100];
	char *temp = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	(*outnode) = NULL;

	debug_printf(DEBUG_IPC, "Got an IPC get SSIDs request!\n");

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't get context for requested interface!\n");
		return ipc_callout_create_error(NULL, "Enum_Known_SSIDs",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);
	}

	if (ctx->intType != ETH_802_11_INT) {
		debug_printf(DEBUG_NORMAL,
			     "Requested wireless information on an interface that isn't wireless.\n");
		return ipc_callout_create_error(NULL, "Enum_Known_SSIDs",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	if (ctx->intTypeData == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Requested wireless information, but there isn't a wireless context?\n");
		return ipc_callout_create_error(NULL, "Enum_Known_SSIDs",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);
	}

	wctx = (wireless_ctx *) ctx->intTypeData;

	n = xmlNewNode(NULL, (xmlChar *) "Known_SSID_List");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Enum_Known_SSIDs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	count = liblist_num_nodes((genlist *) wctx->ssid_cache);

	sprintf((char *)&res, "%d", count);
	if (xmlNewChild(n, NULL, (xmlChar *) "SSIDs_Count", (xmlChar *) res) ==
	    NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Known_SSIDs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	cur = wctx->ssid_cache;

	while (cur != NULL) {
		t = xmlNewChild(n, NULL, (xmlChar *) "SSID", NULL);
		if (t == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Enum_Known_SSIDs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (cur->ssid_name != NULL) {
			ipc_callout_convert_amp(cur->ssid_name, &temp);
		} else {
			memset(&temp, 0x00, 2);
		}

		if (xmlNewChild
		    (t, NULL, (xmlChar *) "SSID_Name",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			return ipc_callout_create_error(NULL,
							"Enum_Known_SSIDs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		sprintf((char *)&res, "%d", cur->abilities);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "SSID_Abilities",
		     (xmlChar *) res) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Enum_Known_SSIDs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&res, "%d", cur->strength);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Signal_Strength",
		     (xmlChar *) res) == NULL) {
			xmlFreeNode(n);
			return ipc_callout_create_error(NULL,
							"Enum_Known_SSIDs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		cur = cur->next;
	}

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to start a scan.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_wireless_scan(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	context *ctx = NULL;
	char *value = NULL;
	int tf = FALSE;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC wireless scan request!\n");

	n = ipc_callout_find_node(innode, "Wireless_Scan");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Wireless_Scan' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't get context for requested interface!\n");
		return ipc_callout_create_error(NULL, "Wireless_Scan",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);
	}

	t = ipc_callout_find_node(n, "Passive");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Passive> node in the request!\n");
		return ipc_callout_create_error(ctx->intName, "Wireless_Scan",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	value = (char *)xmlNodeGetContent(t);
	if (value == NULL) {
		// If value is NULL, assume we want an active scan.
		tf = FALSE;
	} else {
		tf = atoi(value);
	}

	if (value != NULL)
		free(value);

	switch (cardif_do_wireless_scan(ctx, tf)) {
	case XECANTPASSIVE:
		debug_printf(DEBUG_NORMAL,
			     "Request for a passive scan, but the OS or interface can't do it.\n");
		return ipc_callout_create_error(ctx->intName, "Wireless_Scan",
						IPC_ERROR_CANT_PASSIVE_SCAN,
						outnode);
		break;

	case XENONE:
		// Fall through;
		break;

	default:
		debug_printf(DEBUG_NORMAL,
			     "Unhandled error while attempting to scan.\n");
		return ipc_callout_create_error(ctx->intName, "Wireless_Scan",
						IPC_ERROR_UNKNOWN_SCAN_ERROR,
						outnode);
		break;
	}

	return ipc_callout_create_ack(NULL, "Wireless_Scan", outnode);
}

/**
 * \brief Catch an IPC request to get a version string.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_version_string(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	char value[100];

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC get version request!\n");

	n = xmlNewNode(NULL, (xmlChar *) "Version_String");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Get_Version_String",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	memset((char *)&value, 0x00, sizeof(value));

	sprintf((char *)&value, "XSupplicant %s.%s", VERSION, BUILDNUM);

	xmlNodeAddContent(n, (xmlChar *) value);

	(*outnode) = n;

	return IPC_SUCCESS;
}

/**
 * \brief Search a string for "&" characters, and convert them to &amp; since libxml2 
 *        seems to have issues doing it.
 *
 * @param[in] instr   The original string that may contain the "&" characters.
 * @param[in,out] outstr   The new string that contains "&amp;" tags instead.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_convert_amp(char *instr, char **outstr)
{
	int numamps = 0;
	int i = 0;
	char *newstr = NULL;
	int newi = 0;

	if (instr == NULL) {
		(*outstr) = NULL;
		return IPC_SUCCESS;
	}

	for (i = 0; i < strlen(instr); i++) {
		if (instr[i] == '&')
			numamps++;
	}

	if (numamps == 0) {
		(*outstr) = _strdup(instr);
		return IPC_SUCCESS;
	}
	// Otherwise, we need to do some conversion, and add some extra space.
	newstr = Malloc(strlen(instr) + (numamps * 5));	// Will result in more than we need.
	if (newstr == NULL)
		return IPC_FAILURE;

	for (i = 0; i < strlen(instr); i++) {
		if (instr[i] != '&') {
			newstr[newi] = instr[i];
			newi++;
		} else {
			// Put in the &amp;
			strcpy(&newstr[newi], "&amp;");
			newi += strlen("&amp;");
		}
	}

	(*outstr) = newstr;

	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to enumerate the Root CA certificates.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_enum_root_ca_certs(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL, b = NULL;
	char value[100];
	int numcas = 0;
	int i = 0;
	char *temp = NULL;
	cert_enum *casa = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC enumerate Root CA certs request!\n");

	n = xmlNewNode(NULL, (xmlChar *) "Root_CA_Certs_Enum");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Enum_Root_CA_Certs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Getting number of available certificates.\n");
	numcas = cert_handler_num_root_ca_certs();
	if (numcas < 0) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Root_CA_Certs",
						IPC_ERROR_CERT_STORE_ERROR,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Getting list of available certificates.\n");
	if (cert_handler_enum_root_ca_certs(&numcas, &casa) < 0) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Root_CA_Certs",
						IPC_ERROR_CERT_STORE_ERROR,
						outnode);
	}

	if (casa == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_Root_CA_Certs",
						IPC_ERROR_CERT_STORE_ERROR,
						outnode);
	}

	sprintf((char *)&value, "%d", numcas);
	t = xmlNewChild(n, NULL, (xmlChar *) "Number_Of_Certs",
			(xmlChar *) value);
	if (t == NULL) {
		xmlFreeNode(n);
		cert_handler_free_cert_enum(numcas, &casa);
		return ipc_callout_create_error(NULL, "Enum_Root_CA_Certs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Certificates", NULL);
	if (t == NULL) {
		xmlFreeNode(n);
		cert_handler_free_cert_enum(numcas, &casa);
		return ipc_callout_create_error(NULL, "Enum_Root_CA_Certs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	for (i = 0; i < numcas; i++) {
		b = xmlNewChild(t, NULL, (xmlChar *) "Certificate", NULL);
		if (b == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (ipc_callout_convert_amp(casa[i].storetype, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild
		    (b, NULL, (xmlChar *) "Store_Type",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].certname, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Name", (xmlChar *) temp)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].friendlyname, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild
		    (b, NULL, (xmlChar *) "Friendly_Name",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].issuer, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Issuer", (xmlChar *) temp)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].commonname, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild
		    (b, NULL, (xmlChar *) "CommonName",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].location, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild
		    (b, NULL, (xmlChar *) "Location",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		sprintf((char *)&value, "%d", casa[i].month);
		if (xmlNewChild(b, NULL, (xmlChar *) "Month", (xmlChar *) value)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&value, "%d", casa[i].day);
		if (xmlNewChild(b, NULL, (xmlChar *) "Day", (xmlChar *) value)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&value, "%d", casa[i].year);
		if (xmlNewChild(b, NULL, (xmlChar *) "Year", (xmlChar *) value)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL,
							"Enum_Root_CA_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
	}

	cert_handler_free_cert_enum(numcas, &casa);

	(*outnode) = n;

	return IPC_SUCCESS;
}

/**
 * \brief Get certificate information for a specific certificate.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_cert_info(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	char *storetype = NULL;
	char *location = NULL;
	char *temp = NULL;
	cert_info cinfo;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC wireless scan request!\n");

	n = ipc_callout_find_node(innode, "Get_Certificate_Info");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Certificate_Info' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Store_Type");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Store_Type> node in the request!\n");
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	value = (char *)xmlNodeGetContent(t);
	if ((value == NULL) || (strlen(value) == 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Client requested that we get data for a NULL store type!\n");
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_PARSING, outnode);
	}

	storetype = value;

	t = ipc_callout_find_node(n, "Location");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Location> node in the request!\n");
		FREE(storetype);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_LOCATE_NODE,
						outnode);
	}

	value = (char *)xmlNodeGetContent(t);
	if ((value == NULL) || (strlen(value) == 0)) {
		debug_printf(DEBUG_NORMAL,
			     "Client requested that we get data for a NULL location!\n");
		FREE(storetype);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_PARSING, outnode);
	}

	location = value;

	if (cert_handler_get_info_from_store(storetype, location, &cinfo) != 0) {
		debug_printf(DEBUG_NORMAL, "Unable to get certificate info!\n");
		FREE(storetype);
		FREE(location);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_GET_CERT_INFO,
						outnode);
	}

	FREE(storetype);
	FREE(location);

	t = xmlNewNode(NULL, (xmlChar *) "Certificate_Info");
	if (t == NULL) {
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	n = xmlNewChild(t, NULL, (xmlChar *) "Certificate", NULL);
	if (n == NULL) {
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (ipc_callout_convert_amp(cinfo.O, &temp) != IPC_SUCCESS) {
		debug_printf(DEBUG_NORMAL, "Couldn't convert string!\n");
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "O", (xmlChar *) temp) == NULL) {
		xmlFreeNode(n);
		FREE(temp);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	FREE(temp);

	if (ipc_callout_convert_amp(cinfo.OU, &temp) != IPC_SUCCESS) {
		debug_printf(DEBUG_NORMAL, "Couldn't convert string!\n");
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "OU", (xmlChar *) temp) == NULL) {
		xmlFreeNode(n);
		FREE(temp);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	FREE(temp);

	if (ipc_callout_convert_amp(cinfo.S, &temp) != IPC_SUCCESS) {
		debug_printf(DEBUG_NORMAL, "Couldn't convert string!\n");
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "S", (xmlChar *) temp) == NULL) {
		xmlFreeNode(n);
		FREE(temp);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	FREE(temp);

	if (ipc_callout_convert_amp(cinfo.C, &temp) != IPC_SUCCESS) {
		debug_printf(DEBUG_NORMAL, "Couldn't convert string!\n");
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "C", (xmlChar *) temp) == NULL) {
		xmlFreeNode(n);
		FREE(temp);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	FREE(temp);

	if (ipc_callout_convert_amp(cinfo.CN, &temp) != IPC_SUCCESS) {
		debug_printf(DEBUG_NORMAL, "Couldn't convert string!\n");
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "CN", (xmlChar *) temp) == NULL) {
		xmlFreeNode(n);
		FREE(temp);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	FREE(temp);

	if (ipc_callout_convert_amp(cinfo.L, &temp) != IPC_SUCCESS) {
		debug_printf(DEBUG_NORMAL, "Couldn't convert string!\n");
		xmlFreeNode(n);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	if (xmlNewChild(n, NULL, (xmlChar *) "L", (xmlChar *) temp) == NULL) {
		xmlFreeNode(n);
		FREE(temp);
		cert_handler_free_cert_info(&cinfo);
		return ipc_callout_create_error(NULL, "Get_Certificate_Info",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	FREE(temp);

	cert_handler_free_cert_info(&cinfo);

	(*outnode) = t;
	return IPC_SUCCESS;
}

/**
 * \brief Notify the TNC IMC of the response to a question it asked.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_tnc_request_response(xmlNodePtr innode,
					 xmlNodePtr * outnode)
{
#ifndef HAVE_TNC
	return IPC_FAILURE;
#else
	xmlNodePtr n = NULL, t = NULL;
	char *value = NULL;
	uint32_t imcID, connID, oui, response, notification;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC TNC request event response event!\n");

	n = ipc_callout_find_node(innode, "TNC_Request_Event_Response");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'TNC_Request_Event_Response' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "imcID");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get imcID from 'TNC_Request_Event_Response' node.\n");
		return IPC_FAILURE;
	}

	value = xmlNodeGetContent(t);
	imcID = atoi(value);
	free(value);

	t = ipc_callout_find_node(n, "connID");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get connID from 'TNC_Request_Event_Response' node.\n");
		return IPC_FAILURE;
	}

	value = xmlNodeGetContent(t);
	connID = atoi(value);
	free(value);

	t = ipc_callout_find_node(n, "OUI");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get OUI from 'TNC_Request_Event_Response' node.\n");
		return IPC_FAILURE;
	}

	value = xmlNodeGetContent(t);
	oui = atoi(value);
	free(value);

	t = ipc_callout_find_node(n, "Response");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get response from 'TNC_Request_Event_Response' node.\n");
		return IPC_FAILURE;
	}

	value = xmlNodeGetContent(t);
	response = atoi(value);
	free(value);

	t = ipc_callout_find_node(n, "Notification");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get notification from 'TNC_Request_Event_Response' node.\n");
		return IPC_FAILURE;
	}

	value = xmlNodeGetContent(t);
	notification = atoi(value);
	free(value);

	if (tnc_compliance_callbacks_call
	    (imcID, connID, oui, notification, response) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Request to execute a TNC response command failed.\n");
		return ipc_callout_create_error(NULL,
						"TNC_Request_Event_Response",
						IPC_ERROR_BAD_TNC_UI_RESPONSE,
						outnode);
	}

	return ipc_callout_create_ack(NULL, "TNC_Request_Event_Response",
				      outnode);
#endif
}

/**
 * \brief Notify the TNC IMC of the response to a question it asked.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_os_specific_int_data(xmlNodePtr innode,
					 xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *retstr = NULL;
	char *value = NULL;
	char tempstatic[10];
	context *ctx = NULL;
	char *temp = NULL;
	int retval = XENONE;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get OS specific interface data request!\n");

	n = ipc_callout_find_node(innode, "Get_OS_Specific_Int_Data");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_OS_Specific_Int_Data' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	n = ipc_callout_find_node(n, "Interface");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Interface' node!\n");
		return IPC_FAILURE;
	}

	value = (char *)xmlNodeGetContent(n);

	debug_printf(DEBUG_IPC, "Looking for data about interface '%s'.\n",
		     value);

	ctx = event_core_locate(value);
	if (ctx != NULL) {
		// This interface is already operational.  The UI shouldn't be asking about it!
		retval =
		    ipc_callout_create_error(value, "Get_OS_Specific_Int_Data",
					     IPC_ERROR_INTERFACE_IN_USE,
					     outnode);
		xmlFree(value);
		return retval;
	}

	t = xmlNewNode(NULL, (xmlChar *) "OS_Specific_Int_Data");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't create response to 'get interface data' query.\n");
		xmlFree(value);
		return IPC_FAILURE;
	}
	// Get the interface's description.
	retstr = cardif_find_description(value);
	if (retstr == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find interface description from name!\n");
		xmlFree(value);
		return IPC_FAILURE;
	}

	ipc_callout_convert_amp(retstr, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Description", (xmlChar *) temp) ==
	    NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't create response node for interface description.\n");
		free(temp);
		xmlFree(value);
		return IPC_FAILURE;
	}
	free(temp);
	FREE(retstr);

	// Get the interface's MAC address.
	retstr = cardif_get_mac_str(value);
	if (retstr == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find MAC address from name!\n");
		xmlFree(value);
		return IPC_FAILURE;
	}

	if (xmlNewChild(t, NULL, (xmlChar *) "MAC", (xmlChar *) retstr) == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't create response node for interface MAC address.\n");
		xmlFree(value);
		return IPC_FAILURE;
	}
	FREE(retstr);

	// Determine if the interface is wireless.
	sprintf((char *)&tempstatic, "%d", cardif_is_wireless_by_name(value));
	if (xmlNewChild(t, NULL, (xmlChar *) "Wireless", (xmlChar *) tempstatic)
	    == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't create response node for interface wirelessness.\n");
		xmlFree(value);
		return IPC_FAILURE;
	}

	xmlFree(value);

	(*outnode) = t;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to get the connection name that is in use on an interface.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_conn_from_int(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	context *ctx = NULL;
	char *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get connection from interface request!\n");

	n = ipc_callout_find_node(innode, "Get_Connection_From_Interface");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Connection_From_Interface' node.\n");
		return ipc_callout_create_error(NULL,
						"Get_Connection_From_Interface",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		return ipc_callout_create_error(NULL,
						"Get_Connection_From_Interface",
						IPC_ERROR_INVALID_INTERFACE,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Connection_From_Interface");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create response message!\n");
		return ipc_callout_create_error(NULL,
						"Get_Connection_From_Interface",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(ctx->intName, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) temp) ==
	    NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Interface> node!\n");
		free(temp);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Connection_From_Interface",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	if (ctx->conn == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Connection_From_Interface",
						IPC_ERROR_NO_CONNECTION,
						outnode);
	}

	ipc_callout_convert_amp(ctx->conn->name, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Connection", (xmlChar *) temp) ==
	    NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Connection> node!\n");
		free(temp);
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL,
						"Get_Connection_From_Interface",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Catch an IPC request to get the error queue.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_error_queue(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int events = 0;
	char numevents[10];
	err_prequeue *cur = NULL;
	char *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC get error queue request!\n");

	n = ipc_callout_find_node(innode, "Get_Error_Queue");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Error_Queue' node.\n");
		return ipc_callout_create_error(NULL, "Get_Error_Queue",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Error_Queue");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create response message!\n");
		return ipc_callout_create_error(NULL, "Get_Error_Queue",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	events = error_prequeue_events_available();
	sprintf((char *)&numevents, "%d", events);

	if (xmlNewChild
	    (n, NULL, (xmlChar *) "Number_Of_Events",
	     (xmlChar *) numevents) == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create a node in the response message!\n");
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Error_Queue",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	cur = error_prequeue_get_head();

	t = xmlNewChild(n, NULL, (xmlChar *) "Errors", NULL);
	if (t == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create a node in the response message!\n");
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Get_Error_Queue",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	while (cur != NULL) {
		ipc_callout_convert_amp(cur->errstr, &temp);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Message",
		     (xmlChar *) temp) == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create the error string node.\n");
			xmlFreeNode(n);
			free(temp);
			return ipc_callout_create_error(NULL, "Get_Error_Queue",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		free(temp);

		cur = cur->next;
	}

	(*outnode) = n;
	error_prequeue_flush();
	return IPC_SUCCESS;
}

/**
 * \brief Request that an interface unbind all connection information.
 *
 * \param[in] innode   A pointer to the nodes that contain the request for an interface
 *                     to unbind a connection from.
 *
 * \param[out] outnode   A pointer to the nodes that contain an ACK on success, or an
 *                       error on failure.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 * \note This call will ONLY unbind the connection/profile from the context (and interface).
 *       It shouldn't be used by itself, and should be called after a logoff and/or disassociate
 *       call.   Unbinding a connection in the middle of a session shouldn't have any side effects,
 *       but will leave your connection in a funny limbo state.
 *
 **/
int ipc_callout_request_unbind_connection(xmlNodePtr innode,
					  xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Unbind_Connection",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->conn != NULL)
		ipc_events_ui(NULL, IPC_EVENT_CONNECTION_UNBOUND,
			      ctx->conn->name);

	ctx->conn = NULL;
	FREE(ctx->conn_name);
	ctx->prof = NULL;

	if (ctx->intType == ETH_802_11_INT) {
		if (ctx->intTypeData != NULL) {
			wctx = (wireless_ctx *) ctx->intTypeData;

			FREE(wctx->cur_essid);
		}
	}
#ifdef HAVE_TNC
	// If we are using a TNC enabled build, signal the IMC to clean up.
	if (ctx->tnc_data != NULL) {
		if (imc_disconnect_callback != NULL)
			imc_disconnect_callback(ctx->tnc_data->connectionID);

		libtnc_tncc_DeleteConnection(ctx->tnc_data);

		ctx->tnc_data = NULL;
	}
#endif

	return ipc_callout_create_ack(ctx->intName, "Unbind_Connection",
				      outnode);
}

/**
 * \brief Rename a connection.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to change a
 *					   connection name.
 *
 * \param[out] outnode   A pointer to the nodes that contain an ACK on success, or an
 *                       error on failure.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_request_rename_connection(xmlNodePtr innode,
					  xmlNodePtr * outnode)
{
	context *ctx = NULL;
	char *oldname = NULL;
	char *newname = NULL;
	int done = FALSE;
	struct config_connection *confcon = NULL;
	xmlNodePtr n = NULL;
	xmlChar *content = NULL;
	uint8_t config_type = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	n = ipc_callout_find_node(innode, "Rename_Connection");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Rename_Connection' node.\n");
		return ipc_callout_create_error(NULL, "Rename_Connection",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	n = n->children;

	n = ipc_callout_find_node(n, "Config_Type");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Config_Type' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Connection",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	config_type = (uint8_t) atoi((char *)content);
	xmlFree(content);

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			return ipc_callout_create_error(NULL,
							"Rename_Connection",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}

	n = ipc_callout_find_node(n, "Old_Name");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Old_Name' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Connection",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	oldname = (char *)xmlNodeGetContent(n);

	n = ipc_callout_find_node(n, "New_Name");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'New_Name' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Connection",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	newname = (char *)xmlNodeGetContent(n);

	debug_printf(DEBUG_IPC, "Renaming connection '%s' to '%s'.\n", oldname,
		     newname);

	confcon = config_get_connections(config_type);

	while (confcon != NULL) {
		if ((confcon != NULL) && (confcon->name != NULL)
		    && (strcmp(newname, confcon->name) == 0)) {
			// We already have something named this!
			return ipc_callout_create_error(NULL,
							"Rename_Connection",
							IPC_ERROR_NAME_IN_USE,
							outnode);
		}

		confcon = confcon->next;
	}

	// Make sure a connection by the same name doesn't exist in the opposite config.
	if (config_type == CONFIG_LOAD_GLOBAL) {
		confcon = config_get_connections(CONFIG_LOAD_USER);
	} else {
		confcon = config_get_connections(CONFIG_LOAD_GLOBAL);
	}

	while (confcon != NULL) {
		if ((confcon != NULL) && (confcon->name != NULL)
		    && (strcmp(newname, confcon->name) == 0)) {
			// We already have something named this!
			return ipc_callout_create_error(NULL,
							"Rename_Connection",
							IPC_ERROR_NAME_IN_USE,
							outnode);
		}

		confcon = confcon->next;
	}

	// Rename any context(s) that are using this connection.
	event_core_reset_locator();
	ctx = event_core_get_next_context();
	while (ctx != NULL) {
		if ((ctx->conn_name != NULL)
		    && (strcmp(ctx->conn_name, oldname) == 0)) {
			FREE(ctx->conn_name);
			ctx->conn_name = _strdup(newname);

			if ((done != TRUE) && (ctx->conn != NULL)) {
				// Free the old name. And set the new one.  Since this pointer is
				// to our master structure for this connection, changing it here will
				// change it globally.
				FREE(ctx->conn->name);
				ctx->conn->name = _strdup(newname);
				done = TRUE;
			}
		}

		ctx = event_core_get_next_context();
	}

	if (done == FALSE)	// The global value didn't get changed.
	{
		// Find the value and change it.
		confcon = config_get_connections(config_type);

		while (confcon != NULL) {
			if (strcmp(confcon->name, oldname) == 0) {
				FREE(confcon->name);
				confcon->name = _strdup(newname);
				done = TRUE;
			}

			confcon = confcon->next;
		}
	}

	if (done == TRUE) {
		return ipc_callout_create_ack(NULL, "Rename_Connection",
					      outnode);
	} else {
		return ipc_callout_create_error(NULL, "Rename_Connection",
						IPC_ERROR_CANT_RENAME, outnode);
	}
}

/**
 * \brief Rename a profile.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to change a
 *					   profile.
 *
 * \param[out] outnode   A pointer to the nodes that contain an ACK on success, or an
 *                       error on failure.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_request_rename_profile(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	char *oldname = NULL;
	char *newname = NULL;
	int done = FALSE;
	struct config_profiles *confprof = NULL;
	struct config_connection *confcon = NULL;
	xmlNodePtr n = NULL;
	xmlChar *content = NULL;
	uint8_t config_type = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	n = ipc_callout_find_node(innode, "Rename_Profile");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Rename_Profile' node.\n");
		return ipc_callout_create_error(NULL, "Rename_Profile",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	n = n->children;

	n = ipc_callout_find_node(n, "Config_Type");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Config_Type' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Profile",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	config_type = (uint8_t) atoi((char *)content);
	xmlFree(content);

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			return ipc_callout_create_error(NULL, "Rename_Profile",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}

	n = ipc_callout_find_node(n, "Old_Name");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Old_Name' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Profile",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	oldname = _strdup((char *)content);
	xmlFree(content);

	n = ipc_callout_find_node(n, "New_Name");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'New_Name' node!\n");
		FREE(oldname);
		return ipc_callout_create_error(NULL, "Rename_Profile",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	newname = _strdup((char *)content);
	xmlFree(content);

	debug_printf(DEBUG_IPC, "Renaming profile '%s' to '%s'.\n", oldname,
		     newname);

	confprof = config_get_profiles(config_type);

	while (confprof != NULL) {
		if ((confprof != NULL) && (confprof->name != NULL)
		    && (strcmp(confprof->name, newname) == 0)) {
			FREE(oldname);
			FREE(newname);
			return ipc_callout_create_error(NULL, "Rename_Profile",
							IPC_ERROR_NAME_IN_USE,
							outnode);
		}

		confprof = confprof->next;
	}

	// Rename any profile(s) that are using this connection.
	event_core_reset_locator();
	ctx = event_core_get_next_context();
	while (ctx != NULL) {
		if ((ctx->conn != NULL) && (ctx->conn->profile != NULL)
		    && (strcmp(ctx->conn->profile, oldname) == 0)) {
			FREE(ctx->conn->profile);
			ctx->conn->profile = _strdup(newname);

			if ((done != TRUE) && (ctx->prof != NULL)) {
				// Free the old name. And set the new one.  Since this pointer is
				// to our master structure for this connection, changing it here will
				// change it globally.
				FREE(ctx->prof->name);
				ctx->prof->name = _strdup(newname);
				done = TRUE;
			}
		}

		ctx = event_core_get_next_context();
	}

	if (done == FALSE)	// The global value didn't get changed.
	{
		// Find the value and change it.
		confprof = config_get_profiles(config_type);

		while (confprof != NULL) {
			if (strcmp(confprof->name, oldname) == 0) {
				FREE(confprof->name);
				confprof->name = _strdup(newname);
				done = TRUE;
			}

			confprof = confprof->next;
		}
	}

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		confcon = config_get_connections(CONFIG_LOAD_GLOBAL);

		while (confcon != NULL) {
			if ((confcon->profile != NULL)
			    && (strcmp(confcon->profile, oldname) == 0)) {
				FREE(confcon->profile);
				confcon->profile = _strdup(newname);
			}

			confcon = confcon->next;
		}
	}

	confcon = config_get_connections(CONFIG_LOAD_USER);

	while (confcon != NULL) {
		if ((confcon->profile != NULL)
		    && (strcmp(confcon->profile, oldname) == 0)) {
			FREE(confcon->profile);
			confcon->profile = _strdup(newname);
		}

		confcon = confcon->next;
	}

	FREE(oldname);
	FREE(newname);

	if (done == TRUE) {
		return ipc_callout_create_ack(NULL, "Rename_Profile", outnode);
	} else {
		return ipc_callout_create_error(NULL, "Rename_Profile",
						IPC_ERROR_CANT_RENAME, outnode);
	}
}

/**
 * \brief Rename a trusted server.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to change a
 *					   trusted server.
 *
 * \param[out] outnode   A pointer to the nodes that contain an ACK on success, or an
 *                       error on failure.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_request_rename_trusted_server(xmlNodePtr innode,
					      xmlNodePtr * outnode)
{
	char *oldname = NULL;
	char *newname = NULL;
	int done = FALSE;
	struct config_profiles *confprof = NULL;
	struct config_trusted_server *confts = NULL;
	struct config_trusted_servers *conftss = NULL;
	xmlNodePtr n = NULL;
	xmlChar *content = NULL;
	uint8_t config_type = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	n = ipc_callout_find_node(innode, "Rename_Trusted_Server");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Rename_Trusted_Server' node.\n");
		return ipc_callout_create_error(NULL, "Rename_Trusted_Server",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	n = n->children;

	n = ipc_callout_find_node(n, "Config_Type");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Config_Type' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Trusted_Server",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	config_type = (uint8_t) atoi((char *)content);
	xmlFree(content);

	if ((config_type & CONFIG_LOAD_GLOBAL) == CONFIG_LOAD_GLOBAL) {
		if (platform_user_is_admin() != TRUE) {
			return ipc_callout_create_error(NULL,
							"Rename_Trusted_Server",
							IPC_ERROR_USER_NOT_ADMIN,
							outnode);
		}
	}

	n = ipc_callout_find_node(n, "Old_Name");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Old_Name' node!\n");
		return ipc_callout_create_error(NULL, "Rename_Trusted_Server",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	oldname = _strdup((char *)content);
	xmlFree(content);

	n = ipc_callout_find_node(n, "New_Name");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'New_Name' node!\n");
		FREE(oldname);
		return ipc_callout_create_error(NULL, "Rename_Trusted_Server",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	content = xmlNodeGetContent(n);
	newname = _strdup((char *)content);
	xmlFree(content);

	debug_printf(DEBUG_IPC, "Renaming trusted server '%s' to '%s'.\n",
		     oldname, newname);

	conftss = config_get_trusted_servers(config_type);

	if (conftss == NULL) {
		debug_printf(DEBUG_IPC, "Requested non-existant server!\n");
		FREE(newname);
		FREE(oldname);
		return ipc_callout_create_error(NULL, "Rename_Trusted_Server",
						IPC_ERROR_INVALID_TRUSTED_SVR,
						outnode);
	}

	confts = conftss->servers;

	while (confts != NULL) {
		if ((confts != NULL) && (confts->name != NULL)
		    && (strcmp(confts->name, newname) == 0)) {
			FREE(newname);
			FREE(oldname);
			return ipc_callout_create_error(NULL,
							"Rename_Trusted_Server",
							IPC_ERROR_NAME_IN_USE,
							outnode);
		}

		confts = confts->next;
	}

	if (conftss != NULL) {
		confts = conftss->servers;

		while ((confts != NULL) && (done == FALSE)) {
			if ((confts->name != NULL)
			    && (strcmp(confts->name, oldname) == 0)) {
				FREE(confts->name);
				confts->name = _strdup(newname);
				done = TRUE;
			}

			confts = confts->next;
		}

		if (done == TRUE)	// A server was renamed, so look for any profiles that use it.
		{
			// Find the value and change it.
			if ((config_type & CONFIG_LOAD_GLOBAL) ==
			    CONFIG_LOAD_GLOBAL) {
				confprof =
				    config_get_profiles(CONFIG_LOAD_GLOBAL);

				ipc_callout_helper_trusted_server_renamed_check_profiles
				    (confprof, oldname, newname);
			}

			confprof = config_get_profiles(CONFIG_LOAD_USER);

			ipc_callout_helper_trusted_server_renamed_check_profiles
			    (confprof, oldname, newname);
		}
	}

	FREE(newname);
	FREE(oldname);

	if (done == TRUE) {
		return ipc_callout_create_ack(NULL, "Rename_Trusted_Server",
					      outnode);
	} else {
		return ipc_callout_create_error(NULL, "Rename_Trusted_Server",
						IPC_ERROR_CANT_RENAME, outnode);
	}
}

/**
 * \brief Catch an IPC request to get the link state for a specific interface.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_link_state_for_int(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	context *ctx = NULL;
	char *temp = NULL;
	char stattemp[10];
	int state = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC get link state from interface request!\n");

	n = ipc_callout_find_node(innode, "Get_Link_State_From_Interface");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Link_State_From_Interface' node.\n");
		return ipc_callout_create_error(NULL,
						"Get_Link_State_From_Interface",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		return ipc_callout_create_error(NULL,
						"Get_Link_State_From_Interface",
						IPC_ERROR_INVALID_INTERFACE,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *) "Link_State_From_Interface");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create response message!\n");
		return ipc_callout_create_error(NULL,
						"Get_Link_State_From_Interface",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	ipc_callout_convert_amp(ctx->intName, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Interface", (xmlChar *) & temp) ==
	    NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Interface> node!\n");
		free(temp);
		return ipc_callout_create_error(NULL,
						"Get_Link_State_From_Interface",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	if (ctx->conn == NULL) {
		return ipc_callout_create_error(NULL,
						"Get_Link_State_From_Interface",
						IPC_ERROR_NO_CONNECTION,
						outnode);
	}

	state = cardif_get_link_state(ctx);
	sprintf((char *)&stattemp, "%d", state);

	ipc_callout_convert_amp(stattemp, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *) "Link_State", (xmlChar *) & temp)
	    == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Link_State> node!\n");
		free(temp);
		return ipc_callout_create_error(NULL,
						"Get_Link_State_From_Interface",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;
	return IPC_SUCCESS;
}

/**
 * \brief Generate a trouble ticket by requesting any plugins dump their data, and by
 *        using the crash dump collector to gather any data that is available.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to generate the
 *                     crash dump data.
 *
 * \param[out] outnode   A pointer to the nodes that contain the success or failure
 *                       values for the call.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 **/
int ipc_callout_request_create_trouble_ticket(xmlNodePtr innode,
					      xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL;
	char *temp_data_path = NULL;
	char *tt_data_path = NULL;
	int overwrite = 0;
	FILE *fh = NULL;
	char *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	n = ipc_callout_find_node(innode, "Create_Trouble_Ticket");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Create_Trouble_Ticket' node.\n");
		return ipc_callout_create_error(NULL, "Create_Trouble_Ticket",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	n = n->children;	// Look at our children.

	n = ipc_callout_find_node(n, "Temp_Data_Path");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No <Temp_Data_Path> specified in 'Create_Trouble_Ticket' request!\n");
		return ipc_callout_create_error(NULL, "Create_Trouble_Ticket",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	temp_data_path = (char *)xmlNodeGetContent(n);

	n = ipc_callout_find_node(n, "Trouble_Ticket_File");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No <Trouble_Ticket_File> specified in 'Create_Trouble_Ticket' request!\n");
		xmlFree(temp_data_path);
		return ipc_callout_create_error(NULL, "Create_Trouble_Ticket",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	tt_data_path = (char *)xmlNodeGetContent(n);

	n = ipc_callout_find_node(n, "Overwrite");
	if (n == NULL) {
		overwrite = 0;	// By default, don't overwrite.  Return an error.
	} else {
		temp = (char *)xmlNodeGetContent(n);
		overwrite = atoi(temp);
		xmlFree(temp);
	}

	fh = fopen(tt_data_path, "r");
	if ((fh != NULL) && (overwrite == 0)) {
		fclose(fh);
		xmlFree(temp_data_path);
		xmlFree(tt_data_path);
		return ipc_callout_create_error(NULL, "Create_Trouble_Ticket",
						IPC_ERROR_FILE_EXISTS, outnode);
	}
	if (fh != NULL)
		fclose(fh);

#if (WINDOWS || LINUX)
	tthandler_create_troubleticket(temp_data_path, tt_data_path);
#else
#warning Need to implement crash dump file handling for this platform.
#endif				// (WINDOWS || LINUX)

	xmlFree(temp_data_path);
	xmlFree(tt_data_path);

	// We have the data we need, so create the response.
	return ipc_callout_create_ack(NULL, "Create_Trouble_Ticket", outnode);
}

/**
 * \brief Request the card capabilities.
 *
 * \param[in] innode   A pointer to the nodes that contain the request to get the
 *                     association type for an interface.
 * \param[out] outnode   A pointer to the nodes that contain a numeric representation of
 *                       the association type.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 **/
int ipc_callout_get_interface_capabilities(xmlNodePtr innode,
					   xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL,
						"Get_Interface_Capabilities",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	wctx = (wireless_ctx *) ctx->intTypeData;
	if (wctx == NULL)
		return ipc_callout_create_error(ctx->intName,
						"Get_Interface_Capabilities",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	return ipc_callout_some_state_response("Get_Interface_Capabilities",
					       "Interface_Capabilities",
					       wctx->enc_capa, "Capabilities",
					       ctx->intName, outnode);
}

/**
 * \brief Request that a certificate be added to the certificate store.
 *
 * \param[in] innode   A pointer to the nodes that contain the request for an interface
 *                     to unbind a connection from.
 *
 * \param[out] outnode   A pointer to the nodes that contain an ACK on success, or an
 *                       error on failure.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 *
 **/
int ipc_callout_add_cert_to_store(xmlNodePtr innode, xmlNodePtr * outnode)
{
	char *cert_to_add = NULL;
	int retval = 0;
	xmlNodePtr n = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	n = ipc_callout_find_node(innode, "Add_Cert_to_Store");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Add_Cert_to_Store' node.\n");
		return ipc_callout_create_error(NULL, "Add_Cert_to_Store",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	n = n->children;	// Look at our children.

	n = ipc_callout_find_node(n, "Cert_Path");
	if (n == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No <Cert_Path> specified in 'Add_Cert_to_Store' request!\n");
		return ipc_callout_create_error(NULL, "Add_Cert_to_Store",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	cert_to_add = (char *)xmlNodeGetContent(n);

	retval = cert_handler_add_cert_to_store(cert_to_add);
	xmlFree(cert_to_add);

	if (retval != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Unable to add the certificate at '%s' to the certificate store.\n",
			     cert_to_add);
		return ipc_callout_create_error(NULL, "Add_Cert_to_Store",
						IPC_ERROR_INVALID_NODE,
						outnode);
	}

	return ipc_callout_create_ack(NULL, "Add_Cert_to_Store", outnode);
}

/**
 *  \brief Return the connection ID used by TNC for the named interface.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     interface's connection ID.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 **/
int ipc_callout_get_tnc_conn_id(xmlNodePtr innode, xmlNodePtr * outnode)
{
#ifdef HAVE_TNC
	context *ctx = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		debug_printf(DEBUG_VERBOSE,
			     "Unable to locate context for IPC request.\n");
		return ipc_callout_create_error(NULL, "Get_TNC_Conn_ID",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);
	}

	if (ctx->tnc_data == NULL) {
		debug_printf(DEBUG_VERBOSE,
			     "Context does not posess TNC data.\n");

		return ipc_callout_some_state_response("Get_TNC_Conn_ID",
						       "TNC_Conn_ID", -1,
						       "Conn_ID", ctx->intName,
						       outnode);
	}

	debug_printf(DEBUG_VERBOSE, "Returning TNC connection ID : %d\n",
		     ctx->tnc_data->connectionID);
	return ipc_callout_some_state_response("Get_TNC_Conn_ID", "TNC_Conn_ID",
					       ctx->tnc_data->connectionID,
					       "Conn_ID", ctx->intName,
					       outnode);
#else
	return -1;
#endif				// HAVE_TNC
}

/**
 *  \brief Enable or Disable the FORCED_CONN lock on a context based on the interface name.
 *
 * \param[in] innode   The XML node tree that contains the request to set the
 *                     context's connection lock.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \note While this function will operate on a wired interface, it may not do anything interesting
 *       to that interface.  (The connection lock is mainly to avoid roaming to a different prioritized
 *		 network.)
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_set_conn_lock(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *temp = NULL;
	int retval = IPC_SUCCESS;
	char *iface = NULL;
	context *ctx = NULL;
	int newval = 0;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC set connection lock request!\n");

	n = ipc_callout_find_node(innode, "Set_Connection_Lock");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Set_Connection_Lock' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Interface");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Interface> node in the request!\n");
		return ipc_callout_create_error(NULL, "Set_Connection_Lock",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	iface = (char *)xmlNodeGetContent(t);
	if (iface == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No interface specified to execute a conn lock change on!\n");
		return ipc_callout_create_error(NULL, "Set_Connection_Lock",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	t = ipc_callout_find_node(n, "Connection_Lock");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Connection_Lock> node in the request!\n");
		return ipc_callout_create_error(NULL, "Set_Connection_Lock",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	temp = xmlNodeGetContent(t);
	newval = atoi((char *)temp);
	xmlFree(temp);

	debug_printf(DEBUG_IPC, "Setting connlock on interface %s to %d.\n",
		     iface, newval);

	ctx = event_core_locate(iface);
	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate the interface requested over IPC!\n");
		retval =
		    ipc_callout_create_error(iface, "Set_Connection_Lock",
					     IPC_ERROR_INTERFACE_NOT_FOUND,
					     outnode);
		goto lock_done;
	}

	if (newval == TRUE) {
		SET_FLAG(ctx->flags, FORCED_CONN);
	} else {
		UNSET_FLAG(ctx->flags, FORCED_CONN);

		// Since we are allowing the connection to 'float' we need to clear any posture state that may
		// already be stored.
#ifdef HAVE_TNC
		if (ctx->tnc_data != NULL) {
			if (imc_disconnect_callback != NULL)
				imc_disconnect_callback(ctx->
							tnc_data->connectionID);

			libtnc_tncc_DeleteConnection(ctx->tnc_data);

			ctx->tnc_data = NULL;
		}
#endif
	}

	retval = ipc_callout_create_ack(iface, "Set_Connection_Lock", outnode);

 lock_done:
	free(iface);

	return retval;
}

/**
 * \brief Request the interface name that maps to a specific TNC connection ID.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     interface name from the TNC connection ID.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_interface_from_tnc_connid(xmlNodePtr innode,
					      xmlNodePtr * outnode)
{
#ifndef HAVE_TNC
	return ipc_callout_create_error(NULL, "Get_Interface_From_TNC_Conn_ID",
					IPC_ERROR_NOT_SUPPORTED, outnode);
#else
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS;
	context *ctx = NULL;
	int newval = 0;
	char *temp = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC set connection lock request!\n");

	n = ipc_callout_find_node(innode, "Get_Interface_From_TNC_Conn_ID");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'Get_Interface_From_TNC_Conn_ID' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Connection_ID");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Connection_ID> node in the request!\n");
		return ipc_callout_create_error(NULL,
						"Get_Interface_From_TNC_Conn_ID",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	newval = atoi((char *)xmlNodeGetContent(t));

	debug_printf(DEBUG_IPC, "Getting interface for TNC ID %d.\n", newval);

	event_core_reset_locator();

	ctx = event_core_get_next_context();
	while ((ctx != NULL) && (ctx->tnc_data != NULL)
	       && (ctx->tnc_data->connectionID != newval)) {
		ctx = event_core_get_next_context();
	}

	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate context that mapped to TNC ID %d.\n",
			     newval);
		return ipc_callout_create_error(NULL,
						"Get_Interface_From_TNC_Conn_ID",
						IPC_ERROR_INVALID_INTERFACE,
						outnode);
	}

	n = xmlNewNode(NULL, (xmlChar *)"Interface_From_TNC_Conn_ID");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't create <Interface_From_TNC_Conn_ID node.\n");
		return ipc_callout_create_error(NULL,
						"Get_Interface_From_TNC_Conn_ID",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	// Otherwise, we should have what we need to know.
	ipc_callout_convert_amp(ctx->intName, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *)"Interface_Name", (xmlChar *)temp) == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't create <Interface_Name> node!\n");
		free(temp);
		return ipc_callout_create_error(NULL,
						"Get_Interface_From_TNC_Conn_ID",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}
	free(temp);

	(*outnode) = n;

	return retval;
#endif
}

/**
 * \brief Determine if an interface is in the middle of doing WPA(2)-PSK.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     WPA(2)-PSK state for an interface name.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_doing_psk(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	wireless_ctx *wctx = NULL;
	int doing_psk = 0;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL)
		return ipc_callout_create_error(NULL, "Get_Are_Doing_PSK",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	if (ctx->intType != ETH_802_11_INT)
		return ipc_callout_create_error(ctx->intName,
						"Get_Are_Doing_PSK",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);

	wctx = (wireless_ctx *) ctx->intTypeData;
	if (TEST_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK)) {
		doing_psk = TRUE;
	} else {
		doing_psk = FALSE;
	}

	return ipc_callout_some_state_response("Get_Are_Doing_PSK",
					       "Are_Doing_PSK", doing_psk,
					       "Doing_PSK", ctx->intName,
					       outnode);
}

/**
 *  \brief Issue a DHCP release/renew for the specified interface.
 *
 * \param[in] innode   The XML node tree that contains the request to set the
 *                     context's connection lock.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_dhcp_release_renew(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	int retval = IPC_SUCCESS;
	char *iface = NULL;
	context *ctx = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC DHCP release/renew request!\n");

	n = ipc_callout_find_node(innode, "DHCP_Release_Renew");
	if (n == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't get 'DHCP_Release_Renew' node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Interface");
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <Interface> node in the request!\n");
		return ipc_callout_create_error(NULL, "DHCP_Release_Renew",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	iface = (char *)xmlNodeGetContent(t);
	if (iface == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No interface specified to execute a conn lock change on!\n");
		return ipc_callout_create_error(NULL, "DHCP_Release_Renew",
						IPC_ERROR_INTERFACE_NOT_FOUND,
						outnode);
	}

	debug_printf(DEBUG_IPC, "DHCP release/renew on interface %s.\n", iface);

	ctx = event_core_locate(iface);
	if (ctx == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't locate the interface requested over IPC!\n");
		retval =
		    ipc_callout_create_error(iface, "DHCP_Release_Renew",
					     IPC_ERROR_INTERFACE_NOT_FOUND,
					     outnode);
		goto done;
	}
	// NOTE : The release/renew call CANNOT block!  If it does, then the UI may assume
	// that the engine is dead.  If you *HAVE* to use a blocking call, it should be 
	// threaded!
#ifdef WINDOWS
	cardif_windows_release_renew(ctx);
#else
#warning Add DHCP release/renew call for your OS here!
#endif

	retval = ipc_callout_create_ack(iface, "DHCP_Release_Renew", outnode);

 done:
	free(iface);

	return retval;
}

/**
 *  \brief Return the frequency used for the specified interface.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     interface's connection ID.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_frequency(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;
	uint32_t freq = 0;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		debug_printf(DEBUG_VERBOSE,
			     "Unable to locate context for IPC request.\n");
		return ipc_callout_create_error(NULL, "Get_Frequency",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);
	}

	if (ctx->intType != ETH_802_11_INT) {
		debug_printf(DEBUG_VERBOSE,
			     "UI requested the frequency for a wired interface?\n");
		return ipc_callout_create_error(NULL, "Get_Frequency",
						IPC_ERROR_INT_NOT_WIRELESS,
						outnode);
	}

	if (cardif_get_freq(ctx, &freq) != XENONE) {
		debug_printf(DEBUG_VERBOSE,
			     "Unable to determine the frequency that interface '%s' is on!\n",
			     ctx->desc);
		return ipc_callout_create_error(NULL, "Get_Frequency",
						IPC_ERROR_CANT_GET_CONFIG,
						outnode);
	}

	debug_printf(DEBUG_VERBOSE, "Returning Freq : %d\n", freq);
	return ipc_callout_some_state_response("Get_Frequency", "Frequency",
					       freq, "Freq", ctx->intName,
					       outnode);
}

/**
 *  \brief Request that a connection be disconnected.
 *
 * \param[in] innode   The XML node tree that contains the request to disconnect.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_disconnect_connection(xmlNodePtr innode, xmlNodePtr * outnode)
{
	context *ctx = NULL;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	ctx = ipc_callout_get_context_from_int(innode);
	if (ctx == NULL) {
		debug_printf(DEBUG_VERBOSE,
			     "Unable to locate context for IPC request.\n");
		return ipc_callout_create_error(NULL, "Disconnect_Connection",
						IPC_ERROR_INVALID_CONTEXT,
						outnode);
	}

	if (ctx->intType == ETH_802_11_INT) {
		if (cardif_disassociate(ctx, 1) != 0)	// 1 = UNSPECIFIED_REASON
		{
			debug_printf(DEBUG_VERBOSE,
				     "Unable to disassocated wireless interface '%s'.\n",
				     ctx->desc);
			return ipc_callout_create_error(NULL,
							"Disconnect_Connection",
							IPC_ERROR_REQUEST_FAILED,
							outnode);
		}
		// Make sure this flag is cleared so that we don't get any absurd screaming with PSK when the users hits
		// connect/disconnect over and over again. ;)
		UNSET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
			   WIRELESS_SM_DOING_PSK);

		// Let ourselves know that a UI requested this disconnect.
		SET_FLAG(((wireless_ctx *) ctx->intTypeData)->flags,
			 WIRELESS_SM_DISCONNECT_REQ);

		// Force a state machine reinit.
		eap_sm_force_init(ctx->eap_state);
	} else {
		if (statemachine_change_state(ctx, LOGOFF) == 0) {
			eap_sm_deinit(&ctx->eap_state);
			eap_sm_init(&ctx->eap_state);

			txLogoff(ctx);

#ifdef WINDOWS
			cardif_windows_release_ip(ctx);
#else
#warning Fill this in for your OS!
#endif
		}
	}

#ifdef HAVE_TNC
	// If we are using a TNC enabled build, signal the IMC to clean up.
	// We didn't reset the tnc_data structure here... why?
	if (ctx->tnc_data != NULL) {
		if (imc_disconnect_callback != NULL)
			imc_disconnect_callback(ctx->tnc_data->connectionID);

		libtnc_tncc_DeleteConnection(ctx->tnc_data);

		ctx->tnc_data = NULL;
	}
#endif

	context_disconnect(ctx);
	ipc_events_ui(ctx, IPC_EVENT_UI_CONNECTION_DISCONNECT, ctx->intName);

	// Clear out any memory cached passwords of PSKs.
	if (ctx->conn != NULL)
		if (ctx->conn->association.temp_psk != NULL)
			FREE(ctx->conn->association.temp_psk);

	if (ctx->prof != NULL) {
		if (ctx->prof->temp_password != NULL)
			FREE(ctx->prof->temp_password);
		if (ctx->prof->temp_username != NULL)
			FREE(ctx->prof->temp_username);
	}

	ctx->conn = NULL;
	FREE(ctx->conn_name);
	ctx->auths = 0;		// So that we renew DHCP on the next authentication.
	SET_FLAG(ctx->flags, FORCED_CONN);

	return ipc_callout_create_ack(ctx->intName, "Disconnect_Connection",
				      outnode);
}

/**
 * \brief Get a string out of a command XML blob.
 *
 * @param[in] cmd_root   The "root" command name.  (Used to verify the command structure.)
 * @param[in] subvalue   The tag under the root that contains the string we are looking for.
 *
 * \retval NULL on error, ptr to string on success
 **/
char *ipc_callout_get_value_from_command(xmlNodePtr innode, char *cmd_root,
					 char *subvalue)
{
	xmlNodePtr n = NULL, t = NULL;
	char *retsval = NULL;
	xmlChar *temp = NULL;

	if ((cmd_root == NULL) || (subvalue == NULL))
		return NULL;

	n = ipc_callout_find_node(innode, cmd_root);
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get '%s' node.\n", cmd_root);
		return NULL;
	}

	n = n->children;

	t = ipc_callout_find_node(n, subvalue);
	if (t == NULL) {
		debug_printf(DEBUG_IPC,
			     "Couldn't find the <%s> node in the request!\n",
			     subvalue);
		return NULL;
	}

	temp = xmlNodeGetContent(t);
	retsval = _strdup((char *)temp);
	xmlFree(temp);

	return retsval;
}

/**
 * \brief Determine if a named connection is currently in use.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     'in use' state of the named connection.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_is_connection_in_use(xmlNodePtr innode,
					 xmlNodePtr * outnode)
{
	char *value = NULL;
	int retval = FALSE;

	value =
	    ipc_callout_get_value_from_command(innode,
					       "Get_Is_Connection_In_Use",
					       "Connection_Name");
	if (value == NULL) {
		return ipc_callout_create_error(NULL,
						"Get_Is_Connection_In_Use",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	retval = ipc_callout_is_connection_in_use(value);
	free(value);

	return ipc_callout_some_state_response("Get_Is_Connection_In_Use",
					       "Is_Connection_In_Use", retval,
					       "Use_State", NULL, outnode);
}

/**
 * \brief Determine if a named profile is currently in use.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     'in use' state of the named profile.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_is_profile_in_use(xmlNodePtr innode, xmlNodePtr * outnode)
{
	char *value = NULL;
	int retval = FALSE;

	value =
	    ipc_callout_get_value_from_command(innode, "Get_Is_Profile_In_Use",
					       "Profile_Name");
	if (value == NULL) {
		return ipc_callout_create_error(NULL, "Get_Is_Profile_In_Use",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	retval = ipc_callout_is_profile_in_use(value);
	free(value);

	return ipc_callout_some_state_response("Get_Is_Profile_In_Use",
					       "Is_Profile_In_Use", retval,
					       "Use_State", NULL, outnode);
}

/**
 * \brief Determine if a named trusted server is currently in use.
 *
 * \param[in] innode   The XML node tree that contains the request to get the
 *                     'in use' state of the named trusted server.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_is_trusted_server_in_use(xmlNodePtr innode,
					     xmlNodePtr * outnode)
{
	char *value = NULL;
	int retval = FALSE;

	value =
	    ipc_callout_get_value_from_command(innode,
					       "Get_Is_Trusted_Server_In_Use",
					       "Trusted_Server_Name");
	if (value == NULL) {
		return ipc_callout_create_error(NULL,
						"Get_Is_Trusted_Server_In_Use",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	retval = ipc_callout_is_trusted_server_in_use(value);
	free(value);

	return ipc_callout_some_state_response("Get_Is_Trusted_Server_In_Use",
					       "Is_Trusted_Server_In_Use",
					       retval, "Use_State", NULL,
					       outnode);
}

/**
 * \brief Determine if the user on the console is an administrator.
 *
 * \param[in] innode   The XML node tree that contains the request to determine
 *                     if the user on the console is administrator/root.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_get_are_administrator(xmlNodePtr innode, xmlNodePtr * outnode)
{
	int are_admin = FALSE;

	if (!xsup_assert((innode != NULL), "innode != NULL", FALSE))
		return IPC_FAILURE;

	are_admin = platform_user_is_admin();

	return ipc_callout_some_state_response("Get_Are_Administrator",
					       "Are_Administrator", are_admin,
					       "Administrator", NULL, outnode);
}

/**
 * \brief Enumerate the smart card readers installed on the system.
 *
 * \param[in] innode   The XML node tree that contains the request to enumerate
 *                     the smart card readers installed on the system.
 * \param[out] outnode   The XML node tree that contains either the response to the
 *                        request, or an error message.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_enum_smartcard_readers(xmlNodePtr innode, xmlNodePtr * outnode)
{
#ifndef EAP_SIM_ENABLE
	// If we aren't built with SIM/AKA, then we return an error.
	return ipc_callout_create_error(NULL, "Enum_Smartcard_Readers",
					IPC_ERROR_NOT_SUPPORTED, outnode);
#else
	char *readers = NULL;
	char *pReader = NULL;
	SCARDCONTEXT sctx;
	xmlNodePtr n = NULL;

	if (sm_handler_init_ctx(&sctx) != 0) {
		return ipc_callout_create_error(NULL, "Enum_Smartcard_Readers",
						IPC_ERROR_NOT_SUPPORTED,
						outnode);
	}

	readers = sm_handler_get_readers(&sctx);
	pReader = readers;

	n = xmlNewNode(NULL, (xmlChar *)"Smartcard_Readers");
	if (n == NULL) {
		free(readers);
		SCardReleaseContext(sctx);
		return ipc_callout_create_error(NULL, "Enum_Smartcard_Readers",
						IPC_ERROR_NOT_SUPPORTED,
						outnode);
	}

	if (readers != NULL) {
		while ('\0' != (*pReader)) {
			debug_printf(DEBUG_IPC, "Found SC reader : %s\n",
				     pReader);
			if (xmlNewChild(n, NULL, (xmlChar *)"Reader", (xmlChar *)pReader) == NULL) {
				free(readers);
				SCardReleaseContext(sctx);
				return ipc_callout_create_error(NULL,
								"Enum_Smartcard_Readers",
								IPC_ERROR_NOT_SUPPORTED,
								outnode);
			}

			pReader = pReader + strlen(pReader) + 1;
		}
	}

	FREE(readers);

	(*outnode) = n;

	return IPC_SUCCESS;
#endif
}

/**
 * \brief Catch an IPC request to enumerate the user's certificates.
 *
 * \param[in] innode  The root of the XML tree that contains the information we
 *                    are interested in.
 * \param[out] outnode   The root of the XML tree that contains the return information
 *                       used to let the IPC caller know the status of the request.
 *
 * \retval IPC_SUCCESS on success
 * \retval IPC_FAILURE on failure
 **/
int ipc_callout_enum_user_certs(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL, b = NULL;
	char value[100];
	int numcas = 0;
	int i = 0;
	char *temp = NULL;
	cert_enum *casa = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC, "Got an IPC enumerate user certs request!\n");

	n = xmlNewNode(NULL, (xmlChar *) "User_Certs_Enum");
	if (n == NULL) {
		return ipc_callout_create_error(NULL, "Enum_User_Certs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Getting number of available certificates.\n");

#ifdef WINDOWS
	if (win_impersonate_desktop_user() != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Unable to impersonate the desktop user.  Will attempt to continue anyway, but no certificates may be listed.\n");
	}
#endif

	numcas = cert_handler_num_user_certs();
	if (numcas < 0) {
		xmlFreeNode(n);

#ifdef WINDOWS
		win_impersonate_back_to_self();
#endif
		return ipc_callout_create_error(NULL, "Enum_User_Certs",
						IPC_ERROR_CERT_STORE_ERROR,
						outnode);
	}

	debug_printf(DEBUG_IPC, "Getting list of available certificates.\n");
	if (cert_handler_enum_user_certs(&numcas, &casa) < 0) {
		xmlFreeNode(n);
#ifdef WINDOWS
		win_impersonate_back_to_self();
#endif
		return ipc_callout_create_error(NULL, "Enum_User_Certs",
						IPC_ERROR_CERT_STORE_ERROR,
						outnode);
	}
#ifdef WINDOWS
	win_impersonate_back_to_self();
#endif

	if (casa == NULL) {
		xmlFreeNode(n);
		return ipc_callout_create_error(NULL, "Enum_User_Certs",
						IPC_ERROR_CERT_STORE_ERROR,
						outnode);
	}

	sprintf((char *)&value, "%d", numcas);
	t = xmlNewChild(n, NULL, (xmlChar *) "Number_Of_Certs",
			(xmlChar *) value);
	if (t == NULL) {
		xmlFreeNode(n);
		cert_handler_free_cert_enum(numcas, &casa);
		return ipc_callout_create_error(NULL, "Enum_User_Certs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Certificates", NULL);
	if (t == NULL) {
		xmlFreeNode(n);
		cert_handler_free_cert_enum(numcas, &casa);
		return ipc_callout_create_error(NULL, "Enum_User_Certs",
						IPC_ERROR_CANT_ALLOCATE_NODE,
						outnode);
	}

	for (i = 0; i < numcas; i++) {
		b = xmlNewChild(t, NULL, (xmlChar *) "Certificate", NULL);
		if (b == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (ipc_callout_convert_amp(casa[i].storetype, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Store_Type",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].certname, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Name", (xmlChar *) temp)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].friendlyname, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Friendly_Name",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].issuer, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Issuer", (xmlChar *) temp)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].commonname, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "CommonName",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		if (ipc_callout_convert_amp(casa[i].location, &temp) !=
		    IPC_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't convert string!\n");
			xmlFreeNode(n);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		if (xmlNewChild(b, NULL, (xmlChar *) "Location",
		     (xmlChar *) temp) == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
		FREE(temp);

		sprintf((char *)&value, "%d", casa[i].month);
		if (xmlNewChild(b, NULL, (xmlChar *) "Month", (xmlChar *) value)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&value, "%d", casa[i].day);
		if (xmlNewChild(b, NULL, (xmlChar *) "Day", (xmlChar *) value)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}

		sprintf((char *)&value, "%d", casa[i].year);
		if (xmlNewChild(b, NULL, (xmlChar *) "Year", (xmlChar *) value)
		    == NULL) {
			xmlFreeNode(n);
			FREE(temp);
			cert_handler_free_cert_enum(numcas, &casa);
			return ipc_callout_create_error(NULL, "Enum_User_Certs",
							IPC_ERROR_CANT_ALLOCATE_NODE,
							outnode);
		}
	}

	cert_handler_free_cert_enum(numcas, &casa);

	(*outnode) = n;

	return IPC_SUCCESS;
}

/**
 *  \brief Store the logon credentials for later user.
 *
 *  \param[in] innode   A pointer to the node tree that contains the request to change
 *                      the username and password for a connection.
 *  \param[out] outnode   A pointer to the node tree that contains either an ACK for
 *                        success, or an error code for failure.
 *
 *  \retval IPC_SUCCESS on success
 *  \retval IPC_FAILURE on failure
 **/
int ipc_callout_store_logon_creds(xmlNodePtr innode, xmlNodePtr * outnode)
{
	xmlNodePtr n = NULL, t = NULL;
	char *username = NULL, *password = NULL;

	if (innode == NULL)
		return IPC_FAILURE;

	debug_printf(DEBUG_IPC,
		     "Got an IPC connection store logon creds request!\n");

	n = ipc_callout_find_node(innode, "Store_Logon_Creds");
	if (n == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get first creds node.\n");
		return IPC_FAILURE;
	}

	n = n->children;

	t = ipc_callout_find_node(n, "Username");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Username' node.\n");
		return ipc_callout_create_error(NULL, "Store_Logon_Creds",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	username = (char *)xmlNodeGetContent(t);
	if ((username != NULL) && (strlen(username) == 0)) {
		xmlFree(username);
		username = NULL;
	}

	t = ipc_callout_find_node(n, "Password");
	if (t == NULL) {
		debug_printf(DEBUG_IPC, "Couldn't get 'Password' node!\n");
		FREE(username);
		return ipc_callout_create_error(NULL, "Store_Logon_Creds",
						IPC_ERROR_INVALID_REQUEST,
						outnode);
	}

	password = (char *)xmlNodeGetContent(t);
	if ((password != NULL) && (strlen(password) == 0)) {
		xmlFree(password);
		password = NULL;
	}

	if (logon_creds_store_username_and_password(username, password) != 0) {
		return ipc_callout_create_error(NULL, "Store_Logon_Creds",
						IPC_ERROR_REQUEST_FAILED,
						outnode);
	}

	debug_printf(DEBUG_NORMAL, "Stored global user credentials!\n");

	FREE(username);
	FREE(password);

	return ipc_callout_create_ack(NULL, "Store_Logon_Creds", outnode);
}
