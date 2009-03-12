/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request4.c
 *
 * \author chris@open1x.org
 **/

#include <string.h>
#include <libxml/parser.h>

#ifdef WINDOWS
#include "src/stdintwin.h"
#endif

#include "xsupgui.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"

#include "libxsupconfig/xsupconfig_parse.h"
#include "libxsupconfig/xsupconfig_parse_profile.h"
#include "libxsupconfig/xsupconfig_parse_connection.h"
#include "libxsupconfig/xsupconfig_parse_trusted_servers.h"
#include "libxsupconfig/xsupconfig_parse_devices.h"
#include "libxsupconfig/xsupconfig_defaults.h"
#include "libxsupconfwrite/xsupconfwrite_connection.h"

/**
 * \brief Generic call to delete configuration settings.
 *
 * \warning This call should never be used by an outside program.  (i.e. A program that 
 *          links this library.)
 *
 * @param[in] deletefrom   The command that we want to use to delete a block.  As an example,
 *                         if we wanted to delete something from the <Managed_Networks> block,
 *                         this value would be set to "Delete_Managed_Network_Config".
 * @param[in] searchtag   The name of the XML tag that the supplicant will be using to identify
 *                        the block to be deleted.  Adding to the example above, we would need
 *                        to set this value to OU in order to match the proper configuration
 *                        data in the Managed_Network configuration structures.
 * @param[in] searchitem   The value that will be used with the searchtag to determine the 
 *                         exact configuration block that we should delete.  So, if we wanted
 *                         to delete a <Managed_Network> block with an <OU> of foo, we would
 *                         set this value to foo.
 * @param[in] config_type   The configuration type to use.  (One of CONFIG_LOAD_GLOBAL, or CONFIG_LOAD_USER.)
 *
 * @param[in] force   Should we force the deletion of the item.  (That is, delete it even if it is still
 *                    referenced somewhere else in the config.)  This parameter can take three different
 *                    values.  TRUE, FALSE, and -1.  The -1 means that this parameter isn't relevant to the
 *                    request, and should be left out.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on error
 **/
int xsupgui_request_delete_some_conf(char *deletefrom, char *searchtag,
				     char *searchitem, uint8_t config_type,
				     int force)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	int err = 0;
	char *temp = NULL;
	char tempstr[10];

	if ((deletefrom == NULL) || (searchtag == NULL) || (searchitem == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_delete_some_conf;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) deletefrom, NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_delete_some_conf;
	}

	xsupgui_xml_common_convert_amp(searchitem, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) searchtag, (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_delete_some_conf;
	}
	free(temp);

	sprintf(tempstr, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *) "Config_Type", (xmlChar *) tempstr)
	    == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_delete_some_conf;
	}

	if (force >= 0) {
		sprintf((char *)&tempstr, "%d", force);
		if (xmlNewChild
		    (t, NULL, (xmlChar *) "Force",
		     (xmlChar *) tempstr) == NULL) {
			done = IPC_ERROR_CANT_CREATE_REQUEST;
			goto finish_delete_some_conf;
		}
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_delete_some_conf;
	}
	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto finish_delete_some_conf;
	}

	done = xsupgui_request_is_ack(retdoc);

 finish_delete_some_conf:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Free a string that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_str(char **data)
{
	if ((*data) == NULL)
		return REQUEST_SUCCESS;	// Nothing to do.

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 * \brief Free an int_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_int_enum(int_enum ** data)
{
	int i;
	int_enum *intenum;

	intenum = (*data);

	if (intenum == NULL)
		return REQUEST_SUCCESS;	// Nothing to do.

	i = 0;

	while (intenum[i].name != NULL) {
		if (intenum[i].name != NULL)
			free(intenum[i].name);
		if (intenum[i].desc != NULL)
			free(intenum[i].desc);

		i++;
	}

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 * \brief Free an int_config_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_int_config_enum(int_config_enum ** data)
{
	int i;
	int_config_enum *intenum;

	intenum = (*data);

	if (intenum == NULL)
		return REQUEST_SUCCESS;	// Nothing to do.

	i = 0;

	while (intenum[i].desc != NULL) {
		if (intenum[i].desc != NULL)
			free(intenum[i].desc);
		if (intenum[i].mac != NULL)
			free(intenum[i].mac);

		i++;
	}

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 * \brief Free a namedesc_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_namedesc_enum(namedesc_enum ** data)
{
	int i;
	namedesc_enum *ndenum;

	ndenum = (*data);
	if (ndenum == NULL)
		return REQUEST_SUCCESS;	// Nothing to do.

	i = 0;

	while (ndenum[i].name != NULL) {
		if (ndenum[i].desc == NULL)
			free(ndenum[i].desc);
		if (ndenum[i].name == NULL)
			free(ndenum[i].name);
		i++;
	}

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 * \brief Free a profile_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_profile_enum(profile_enum ** data)
{
	int i;
	profile_enum *penum;

	penum = (*data);
	if (penum == NULL)
		return REQUEST_SUCCESS;

	i = 0;

	while (penum[i].name != NULL) {
		if (penum[i].name != NULL)
			free(penum[i].name);
		i++;
	}

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 * \brief Free a conn_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_conn_enum(conn_enum ** data)
{
	int i = 0;
	conn_enum *cenum = NULL;

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
 * \brief Free an eap_enum that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_eap_enum(eap_enum ** data)
{
	int i;
	eap_enum *eenum;

	eenum = (*data);
	if (eenum == NULL)
		return REQUEST_SUCCESS;	// Nothing to do.

	i = 0;

	while (eenum[i].name != NULL) {
		if (eenum[i].name != NULL)
			free(eenum[i].name);
		i++;
	}

	free((*data));
	(*data) = NULL;

	return REQUEST_SUCCESS;
}

/**
 * \brief Free an ipinfo_type struct that was allocated by one of the request functions.
 *
 * @param[in] data  A double dereferenced pointer to the memory that was allocated by
 *                  one of the xsupgui_request_* functions.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_ip_info(ipinfo_type ** data)
{
	ipinfo_type *ipi;

	ipi = (*data);
	if (ipi == NULL)
		return REQUEST_SUCCESS;

	if (ipi->dns1 != NULL) {
		free(ipi->dns1);
		ipi->dns1 = NULL;
	}

	if (ipi->dns2 != NULL) {
		free(ipi->dns2);
		ipi->dns2 = NULL;
	}

	if (ipi->dns3 != NULL) {
		free(ipi->dns3);
		ipi->dns3 = NULL;
	}

	if (ipi->netmask != NULL) {
		free(ipi->netmask);
		ipi->netmask = NULL;
	}

	if (ipi->gateway != NULL) {
		free(ipi->gateway);
		ipi->gateway = NULL;
	}

	if (ipi->ipaddr != NULL) {
		free(ipi->ipaddr);
		ipi->ipaddr = NULL;
	}

	if ((*data) != NULL) {
		free((*data));
		(*data) = NULL;
	}

	return REQUEST_SUCCESS;
}

/**
 * \brief Request the entire "<Globals>" block from the configuration in the 
 *        supplicant's memory.
 *
 * @param[out] globals_config   A pointer to the buffer that will return a text
 *                              version of the current globals block in memory.
 *
 * \warning In extremely weird circumstances this call could return REQUEST_SUCCESS, but the
 *          value of globals is NULL.  The caller should check for this!!!!
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_get_globals_config(config_globals ** globals)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	struct config_globals *newg = NULL;
	int err = 0;

	if (globals == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	(*globals) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_get_globals;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Globals_Config", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_get_globals;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_globals;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_globals;
	}
	// We now have an XML document that contains the configuration information we want.  It will be
	// the <Globals> tag wrapper in a <Globals_Config> response tag.
	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_get_globals;
	}

	n = xsupgui_request_find_node(n->children, "Globals_Config");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_get_globals;
	}
	// Otherwise, we need to parse the data that is in the child node.
	xsupconfig_parse(n->children, global_and_network, OPTION_ANY_CONFIG,
			 (void **)&newg);
	if (newg == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_globals;
	}

	(*globals) = newg;

 finish_get_globals:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Get the "<Profile>" block for a single named profile.
 *
 * @param[in] config_type   Should we look in the system level, or user level config?
 * @param[in] prof_name   The name of the profile that we want to get the configuration
 *                        block for.
 * @param[out] prof_config   A pointer to a buffer that will return a text version 
 *                           of the requested profile in the supplicant's memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_get_profile_config(uint8_t config_type, char *prof_name,
				       config_profiles ** prof_config)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	struct config_profiles *newp = NULL;
	int err = 0;
	char *temp = NULL;
	char res[5];

	if ((prof_name == NULL) || (prof_config == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*prof_config) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_get_profile;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Profile_Config", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_get_profile;
	}

	xsupgui_xml_common_convert_amp(prof_name, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Name", (xmlChar *) temp) == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_profile;
	}
	free(temp);

	sprintf((char *)&res, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *) "Config_Type", (xmlChar *) res) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_profile;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_profile;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_profile;
	}
	// We now have an XML document that contains the configuration information we want.  It will be
	// the <Profile> tag wrapper in a <Profile_Config> response tag.
	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_get_profile;
	}

	n = xsupgui_request_find_node(n->children, "Profile_Config");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_get_profile;
	}

	n = xsupgui_request_find_node(n->children, "Profile");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_profile;
	}

	if (xsupconfig_defaults_create_profile(&newp) != 0) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_profile;
	}
	// Otherwise, we need to parse the data that is in the child node.
	xsupconfig_parse(n->children, profile, OPTION_ANY_CONFIG,
			 (void **)&newp);
	if (newp == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_profile;
	}

	(*prof_config) = newp;

 finish_get_profile:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Get the "<Connection>" block for a single named connection.
 *
 * \note The caller is expected to free the memory returned by **conn_config.
 *
 * @param[in] config_type   Should we look in the system level, or user level config?
 * @param[in] conn_name   The name of the connection that we want to get the 
 *                        configuration block for.
 * @param[out] conn_config   A pointer to a buffer that will return a text version
 *                           of the requested connection in the supplicant's memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_get_connection_config(uint8_t config_type, char *conn_name,
					  config_connection ** conn_config)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	struct config_connection *newc = NULL;
	int err = 0;
	char *temp = NULL;
	char res[5];

	if ((conn_name == NULL) || (conn_config == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*conn_config) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_get_connection;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Connection_Config", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_get_connection;
	}

	xsupgui_xml_common_convert_amp(conn_name, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Name", (xmlChar *) temp) == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_connection;
	}
	free(temp);

	sprintf((char *)&res, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *) "Config_Type", (xmlChar *) res) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_connection;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_connection;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_connection;
	}
	// We now have an XML document that contains the configuration information we want.  It will be
	// the <Globals> tag wrapper in a <Globals_Config> response tag.
	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_get_connection;
	}

	n = xsupgui_request_find_node(n->children, "Connection_Config");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_get_connection;
	}

	n = xsupgui_request_find_node(n->children, "Connection");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_connection;
	}

	if (xsupconfig_defaults_create_connection(&newc) != 0) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_connection;
	}
	// Otherwise, we need to parse the data that is in the child node.
	xsupconfig_parse(n->children, connection, OPTION_ANY_CONFIG,
			 (void **)&newc);
	if (newc == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_connection;
	}

	(*conn_config) = newc;

 finish_get_connection:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Get the "<Trusted_Server>" block for the single named interface.
 *
 * @param[in] config_type   Should we look in the system level configuration, or user level?
 * @param[in] servname   The name of the server that we want to get the 
 *                       configuration block for.
 * @param[out] int_config   A pointer to a buffer that will return a text version
 *                          of the requested interface in the supplicant's memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_get_trusted_server_config(uint8_t config_type,
					      char *servname,
					      config_trusted_server **
					      ts_config)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	void *temp = NULL, *temp2 = NULL;
	int err = 0;
	char res[5];

	if ((servname == NULL) || (ts_config == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*ts_config) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_get_ts;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Trusted_Server_Config", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_get_ts;
	}

	xsupgui_xml_common_convert_amp(servname, (char **)&temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Name", (xmlChar *) temp) == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_ts;
	}
	free(temp);

	sprintf((char *)&res, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *) "Config_Type", (xmlChar *) res) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_ts;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_ts;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_ts;
	}
	// We now have an XML document that contains the configuration information we want.
	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_get_ts;
	}

	n = xsupgui_request_find_node(n->children, "Trusted_Server_Config");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_get_ts;
	}
	// The temp/temp2 stuff below needs a little explaining.  Because of the way the config parser works, 
	// when you request a parse, you pass in the structure to the parent, and it returns the newly created
	// child node.   So, when we make the call to xsupconfig_parse, we need to pass in a 
	// struct config_trusted_servers, but the result will be a struct config_trusted_server.  So, we need
	// to create a temp variable that is the size of "struct config_trusted_servers", and save it's 
	// location, so that we can free it when we are done with xsupconfig_parse().  This is because the
	// value coming back will point to something different.  (If we don't track it, we will leak memory.)

	temp = malloc(sizeof(struct config_trusted_servers));
	if (temp == NULL) {
		done = REQUEST_FAILURE;
		goto finish_get_ts;
	}

	memset(temp, 0x00, sizeof(struct config_trusted_servers));
	temp2 = temp;

	// Otherwise, we need to parse the data that is in the child node.
	xsupconfig_parse(n->children, trusted_servers, OPTION_ANY_CONFIG,
			 &temp2);
	if (temp2 == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_ts;
	}

	free(temp);

	(*ts_config) = temp2;

 finish_get_ts:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Get the "<Interface>" block for a single named interface.
 * 
 * \note The caller is expected to free the memory returned by **int_config.
 *
 * @param[in] intname   The name of the interface that we want to get the 
 *                      configuration block for.
 * @param[out] int_config   A pointer to a buffer that will return a text version
 *                          of the requested interface in the supplicant's memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_get_interface_config(char *intname,
					 config_interfaces ** int_config)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	void *temp = NULL, *temp2 = NULL;
	int err = 0;

	if ((intname == NULL) || (int_config == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	(*int_config) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_get_int;
	}

	t = xmlNewChild(n, NULL, (xmlChar *) "Get_Interface_Config", NULL);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_get_int;
	}

	xsupgui_xml_common_convert_amp(intname, (char **)&temp);
	if (xmlNewChild(t, NULL, (xmlChar *) "Description", (xmlChar *) temp) ==
	    NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_int;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_int;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_get_int;
	}
	// We now have an XML document that contains the configuration information we want.
	n = xmlDocGetRootElement(retdoc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_get_int;
	}

	n = xsupgui_request_find_node(n->children, "Interface_Config");
	if (n == NULL) {
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_get_int;
	}
	// The temp/temp2 stuff below needs a little explaining.  Because of the way the config parser works, 
	// when you request a parse, you pass in the structure to the parent, and it returns the newly created
	// child node.   So, when we make the call to xsupconfig_parse, we need to pass in a 
	// struct config_trusted_servers, but the result will be a struct config_trusted_server.  So, we need
	// to create a temp variable that is the size of "struct config_trusted_servers", and save it's 
	// location, so that we can free it when we are done with xsupconfig_parse().  This is because the
	// value coming back will point to something different.  (If we don't track it, we will leak memory.)

	temp = malloc(sizeof(config_interfaces));
	if (temp == NULL) {
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_get_int;
	}

	memset(temp, 0x00, sizeof(config_interfaces));
	temp2 = temp;

	// Otherwise, we need to parse the data that is in the child node.
	xsupconfig_parse(n->children, devices, OPTION_ANY_CONFIG, &temp2);
	if (temp2 == NULL) {
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_int;
	}

	free(temp);

	(*int_config) = temp2;

 finish_get_int:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Set the connection configuration for a single connection.
 *
 * @param[in] conn_config   A pointer to a libxml2 version of the new connection 
 *                          configuration that we want to store in the 
 *                          supplicant's memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_set_connection_config(uint8_t config_type,
					  config_connection * conn_config)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	int err = 0;
	char temp[5];

	if (conn_config == NULL)
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL)
		return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_set_connection_config;
	}

	n = xmlNewChild(n, NULL, (xmlChar *) "Set_Connection_Config", NULL);
	if (n == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_set_connection_config;
	}

	t = xsupconfwrite_connection_create_tree(conn_config, config_type,
						 TRUE);
	if (t == NULL) {
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_set_connection_config;
	}

	if (xmlAddChild(n, t) == NULL) {
		done = IPC_ERROR_CANT_ADD_NODE;
		goto finish_set_connection_config;
	}

	sprintf((char *)&temp, "%d", config_type);
	if (xmlNewChild(n, NULL, (xmlChar *) "Config_Type", (xmlChar *) & temp)
	    == NULL) {
		done = IPC_ERROR_CANT_ADD_NODE;
		goto finish_set_connection_config;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS) {
		done = err;
		goto finish_set_connection_config;
	}
	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) {
		done = err;
		goto finish_set_connection_config;
	}

	done = xsupgui_request_is_ack(retdoc);

 finish_set_connection_config:
	if (doc)
		xmlFreeDoc(doc);
	if (retdoc)
		xmlFreeDoc(retdoc);

	return done;
}
