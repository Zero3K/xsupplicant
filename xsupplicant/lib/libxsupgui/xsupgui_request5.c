/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request5.c
 *
 * \author chris@open1x.org
 *
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
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfwrite/xsupconfwrite_globals.h"
#include "libxsupconfwrite/xsupconfwrite_profiles.h"
#include "libxsupconfwrite/xsupconfwrite_interface.h"
#include "libxsupconfwrite/xsupconfwrite_trusted_server.h"


/**
 * \brief Set the profile configuration for a single profile.
 *
 * @param[in] prof_config   A pointer to a libxml2 version of the new profile 
 *                          configuration that we want to store in the
 *                          supplicant's memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_set_profile_config(uint8_t config_type, config_profiles *prof_config)
{
  xmlDocPtr doc = NULL;
  xmlDocPtr retdoc = NULL;
  xmlNodePtr n = NULL, t = NULL;
  int done = REQUEST_SUCCESS;
  int err = 0;
  char res[5];

  if (prof_config == NULL) return IPC_ERROR_INVALID_PARAMETERS;

  doc = xsupgui_xml_common_build_msg();
  if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

  n = xmlDocGetRootElement(doc);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
      goto finish_set_profile_config;
    }

  n = xmlNewChild(n, NULL, (xmlChar *)"Set_Profile_Config", NULL);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_CREATE_REQUEST;
      goto finish_set_profile_config;
    }

  sprintf(res, "%d", config_type);
  if (xmlNewChild(n, NULL, (xmlChar *)"Config_Type", res) == NULL)
  {
	  done = IPC_ERROR_CANT_CREATE_REQUEST;
	  goto finish_set_profile_config;
  }

  t = xsupconfwrite_profile_create_tree(prof_config, config_type, TRUE);
  if (t == NULL)
  {
	  done = IPC_ERROR_CANT_CREATE_REQUEST;
	  goto finish_set_profile_config;
  }

  if (xmlAddChild(n, t) == NULL)
  {
	  done = IPC_ERROR_CANT_ADD_NODE;
	  goto finish_set_profile_config;
  }

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_set_profile_config;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_set_profile_config;
	}

	done = xsupgui_request_is_ack(retdoc); 

finish_set_profile_config:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Set the interface configuration for a single interface.
 *
 * @param[in] int_config   A pointer to a text version of the new interface
 *                         configuration that we want to store in memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_set_interface_config(config_interfaces *int_config)
{
  xmlDocPtr doc = NULL;
  xmlDocPtr retdoc = NULL;
  xmlNodePtr n = NULL, t = NULL;
  int done = REQUEST_SUCCESS;
  int err = 0;

  if (int_config == NULL) return IPC_ERROR_INVALID_PARAMETERS;

  doc = xsupgui_xml_common_build_msg();
  if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

  n = xmlDocGetRootElement(doc);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
      goto finish_set_interface_config;
    }

  n = xmlNewChild(n, NULL, (xmlChar *)"Set_Interface_Config", NULL);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_CREATE_REQUEST;
      goto finish_set_interface_config;
    }

  t = xsupconfwrite_interface_create_tree(int_config, TRUE);
  if (t == NULL)
  {
	  done = IPC_ERROR_UNSPEC_REQ_FAILURE;
	  goto finish_set_interface_config;
  }

  if (xmlAddChild(n, t) == NULL)
  {
	  done = IPC_ERROR_CANT_ADD_NODE;
	  goto finish_set_interface_config;
  }

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_set_interface_config;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_set_interface_config;
	}

	done = xsupgui_request_is_ack(retdoc); 

finish_set_interface_config:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Set the global variables configuration.
 *
 * @param[in] globals_config   A pointer to the text version of the new global
 *                             variables configuration that we want to store in
 *                             memory.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_TIMEOUT on timeout
 * \retval >299 on failure
 **/
int xsupgui_request_set_globals_config(config_globals *globals)
{
  xmlDocPtr doc = NULL;
  xmlDocPtr retdoc = NULL;
  xmlNodePtr n = NULL, t = NULL;
  int done = REQUEST_SUCCESS;
  int err = 0;

  if (globals == NULL) return IPC_ERROR_INVALID_PARAMETERS;

  doc = xsupgui_xml_common_build_msg();
  if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

  n = xmlDocGetRootElement(doc);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
      goto finish_set_globals_config;
    }

  n = xmlNewChild(n, NULL, (xmlChar *)"Set_Globals_Config", NULL);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_CREATE_REQUEST;
      goto finish_set_globals_config;
    }

  t = xsupconfwrite_globals_create_tree(globals, TRUE);
  if (t == NULL)
  {
	  done = IPC_ERROR_UNSPEC_REQ_FAILURE;
	  goto finish_set_globals_config;
  }

  if (xmlAddChild(n, t) == NULL)
  {
	  done = IPC_ERROR_CANT_ADD_NODE;
	  goto finish_set_globals_config;
  }

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_set_globals_config;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_set_globals_config;
	}

	done = xsupgui_request_is_ack(retdoc); 

finish_set_globals_config:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request a list of known trusted root CA (servers)
 *
 * @param[in] config_type   One (or both) of CONFIG_LOAD_GLOBAL (for system level configs) or CONFIG_LOAD_USER (for user level configs)
 * @param[out] servers   A structure that contains the list of known root CA servers.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_enum_trusted_servers(uint8_t config_type, trusted_servers_enum **servers)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL, x = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numsvrs = 0, i = 0, err = 0;
	trusted_servers_enum *svrs = NULL;
	char temp[5];

	if (servers == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	(*servers) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_trusted_servers;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Enum_Trusted_Servers", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_trusted_servers;
	}

	sprintf((char *)&temp, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *)"Config_Type", temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_trusted_servers;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_enum_trusted_servers;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_enum_trusted_servers;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_enum_trusted_servers;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Trusted_Servers_List");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_trusted_servers;
	}

	t = xsupgui_request_find_node(n->children, "Trusted_Servers_Count");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_trusted_servers;
	}

	content = xmlNodeGetContent(t);
	if ((content == NULL) || (strlen((char *)content) == 0))
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_trusted_servers;
	}

#ifdef REQUEST_DEBUG
	printf("%s trusted server(s) found!\n", content);
#endif
	if (content != NULL)
	{
		numsvrs = atoi((char *)content);

		if (content != NULL) xmlFree(content);
	}
	else
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_trusted_servers;
	}

	// Allocate memory for our return structure.
	svrs = malloc(sizeof(trusted_servers_enum)*(numsvrs+1));
	if (svrs == NULL) 
	{
#ifdef REQUEST_DEBUG
		printf("Couldn't allocate memory to return trusted servers data!\n");
#endif
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_trusted_servers;
	}

	// Clear the memory.
	memset(svrs, 0x00, (sizeof(trusted_servers_enum)*(numsvrs+1)));

	n = n->children;
	for (i=0; i <numsvrs; i++)
	{
		n = xsupgui_request_find_node(n, "Server");
		if (n == NULL)
		{
			if (svrs != NULL) free(svrs);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_trusted_servers;
		}

		x = xsupgui_request_find_node(n->children, "Server_Name");
		if (x == NULL) 
		{
			if (svrs != NULL) free(svrs);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_trusted_servers;
		}

		svrs[i].name = (char *)xmlNodeGetContent(x);

		x = xsupgui_request_find_node(n->children, "Config_Type");
		if (x == NULL)
		{
			if (svrs != NULL) free(svrs);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_trusted_servers;
		}

		content = xmlNodeGetContent(x);
		svrs[i].config_type = atoi(content);
		xmlFree(content);

		n = n->next;
	}

	(*servers) = svrs;
	done = REQUEST_SUCCESS;

finish_enum_trusted_servers:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;  
}

/**
 * \brief Free the memory for the list of known trusted root CA (servers)
 *
 * @param[in] servers   The structure that contains the list of known root CA servers
 *                      that we want to free.
 *
 * \retval >299 on failure
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_free_trusted_servers_enum(trusted_servers_enum **servers)
{
	int i = 0;
	trusted_servers_enum *svrs;

	svrs = (*servers);

	if (svrs == NULL) return REQUEST_SUCCESS;

	while (svrs[i].name != NULL)
	{
		free(svrs[i].name);
		svrs[i].name = NULL;
		i++;
	}

	free((*servers));

	(*servers) = NULL;

  return REQUEST_SUCCESS;
}

/**
 * \brief Request that the supplicant write the configuration it currently has in memory
 *        out to the disk.
 *
 * @param[in] config_type   The type of configuration that we want to write.  (Currently either CONFIG_LOAD_GLOBAL,
 *							or CONFIG_LOAD_USER.)
 * @param[in] filename   The filename that we wish to write the configuration to.  If this is NULL, then
 *                       the configuration file that the configuration was read from will be overwritten.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_write_config(uint8_t config_type, char *filename)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	int err = 0;
	char temp[5];

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_write_config;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Write_Config", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_write_config;
	}

	if (xmlNewChild(t, NULL, (xmlChar *)"Filename", (xmlChar *)filename) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_write_config;
	}

	sprintf((char *)&temp, "%d", config_type);
	if (xmlNewChild(t, NULL, (xmlChar *)"Config_Type", temp) == NULL)
	{
		done = IPC_ERROR_CANT_ADD_NODE;
		goto finish_write_config;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_write_config;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_write_config;
	}

	done = xsupgui_request_is_ack(retdoc);

finish_write_config:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Ask the supplicant to delete a profile from it's configuration in 
 *        memory.
 *
 * \note If you want this change to be perminant, you need to call the request
 *       to write the configuration to disk!
 *
 * @param[in] prof_name   The name of the profile that we want to delete from
 *                        the configuration in memory.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_delete_profile_config(uint8_t config_type, char *prof_name, int force)
{
	return xsupgui_request_delete_some_conf("Delete_Profile_Config", "Name", prof_name, config_type, force);
}

/**
 * \brief Ask the supplicant to delete a connection from it's configuration in
 *        memory.
 *
 * \note If you want this change to be perminant, you need to call the request
 *       to write the configuration to disk!
 *
 * @param[in] conn_name   The name of the connection that we want to delete from
 *                        the configuration in memory.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_delete_connection_config(uint8_t config_type, char *conn_name)
{
	return xsupgui_request_delete_some_conf("Delete_Connection_Config", "Name", conn_name, config_type, -1);
}

/**
 * \brief Ask the supplicant to delete an interface from it's configuration in
 *        memory.
 *
 * \note If you want this change to be perminant, you need to call the request
 *       to write the configuration to disk!
 *
 * @param[in] intname   The description of the interface that we want to delete
 *                      from the configuration in memory.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_delete_interface_config(char *intname)
{
	return xsupgui_request_delete_some_conf("Delete_Interface_Config", "Description", intname, CONFIG_LOAD_GLOBAL, -1);
}

/**
 * \brief Set information about a trusted server in to the supplicant's 
 *        configuration memory.
 *
 * \note This will not store the change to disk!  You need to request a write
 *       for that to happen.
 *
 * @param[in] tserver   The config_trusted_server structure that should be
 *                      stored in the configuration memory of the supplicant.
 *                      If the named trusted server already exists, it will be
 *                      overwritten.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_set_trusted_server_config(uint8_t config_type, config_trusted_server *tserver)
{
  xmlDocPtr doc = NULL;
  xmlDocPtr retdoc = NULL;
  xmlNodePtr n = NULL, t = NULL;
  int done = REQUEST_SUCCESS;
  int err = 0;
  char res[5];

  if (tserver == NULL) return IPC_ERROR_INVALID_PARAMETERS;

  doc = xsupgui_xml_common_build_msg();
  if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

  n = xmlDocGetRootElement(doc);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
      goto finish_set_trusted_server_config;
    }

  n = xmlNewChild(n, NULL, (xmlChar *)"Set_Trusted_Server_Config", NULL);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_CREATE_REQUEST;
      goto finish_set_trusted_server_config;
    }

  sprintf(res, "%d", config_type);
  if (xmlNewChild(n, NULL, (xmlChar *)"Config_Type", res) == NULL)
  {
	  done = IPC_ERROR_CANT_CREATE_REQUEST;
	  goto finish_set_trusted_server_config;
  }

  t = xsupconfwrite_trusted_server_create_tree(tserver, TRUE);
  if (t == NULL)
  {
	  done = IPC_ERROR_UNSPEC_REQ_FAILURE;
	  goto finish_set_trusted_server_config;
  }

  if (xmlAddChild(n, t) == NULL)
  {
	  done = IPC_ERROR_CANT_ADD_NODE;
	  goto finish_set_trusted_server_config;
  }

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_set_trusted_server_config;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_set_trusted_server_config;
	}

	done = xsupgui_request_is_ack(retdoc); 

finish_set_trusted_server_config:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Free the memory that was allocated for config globals.
 *
 * @param[in] globals   The structure that contains the globals that we want
 *                      to free the memory for.  After the function returns, 
 *                      this value should be set to NULL.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_free_config_globals(config_globals **globals)
{
	delete_config_globals(globals);

  return REQUEST_SUCCESS;
}

/**
 * \brief Free the memory that was allocated for the profile configuration.
 *
 * @param[in] profile   The structure that contains the profile that we want
 *                      to free the memory for.  After the function returns,
 *                      this value should be set to NULL.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_free_profile_config(config_profiles **profile)
{
	delete_config_profiles(profile);

  return REQUEST_SUCCESS;
}

/**
 * \brief Free the memory that was allocated for the connection configuration.
 *
 * @param[in] conn   The structure that contains the connection that we want
 *                   to free the memory for.  After the function returns, 
 *                   this value should be set to NULL.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_free_connection_config(config_connection **conn)
{
	delete_config_connections(conn);

  return REQUEST_SUCCESS;
}

/**
 * \brief Free the memory that was allocated for the interface configuration.
 *
 * @param[in] intf   The structure that contains the interface that we want
 *                   to free the memory for.  After this function returns,
 *                   this value should be set to NULL.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_free_interface_config(config_interfaces **intf)
{
	delete_config_interface(intf);

  return REQUEST_SUCCESS;
}

/**
 * \brief Free the memory that was allocated for the trusted server 
 *        configuration.
 *
 * @param[in] tserver   The structure that contains the trusted server
 *                      configuration that we want to free memory for.  After
 *                      this function returns, this value should be set to 
 *                      NULL.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_free_trusted_server_config(config_trusted_server **tserver)
{
	delete_config_trusted_server(tserver);

  return REQUEST_SUCCESS;
}

/**
 * \brief Request that the supplicant delete a trusted server from it's configuration
 *        memory.
 *
 * @param[in] tserver   The structure that contains the trusted server
 *                      configuration that we want to free memory for.  After
 *                      this function returns, this value should be set to 
 *                      NULL.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_delete_trusted_server_config(uint8_t config_type, char *servname, int force)
{
	return xsupgui_request_delete_some_conf("Delete_Trusted_Server_Config", "Name", servname, config_type, force);
}


