/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request6.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupgui_request6.c,v 1.6 2007/10/20 06:14:53 galimorerpg Exp $
 * $Date: 2007/10/20 06:14:53 $
 **/

#include <string.h>
#include <libxml/parser.h>

#ifdef WINDOWS
#include "src/stdintwin.h"
#else
#define _strdup strdup
#endif // WINDOWS

#include "xsupgui.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"

#include "libxsupconfig/xsupconfig_parse.h"
#include "libxsupconfig/xsupconfig_parse_managed_networks.h"
#include "libxsupconfwrite/xsupconfwrite_managed_networks.h"

#include "src/xsup_common.h"


/**
 * \brief Request that the supplicant delete (from memory) the managed network 
 *        identified by ouname.
 *
 * @param[in] ouname   The name of the OU that we want to delete from our configuration.
 *
 * \retval REQUEST_FAILURE on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_delete_managed_network_config(char *ouname)
{
	return xsupgui_request_delete_some_conf("Delete_Managed_Network_Config", "OU", ouname, FALSE);
}

/**
 * \brief Request the full configuration for the "<Managed_Network>" block that 
 *        can be identified by the OU specified by ouname.
 *
 * @param[in] ouname   The name of the OU that we want to get the data for.
 * @param[out] mnconfig   A config_managed_networks structure that contains the values
 *                        for all of the settings for the requested OU.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_get_managed_network_config(char *ouname, config_managed_networks **mnconfig)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	struct config_managed_networks *newn = NULL;
	int err = 0;
	char *temp = NULL;

	if ((ouname == NULL) || (mnconfig == NULL)) return IPC_ERROR_INVALID_PARAMETERS;

	(*mnconfig) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_get_managed_nets_conf;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Get_Managed_Network_Config", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_get_managed_nets_conf;
	}

	xsupgui_xml_common_convert_amp(ouname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"OU", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto finish_get_managed_nets_conf;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_get_managed_nets_conf;
	}

	err = xsupgui_request_check_exceptions(retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_get_managed_nets_conf;
	}

	// We now have an XML document that contains the configuration information we want.  It will be
	// the <Managed_Network> tag wrapped in a <Managed_Network_Config> response tag.
	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_get_managed_nets_conf;
	}

	n = xsupgui_request_find_node(n->children, "Managed_Network_Config");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_get_managed_nets_conf;
	}

	// Otherwise, we need to parse the data that is in the child node.
	xsupconfig_parse(n->children, managed_networks, (void **)&newn);
	if (newn == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_get_managed_nets_conf;
	}

	(*mnconfig) = newn;

finish_get_managed_nets_conf:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request that a new configuration be created, or that an existing configuration
 *        be updated.  The decision to create or update will be based on the OU field
 *        in the structure matching an existing OU.
 *
 * @param[in] mnconfig   A managed network configuration structure that we want the
 *                       supplicant to update in memory.  
 *
 * \warning This function will *NOT* write the configuration file.  If you want the file
 *          written you will need to make another call.
 *
 * \retval >299 on failure
 * \retval REQUEST_TIMEOUT on timeout
 * \retval REQUEST_SUCCESS on success
 **/
int xsupgui_request_set_managed_network_config(config_managed_networks *mnconfig)
{
  xmlDocPtr doc = NULL;
  xmlDocPtr retdoc = NULL;
  xmlNodePtr n = NULL, t = NULL;
  int done = REQUEST_SUCCESS;
  int err = 0;

  if (mnconfig == NULL) return IPC_ERROR_INVALID_PARAMETERS;

  doc = xsupgui_xml_common_build_msg();
  if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

  n = xmlDocGetRootElement(doc);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
      goto finish_set_managed_network_config;
    }

  n = xmlNewChild(n, NULL, (xmlChar *)"Set_Managed_Network_Config", NULL);
  if (n == NULL)
    {
      done = IPC_ERROR_CANT_CREATE_REQUEST;
      goto finish_set_managed_network_config;
    }

  t = xsupconfwrite_managed_network_create_tree(mnconfig, TRUE);
  if (t == NULL)
  {
	  done = IPC_ERROR_UNSPEC_REQ_FAILURE;
	  goto finish_set_managed_network_config;
  }

  if (xmlAddChild(n, t) == NULL)
  {
	  done = IPC_ERROR_CANT_ADD_NODE;
	  goto finish_set_managed_network_config;
  }

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_set_managed_network_config;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_set_managed_network_config;
	}

	done = xsupgui_request_is_ack(retdoc); 

finish_set_managed_network_config:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;
}

/**
 *  \brief Request that the supplicant send us a list of known interfaces from the  
 *         configuration file, and their descriptions.
 *
 *  \retval >299 on error (retints will contain nothing interesting)
 *  \retval REQUEST_SUCCESS on success (retints will be populated, with a NULL set at the end.)
 *  \retval REQUEST_TIMEOUT on timeout (retints will contain nothing interesting)
 *
 *  \note The caller is expected to free the memory that '**retints' occupies.  As this
 *        data is returned as an array, the caller should be able to free((*retints)) and 
 *        be fine.
 **/
int xsupgui_request_enum_ints_config(int_config_enum **retints)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numints = 0, i = 0, err = 0;
	int_config_enum *ints = NULL;

	if (retints == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	(*retints) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_ints;
	}

	if (xmlNewChild(n, NULL, (xmlChar *)"Enum_Config_Interfaces", NULL) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_ints;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_enum_ints;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_enum_ints;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_enum_ints;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Interface_Config_List");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_ints;
	}

	t = xsupgui_request_find_node(n->children, "Interface_Count");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_ints;
	}

	content = xmlNodeGetContent(t);
	if ((content == NULL) || (strlen((char *)content) == 0))
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_ints;
	}

#ifdef REQUEST_DEBUG
	printf("%s interface(s) found!\n", content);
#endif
	if (content != NULL)
	{
		numints = atoi((char *)content);

		if (content != NULL) free(content);
	}
	else
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_ints;
	}

	// Allocate memory for our return structure.
	ints = malloc(sizeof(int_config_enum)*(numints+1));
	if (ints == NULL) 
	{
#ifdef REQUEST_DEBUG
		printf("Couldn't allocate memory to return interface data!\n");
#endif
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_ints;
	}

	// Clear the memory.
	memset(ints, 0x00, (sizeof(int_config_enum)*(numints+1)));

	n = n->children;
	for (i=0; i <numints; i++)
	{
		n = xsupgui_request_find_node(n, "Interface");
		if (n == NULL) 
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		t = xsupgui_request_find_node(n->children, "Interface_MAC");
		if (t == NULL) 
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		ints[i].mac = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Interface_Description");
		if (t == NULL)
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		ints[i].desc = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Is_Wireless");
		if (t == NULL)
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		content = xmlNodeGetContent(t);
		if (strcmp((char *)content, "YES") == 0)
		{
			ints[i].is_wireless = TRUE;
		}
		else
		{
			ints[i].is_wireless = FALSE;
		}

		xmlFree(content);

		t = xsupgui_request_find_node(n->children, "Default_Connection");
		if (t == NULL)
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		content = xmlNodeGetContent(t);
		if ((content == NULL) || (strlen((char *)content) == 0))
		{
			ints[i].default_connection = NULL;
		}
		else
		{
			ints[i].default_connection = _strdup((char *)content);
		}

		xmlFree(content);

		n = n->next;
	}

	(*retints) = ints;
	done = REQUEST_SUCCESS;

finish_enum_ints:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;  
}

/**
 * \brief Request that the supplicant list all of the known SSIDs in it's SSID
 *        cache.
 *
 * \note This function will return the scan cache of the supplicant for a given
 *       interface.  The scan cache will likely have duplicate entries if more 
 *       that one AP is broadcasting the same SSID. 
 *
 * @param[in] device   The OS specific device name that we want to query the 
 *                     scan cache for.
 * @param[out] ssids   An array of ssid_info_enum that will contain the name
 *                     of an SSID, and any associated info.
 *
 *  \retval >299 on error (retints will contain nothing interesting)
 *  \retval REQUEST_SUCCESS on success (retints will be populated, with a NULL set at the end.)
 *  \retval REQUEST_TIMEOUT on timeout (retints will contain nothing interesting)
 **/ 
int xsupgui_request_enum_ssids(char *device, ssid_info_enum **ssids)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numssids = 0, i = 0, err = 0;
	ssid_info_enum *ssidarray = NULL;
	char *temp = NULL;

	if ((device == NULL) || (ssids == NULL)) return IPC_ERROR_INVALID_PARAMETERS;

	(*ssids) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_ssids;
	}

	n = xmlNewChild(n, NULL, (xmlChar *)"Enum_Known_SSIDs", NULL);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_ssids;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(n, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto finish_enum_ssids;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_enum_ssids;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_enum_ssids;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_enum_ssids;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Known_SSID_List");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_ssids;
	}

	t = xsupgui_request_find_node(n->children, "SSIDs_Count");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_ssids;
	}

	content = xmlNodeGetContent(t);
	if (content == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_ssids;
	}

#ifdef REQUEST_DEBUG
	printf("%s SSID(s) found!\n", content);
#endif
	if (content != NULL)
	{
		numssids = atoi((char *)content);

		if (content != NULL) free(content);
	}
	else
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_ssids;
	}

	// Allocate memory for our return structure.
	ssidarray = malloc(sizeof(ssid_info_enum)*(numssids+1));
	if (ssidarray == NULL) 
	{
#ifdef REQUEST_DEBUG
		printf("Couldn't allocate memory to return SSID data!\n");
#endif
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_ssids;
	}

	// Clear the memory.
	memset(ssidarray, 0x00, (sizeof(ssid_info_enum)*(numssids+1)));

	n = n->children;
	for (i=0; i <numssids; i++)
	{
		n = xsupgui_request_find_node(n, "SSID");
		if (n == NULL) 
		{
			if (ssidarray != NULL) free(ssidarray);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ssids;
		}

		t = xsupgui_request_find_node(n->children, "SSID_Name");
		if (t == NULL) 
		{
			if (ssidarray != NULL) free(ssidarray);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ssids;
		}

		ssidarray[i].ssidname = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "SSID_Abilities");
		if (t == NULL)
		{
			if (ssidarray != NULL) free(ssidarray);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ssids;
		}

		content = xmlNodeGetContent(t);
		ssidarray[i].abil = atoi((char *)content);
		xmlFree(content);

		t = xsupgui_request_find_node(n->children, "Signal_Strength");
		if (t == NULL)
		{
			if (ssidarray != NULL) free(ssidarray);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ssids;
		}

		content = xmlNodeGetContent(t);
		ssidarray[i].percentage = atoi((char *)content);
		xmlFree(content);

		n = n->next;
	}

	(*ssids) = ssidarray;
	done = REQUEST_SUCCESS;

finish_enum_ssids:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;  
}

/**
 * \brief Free the memory used by the SSID enum structure.
 *
 * @param[in] ssids   The array of SSID enum data that we want to free
 *                    the memory from.
 *
 * \retval REQUEST_SUCCESS on success
 * \retval REQUEST_FAILURE on failure
 **/
int xsupgui_request_free_ssid_enum(ssid_info_enum **ssids)
{
	int i = 0;
	ssid_info_enum *ssid;

	ssid = (*ssids);

  if (!ssid)
    return REQUEST_SUCCESS;
	while (ssid[i].ssidname != NULL)
	{
		free(ssid[i].ssidname);

		i++;
	}

	free((*ssids));

	return REQUEST_SUCCESS;
}

/**
 * \brief Request that the supplicant start a new scan.
 *
 * \warning If this request is for an active scan, the user
 *          will be disconnected from the current wireless 
 *          network.  However, a passive scan may not be possible
 *          depending on the platform in use.  (And attempting
 *          to do a passive scan may not return an error, depending
 *          on the OS.)
 *
 * @param[in] devname   The OS specific device name that we want to start the 
 *                      scan on.
 * @param[in] passive   A TRUE or FALSE value indicating if we would like to
 *                      initiate a passive scan.  If this is set to TRUE, and
 *                      there is a way to trap an error from the OS that 
 *                      indicates that it can't do a passive scan, an error will
 *                      be returned.  Right now, Linux doesn't seem able to trap
 *                      an error, and will initiate an active scan.
 *
 * \retval >299 the request to the supplicant failed, if passive == TRUE, then you
 *                         may want to consider calling this function again with passive == FALSE.
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded.
 **/
int xsupgui_request_wireless_scan(char *devname, uint8_t passive)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	char tempstatic[100];
	int done = REQUEST_SUCCESS;
	int err = 0;
	char *temp = NULL;

	if (devname == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_wireless_scan;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Wireless_Scan", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_wireless_scan;
	}

	xsupgui_xml_common_convert_amp(devname, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto finish_wireless_scan;
	}
	free(temp);

	sprintf((char *)&tempstatic, "%d", passive);
	if (xmlNewChild(t, NULL, (xmlChar *)"Passive", (xmlChar *)tempstatic) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_wireless_scan;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_wireless_scan;
	}

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_wireless_scan;
	}

	done = xsupgui_request_is_ack(retdoc);

finish_wireless_scan:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Request that the supplicant send us version information.
 *
 * @param[out] verstr   The version string for the running supplicant.
 * @param[out] errcode   An error code that indicates what went wrong.
 *
 * \retval >299 the request to the supplicant failed
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded
 **/
int xsupgui_request_version_string(char **verstr)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = REQUEST_SUCCESS;
	int err = 0;

	if (verstr == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	(*verstr) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Get_Version_String", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Version_String");
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESPONSE;
		goto finish;
	}

	(*verstr) = (char *)xmlNodeGetContent(n);

	if (((*verstr) == NULL) || (strlen((*verstr)) == 0))
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
	}

	done = REQUEST_SUCCESS;

finish:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Return an array of root CA certificates.
 *
 * @param[in,out] casa   An array of root CA certificates.  The final element in the 
 *                       array will be NULL.
 *
 * \retval REQUEST_FAILURE the request to the supplicant failed
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded
 **/
int xsupgui_request_enum_root_ca_certs(cert_enum **casa)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL, b = NULL;
	int done = REQUEST_SUCCESS;
	int err = 0;
	int i = 0;
	int numcerts = 0;
	char *value = NULL;
	cert_enum *cas = NULL;

	if (casa == NULL) return IPC_ERROR_INVALID_PARAMETERS;

	(*casa) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Enum_Root_CA_Certs", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish;
	}

	n = xsupgui_request_find_node(n->children, "Root_CA_Certs_Enum");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "Number_Of_Certs");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish;
	}

	value = (char *)xmlNodeGetContent(n);

	if ((value == NULL) || (strlen(value) == 0))
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish;
	}

	numcerts = atoi(value);

	cas = (cert_enum *)Malloc((sizeof(cert_enum) * (numcerts+1)));
	if (cas == NULL)
	{
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish;
	}

	n = xsupgui_request_find_node(n, "Certificates");
	if (n == NULL)
	{
		free(cas);
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish;
	}

	n = n->children;

	for (i = 0; i < numcerts; i++)
	{
		t = xsupgui_request_find_node(n, "Certificate");
		if (t == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		t = t->children;

		b = xsupgui_request_find_node(t, "Store_Type");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].storetype = NULL;   // Which shouldn't EVER happen!
		}
		else
		{
			cas[i].storetype = value;
		}

		b = xsupgui_request_find_node(t, "Name");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].certname = NULL;
		}
		else
		{
			cas[i].certname = value;
		}

		b = xsupgui_request_find_node(t, "Friendly_Name");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].friendlyname = NULL;
		}
		else
		{
			cas[i].friendlyname = value;
		}

		b = xsupgui_request_find_node(t, "Issuer");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].issuer = NULL;
		}
		else
		{
			cas[i].issuer = value;
		}

		b = xsupgui_request_find_node(t, "CommonName");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].commonname = NULL;
		}
		else
		{
			cas[i].commonname = value;
		}

		b = xsupgui_request_find_node(t, "Location");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].location = NULL;
		}
		else
		{
			cas[i].location = value;
		}

		b = xsupgui_request_find_node(t, "Month");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].month = 0;
		}
		else
		{
			cas[i].month = atoi(value);
		}
		xmlFree(value);

		b = xsupgui_request_find_node(t, "Day");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].day = 0;
		}
		else
		{
			cas[i].day = atoi(value);
		}
		xmlFree(value);

		b = xsupgui_request_find_node(t, "Year");
		if (b == NULL)
		{
			free(cas);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish;
		}

		value = (char *)xmlNodeGetContent(b);

		if ((value == NULL) || (strlen(value) == 0))
		{
			cas[i].year = 0;
		}
		else
		{
			cas[i].year = atoi(value);
		}
		xmlFree(value);

		n = n->next;
	}

	(*casa) = cas;

finish:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}

/**
 * \brief Free the memory that was allocated to store the certificate enumeration.
 *
 * @param[in] numcas   The number of CAs that are represented in the enumeration.
 * @param[in] cas   The array of CA names.
 **/
void xsupgui_request_free_cert_enum(cert_enum **cas)
{
	cert_enum *casa = NULL;
	int i = 0;

	casa = (*cas);

	if (casa == NULL) return;

	while (casa[i].certname != NULL)
	{
		if (casa[i].certname != NULL) free(casa[i].certname);
		i++;
	}

	free((*cas));
	(*cas) = NULL;
}

/**
 * \brief Free all of the fields that are included in a cert_info structure.
 *
 * @param[in] cinfo   A pointer to the structure that we want to free the members of.
 **/
void xsupgui_request_free_cert_info(cert_info **incinfo)
{
	cert_info *cinfo = NULL;

	cinfo = (*incinfo);

	if (cinfo->C) free(cinfo->C);
	if (cinfo->CN) free(cinfo->CN);
	if (cinfo->O) free(cinfo->O);
	if (cinfo->L) free(cinfo->L);
	if (cinfo->OU) free(cinfo->OU);
	if (cinfo->S) free(cinfo->S);

	free((*incinfo));
}

/**
 * \brief Request the detailed information about a specific certificate.
 *
 * @param[in] storetype   The store type that we should be looking in.
 * 
 * @param[in] location   The location of the data in the store defined by the
 *                       storetype parameter.
 *
 * @param[in,out] cinfo   The structure that will contain the detailed 
 *                        information about the certificate.
 *
 * \retval REQUEST_FAILURE the request to the supplicant failed
 * \retval REQUEST_TIMEOUT the request timed out
 * \retval REQUEST_SUCCESS the request succeeded
 **/
int xsupgui_request_ca_certificate_info(char *storetype, char *location, cert_info **outcinfo)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int err = 0;
	int done = REQUEST_SUCCESS;
	char *temp = NULL;
	cert_info *cinfo = NULL;

	(*outcinfo) = NULL;

	if ((storetype == NULL) || (location == NULL)) return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)"Get_Certificate_Info", NULL);
	if (t == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto done;
	}

	xsupgui_xml_common_convert_amp(storetype, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Store_Type", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto done;
	}
	free(temp);

	xsupgui_xml_common_convert_amp(location, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Location", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		free(temp);
		goto done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto done;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, "Certificate_Info");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto done;
	}

	n = xsupgui_request_find_node(n->children, "Certificate");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	n = n->children;

	n = xsupgui_request_find_node(n, "O");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	cinfo = (cert_info *)malloc(sizeof(cert_info));
	if (cinfo == NULL)
	{
		done = IPC_ERROR_MALLOC;
		goto done;
	}

	cinfo->O = (char *)xmlNodeGetContent(n);

	n = xsupgui_request_find_node(n, "OU");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	cinfo->OU = (char *)xmlNodeGetContent(n);

	n = xsupgui_request_find_node(n, "S");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	cinfo->S = (char *)xmlNodeGetContent(n);

	n = xsupgui_request_find_node(n, "C");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	cinfo->C = (char *)xmlNodeGetContent(n);

	n = xsupgui_request_find_node(n, "CN");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	cinfo->CN = (char *)xmlNodeGetContent(n);

	n = xsupgui_request_find_node(n, "L");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto done;
	}

	cinfo->L = (char *)xmlNodeGetContent(n);

	(*outcinfo) = cinfo;

done:
	xmlFreeDoc(doc);
	xmlFreeDoc(retdoc);

	return done;
}



