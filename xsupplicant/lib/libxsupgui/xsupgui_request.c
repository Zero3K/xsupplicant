/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_request.c
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
#include "libxsupconfig/xsupconfig_structs.h"
#include "xsupgui_request.h"
#include "xsupgui_xml_common.h"

// Uncomment this to get printf() debug information.
//#define REQUEST_DEBUG  1

/**
 *  \brief Search through the node list, and find the node called 'nodename'.
 *
 *  @param[in] head   An xmlNodePtr to the head of the list of nodes to search.
 *  @param[in] nodename   The name of the node to locate. (Case sensative!)
 *
 *  \note This function should usually only be called from inside \ref xsupgui_request.c.
 **/
xmlNodePtr xsupgui_request_find_node(xmlNodePtr head, char *nodename)
{
	xmlNodePtr cur_node = NULL;

	if ((head == NULL) || (nodename == NULL)) return NULL;

	for (cur_node = head; cur_node; cur_node = cur_node->next)
	{
#if 0
		if (cur_node->type == XML_ELEMENT_NODE) 
			printf("Node Name : %s\n", cur_node->name);
#endif
		if ((cur_node->type == XML_ELEMENT_NODE) && (strcmp((char *)cur_node->name, nodename) == 0))
		{
			return cur_node;			
		}
	}

	return NULL;
}

/**
 *  \brief Send a request on a given interface that will result in a byte string.
 *
 *  @param[in] device   The OS specific name of the device to query.  When the
 *                      request isn't interface specific, this may be NULL.
 *  @param[in] request   A text version of the 'request' node that will be passed
 *                       to the supplicant back end.  (See IPC documentation.)
 *  @param[in] response   A text version of XML node that the 'response' will be
 *                        found in.  (See IPC documentation.)
 *  @param[in] response_key   A text version of the XML node that will contain the
 *                            response string.
 *  @param[out] result   The string value that the supplicant returned inside of the
 *                       'response_key' XML node.
 *
 *  \retval  REQUEST_SUCCESS on success
 *  \retval  REQUEST_TIMEOUT on timeout
 *  \retval  >299 on other error  (See error "#defines" in \ref xsupgui_request.h)
 **/
int xsupgui_request_get_byte_string(char *device, char *request, char *response, 
								   char *response_key, char **result)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	int done = 0, err;
	char *temp = NULL;

	if ((device == NULL) || (request == NULL) || (response == NULL))
		return REQUEST_FAILURE;

	(*result) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto get_some_bytestr_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)request, NULL);   
	if (t == NULL) 
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto get_some_bytestr_done;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto get_some_bytestr_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto get_some_bytestr_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto get_some_bytestr_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto get_some_bytestr_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	t = xsupgui_request_find_node(n, response);
	if (t == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_RESPONSE;
		goto get_some_bytestr_done;
	}

	// The interface will be included in the response, but it really doesn't matter
	// right now, so ignore it.
	t = xsupgui_request_find_node(t->children, response_key);
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto get_some_bytestr_done;
	}

	// Otherwise, we need to return the value of the state.
	(*result) = (char *)xmlNodeGetContent(t);
	done = REQUEST_SUCCESS;

get_some_bytestr_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);
	
	return done;
}

/**
 *  \brief Send a request on a given interface that will result in a long int.
 *
 *  @param[in] device   The OS specific name of the device to query.  When the
 *                      request isn't interface specific, this may be NULL.
 *  @param[in] request   A text version of the 'request' node that will be passed
 *                       to the supplicant back end.  (See IPC documentation.)
 *  @param[in] response   A text version of XML node that the 'response' will be
 *                        found in.  (See IPC documentation.)
 *  @param[in] response_key   A text version of the XML node that will contain the
 *                            response string.
 *  @param[out] result   A pointer to a long int that contains the value that was
 *                       returned in the tag specified by 'response_key'.
 *
 *  \retval  REQUEST_SUCCESS on success
 *  \retval  REQUEST_TIMEOUT on timeout
 *  \retval  >299 on other error  (See error "#defines" in \ref xsupgui_request.h)
 **/
int xsupgui_request_get_long_int(char *device, char *request, char *response, 
								 char *response_key, long int *result)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = 0, err = 0;
	char *temp = NULL;

	if ((device == NULL) || (request == NULL) || (response == NULL)
		|| (response_key == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQUEST;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_CREATE_REQ_HDR;
		goto get_some_longint_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)request, NULL);   
	if (t == NULL) 
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto get_some_longint_done;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto get_some_longint_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto get_some_longint_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto get_some_longint_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto get_some_longint_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	t = xsupgui_request_find_node(n, response);
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto get_some_longint_done;
	}

	// The interface will be included in the response, but it really doesn't matter
	// right now, so ignore it.
	t = xsupgui_request_find_node(t->children, response_key);
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto get_some_longint_done;
	}

	// Otherwise, we need to return the value of the state.
	content = xmlNodeGetContent(t);
	(*result) = atol((char *)content);
	done = REQUEST_SUCCESS;
	if (content != NULL) xmlFree(content);

get_some_longint_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);
	
	return done;
}

/**
 *  \brief Send a request on a given interface that will result in an integer between 0 and
 *         299.
 *
 *  @param[in] device   The OS specific name of the device to query.  When the
 *                      request isn't interface specific, this may be NULL.
 *  @param[in] state_request   A text version of the 'request' node that will be passed
 *                             to the supplicant back end.  (See IPC documentation.)
 *  @param[in] state_response   A text version of XML node that the 'response' will be
 *                              found in.  (See IPC documentation.)
 *  @param[in] response_key   A text version of the XML node that will contain the
 *                            response string.
 *  @param[out] result   The result value.
 *
 *  \retval  REQUEST_FAILURE on error
 *  \retval  REQUEST_SUCCESS on success
 *  \retval  REQUEST_TIMEOUT on timeout
 *  \retval  >299 on other error  (See error "#defines" in \ref xsupgui_request.h)
 **/
int xsupgui_request_get_some_value(char *device, char *state_request, char *state_response, 
								   char *response_key, int *result)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS, err;
	char *temp = NULL;

	if ((device == NULL) || (state_request == NULL) || (state_response == NULL) || 
		(response_key == NULL))
		return IPC_ERROR_INVALID_PARAMETERS;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL) 
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto get_some_value_done;
	}

	t = xmlNewChild(n, NULL, (xmlChar *)state_request, NULL);   
	if (t == NULL) 
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto get_some_value_done;
	}

	xsupgui_xml_common_convert_amp(device, &temp);
	if (xmlNewChild(t, NULL, (xmlChar *)"Interface", (xmlChar *)temp) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_INT_NODE;
		free(temp);
		goto get_some_value_done;
	}
	free(temp);

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto get_some_value_done;
	}

	// Otherwise, parse it and see if we got what we wanted.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto get_some_value_done;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto get_some_value_done;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;
	t = xsupgui_request_find_node(n, state_response);
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto get_some_value_done;
	}

	// The interface will be included in the response, but it really doesn't matter
	// right now, so ignore it.
	t = xsupgui_request_find_node(t->children, response_key);
	if (t == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto get_some_value_done;
	}

	// Otherwise, we need to return the value of the state.
	content = xmlNodeGetContent(t); 

	(*result) = atoi((char *)content);

	if (content != NULL) free(content);

get_some_value_done:
	if (doc != NULL) xmlFreeDoc(doc);
	if (retdoc != NULL) xmlFreeDoc(retdoc);
	
	return done;
}

/**
 *  \brief Verify the XML document returned isn't an error/deprecated message.
 *
 *  @param[in] indoc   An XML document that has been returned from the IPC call, and
 *                     parsed by the XML parser to create a document tree.
 *
 *  \retval  REQUEST_SUCCESS if it isn't an error/deprecated message.
 *  \retval  >299 on other error  (See error "#defines" in \ref xsupgui_request.h)
 *
 *  \note  The error messages contain an interface name.  However, in the current
 *            Xsupplicant implementation the caller will already know the interface 
 *            name that was quired, since the calls are synchronous.  So, for now,
 *            the interface name is ignored.
 **/
int xsupgui_request_check_exceptions(xmlDocPtr indoc)
{
	xmlNodePtr n = NULL, t = NULL, err = NULL;
	int done = REQUEST_SUCCESS;
	char *resval = NULL;

	if (indoc == NULL) return IPC_ERROR_NULL_DOCUMENT;

	// Find the root node.
	n = xmlDocGetRootElement(indoc);
	if (n == NULL) return IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = n->children;

	// See if we have an error block
	t = xsupgui_request_find_node(n, "Error");
	if (t == NULL)
	{
		// See if we have a deprecated block.
		t = xsupgui_request_find_node(n, "Deprecated");
	}

	if (t == NULL) return REQUEST_SUCCESS;   // Everything is good.

	err = xsupgui_request_find_node(t->children, "Error_Code");
	if (err == NULL) return IPC_ERROR_NO_ERROR_CODE;   // WTF!?  We didn't get an error code?

	resval = (char *)xmlNodeGetContent(err);
	if ((resval == NULL) || (strlen(resval) == 0))
		return IPC_ERROR_NO_ERROR_CODE;  // ACK we won't know what the error code is!

	done = atoi(resval);
	free(resval);

	return done;  
}

/**
 * \brief Take an XML document pointer, convert it to text, and send it
 *        across the communications media. 
 *
 * @param[in] indoc   An xmlDocPtr that contains the IPC request that
 *                    will be sent to the supplicant.
 * @param[out] outdoc   An xmlDocPtr that contains the response to the
 *                      IPC request specified by indoc.
 *
 * \retval REQUEST_SUCCESS   success
 * \retval REQUEST_TIMEOUT   request timed out
 * \retval >299   Error message was received.  (See error "#defines" in \ref xsupgui_request.h for
 *         more information.)
 **/
int xsupgui_request_send(xmlDocPtr indoc, xmlDocPtr *outdoc)
{
	xmlChar *docbuf          = NULL;
	int bufsize              = 0;
	unsigned char *resultbuf = NULL;
	int resbufsize           = 0;
	int err                  = 0;

	if (indoc == NULL) return IPC_ERROR_NULL_DOCUMENT;

	// Create a text representation of the document in memory.  Unformatted.
	xmlDocDumpFormatMemory(indoc, &docbuf, &bufsize, 0);
#ifdef REQUEST_DEBUG
	printf("Sending document : %s\n", docbuf);
#endif

	if (docbuf == NULL) return IPC_ERROR_NULL_REQUEST;

	err = xsupgui_send((unsigned char *)docbuf, bufsize, &resultbuf, &resbufsize);

	// We are done with docbuf.
	xmlFree(docbuf);

	if (err != REQUEST_SUCCESS)
	{
		if (resultbuf != NULL) free(resultbuf);
		return err;
	}

#ifdef REQUEST_DEBUG
	printf("Result document : %s\n", (char *)resultbuf);
#endif

	(*outdoc) = xsupgui_xml_common_validate_msg((xmlChar *)resultbuf, resbufsize);
	if ((*outdoc) == NULL) 
	{
#ifdef REQUEST_DEBUG
		printf("Invalid document!\n");
#endif
		if (resultbuf != NULL) free(resultbuf);
		return IPC_ERROR_NULL_RESPONSE;
	}

	if (resultbuf != NULL) free(resultbuf);
	return REQUEST_SUCCESS;
}

/**
 *  \brief Request that the supplicant send us a list of known interfaces from the OS, 
 *         and their descriptions.
 *
 *  \retval REQUEST_SUCCESS on success (retints will be populated, with a NULL set at the end.)
 *  \retval REQUEST_TIMEOUT on timeout (retints will contain nothing interesting)
 *  \retval >299 on other error (retints will contain nothing interesting)
 *
 *  \note The caller is expected to free the memory that '**retints' occupies.  As this
 *        data is returned as an array, the caller should be able to free((*retints)) and 
 *        be fine.
 **/
int xsupgui_request_enum_live_ints(int_enum **retints)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numints = 0, i = 0, err = 0;
	int_enum *ints = NULL;

	// Set their pointer to NULL in case they don't check the return value, and feed us
	// back an invalid pointer to free. :-/
	(*retints) = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_ints;
	}

	if (xmlNewChild(n, NULL, (xmlChar *)"Enum_Live_Interfaces", NULL) == NULL)
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
	n = xsupgui_request_find_node(n->children, "Interface_Live_List");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_ints;
	}

	t = xsupgui_request_find_node(n->children, "Interface_Count");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_ints;
	}

	content = xmlNodeGetContent(t);
	if (content == NULL)
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
	ints = malloc(sizeof(int_enum)*(numints+1));
	if (ints == NULL) 
	{
#ifdef REQUEST_DEBUG
		printf("Couldn't allocate memory to return interface data!\n");
#endif
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_ints;
	}

	// Clear the memory.
	memset(ints, 0x00, (sizeof(int_enum)*(numints+1)));

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

		t = xsupgui_request_find_node(n->children, "Interface_Name");
		if (t == NULL) 
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		ints[i].name = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Interface_Description");
		if (t == NULL)
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		ints[i].desc = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Interface_Is_Wireless");
		if (t == NULL)
		{
			if (ints != NULL) free(ints);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_ints;
		}

		content = xmlNodeGetContent(t);
		if (content == NULL)
		{
			ints[i].is_wireless = 0;
		}
		else
		{
			ints[i].is_wireless = atoi((char *)content);
			if (content != NULL) free(content);
		}

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
 *  \brief Request that the supplicant send us a list of known EAP methods, and their
 *         descriptions.
 *
 *  \retval REQUEST_SUCCESS on success (eaptypes will be populated, with a NULL set at the end.)
 *  \retval REQUEST_TIMEOUT on timeout (eaptypes will contain nothing interesting)
 *  \retval >299 on other error (eaptypes will contain nothing interesting)
 *
 *  \note The caller is expected to free the memory that '**eaptypes' occupies.  As this
 *        data is returned as an array, the caller should be able to free((*eaptypes)) and 
 *        be fine.
 **/
int xsupgui_request_enum_eap_methods(eap_enum **eaptypes)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr retdoc = NULL;
	xmlNodePtr n = NULL, t = NULL;
	xmlChar *content = NULL;
	int done = REQUEST_SUCCESS;
	int numints = 0, i = 0, err = 0;
	eap_enum *myeaps = NULL;

	doc = xsupgui_xml_common_build_msg();
	if (doc == NULL) return IPC_ERROR_CANT_CREATE_REQ_HDR;

	n = xmlDocGetRootElement(doc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_REQ_ROOT_NODE;
		goto finish_enum_eap_methods;
	}

	if (xmlNewChild(n, NULL, (xmlChar *)"Enum_EAP_Methods", NULL) == NULL)
	{
		done = IPC_ERROR_CANT_CREATE_REQUEST;
		goto finish_enum_eap_methods;
	}

	err = xsupgui_request_send(doc, &retdoc);
	if (err != REQUEST_SUCCESS)
	{
		done = err;
		goto finish_enum_eap_methods;
	}

	// Otherwise, parse it and see if we got what we wanted.

	// Check if we got errors.
	err = xsupgui_request_check_exceptions(retdoc);
	if (err != 0) 
	{
		done = err;
		goto finish_enum_eap_methods;
	}

	n = xmlDocGetRootElement(retdoc);
	if (n == NULL)
	{
		done = IPC_ERROR_CANT_FIND_RESP_ROOT_NODE;
		goto finish_enum_eap_methods;
	}

	// If we get here, then we know that the document passed the
	// validation tests imposed.  So, we need to see if we got the result 
	// we wanted.
	n = xsupgui_request_find_node(n->children, "EAP_Methods_List");
	if (n == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE;
		goto finish_enum_eap_methods;
	}

	t = xsupgui_request_find_node(n->children, "Number_Of_Methods");
	if (t == NULL) 
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_eap_methods;
	}

	content = xmlNodeGetContent(t);
	if (content == NULL)
	{
		done = IPC_ERROR_BAD_RESPONSE_DATA;
		goto finish_enum_eap_methods;
	}

#ifdef REQUEST_DEBUG
	printf("%s interface(s) found!\n", content);
#endif

	numints = atoi((char *)content);

	if (content != NULL) free(content);

	// Allocate memory for our return structure.
	myeaps = malloc(sizeof(eap_enum)*(numints+1));
	if (myeaps == NULL) 
	{
#ifdef REQUEST_DEBUG
		printf("Couldn't allocate memory to return interface data!\n");
#endif
		done = IPC_ERROR_CANT_ALLOCATE_MEMORY;
		goto finish_enum_eap_methods;
	}

	// Clear the memory.
	memset(myeaps, 0x00, (sizeof(eap_enum)*(numints+1)));

	n = n->children;
	for (i=0; i <numints; i++)
	{
		n = xsupgui_request_find_node(n, "EAP_Method");
		if (n == NULL) 
		{
			if (myeaps != NULL) free(myeaps);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_eap_methods;
		}

		t = xsupgui_request_find_node(n->children, "Method_Name");
		if (t == NULL) 
		{
			if (myeaps != NULL) free(myeaps);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_eap_methods;
		}

		myeaps[i].name = (char *)xmlNodeGetContent(t);

		t = xsupgui_request_find_node(n->children, "Method_Number");
		if (t == NULL)
		{
			if (myeaps != NULL) free(myeaps);
			done = IPC_ERROR_BAD_RESPONSE_DATA;
			goto finish_enum_eap_methods;
		}

		content = xmlNodeGetContent(t);
		if (content != NULL)
		{
			myeaps[i].num = atoi((char *)content);
			free(content);
		}
		else
		{
			myeaps[i].num = 0;
		}

		n = n->next;
	}

	(*eaptypes) = myeaps;
	done = REQUEST_SUCCESS;

finish_enum_eap_methods:
	if (doc) xmlFreeDoc(doc);
	if (retdoc) xmlFreeDoc(retdoc);

	return done;  
}

