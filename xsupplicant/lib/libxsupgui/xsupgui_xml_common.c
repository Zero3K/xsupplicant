/**
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file xsupgui_xml_common.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <libxml/parser.h>

#ifndef WINDOWS
#include <stdint.h>
#endif				// WINDOWS

#include "xsupgui_xml_common.h"
#include "src/xsup_common.h"

#define CMD_VERSION  "1.0"

// Uncomment this to have debug information dumpped with
// printf()s.
//#define XML_COMMON_DEBUG  1

/**
 * \brief Build the XML "headers" for an IPC message.  
 *
 * This will basically create the XML header message, along with a root node that is called
 *  "<xsup_ipc>" with a version number as defined by CMD_VERSION.
 *
 *  The document root node should *NEVER* have any data defined in it!  It
 *  should only have child nodes!!  (So, any data would be ignored.)
 *
 * \retval ptr   A pointer to an XML "framework" that should be populated with messages to
 *               be sent to the supplicant.
 * \retval NULL   An error occurred.
 **/
xmlDocPtr xsupgui_xml_common_build_msg()
{
	xmlDocPtr doc = NULL;
	xmlNodePtr n = NULL;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc == NULL)
		return NULL;

	n = xmlNewNode(NULL, BAD_CAST "xsup_ipc");
	if (n == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}

	xmlNewProp(n, (xmlChar *) "Version", (xmlChar *) CMD_VERSION);
	xmlDocSetRootElement(doc, n);

	return doc;
}

/**
 * \brief Given a buffer full of XML text, convert it to an xmlDoc, and verifiy that
 *        it has the proper versioning information.
 *
 * @param[in] xmlbuf   A pointer to a character array that contains an XML file.
 * @param[in] buffersize   The size of the buffer that contains the XML document.
 *
 * \retval ptr   An xmlDocPtr that contains the structure of the XML document that was
 *               pointed to by xmlbuf.
 * \retval NULL   An error.
 **/
xmlDocPtr xsupgui_xml_common_validate_msg(xmlChar * xmlbuf, int buffersize)
{
	xmlDocPtr doc;
	xmlNodePtr n;
	xmlChar *prop;

	// Note: We're building a tree from an xmlChar * here... maybe it's better to use
	// xmlRecoverDoc instead?
	doc = xmlReadMemory((char *)xmlbuf, buffersize, "ipc.xml", NULL, 0);
	if (doc == NULL) {
#ifdef XML_COMMON_DEBUG
		printf("Bad document!\n");
#endif
		return NULL;
	}

	n = xmlDocGetRootElement(doc);
	if (n == NULL) {
#ifdef XML_COMMON_DEBUG
		printf("Couldn't find root node!\n");
#endif
		xmlFreeDoc(doc);
		return NULL;
	}

	prop = xmlGetProp(n, (xmlChar *) "Version");
	if (prop == NULL) {
#ifdef XML_COMMON_DEBUG
		printf("No version property found!\n");
#endif
		xmlFreeDoc(doc);
		return NULL;
	}

	if (strcmp((char *)prop, CMD_VERSION) != 0) {
		xmlFreeDoc(doc);
#ifdef XML_COMMON_DEBUG
		printf("Invalid version!  %s != %s!\n", CMD_VERSION, prop);
#endif
		free(prop);
		return NULL;
	}

	free(prop);
	return doc;
}

/**
 * \brief Search a string for "&" characters, and convert them to &amp; since libxml2 
 *        seems to have issues doing it.
 *
 * @param[in] instr   The original string that may contain the "&" characters.
 * @param[in,out] outstr   The new string that contains "&amp;" tags instead.
 *
 * \retval 1 if something was converted (outstr will be the converted string)
 * \retval 0 if nothing was converted (outstr will be a copy of the original string)
 * \retval -1 on error
 **/
int xsupgui_xml_common_convert_amp(char *instr, char **outstr)
{
	int numamps = 0;
	int i = 0;
	char *newstr = NULL;
	int newi = 0;

	if (instr == NULL) {
		(*outstr) = NULL;
		return 0;
	}

	for (i = 0; i < strlen(instr); i++) {
		if (instr[i] == '&')
			numamps++;
	}

	if (numamps == 0) {
		(*outstr) = _strdup(instr);
		return 0;
	}
	// Otherwise, we need to do some conversion, and add some extra space.
	newstr = Malloc(strlen(instr) + (numamps * 5));	// Will result in more than we need.
	if (newstr == NULL) {
		outstr = NULL;
		return -1;
	}

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

	return 1;
}
