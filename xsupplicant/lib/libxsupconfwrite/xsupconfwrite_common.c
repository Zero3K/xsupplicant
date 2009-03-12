/**
 * Implementation of functions that are useful in various places of the 
 * xsupconfwrite library.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_common.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <libxml/parser.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "src/xsup_common.h"

// Uncomment below for debug output
// #define XSUPCONFWRITE_COMMON_DEBUG 1

/**
 * \brief Create a new node with a content if the sibling variable is NULL, or
 *        if it is non-NULL, create the bottom most sibling node.
 *
 * @param[in] sibling   An xmlNodePtr to a node in the list that we want to 
 *                      add a sibling to.
 * @param[in] name   The name of the node that we are adding to the list.
 * @param[in] content   The content for the node we are creating.
 *
 * \retval NULL on error
 * \retval ptr to the newly created node on success
 **/
xmlNodePtr xsupconfwrite_common_newSibling(xmlNodePtr sibling, char *name,
					   char *content)
{
	xmlNodePtr retnode = NULL;

	if (name == NULL)
		return NULL;

	retnode = xmlNewNode(NULL, (xmlChar *) name);
	if (retnode == NULL) {
#ifdef XSUPCONFWRITE_COMMON_DEBUG
		printf("Couldn't create new node node for <%s>!\n", name);
#endif
		return NULL;
	}

	xmlNodeAddContent(retnode, (xmlChar *) content);

	if (sibling == NULL)
		return retnode;

	if (xmlAddSibling(sibling, retnode) == NULL) {
#ifdef XSUPCONFWRITE_COMMON_DEBUG
		printf("Couldn't add new node as a sibling!\n");
#endif
		xmlFreeNode(retnode);
		return NULL;
	}

	return retnode;
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
int xsupconfwrite_convert_amp(char *instr, char **outstr)
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

/**
 * \brief Write a yes/no value to an XML tree node
 *
 * @param[in] xmlNode   An XML node pointer that we want to add a sibling to.
 * @param[in] nodeName   The name of the XML node that we want to add
 * @param[in] yesno		A boolean value that indicates if we should write a yes or no.
 * @param[in] defaultval   A boolean value that indicates what the default value should be.
 * @param[in] force_write   A boolean value that indicates if we should write the value even if it is default.
 * @param[in] sibling   Should this be a sibling or child node?
 *
 * \retval NULL on error otherwise an updated xmlNodePtr value.
 **/
xmlNodePtr xsupconfwrite_common_write_bool(xmlNodePtr xmlNode, char *nodeName,
					   int yesno, int defaultval,
					   int forcewrite, int sibling)
{
	if (yesno > 0)
		yesno = TRUE;

	if ((forcewrite != FALSE) || (yesno != defaultval)) {
		if (yesno != FALSE)	// This needs to be a test against FALSE since TRUE is any value > 0.
		{
			if (sibling == TRUE) {
				if (xsupconfwrite_common_newSibling
				    (xmlNode, nodeName, "yes") == NULL)
					return NULL;
			} else {
				if (xmlNewChild
				    (xmlNode, NULL, (xmlChar *) nodeName,
				     (xmlChar *) "yes") == NULL)
					return NULL;
			}
		} else {
			if (sibling == TRUE) {
				if (xsupconfwrite_common_newSibling
				    (xmlNode, nodeName, "no") == NULL) {
					return NULL;
				}
			} else {
				if (xmlNewChild
				    (xmlNode, NULL, (xmlChar *) nodeName,
				     (xmlChar *) "no") == NULL)
					return NULL;
			}
		}
	}

	return xmlNode;
}
