/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_common.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfig_common.c,v 1.4 2007/10/20 08:10:12 galimorerpg Exp $
 * $Date: 2007/10/20 08:10:12 $
 **/

#include <stdio.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "xsupconfig.h"
#include "xsupconfig_parse.h"
#include "xsupconfig_common.h"
#include "src/error_prequeue.h"
#include "src/xsup_debug.h"

/**
 * \brief Convert a string in to the uppercase version of the string.
 *
 * @param[in,out] strtoconvert   The mixed case string that will be converted to
 *                               all uppercase.
 **/
void xsupconfig_common_upcase(char *strtoconvert)
{
  int i;

  for (i=0;i<strlen(strtoconvert);i++)
    {
      strtoconvert[i] = toupper(strtoconvert[i]);
    }
}

/**
 * \brief Take a string that says either "yes" or "no" and convert it
 *        to a true or false value.  
 *
 * @param[in] yesno   A string that should contain either a "yes" or "no" value.
 *
 * \retval 1 if the value is yes
 * \retval 0 if the value is no
 * \retval 2 if it doesn't appear to be either.
 **/
uint8_t xsupconfig_common_yesno(char *yesno)
{
  xsupconfig_common_upcase(yesno);

  if (strcmp(yesno, "YES") == 0)  return 1;
  if (strcmp(yesno, "NO") == 0)  return 0;

  return 2;
}

/**
 * \brief Return a number based on the text value of a string.
 *
 * @param[in] list_choices   A structure that contains strings to match, and
 *                           numeric values to return when those strings are
 *                           matched.
 *
 * @param[in] request   The string that we want to look for a match for in
 *                      list_choices.
 *
 * \retval int   An integer value from a multichoice structure that matches the
 *               string passed in by request.
 **/
int xsupconfig_common_select_from_list(multichoice list_choices[], 
				       char *request)
{
  int i = 0;

  while ((list_choices[i].text != NULL) && (strcmp(list_choices[i].text,
						   request) != 0))
    {
      i++;
    }

  return list_choices[i].value;
}

/**
 * \brief Verify that a string contains only '0' through '9'.
 *
 * @param[in] number   The string to verify represents a number.
 *
 * \retval 0 if string isn't all numbers
 * \retval 1 if string is all numbers
 **/
uint8_t xsupconfig_common_is_number(char *number)
{
  int i;

  for (i=0; i < strlen(number); i++)
    {
      if ((number[i] < '0') || (number[i] > '9')) return 0;
    }

  return 1;
}

/**
 *  \brief A dummy function used in EAP methods to keep us from screaming about the already
 *         consumed node.  (Usually a <Type> tag.)
 *
 * @param[in] attr   A pointer to the structure that should be manipulated.
 * @param[in] node   The node that we are currently parsing.
 *
 * \retval attr  The same value that was passed in as attr.
 **/
void *xsupcommon_do_nothing(void **attr, xmlNodePtr node)
{
	return (*attr);
}

/**
 * \brief Allocate memory to store a new EAP method.
 *
 * @param[in] mymeth   A pointer to the head of the EAP method list.
 * @param[in] eaptype   A string that identifies the EAP method being allocated.
 *
 * \retval NULL on error
 * \retval ptr to the newly created structure.
 **/
struct config_eap_method *xsupconfig_alloc_method(struct config_eap_method *mymeth,
						  char *eaptype)
{
  struct config_eap_method *meth, *cur;

  meth = malloc(sizeof(struct config_eap_method));
  if (meth == NULL)
    {
      printf("Couldn't allocate memory to store method %s."
	     "  (At line %ld)\n", eaptype,
	     xsupconfig_parse_get_line_num());
      exit(2);
    }

  memset(meth, 0x00, sizeof(struct config_eap_method));

  if (mymeth == NULL)
    {
		return meth;
    }

  cur = mymeth;

  while (cur->next != NULL) cur = cur->next;

  cur->next = meth;

  return meth;
}

/**
 * \brief Convert a character to a binary nibble.
 *
 * @param[in] cnib   The character to convert to a nibble.
 *
 * \retval char   A character that will contain the newly created nibble.
 **/
char ctonib(char cnib)
{
  char retVal=0x00;
  char testval=0x00;

  if ((cnib>='0') && (cnib<='9'))
    {
      retVal = cnib - '0';
    } else {
      testval = toupper(cnib);
      if ((testval>='A') && (testval<='F'))
	{
	  retVal = ((testval - 'A') +10);
	} else {
	  printf("Error in conversion!  (Check ctonibble()) -- %02x\n",testval);
	}
    }
  return retVal;
}

/**
 * \brief Verify that the character that is passed in is a valid hex character.
 *
 * @param[in] inchar   The character to verify has a hex equivalent.
 *
 * \retval TRUE if it is
 * \retval FALSE if it isn't
 **/
int is_hex(char inchar)
{
	if (((inchar >= 'A') && (inchar <= 'F')) || 
		((inchar >='0') && (inchar <= '9')) ||
		((inchar >='a') && (inchar <= 'f'))) return TRUE;

	return FALSE;
}

/**
 * \brief Verify that the character that is passed in is a valid delimiter for a MAC address.
 *
 * @param[in] inchar   The character to verify is a valid delimiter.
 *
 * \retval TRUE if it is a valid delimiter
 * \retval FALSE if it is not a valid delimiter
 **/
int is_delim(char inchar)
{
	if ((inchar == ':') || (inchar = '-')) return TRUE;

	return FALSE;
}

/**
 * \brief Verify that the string is a valid MAC address.
 *
 *  Verify that we have a valid MAC address by making sure it is of the form :
 *  xx:xx:xx:xx:xx:xx
 *   or
 *  xx-xx-xx-xx-xx-xx
 *
 * @param[in] inhexstr   The string that should contain a MAC address.
 *
 * \retval FALSE if the string isn't a MAC address.
 * \retval TRUE if the string is a MAC address.
 **/
int xsupconfig_common_is_valid_mac(char *inhexstr)
{
	int i;

	// A valid MAC should be 17 characters.
	if (strlen(inhexstr) != 17) return FALSE;

	for (i=0; i<17; i++)
	{
		if ((i == 2) || (i == 5) || (i == 8) || (i == 11) || (i == 14))
		{
			if (is_delim(inhexstr[i]) == FALSE) return FALSE;
		}
		else
		{
			if (is_hex(inhexstr[i]) == FALSE) return FALSE;
		}
	}

	return TRUE;
}

/**
 *  \brief Convert a string that has passed the validation test above to
 *			a hex MAC address.
 *
 * @param[in] instr   The string that we need to convert to a binary version 
 *                    of the MAC address.
 *
 * @param[in] mac   The MAC binary version of the MAC address.
 **/
void xsupconfig_common_convert_mac(char *instr, char *mac)
{
	if (strlen(instr) != 17)
	{
		printf("Invalid string passed to %s()!\n", __FUNCTION__);
		return;
	}

  mac[0] = ((ctonib(instr[0]) << 4) | ctonib(instr[1]));
  mac[1] = ((ctonib(instr[3]) << 4) | ctonib(instr[4]));
  mac[2] = ((ctonib(instr[6]) << 4) | ctonib(instr[7]));
  mac[3] = ((ctonib(instr[9]) << 4) | ctonib(instr[10]));
  mac[4] = ((ctonib(instr[12]) << 4) | ctonib(instr[13]));
  mac[5] = ((ctonib(instr[15]) << 4) | ctonib(instr[16]));
}

/**
 *  \brief Search through the node list, and find the node called 'nodename'.
 *
 * @param[in] head   The head of the linked list that we want to search.
 * @param[in] nodename   The name of the node that we are searching for.
 *
 * \retval NULL on error
 * \retval ptr to the found XML node
 **/
xmlNodePtr xsupconfig_common_find_node(xmlNodePtr head, char *nodename)
{
	xmlNodePtr cur_node = NULL;

	if ((head == NULL) || (nodename == NULL)) return NULL;

	for (cur_node = head; cur_node; cur_node = cur_node->next)
	{
		if ((cur_node->type == XML_ELEMENT_NODE) && (strcmp((char *)cur_node->name, nodename) == 0))
		{
			return cur_node;			
		}
	}

	return NULL;
}

/**
 * \brief Handle an error in the parser based on the current state of the supplicant.
 *
 * @param[in] fmt   The format of the string to log.
 * @param[in] ...   Some number of variables that make up the content of the string, similar to printf().
 *
 **/
void xsupconfig_common_log(char *fmt, ...)
{
	char *logmsg = NULL;
	va_list ap;

	va_start(ap, fmt);

	logmsg = malloc(strlen(fmt) + 1024);  // Should be enough.
	if (logmsg == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to create configuration parse error string.\n");
		return;
	}

	vsnprintf(logmsg, (strlen(fmt) + 1024), fmt, ap);

	if (xsup_common_in_startup() == TRUE)
	{
		error_prequeue_add(logmsg);
	}
	else
	{
		debug_printf(DEBUG_NORMAL, "%s\n", logmsg);
	}

	free(logmsg);
}
