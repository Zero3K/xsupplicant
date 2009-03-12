/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * File: xsupconfig_common.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_COMMON_H__
#define __XSUPCONFIG_COMMON_H__

typedef struct multichoice_struct {
	int value;
	char *text;
} multichoice;

uint8_t xsupconfig_common_yesno(char *);
uint8_t xsupconfig_common_is_number(char *);
void xsupconfig_common_upcase(char *strtoconvert);
void *xsupcommon_do_nothing(void **, uint8_t, xmlNodePtr);
int xsupconfig_common_select_from_list(multichoice list_choices[], char *);
struct config_eap_method *xsupconfig_alloc_method(struct config_eap_method *,
						  char *);
int xsupconfig_common_is_valid_mac(char *);
void xsupconfig_common_convert_mac(char *, char *);
xmlNodePtr xsupconfig_common_find_node(xmlNodePtr, char *);
int is_hex(char);
int is_delim(char);
char ctonib(char);
void xsupconfig_common_log(char *fmt, ...);

#endif				// __XSUPCONFIG_COMMON_H__
