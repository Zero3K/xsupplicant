/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapfast_xml.h
 *
 * \author chris@open1x.org
 **/

#ifndef __EAPFAST_XML_H__
#define __EAPFAST_XML_H__

#include <libxml/parser.h>
#include <libxml/tree.h>

xmlDocPtr eapfast_xml_create_pac_struct();
void eapfast_xml_add_content(xmlNodePtr, char *, char *);
int eapfast_xml_add_pac(xmlDocPtr, struct pac_values *);
int eapfast_xml_save(char *, xmlDocPtr);
int eapfast_xml_delete_pac(xmlDocPtr, char *);
void eapfast_xml_init();
void eapfast_xml_deinit(xmlDocPtr);
xmlDocPtr eapfast_xml_open_pac(char *);
int eapfast_xml_find_pac_data(xmlDocPtr, char *, struct pac_values *);

#endif
