/**
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse.h
 *
 * \author chris@open1x.org
 **/

#ifndef __XSUPCONFIG_PARSE_H__
#define __XSUPCONFIG_PARSE_H__

typedef struct conf_parse_struct {
  char *name;
  struct conf_parse_struct *parsedata;
  char descend;
  void *(*process)(void **attr, xmlNodePtr node);
} parser;

extern parser baselevel[];
extern parser global_and_network[];

void xsupconfig_parse(xmlNode *node, parser val[], void **);
xmlDocPtr loadConfig(char *);
long xsupconfig_parse_get_line_num();

#endif // __XSUPCONFIG_PARSE_H__
