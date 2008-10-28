/**
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse.h
 *
 * \author chris@open1x.org
 **/

#ifndef __XSUPCONFIG_PARSE_H__
#define __XSUPCONFIG_PARSE_H__

#define OPTION_GLOBAL_CONFIG_ONLY	BIT(0)
#define OPTION_USER_CONFIG_ONLY		BIT(1)
#define OPTION_ANY_CONFIG			(BIT(0) | BIT(1))

#define CONFIG_LOAD_GLOBAL			OPTION_GLOBAL_CONFIG_ONLY
#define CONFIG_LOAD_USER			OPTION_USER_CONFIG_ONLY

typedef struct conf_parse_struct {
  char *name;
  struct conf_parse_struct *parsedata;
  char descend;
  uint8_t config_allowed;								// Configuration file types this option is allowed in.
  void *(*process)(void **attr, xmlNodePtr node);
} parser;

extern parser baselevel[];
extern parser global_and_network[];

void xsupconfig_parse(xmlNode *node, parser val[], void **);
xmlDocPtr loadConfig(char *);
long xsupconfig_parse_get_line_num();

#endif // __XSUPCONFIG_PARSE_H__
