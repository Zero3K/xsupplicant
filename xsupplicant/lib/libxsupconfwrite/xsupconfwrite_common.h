/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/
#ifndef __XSUPCONFWRITE_COMMON_H__
#define __XSUPCONFWRITE_COMMON_H__

xmlNodePtr xsupconfwrite_common_newSibling(xmlNodePtr, char *, char *);
int xsupconfwrite_convert_amp(char *, char **);
xmlNodePtr xsupconfwrite_common_write_bool(xmlNodePtr xmlNode, char *nodeName, int yesno, int defaultval, int forcewrite, int sibling);

#endif // __XSUPCONFWRITE_COMMON_H__



