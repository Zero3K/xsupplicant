/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _XSUPCONFWRITE_H_
#define _XSUPCONFWRITE_H_

#define CONF_VERSION "1.0"

/* *** (public) Function defs  */

char *mac2str(char *);
int xsupconfwrite_write_config(char *);
int xsupconfwrite_write_user_config(char *);

/* *** Error codes */

#define XSUPCONFWRITE_ERRNONE        0
#define XSUPCONFWRITE_FAILED        -1

#endif /* _XSUPCONFWRITE_H_ */
