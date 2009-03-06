/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 **/

#ifndef __CERTIFICATES_H__
#define __CERTIFICATES_H__

int certificates_load_root(struct tls_vars *, char *);
int certificates_load_user(struct tls_vars *, char *, char *, char *, char *);

#endif // __CERTIFICATES_H__
