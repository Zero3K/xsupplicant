/**
 * Known interfaces cache.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file interfaces.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __INTERFACES_H__
#define __INTERFACES_H__

struct interfaces {
	struct interfaces *next;

	char *intname;
	char *desc;
	char mac[6];
	unsigned char is_wireless;
};

int interfaces_add(char *, char *, char *, unsigned char);
int interfaces_delete(char *);
struct interfaces *interfaces_get_cache_head();
char *interfaces_get_name_from_mac(char *);
void interfaces_flush_cache();
void interfaces_dump_cache();
struct interfaces *interfaces_get_by_desc(char *);

#endif  //__INTERFACES_H__
