/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_profiles.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_PROFILES_H__
#define __XSUPCONFIG_PARSE_PROFILES_H__

extern parser profiles[];
extern parser user_profiles[];

void *xsupconfig_parse_profiles(void **, uint8_t, xmlNodePtr);
void *xsupconfig_parse_user_profiles(void **, uint8_t, xmlNodePtr);

#endif // __XSUPCONFIG_PARSE_PROFILES_H__
