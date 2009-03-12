/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_profile.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_PROFILE_H__
#define __XSUPCONFIG_PARSE_PROFILE_H__

extern parser profile[];

void *xsupconfig_parse_profile(void **, uint8_t, xmlNodePtr);
void *xsupconfig_parse_user_profile(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_PROFILE_H__
