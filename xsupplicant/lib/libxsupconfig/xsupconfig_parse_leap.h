/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_leap.h
 *
 * \author chris@open1x.org
 *
 **/

#ifdef ENABLE_LEAP

#ifndef __XSUPCONFIG_PARSE_LEAP_H__
#define __XSUPCONFIG_PARSE_LEAP_H__

extern parser leap[];

void *xsupconfig_parse_leap(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_LEAP_H__

#endif ENABLE_LEAP
