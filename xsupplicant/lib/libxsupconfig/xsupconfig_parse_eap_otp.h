/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_otp.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_OTP_H__
#define __XSUPCONFIG_PARSE_EAP_OTP_H__

extern parser eap_otp[];

void *xsupconfig_parse_eap_otp(void **, uint8_t, xmlNodePtr);

#endif				// __XSUPCONFIG_PARSE_EAP_OTP_H__
