/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_parse_eap_sim.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __XSUPCONFIG_PARSE_EAP_SIM_H__
#define __XSUPCONFIG_PARSE_EAP_SIM_H__

extern parser eap_sim[];

void *xsupconfig_parse_eap_sim(void **, uint8_t, xmlNodePtr);

#endif  // __XSUPCONFIG_PARSE_EAP_SIM_H__
