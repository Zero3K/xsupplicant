/*******************************************************************
 * A simple NAS implementation to allow direct authentication against a
 * RADIUS server for testing purposes.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_radius.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/
#ifndef __CARDIF_RADIUS_H__
#define __CARDIF_RADIUS_H__

#ifdef USE_DIRECT_RADIUS

struct radius_pkt {
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t authenticator[16];
	// Then, AVPs.
} __attribute__ ((__packed__));

struct radius_avp {
	uint8_t attribute;
	uint8_t length;
} __attribute__ ((__packed__));

#define RADIUS_ACCESS_REQUEST   1
#define RADIUS_ACCESS_ACCEPT    2
#define RADIUS_ACCESS_REJECT    3
#define RADIUS_ACCESS_CHALLENGE 11

#define RADIUS_AVP_USERNAME     1
#define RADIUS_AVP_EAPMSG       0x4f

uint8_t cardif_radius_eap_sm(context *);

#endif				// USE_DIRECT_RADIUS

#endif				// __CARDIF_RADIUS_H__
