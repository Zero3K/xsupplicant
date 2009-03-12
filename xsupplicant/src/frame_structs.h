/**
 * Structs for common frame formats used with 802.1X
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file frame_structs.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _FRAME_STRUCTS_H_
#define _FRAME_STRUCTS_H_

#ifndef WINDOWS
#include <stdint.h>
#endif

// Offsets in to frames where data is located.
#define OFFSET_PAST_MAC       12
#define OFFSET_TO_EAPOL       14
#define OFFSET_TO_EAP         18
#define OFFSET_TO_DATA        23

// EAPOL Frame type
#define EAPOL_FRAME           0x888e

// Structures that can be used as templates to get information out of frames.

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
struct eapol_header {
	uint16_t frame_type;
	uint8_t eapol_version;
	uint8_t eapol_type;
	uint16_t eapol_length;
};
#else
struct eapol_header {
	uint16_t frame_type;
	uint8_t eapol_version;
	uint8_t eapol_type;
	uint16_t eapol_length;
} __attribute__ ((__packed__));
#endif

struct eap_header {
	uint8_t eap_code;
	uint8_t eap_identifier;
	uint16_t eap_length;
	uint8_t eap_type;
}
#ifndef WINDOWS
__attribute__ ((__packed__))
#endif
    ;

#ifdef WINDOWS
#pragma pack()
#endif

#endif
