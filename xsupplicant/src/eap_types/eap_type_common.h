/*******************************************************************
 * EAP Common Header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eap_type_common.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __EAP_TYPE_COMMON_H__
#define __EAP_TYPE_COMMON_H__

// You SHOULD NEVER mess with this value!  It *WILL* make a mess!
#define COMMON_KEY_LEN   32

uint8_t *eap_type_common_buildAck(eap_type_data *, uint8_t);
void eap_type_common_fail(eap_type_data *);
uint8_t eap_type_common_get_eap_reqid(uint8_t *);
uint16_t eap_type_common_get_eap_length(uint8_t *);
uint8_t eap_type_common_get_common_key_len(eap_type_data *);
uint8_t eap_type_common_get_zero_len(eap_type_data *);
char *eap_type_common_convert_hex(uint8_t *, uint16_t);
void eap_type_common_init_eap_data(eap_type_data *);

#endif
