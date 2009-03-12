/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file pwd_crypt.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __PWD_CRYPT_H__
#define __PWD_CRYPT_H__

int pwcrypt_funcs_available();
int pwcrypt_encrypt(uint8_t config_type, uint8_t * toencdata, uint16_t toenclen,
		    uint8_t ** encdata, uint16_t * enclen);
int pwcrypt_decrypt(uint8_t config_type, uint8_t * encdata, uint16_t enclen,
		    uint8_t ** decdata, uint16_t * declen);

#endif				// __PWD_CRYPT_H__
