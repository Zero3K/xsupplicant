/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file lsa_calls.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _LSA_CALLS_H_
#define _LSA_CALLS_H_

int lsa_calls_init();
int lsa_calls_decrypt_secret(uint8_t **outData, uint16_t *outLen);
void lsa_calls_deinit();

#endif  // _LSA_CALLS_H_