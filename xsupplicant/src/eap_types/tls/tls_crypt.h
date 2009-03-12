/**
 * TLS En/Decrypt Function header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file tls_crypt.h
 *
 * \Author Chris.Hessing@utah.edu
 *
 */

#ifndef _TLS_CRYPT_H_
#define _TLS_CRYPT_H_

#include "../../profile.h"

int tls_crypt_decrypt(struct generic_eap_data *, uint8_t *, int, uint8_t *,
		      int *);
int tls_crypt_encrypt(struct generic_eap_data *, uint8_t *, int, uint8_t *,
		      int *);
char *tls_crypt_gen_keyblock(struct generic_eap_data *, char *, int);
int tls_crypt_encrypt_nolen(struct generic_eap_data *, uint8_t *, int,
			    uint8_t *, int *);
#endif
