/**
 * EAPPSK Header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file psk_crypt.h
 *
 * \author chris@open1x.org
 *
 **/  
    
#ifdef EXPERIMENTAL
    
#ifndef _PSK_CRYPT_H_
unsigned char *cmac_aes_128(unsigned char *key, unsigned char *indata,
			     unsigned int size);
int eax_encrypt(unsigned char *key, unsigned char *nonce,
		  unsigned char *header, unsigned char *payload,
		  unsigned int payload_size, unsigned char **out,
		  unsigned int *out_size, unsigned char *tag);
int eax_decrypt(unsigned char *key, unsigned char *nonce,
		  unsigned char *header, unsigned char *tag,
		  unsigned char *payload, unsigned int payload_size,
		  unsigned char **out, unsigned int *out_size);
int pbkdf2(unsigned char *pw, unsigned int pwlen, char *salt,
	     unsigned long long saltlen, unsigned int ic, unsigned char *dk,
	     unsigned long long dklen);

#endif				// _PSK_CRYPT_H_
    
#endif				// EXPERIMENTAL
