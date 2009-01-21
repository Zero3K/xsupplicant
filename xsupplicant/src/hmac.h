/**
 *
 *  \file hmac.h
 *
 **/
#ifndef _HMAC_H_
#define _HMAC_H_

void hmac_md5(unsigned char *text, int text_len, unsigned char *key,
	      int key_len, unsigned char *digest);

#endif
