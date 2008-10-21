/**
 * EAPTLS (RFC 2716) Function header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file eaptls.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EAPTLS_H_
#define _EAPTLS_H_

#ifndef USE_GNUTLS
#include <openssl/ssl.h>
#else
#include <gnutls/gnutls.h>
#endif 

#ifndef WINDOWS
#include <netinet/in.h>
#endif

#include "../../context.h"

#define EAPTLS_LENGTH_INCL   0x80
#define EAPTLS_MORE_FRAGS    0x40
#define EAPTLS_START         0x20
#define EAPTLS_ACK           0x00
#define EAPTLS_FINAL         0x00

#define TLS_SESSION_KEY_CONST       "client EAP encryption"
#define TLS_SESSION_KEY_CONST_SIZE  21
#define TLS_SESSION_KEY_SIZE        512  //192

// This could be 1398, but some authenticators are stupid, and won't handle
// anything larger.
#define MAX_CHUNK                   1000

#define ROOT_CERTS_LOADED           0x01
#define USER_CERTS_LOADED           0x02
#define RANDOM_LOADED               0x04



int eaptls_setup(eap_type_data *);
void eaptls_process(eap_type_data *);
uint8_t *eaptls_buildResp(eap_type_data *);
uint8_t *eaptls_getKey(eap_type_data *);
uint8_t eaptls_isKeyAvailable(eap_type_data *);
void eaptls_deinit(eap_type_data *);
void eaptls_check(eap_type_data *);

#endif
