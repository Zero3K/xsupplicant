/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _EAPOL_H_
#define _EAPOL_H_

#include "context.h"

#define MAX_EAPOL_VER     2

// EAPOL Types
#define EAP_PACKET        0
#define EAPOL_START       1
#define EAPOL_LOGOFF      2
#define EAPOL_KEY         3
#define EAPOL_ASF_ALERT   4

int eapol_init(context *);
int eapol_cleanup(context *);
void eapol_build_header(context *, int, int, char *);
int eapol_execute(context *);
int eapol_withframe(context *, int);
uint8_t eapol_get_eapol_ver(context *);
int eapol_get_eap_type(context * ctx);

#endif
