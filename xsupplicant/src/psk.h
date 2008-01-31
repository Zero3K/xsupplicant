/*******************************************************************
 * WPA-PSK Function implementations for supplicant
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file psk.c
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _PSK_H_
#define _PSK_H_

int psk_wpa_pbkdf2(char *, unsigned char *, int, unsigned char *);

#endif
