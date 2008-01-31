/**
 * Wireless calls for interfacing with libdarwinwireless.a
 *  
 * Licensed under a dual GPL/BSD license.  (But, libdarwinwireless IS NOT!)
 *
 *  \file cardif_macosx_wireless.h
 *
 *  \author chris@open1x.org
 **/

#ifndef __CARDIF_MACOSX_WIRELESS_H__
#define __CARDIF_MACOSX_WIRELESS_H__

extern struct cardif_funcs cardif_macosx_wireless_driver;

int cardif_macosx_wireless_scan(context *, char);
int cardif_macosx_wireless_disassociate(context *, int);
int cardif_macosx_wireless_set_WEP_key(context *, uint8_t *, int, int);
int cardif_macosx_wireless_get_ssid(context *, char *);
int cardif_macosx_wireless_set_tkip_key(context *, unsigned char *, int, int,
					char *, int);
int cardif_macosx_wireless_set_ccmp_key(context *, unsigned char *, int, int,
					char *, int);
int cardif_macosx_wireless_delete_key(context *, int, int);
int cardif_macosx_wireless_set_key_material(context *);

#endif // __CARDIF_MACOSX_WIRELESS_H__
