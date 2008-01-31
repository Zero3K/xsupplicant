/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: cardif_windows_wmi_async.h,v 1.1 2008/01/30 20:46:43 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:43 $
 **/
#ifndef __CARDIF_WINDOWS_WMI_ASYNC_H__
#define __CARDIF_WINDOWS_WMI_ASYNC_H__

int cardif_windows_wmi_async(char *, context *, IWbemCallResult *, void *);
void cardif_windows_wmi_async_check();
void cardif_windows_wmi_async_dhcp_renew_callback(char *, context *, int);
void cardif_windows_wmi_async_static_ip_callback(char *, context *, int);
void cardif_windows_wmi_async_clear_by_ctx(context *);
void cardif_windows_wmi_async_dhcp_release_renew_callback(char *, context *, int);

#endif // __CARDIF_WINDOWS_WMI_ASYNC_H__