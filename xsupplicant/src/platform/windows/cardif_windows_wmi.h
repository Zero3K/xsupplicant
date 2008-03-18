/**
 * Windows WMI interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_wmi.h
 *
 * \author chris@open1x.org
 *
 */

#ifndef __CARDIF_WINDOWS_WMI_H__
#define __CARDIF_WINDOWS_WMI_H__

#define INVALID_WMI_IDX    -1
#define DEFAULT_GW_METRIC  20     // Seems to be the default for Windows interfaces.

#define WMI_BIND_ADD     0
#define WMI_BIND_CHECK   1

int cardif_windows_wmi_connect();
int cardif_windows_wmi_disconnect();
char *cardif_windows_wmi_get_ip_utf8(context *);
wchar_t *cardif_windows_wmi_get_ip(context *);
wchar_t *cardif_windows_wmi_get_netmask(context *);
char *cardif_windows_wmi_get_netmask_utf8(context *);
wchar_t *cardif_windows_wmi_get_ip(context *);
char *cardif_windows_wmi_get_gw_utf8(context *);
int cardif_windows_wmi_get_idx(context *, char **);

#ifdef WINDOWS_USE_WMI
int cardif_windows_wmi_get_uptime(uint64_t *);
#endif

int cardif_windows_wmi_set_dns_domain(context *, char *);
int cardif_windows_wmi_set_dns_servers(context *, char *, char *, char *);
int cardif_windows_wmi_release_dhcp(context *);
int cardif_windows_wmi_renew_dhcp(context *);
int cardif_windows_wmi_enable_dhcp(context *);
int cardif_windows_wmi_set_static_ip(context *, char *, char *);
int cardif_windows_wmi_set_static_gw(context *, char *);

int cardif_windows_wmi_event_connect();
int cardif_windows_wmi_event_disconnect();
void cardif_windows_wmi_late_bind_insert_check(int action, wchar_t *name);
int cardif_windows_wmi_post_insert_bind(wchar_t *name);

#ifdef WINDOWS_USE_WMI
void cardif_windows_wmi_ip_update();
#endif

int cardif_windows_wmi_init();
int cardif_windows_wmi_deinit();

void cardif_windows_wmi_check_events();

#endif // __CARDIF_WINDOWS_WMI_H__
