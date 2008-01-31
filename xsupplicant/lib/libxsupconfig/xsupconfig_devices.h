/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_devices.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef __XSUPCONFIG_DEVICES_H__
#define __XSUPCONFIG_DEVICES_H__

void xsupconfig_devices_init();
void xsupconfig_devices_deinit(struct xsup_devices **);
struct xsup_interfaces *xsupconfig_devices_get_interfaces();
void xsupconfig_devices_dump(struct xsup_devices *);

#endif // XSUPCONFIG_DEVICES
