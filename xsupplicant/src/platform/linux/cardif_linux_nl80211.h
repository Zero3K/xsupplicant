/**
 * Linux nl80211 interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * file cardif_linux_nl80211.h
 *
 */
#ifndef DISABLE_LIBNL

#ifndef _CARDIF_LINUX_NL80211_
#define _CARDIF_LINUX_NL80211_

#include <stdlib.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include "libxsupconfig/xsupconfig.h"
#include "context.h"

extern struct cardif_funcs cardif_linux_nl80211_driver;

typedef enum { DRV_ALG_NONE,
	DRV_ALG_WEP,
	DRV_ALG_TKIP,
	DRV_ALG_CCMP
} drv_alg;

struct lin_nl80211_drv_handle {
	struct nl_handle *nl_handle;
	struct nl_cache *nl_cache;
	struct nl_cb *nl_cb;
	struct genl_family *nl80211;
};

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

int driver_nl80211_init(context * ctx);
unsigned int driver_nl80211_deinit(context * ctx);

#endif

#endif				// DISABLE_LIBNL
