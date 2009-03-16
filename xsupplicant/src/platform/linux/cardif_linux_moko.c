/**
 * Linux wireless extensions interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_linux_moko.c
 *
 * \authors chris@open1x.org
 *
 **/


#ifdef ENABLE_MOKO


#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <iwlib.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>

#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "config_ssid.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "wpa.h"
#include "wpa2.h"
#include "wpa_common.h"
#include "platform/cardif.h"
#include "platform/linux/cardif_linux.h"
#include "platform/linux/cardif_linux_wext.h"
#include "wireless_sm.h"
#include "platform/linux/cardif_linux_rtnetlink.h"
#include "timer.h"
#include "wpa.h"
#include "wpa2.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 * \brief The ar6k driver used on the moko doesn't have any way to determine
 *        its capabilities.  So we just statically assign some.
 *
 * @param[in] ctx   The context for an interface on the Moko.
 **/
void cardif_linux_wext_enc_capabilities(context * ctx)
{
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) 
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  wctx->enc_capa = (DOES_WEP40 | DOES_WEP104 | DOES_WPA | DOES_WPA2 | DOES_TKIP | DOES_CCMP);
}



#endif  // ENABLE_MOKO
