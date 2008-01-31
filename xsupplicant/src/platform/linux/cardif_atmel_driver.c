/*******************************************************************
 * Linux card interface implementation.
 *
 * Licensed under the GPLv2 as stated in the copyright notice below.
 *
 * File: cardif_atmel_driver.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: cardif_atmel_driver.c,v 1.2 2008/01/30 22:07:46 galimorerpg Exp $
 * $Date: 2008/01/30 22:07:46 $
 * $Log: cardif_atmel_driver.c,v $
 * Revision 1.2  2008/01/30 22:07:46  galimorerpg
 * Platform patch cleanups for Linux.
 *
 * Revision 1.1  2008/01/30 20:46:41  galimorerpg
 * Moved cardif->platform
 *
 * Revision 1.30  2008/01/24 07:35:32  galimorerpg
 * Applied Renato Caldas' Linux wireless patch.
 * Modified configure.ac to default to the newer IWLIB calls temporarily.
 * Temporarily disabled log rolling in Linux due to some issues getting struct stat64 figured out with Ubuntu.
 *
 * Revision 1.29  2007/10/23 06:16:09  galimorerpg
 * Added Renato's host_os_cleanup.patch with a few slight tweaks to make it behave properly on Mac OS X.
 *
 * Revision 1.28  2006/10/08 03:42:53  chessing
 * Last batch of changes before 1.2.8.
 *
 * Revision 1.27  2006/08/28 15:59:31  chessing
 * Fixed a few things.
 *
 * Revision 1.26  2006/08/25 23:37:18  chessing
 * Numerous patches that have come in over the last month or two.
 *
 * Revision 1.25  2006/06/23 00:45:19  chessing
 * Completed basic implementation of operstate support.  Probably need to consider extending it to be used to populate the up/down state of the interface in the statemachine.
 *
 * Revision 1.24  2006/06/20 18:17:18  chessing
 * Fix some endianness problems with WPA and WPA2 IE parsing.
 *
 * Revision 1.23  2006/05/26 22:04:58  chessing
 * Fixed some memory access errors, and cleaned up some wext stuff that was causing issues with the madwifi driver in wext mode.
 *
 * Revision 1.22  2006/05/14 22:09:28  chessing
 * A few small changes in the Xsupplicant code.  Beginning of a configuration/monitor program can be found in gui_tools. (Very simple for now, with several known bugs, but no showstopper bugs know.)
 *
 * Revision 1.21  2006/05/13 03:53:03  chessing
 * A couple of forgotten things from the last big patch.
 *
 * Revision 1.20  2006/04/25 01:17:43  chessing
 * LOTS of code cleanups, new error checking/debugging code added, and other misc. fixes/changes.
 *
 * Revision 1.19  2006/02/23 22:26:53  chessing
 * Fix for bug id #1415020.  'Building Xsupplicant 1.2.3 Fails on FC4'.
 *
 * Revision 1.18  2006/01/19 05:37:04  chessing
 * WPA2 is working correctly.  Added the ability to query the card to gather encryption/authentication capabilities.  1.2.3 is now ready to go.
 *
 * Revision 1.17  2005/12/24 02:39:48  chessing
 * Fixes to autoconf script to correctly identify the number of arguments that iw_extract_event_stream() takes, along with checking iwlib.h compiles correctly.
 *
 * Revision 1.16  2005/12/03 22:18:50  chessing
 * Added an include to fix some problems when compiling with WE19.
 *
 * Revision 1.15  2005/11/10 04:56:54  chessing
 * Added patch from Ben Gardner to add support for setting a specific WEP key prior to attempting to associte.  (With a few slight modifications by me to make it fit in the current CVS code, and get it supported in config-parse.)  Added patch from Pekka Savola to fix some header ordering issues, and a potential buffer overflow.
 *
 * Revision 1.14  2005/10/17 03:56:54  chessing
 * Updates to the libxsupconfig library.  It no longer relies on other source from the main tree, so it can be used safely in other code with problems.
 *
 * Revision 1.13  2005/09/05 01:00:36  chessing
 * Major overhaul to most of the state machines in Xsupplicant.  Also added additional error messages to the TLS functions to try to debug the one of the problems reported on the list.  Basic testing shows this new code to be more stable than previous code, but it needs more testing.
 *
 * Revision 1.12  2005/08/20 19:06:54  chessing
 * Patch from Carsten Grohmann to fix a few things in xsup_get_state.c.  Also added the ability to define an empty network clause, that will set the card in to encryption disabled mode.  From there, anything short of changing the SSID will be ignored by Xsupplicant.
 *
 * Revision 1.11  2005/08/09 01:39:15  chessing
 * Cleaned out old commit notes from the released version.  Added a few small features including the ability to disable the friendly warnings that are spit out.  (Such as the warning that is displayed when keys aren't rotated after 10 minutes.)  We should also be able to start when the interface is down.  Last, but not least, we can handle empty network configs.  (This may be useful for situations where there isn't a good reason to have a default network defined.)
 *
 *
 ********************************************************************/


// This code was derived from the atmel driver component of wpa_supplicant,
// which contained the following copyright notice :

/***************************************************************************************
	Copyright 2000-2001 ATMEL Corporation.
	
    WPA Supplicant - driver interaction with Atmel Wireless lan drivers.
    
    This is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Atmel wireless lan drivers; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

**************************************************************************************/


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/compiler.h>
#include <iwlib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <linux/wireless.h>

#ifdef USE_EFENCE
#include <efence.h>
#endif

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int8_t s8;

#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "xsupconfig.h"
#include "profile.h"
#include "wireless_sm.h"
#include "netlink.h"
#include "platform/cardif.h"
#include "platform/linux/cardif_linux_wext.h"
#include "platform/linux/cardif_atmel_driver.h"
#include "wpa.h"
#include "cardif_linux_rtnetlink.h"

#define ATMEL_WPA_IOCTL                (SIOCIWFIRSTPRIV + 2)
#define ATMEL_WPA_IOCTL_PARAM          (SIOCIWFIRSTPRIV + 3)
#define ATMEL_WPA_IOCTL_GET_PARAM      (SIOCIWFIRSTPRIV + 4)


/* ATMEL_WPA_IOCTL ioctl() cmd: */
enum {
    SET_WPA_ENCRYPTION  = 1,
    SET_CIPHER_SUITES   = 2,
    MLME_STA_DEAUTH     = 3,
    MLME_STA_DISASSOC   = 4,
};

/* ATMEL_WPA_IOCTL_PARAM ioctl() cmd: */
enum {
            ATMEL_PARAM_WPA = 1,
            ATMEL_PARAM_PRIVACY_INVOKED = 2,
            ATMEL_PARAM_WPA_TYPE = 3,
};

#define MAX_KEY_LENGTH      40

struct atmel_param{
    unsigned char sta_addr[6];
        int     cmd;
        u8      alg;
        u8      key_idx;
        u8      set_tx;
        u8      seq[8];
        u8      seq_len;
        u16     key_len;
        u8      key[MAX_KEY_LENGTH];
    struct{
        int     reason_code;
        u8      state;
    }mlme;
    u8          pairwise_suite;
    u8          group_suite;
    u8          key_mgmt_suite;
};

    
    
static int atmel_ioctl(const char *dev, struct atmel_param *param,
			 int len, int show_err)
{
	int s;
	struct iwreq iwr;

	if (!xsup_assert((dev != NULL), "dev != NULL", FALSE))
	  return -1;

	if (!xsup_assert((param != NULL), "param != NULL", FALSE))
	  return -1;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
	  debug_printf(DEBUG_NORMAL, "Error with ATMEL IOCTL! (%s:%d)\n",
		       __FUNCTION__, __LINE__);
	  return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	Strncpy(iwr.ifr_name, dev, sizeof(iwr.ifr_name));
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = len;

	if (ioctl(s, ATMEL_WPA_IOCTL, &iwr) < 0) {
		int ret;
		close(s);
		ret = errno;
		if (show_err) 
		  debug_printf(DEBUG_NORMAL, "Error with ATMEL IOCTL! (%s:%d)"
			       "\n", __FUNCTION__, __LINE__);
		return ret;
	}
	close(s);

	return 0;
}


static int atmel2param(const char *ifname, int param, int value)
{
	struct iwreq iwr;
	int *i, s, ret = 0;

	if (!xsup_assert((ifname != NULL), "ifname != NULL", FALSE))
	  return XEMALLOC;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
	  debug_printf(DEBUG_NORMAL, "Error getting socket! (%s:%d)\n",
		       __FUNCTION__, __LINE__);
	  return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	Strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
	i = (int *) iwr.u.name;
	*i++ = param;
	*i++ = value;

	if (ioctl(s, ATMEL_WPA_IOCTL_PARAM, &iwr) < 0) {
	  debug_printf(DEBUG_NORMAL, "Error with ATMEL WPA IOCTL! (%s:%d)\n",
		       __FUNCTION__, __LINE__);
	  ret = -1;
	}
	close(s);
	return ret;
}

int cardif_atmel_driver_wpa(struct interface_data *intdata, char endis)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (atmel2param(intdata->intName, ATMEL_PARAM_WPA, endis) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error enabling WPA!\n");
      return -1;
    }

  return XENONE;
}

int cardif_atmel_driver_wpa_state(struct interface_data *intdata, char endis)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  // Normally we would call wpa_gen_ie here, but since the atmel cards
  // don't set the IEs in this way, we don't do it.
  if (atmel2param(intdata->intName, ATMEL_PARAM_PRIVACY_INVOKED, endis) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't set privacy flag!  (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return -1;
    }

  if (atmel2param(intdata->intName, ATMEL_PARAM_WPA, endis) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't enable WPA! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return -1;
    }

  return XENONE;
}

int cardif_atmel_driver_wpa_disable(char *intname)
{
  // XXX Finish!
  return XENONE;
}

int cardif_atmel_driver_set_key(char *dev, int alg, unsigned char *addr,
				int key_idx, int set_tx, char *seq, 
				int seq_len, char *key, int key_len)
{
  int ret = XENONE;
  struct atmel_param *param;
  u8 *buf;
  u8 alg_type;

  size_t blen;
  char *alg_name;

  if (!xsup_assert((dev != NULL), "dev != NULL", FALSE))
    return XEMALLOC;

  switch (alg)
    {
    case WPA_NONE:
      alg_name = "none";
      alg_type = 0;
      break;

    case WPA_WEP:
      alg_name = "WEP";
      alg_type = 1;
      break;

    case WPA_TKIP:
      alg_name = "TKIP";
      alg_type = 2;
      break;

    case WPA_CCMP:
      alg_name = "CCMP";
      alg_type = 3;
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Couldn't get key! (%s:%d)\n", __FUNCTION__,
		   __LINE__);
      return -1;
    }

  debug_printf(DEBUG_NORMAL, "alg=%s  key_idx=%d set_tx=%d seq_len=%d key_len=%d\n", alg_name, key_idx, set_tx, seq_len, key_len);

  if (seq_len > 8)
    {
      debug_printf(DEBUG_NORMAL, "seq_len > 8!\n");
      return -1;
    }

  blen = sizeof(*param) + key_len;
  buf = malloc(blen);
  if (buf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return -1;
    }

  bzero(buf, blen);

  param = (struct atmel_param *)buf;

  param->cmd = SET_WPA_ENCRYPTION;

  if (addr == NULL)
    memset(param->sta_addr, 0xff, 6);
  else
    memcpy(param->sta_addr, addr, 6);

  param->alg = alg_type;
  param->key_idx = key_idx;
  param->set_tx = set_tx;
  memcpy(param->seq, seq, seq_len);
  param->seq_len = seq_len;
  param->key_len = key_len;
  memcpy((u8 *)param->key, key, key_len);

  if (atmel_ioctl(dev, param, blen, 1))
    {
      debug_printf(DEBUG_NORMAL, "Failed to set key! (%s%d)\n", __FUNCTION__,
		   __LINE__);
      return -1;
    }
  free(buf);

  return ret;
}

/**************************************
 *
 * Set a TKIP key to the card.
 *
 **************************************/
int cardif_atmel_driver_set_tkip_key(struct interface_data *intdata, 
				   unsigned char *addr, int keyidx, int settx, 
				     char *key, int keylen)
{
  char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  return cardif_atmel_driver_set_key(intdata->intName, WPA_TKIP, addr, keyidx,
				     settx, seq, 6, key, keylen);
}

/**************************************
 *
 * Set a CCMP (AES) key to the card.
 *
 **************************************/
int cardif_atmel_driver_set_ccmp_key(struct interface_data *intdata,
				     unsigned char *addr, int keyidx, 
				     int settx, char *key, int keylen)
{
  char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  return cardif_atmel_driver_set_key(intdata->intName, WPA_CCMP, addr, keyidx,
				     settx, seq, 6, key, keylen);
}

/**************************************
 *
 * Delete a key from the card.
 *
 **************************************/
int cardif_atmel_driver_delete_key(struct interface_data *intdata,
				   int key_idx, int set_tx)
{
  char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  return cardif_atmel_driver_set_key(intdata->intName, WPA_NONE, NULL, key_idx,
				     set_tx, seq, 6, NULL, 0);
}

/**************************************
 *
 * Send a disassociate request.
 *
 **************************************/
int cardif_atmel_driver_disassociate(struct interface_data *intdata, 
				     int reason_code)
{
  struct atmel_param param;
  int ret;
  int mgmt_error = 0xaa;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  memset(&param, 0, sizeof(param));
  memcpy(param.sta_addr, intdata->source_mac, 6);
  param.cmd = MLME_STA_DISASSOC;
  param.mlme.reason_code = reason_code;
  param.mlme.state = mgmt_error;
  ret = atmel_ioctl(intdata->intName, &param, sizeof(param), 1);
  return ret;
}

int cardif_atmel_driver_countermeasures(struct interface_data *intdata,
					 char endis)
{
  debug_printf(DEBUG_NORMAL, "ATMEL countermeasures not implemented!!!!\n");
  return XENONE;
}

int cardif_atmel_driver_drop_unencrypted(struct interface_data *intdata,
					 char endis)
{
  debug_printf(DEBUG_NORMAL, "ATMEL drop unencrypted not implemented!!!!\n");
  return XENONE;
}

int cardif_atmel_driver_get_wpa_ie(struct interface_data *intdata, 
				   char *iedata, int *ielen)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return XEMALLOC;

  // The ATMEL cards are hardcoded to put 00s in the capabilities field.
  wpa_gen_ie_caps(intdata, iedata);
  *ielen = 26;
  return XENONE;
}

int cardif_atmel_driver_get_wpa2_ie(struct interface_data *intdata,
				    char *iedata, int *ielen)
{
  debug_printf(DEBUG_NORMAL, "WPA2/802.11i is not implemented for the ATMEL"
	       " driver!\n");
  return XENOTSUPPORTED;
}

void cardif_atmel_driver_associate(struct interface_data *intdata)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  cardif_linux_wext_set_ssid(intdata, intdata->cur_essid);
}

struct cardif_funcs cardif_atmel_driver = {
  .scan = cardif_linux_wext_scan,
  .disassociate = cardif_atmel_driver_disassociate,
  .set_wep_key = cardif_linux_wext_set_WEP_key,
  .set_tkip_key = cardif_atmel_driver_set_tkip_key,
  .set_ccmp_key = cardif_atmel_driver_set_ccmp_key,
  .delete_key = cardif_atmel_driver_delete_key,
  .associate = cardif_atmel_driver_associate,
  .get_ssid = cardif_linux_wext_get_ssid,
  .get_bssid = cardif_linux_wext_get_bssid,
  .wpa_state = cardif_atmel_driver_wpa_state,
  .wpa = cardif_atmel_driver_wpa,
  .wep_associate = cardif_linux_wext_wep_associate,
  .countermeasures = cardif_atmel_driver_countermeasures,
  .drop_unencrypted = cardif_atmel_driver_drop_unencrypted,
  .get_wpa_ie = cardif_atmel_driver_get_wpa_ie,
  .get_wpa2_ie = cardif_atmel_driver_get_wpa2_ie,
  .enc_disable = cardif_linux_wext_enc_disable,
  .enc_capabilities = NULL,
  .setbssid = cardif_linux_wext_set_bssid,
  .set_operstate = cardif_linux_rtnetlink_set_operstate,
  .set_linkmode = cardif_linux_rtnetlink_set_linkmode,
};
