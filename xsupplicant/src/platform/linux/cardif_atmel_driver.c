/*******************************************************************
 * Linux card interface implementation.
 *
 * Licensed under the GPLv2 as stated in the copyright notice below.
 *
 * \file cardif_atmel_driver.c
 *
 * \authors chris@open1x.org
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
	SET_WPA_ENCRYPTION = 1,
	SET_CIPHER_SUITES = 2,
	MLME_STA_DEAUTH = 3,
	MLME_STA_DISASSOC = 4,
};

/* ATMEL_WPA_IOCTL_PARAM ioctl() cmd: */
enum {
	ATMEL_PARAM_WPA = 1,
	ATMEL_PARAM_PRIVACY_INVOKED = 2,
	ATMEL_PARAM_WPA_TYPE = 3,
};

#define MAX_KEY_LENGTH      40

struct atmel_param {
	unsigned char sta_addr[6];
	int cmd;
	u8 alg;
	u8 key_idx;
	u8 set_tx;
	u8 seq[8];
	u8 seq_len;
	u16 key_len;
	u8 key[MAX_KEY_LENGTH];
	struct {
		int reason_code;
		u8 state;
	} mlme;
	u8 pairwise_suite;
	u8 group_suite;
	u8 key_mgmt_suite;
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
			debug_printf(DEBUG_NORMAL,
				     "Error with ATMEL IOCTL! (%s:%d)" "\n",
				     __FUNCTION__, __LINE__);
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
	i = (int *)iwr.u.name;
	*i++ = param;
	*i++ = value;

	if (ioctl(s, ATMEL_WPA_IOCTL_PARAM, &iwr) < 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error with ATMEL WPA IOCTL! (%s:%d)\n",
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

	if (atmel2param(intdata->intName, ATMEL_PARAM_WPA, endis) < 0) {
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
	if (atmel2param(intdata->intName, ATMEL_PARAM_PRIVACY_INVOKED, endis) <
	    0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't set privacy flag!  (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return -1;
	}

	if (atmel2param(intdata->intName, ATMEL_PARAM_WPA, endis) < 0) {
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

	switch (alg) {
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
		debug_printf(DEBUG_NORMAL, "Couldn't get key! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return -1;
	}

	debug_printf(DEBUG_NORMAL,
		     "alg=%s  key_idx=%d set_tx=%d seq_len=%d key_len=%d\n",
		     alg_name, key_idx, set_tx, seq_len, key_len);

	if (seq_len > 8) {
		debug_printf(DEBUG_NORMAL, "seq_len > 8!\n");
		return -1;
	}

	blen = sizeof(*param) + key_len;
	buf = malloc(blen);
	if (buf == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory! (%s:%d)\n",
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
	memcpy((u8 *) param->key, key, key_len);

	if (atmel_ioctl(dev, param, blen, 1)) {
		debug_printf(DEBUG_NORMAL, "Failed to set key! (%s%d)\n",
			     __FUNCTION__, __LINE__);
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
	char seq[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
		return XEMALLOC;

	return cardif_atmel_driver_set_key(intdata->intName, WPA_TKIP, addr,
					   keyidx, settx, seq, 6, key, keylen);
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
	char seq[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
		return XEMALLOC;

	return cardif_atmel_driver_set_key(intdata->intName, WPA_CCMP, addr,
					   keyidx, settx, seq, 6, key, keylen);
}

/**************************************
 *
 * Delete a key from the card.
 *
 **************************************/
int cardif_atmel_driver_delete_key(struct interface_data *intdata,
				   int key_idx, int set_tx)
{
	char seq[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
		return XEMALLOC;

	return cardif_atmel_driver_set_key(intdata->intName, WPA_NONE, NULL,
					   key_idx, set_tx, seq, 6, NULL, 0);
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
	debug_printf(DEBUG_NORMAL,
		     "ATMEL countermeasures not implemented!!!!\n");
	return XENONE;
}

int cardif_atmel_driver_drop_unencrypted(struct interface_data *intdata,
					 char endis)
{
	debug_printf(DEBUG_NORMAL,
		     "ATMEL drop unencrypted not implemented!!!!\n");
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
	debug_printf(DEBUG_NORMAL,
		     "WPA2/802.11i is not implemented for the ATMEL"
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
