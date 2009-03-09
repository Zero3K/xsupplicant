/**
 * Linux nl80211  interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * file cardif_linux_nl80211.c
 *
 *
 **/
/* File best viewed with set ts=4 */
/*
Function Description:TODO
*/
#ifndef DISABLE_LIBNL

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <iwlib.h>
#include <linux/if_packet.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <linux/nl80211.h>
#include "platform/linux/cardif_linux_nl80211.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "platform/cardif.h"
#include "platform/linux/cardif_linux.h"
#include "platform/linux/cardif_linux_wext.h"
#include "platform/linux/cardif_linux_rtnetlink.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}


static int send_and_recv_msgs(context *ctx,
			      struct nl_msg *msg,
			      int (*valid_handler)(struct nl_msg *, void *),
			      void *valid_data)
{
	struct nl_cb *cb;
	int err = 0;
	struct lin_nl80211_drv_handle *drv_handle = NULL;

	printf("-------> %s \n ", __FUNCTION__ );
	if (ctx->drv_handle == NULL)
	{
		debug_printf(DEBUG_NORMAL,"Couldn't find Context Netlink Driver Handle");
		return 1;
	}
	drv_handle=(struct lin_nl80211_drv_handle *)(ctx->drv_handle);
	cb = nl_cb_clone(drv_handle->nl_cb);
	if (!cb)
		goto out;

	err = nl_send_auto_complete(drv_handle->nl_handle, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0)
		nl_recvmsgs(drv_handle->nl_handle, cb);
 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}

static int cardif_linux_nl80211_set_key(context *ctx, drv_alg alg, 
				 const unsigned char *addr,
				 int key_idx, int set_tx, 
				 const unsigned char *seq,
				 int seq_len, const char *key,
				 int key_len )
{
	int err = 0;
	struct nl_msg *msg;
 	struct lin_nl80211_drv_handle *drv_handle = NULL;
	struct lin_sock_data *sockData = NULL;
	printf("-------> %s \n ", __FUNCTION__ );
 	if (ctx->drv_handle == NULL ) 
	{
		debug_printf(DEBUG_NORMAL,
			"Couldn't find Context Netlink Driver Handle");
		return 1; 
	}
 	drv_handle=(struct lin_nl80211_drv_handle *)(ctx->drv_handle);
	sockData = ctx->sockData;
	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Couldn't find Context Socket Data");
		return 1; 
	}	
	msg = nlmsg_alloc();
	if (msg == NULL)
	{
	 	debug_printf(DEBUG_NORMAL,
			"Unable to allocate an empty netlink message\n");
		return 1;
	}	
	if ( alg == DRV_ALG_NONE )
	{
		genlmsg_put(msg, 0, 0, genl_family_get_id(drv_handle->nl80211),
			     0, 0, NL80211_CMD_DEL_KEY, 0);
	}
	else 
	{
		genlmsg_put(msg, 0, 0, genl_family_get_id(drv_handle->nl80211),
			    0, 0, NL80211_CMD_NEW_KEY, 0);
		NLA_PUT(msg, NL80211_ATTR_KEY_DATA, key_len, key);
		switch (alg) {
		case DRV_ALG_WEP:
			if (key_len == 5)
				NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER,
					    0x000FAC01);
			else
				NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER,
					    0x000FAC05);
			break;
		case DRV_ALG_TKIP:
			NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER, 0x000FAC02);
			break;
		case DRV_ALG_CCMP:
			NLA_PUT_U32(msg, NL80211_ATTR_KEY_CIPHER, 0x000FAC04);
			break;
		default:
			nlmsg_free(msg);
			return 1;
		}
	}
	if (addr && memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) != 0)
	{
		debug_printf(DEBUG_NORMAL, "   addr=" MACSTR, MAC2STR(addr));
		NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
	}
	NLA_PUT_U8(msg, NL80211_ATTR_KEY_IDX, key_idx);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, sockData->sll.sll_ifindex);
	err = send_and_recv_msgs(ctx, msg, NULL, NULL);
	if (err) 
	{
		debug_printf(DEBUG_NORMAL, 
			"nl80211: set_key failed; err=%d", err);
		return 1;
	}
	if (set_tx && alg != DRV_ALG_NONE)
	{
		msg = nlmsg_alloc();
		if (msg == NULL)
		{
	 		debug_printf(DEBUG_NORMAL,
			"Unable to allocate an empty netlink message\n");
			return 1;
		}	
		genlmsg_put(msg, 0, 0, genl_family_get_id(drv_handle->nl80211),
				 0, 0, NL80211_CMD_SET_KEY, 0);
		NLA_PUT_U8(msg, NL80211_ATTR_KEY_IDX, key_idx);
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX,
				sockData->sll.sll_ifindex);
		NLA_PUT_FLAG(msg, NL80211_ATTR_KEY_DEFAULT);
		err = send_and_recv_msgs(ctx, msg, NULL, NULL);
		if (err) {
			debug_printf(DEBUG_NORMAL, 
			"nl80211: set default key failed err = %d",err);
			return 1;
		}
	}
	return 0;
nla_put_failure:
	return 1;
}

int driver_nl80211_init(context *ctx)
{
 struct lin_nl80211_drv_handle *drv_handle = NULL;

	printf("-------> %s \n ", __FUNCTION__ );
 ctx->drv_handle = Malloc(sizeof(struct lin_nl80211_drv_handle));
 if (ctx->drv_handle == NULL ) 
 {
	debug_printf(DEBUG_INIT,
		"Couldn't allocate memory for context netlink handle\n");
	return XEMALLOC; 
 }
 drv_handle=(struct lin_nl80211_drv_handle *)(ctx->drv_handle);

 drv_handle->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
 if ( drv_handle->nl_cb == NULL) 
 {
	debug_printf(DEBUG_INIT,"Couldn't allocate libnl callback set\n");
	return XEMALLOC;
 }
 drv_handle->nl_handle = nl_handle_alloc_cb( drv_handle->nl_cb);
 if ( drv_handle->nl_handle == NULL )
 {
	debug_printf(DEBUG_INIT,"Couldn't allocate libnl callback handle\n");
	nl_cb_put(drv_handle->nl_cb);
	return XEMALLOC;
 } 

 if ( genl_connect(drv_handle->nl_handle) )
 {
	debug_printf(DEBUG_INIT,"genl_connect call failed\n");
	nl_handle_destroy(drv_handle->nl_handle);
	nl_cb_put(drv_handle->nl_cb);
	return XEGENERROR;
 }

 drv_handle->nl_cache = genl_ctrl_alloc_cache(drv_handle->nl_handle);
 if ( drv_handle->nl_cache == NULL )
 {
	debug_printf(DEBUG_INIT,"Couldn't allocate cache in libnl\n");
	nl_handle_destroy(drv_handle->nl_handle);
	nl_cb_put(drv_handle->nl_cb);
	return XEMALLOC;
 }

 drv_handle->nl80211 = genl_ctrl_search_by_name(drv_handle->nl_cache,"nl80211"); if ( drv_handle->nl80211 == NULL )
 {
	debug_printf(DEBUG_INIT,
		"look up of nl80211 family in libnl cache failed\n");
	nl_cache_free(drv_handle->nl_cache);
	nl_handle_destroy(drv_handle->nl_handle);
	nl_cb_put(drv_handle->nl_cb);
	return XEMALLOC;
 }
 return XENONE;

}

unsigned int driver_nl80211_deinit(context *ctx)
{
 	struct lin_nl80211_drv_handle *drv_handle = NULL;
	printf("-------> %s \n ", __FUNCTION__ );
 	if (ctx->drv_handle == NULL ) 
	{
		debug_printf(DEBUG_NORMAL,
			"Couldn't find Context Netlink Driver Handle");
		return 1; 
	}
 	drv_handle=(struct lin_nl80211_drv_handle *)(ctx->drv_handle);

	genl_family_put(drv_handle->nl80211);
	nl_cache_free(drv_handle->nl_cache);
        nl_handle_destroy(drv_handle->nl_handle);
        nl_cb_put(drv_handle->nl_cb);
	free(ctx->drv_handle);
	return 0;
}


int  cardif_linux_nl80211_set_WEP_key(context *thisint, uint8_t *key, 
				  int keylen, int index)
{
	int rc = 0;
	int settx = 0;
	struct iwreq wrq;
	struct lin_sock_data *sockData;
	wireless_ctx *wctx = NULL;
	unsigned char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

	printf("-------> %s \n ", __FUNCTION__ );
	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    	return XEMALLOC;

	if (!xsup_assert((thisint->intTypeData != NULL), 
		"thisint->intTypeData != NULL",FALSE))
    return XEMALLOC;

	wctx = (wireless_ctx *)thisint->intTypeData;

	if (index & 0x80) settx = 1;

	rc = cardif_linux_nl80211_set_key(thisint, DRV_ALG_WEP, addr,
					  (index & 0x7f), settx, seq, 6, (char *)key,
				     keylen);
	if (rc == XENONE) return rc;
	debug_printf(DEBUG_INT, "Couldn't use extended key calls to set keys. \n");
	debug_printf(DEBUG_INT, "Trying old method.\n");

	memset(&wrq, 0x00, sizeof(wrq));

	if (thisint->intType != ETH_802_11_INT)
    {
		debug_printf(DEBUG_NORMAL, "Interface isn't wireless, but an attempt"
		   " to set a key was made!\n");
      return XENOWIRELESS;
    }

	sockData = thisint->sockData;
	xsup_assert((sockData != NULL), "sockData != NULL", TRUE);
 	if (sockData->sockInt <= 0)
    	return XENOSOCK;
 	Strncpy(wrq.ifr_name, sizeof(wrq.ifr_name), thisint->intName, 
	  strlen(thisint->intName)+1);
 	if (strlen(wrq.ifr_name) == 0)
	{
		debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
                   __FUNCTION__, __LINE__);
		return XEGENERROR;
	}
	wrq.u.data.flags = ((index & 0x7f)+1);
	if (TEST_FLAG(wctx->flags, WIRELESS_DONT_USE_TEMP))
    	wrq.u.data.flags |= IW_ENCODE_OPEN;
	else
		wrq.u.data.flags |= IW_ENCODE_OPEN | IW_ENCODE_TEMP;
	wrq.u.data.length = keylen;
	wrq.u.data.pointer = (caddr_t)key;
	if ((rc = ioctl(sockData->sockInt, SIOCSIWENCODE, &wrq)) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to set WEP key [%d], error %d : %s\n",
		   (index & 0x7f) + 1, errno, strerror(errno));
      rc = XENOKEYSUPPORT;
    } else 
	{
		debug_printf(DEBUG_INT, "Successfully set WEP key [%d]\n",
					(index & 0x7f)+1);
		if (index & 0x80)
		{
			Strncpy(wrq.ifr_name, sizeof(wrq.ifr_name), thisint->intName, 
		  			strlen(thisint->intName)+1);
			if (strlen(wrq.ifr_name) == 0)
			{
				debug_printf(DEBUG_NORMAL, 
							"Invalid interface name in %s():%d\n",
			   				__FUNCTION__, __LINE__);
				return XEGENERROR;
			}
			wrq.u.data.flags = 	(((index & 0x7f) + 1) & IW_ENCODE_INDEX) | 
								IW_ENCODE_NOKEY;
	  		if (TEST_FLAG(wctx->flags, WIRELESS_DONT_USE_TEMP))
	    		wrq.u.data.flags |= IW_ENCODE_OPEN;
			else
				wrq.u.data.flags |= IW_ENCODE_OPEN | IW_ENCODE_TEMP;
			wrq.u.data.length = 0;
			wrq.u.data.pointer = (caddr_t)NULL;
			if (ioctl(sockData->sockInt, SIOCSIWENCODE, &wrq) < 0)
			{
	      		debug_printf(	DEBUG_NORMAL,
								"Failed to set the WEP transmit key ID [%d]\n", 
								(index & 0x7f)+1);
	      		rc = XENOKEYSUPPORT;
	    	} else 
			{	
	      		debug_printf(	DEBUG_INT, 
								"Successfully set the WEP transmit key [%d]\n", 
								(index & 0x7f)+1);
	    	}
		}  
    }
	return rc;
}

int cardif_linux_nl80211_set_tkip_key(context *intdata, 
				   unsigned char *addr, int keyidx, int settx, 
				   char *key, int keylen)
{
  unsigned char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  return cardif_linux_nl80211_set_key(intdata, DRV_ALG_TKIP, addr,
				       keyidx, settx, seq, 6, key, keylen);
}

int cardif_linux_nl80211_set_ccmp_key(context *intdata,
				   unsigned char *addr, int keyidx, int settx,
				   char *key, int keylen)
{
  	unsigned char seq[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

  	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    	return XEMALLOC;
  
	return cardif_linux_nl80211_set_key(intdata, DRV_ALG_CCMP, addr,
				       keyidx, settx, seq, 6, key,keylen);
}

int cardif_linux_nl80211_delete_key(context *intdata, int key_idx, int set_tx)
{
  	if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    	return XEMALLOC;

  	debug_printf(DEBUG_INT, "Deleting key %d, with tx set to %d.\n", key_idx,
	       set_tx);
	
  	return cardif_linux_nl80211_set_key(intdata, DRV_ALG_NONE, NULL,
				       key_idx, set_tx, NULL, 0, NULL, 0);
}



struct cardif_funcs cardif_linux_nl80211_driver = {
  .scan = cardif_linux_wext_scan,
  .disassociate = cardif_linux_wext_disassociate,
  .set_wep_key = cardif_linux_nl80211_set_WEP_key,
  .set_tkip_key = cardif_linux_nl80211_set_tkip_key,
  .set_ccmp_key = cardif_linux_nl80211_set_ccmp_key,
  .delete_key = cardif_linux_nl80211_delete_key,
  .associate = cardif_linux_wext_associate,
  .get_ssid = cardif_linux_wext_get_ssid,
  .get_bssid = cardif_linux_wext_get_bssid,
  .wpa_state = cardif_linux_wext_wpa_state,
  .wpa = cardif_linux_wext_wpa,
  .wep_associate = cardif_linux_wext_wep_associate,
  .countermeasures = cardif_linux_wext_countermeasures,
  .drop_unencrypted = cardif_linux_wext_drop_unencrypted,
  .get_wpa_ie = cardif_linux_wext_get_wpa_ie,
  .get_wpa2_ie = cardif_linux_wext_get_wpa2_ie,
  .enc_disable = cardif_linux_wext_enc_disable,
  .enc_capabilities = cardif_linux_wext_enc_capabilities,
  .setbssid = cardif_linux_wext_set_bssid,
  .set_operstate = cardif_linux_rtnetlink_set_operstate,
  .set_linkmode = cardif_linux_rtnetlink_set_linkmode,
};



#endif // DISABLE_LIBNL



