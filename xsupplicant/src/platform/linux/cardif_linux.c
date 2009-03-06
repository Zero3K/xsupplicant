/**
 * Linux card interface implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_linux.c
 *
 * \author chris@open1x.org
 *
 **/

#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <iwlib.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <utmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <string.h>

#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "config_ssid.h"
#include "platform/linux/cardif_linux_wext.h"
#include "platform/cardif.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "snmp.h"
#include "statemachine.h"
#include "wireless_sm.h"
#include "platform/linux/cardif_linux.h"
#include "platform/linux/cardif_linux_rtnetlink.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "timer.h"
#include "event_core.h"
#include "eapol.h"
#include "interfaces.h"
#include "platform/linux/cardif_linux_nl80211.h"
#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

// Define this, so the compiler doesn't complain.
extern unsigned int if_nametoindex(const char *);

// This contains a pointer to the functions needed for wireless.  
struct cardif_funcs *wireless;

// Store values about what state our interface was in before we start messing
// with it.
struct int_starting_data *startup;

/**
 * \brief Get the MAC address of an interface based on it's name. (Without
 *        using a context.)
 *
 * @param[in] intname   A string that contains the interface name that we
 *                      want to get the MAC address for.
 *
 * @param[out] intmac   The interface MAC address of the interface named by
 *                      intname.
 *
 * \retval XEGENERROR on general error
 * \retval XENONE on success
 **/
int get_mac_by_name_no_ctx(char *intname, char *intmac)
{
  struct ifreq ifr;
  int sock = -1;
  int retval = XENONE;
 
  sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));
  if (sock < 0) return XEGENERROR;

  memset(&ifr, 0x00, sizeof(ifr));

  if (strlen(intname) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
		   __FUNCTION__, __LINE__);
      close(sock);
      return XEGENERROR;
    }

  ifr.ifr_ifindex = if_nametoindex(intname);

  // Tell the ifreq struct which interface we want to use.
  Strncpy((char *)&ifr.ifr_name, sizeof(ifr.ifr_name), intname, strlen(intname)+1);

  // Get our MAC address.
  retval = ioctl(sock, SIOCGIFHWADDR, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting hardware (MAC) address for "
		   "interface %s!\n", intname);
      debug_printf(DEBUG_NORMAL, "Error was (%d) : %s\n", errno, strerror(errno));
    }

  memcpy(intmac, (char *)&ifr.ifr_hwaddr.sa_data[0], 6);

  close(sock);

  return XENONE;
}

/**
 * \brief Get the MAC address of an interface based on it's name.
 *
 * @param[in] intname   A string that contains the interface name that we
 *                      want to get the MAC address for.
 *
 * @param[out] intmac   The interface MAC address of the interface named by
 *                      intname.
 *
 * \retval XEGENERROR on general error
 * \retval XENONE on success
 **/
int get_mac_by_name(char *intname, char *intmac)
{
  struct ifreq ifr;
  struct lin_sock_data *sockData = NULL;
  int retval = XENONE;
  context *ctx = NULL;
 
  ctx = event_core_get_active_ctx();

  if (ctx == NULL) return get_mac_by_name_no_ctx(intname, intmac);

  sockData = ctx->sockData;

  memset(&ifr, 0x00, sizeof(ifr));

  if (strlen(intname) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
		   __FUNCTION__, __LINE__);
      return XEGENERROR;
    }

  ifr.ifr_ifindex = if_nametoindex(intname);

  // Tell the ifreq struct which interface we want to use.
  Strncpy((char *)&ifr.ifr_name, sizeof(ifr.ifr_name), intname, strlen(intname)+1);

  // Get our MAC address.
  retval = ioctl(sockData->sockInt, SIOCGIFHWADDR, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting hardware (MAC) address for "
		   "interface %s!\n", intname);
      debug_printf(DEBUG_NORMAL, "Error was (%d) : %s\n", errno, strerror(errno));
    }

  memcpy(intmac, (char *)&ifr.ifr_hwaddr.sa_data[0], 6);

  return XENONE;
}


/**
 * Clear all keys, and accept unencrypted traffic again.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to allow unencrypted traffic on again.
 **/
void cardif_linux_clear_keys(context *ctx)
{
  int i;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  debug_printf(DEBUG_INT, "Clearing keys!\n");

  debug_printf(DEBUG_INT, "Allowing unencrypted frames again.\n");
  cardif_drop_unencrypted(ctx, 0);
  
  // Clear the PTK.
  debug_printf(DEBUG_INT, "Clearing PTK.\n");
  cardif_delete_key(ctx, 0, 1);

  for (i=0;i<4;i++)
    {
      debug_printf(DEBUG_INT, "Clearing key index %d.\n", i);
      cardif_delete_key(ctx, i, 0);
    }

  cardif_linux_wext_enc_disable(ctx);
}

/**
 * \brief Determine if we are currently associated. 
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  check the association status on.
 *
 * \retval XEMALLOC on error
 * \retval IS_UNASSOCIATED when the interface isn't associated
 * \retval IS_ASSOCIATED when the interface is associated
 **/
int cardif_check_associated(context *ctx)
{
  char newmac[6], curbssid[6];

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  // If we are wired, this function doesn't do anything useful.
  if (ctx->intType != ETH_802_11_INT) return XENONE;

  cardif_GetBSSID(ctx, curbssid);

  memset(newmac, 0x00, 6);
  if (memcmp(newmac, curbssid, 6) == 0)
    {
      return IS_UNASSOCIATED;
    }

  memset(newmac, 0x44, 6);
  if (memcmp(newmac, curbssid, 6) == 0)
    {
      return IS_UNASSOCIATED;
    }

  memset(newmac, 0xFF, 6);
  if (memcmp(newmac, curbssid, 6) == 0)
    {
      return IS_UNASSOCIATED;
    }

  //Otherwise, we are associated.
  return IS_ASSOCIATED;
}

/**
 * \brief Set up the wireless cardif_funcs structure to the driver that the 
 *        user has requested.
 *
 * @param[in] driver   A number that identifies the driver that we want to use.
 **/
void cardif_set_driver(char driver, context *ctx)
{
  switch (driver)
    {
    case DRIVER_NONE:
      wireless = NULL;
      break;

#ifndef DISABLE_LIBNL
    case DRIVER_NL80211:
        if ( driver_nl80211_init(ctx) )
        {
                return;
        }
                else
        {
                wireless = &cardif_linux_nl80211_driver;
        }
        break;
#endif // DISABLE_LIBNL

    default:
    case DRIVER_WEXT:
      wireless = &cardif_linux_wext_driver;
      break;
    }
}

/**
 * \brief Initialize an interface.
 *
 * Do whatever is needed to get the interface in to a state that we can send
 * and recieve frames on the network.  Any information that we need to later
 * use should be stored in the context structure.
 *
 * @param[in] ctx   The context that contains enough information for us to
 *                  init the interface.
 * @param[in] driver   A number that identifies the driver that this card is
 *                     using.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XEGENERROR on general error
 * \retval XENONE on success
 **/
int cardif_init(context *ctx, char driver)
{
  struct ifreq ifr;
  struct lin_sock_data *sockData;
  int retval;
  struct config_globals *globals;
  wireless_ctx *wctx = NULL;
  wctx = (wireless_ctx *) ctx->intTypeData;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  // Get the information about the global settings from the config file.
  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return XEGENERROR;

  debug_printf(DEBUG_INT, "Initializing socket for interface %s..\n",
	       ctx->intName);

  // Allocate memory for the things we need.
  ctx->sockData = (void *)Malloc(sizeof(struct lin_sock_data));
  if (ctx->sockData == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error allocating memory!\n");
      return XEMALLOC;
    }

  sockData = ctx->sockData;

  // Establish a socket handle.
  sockData->sockInt = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));
  if (sockData->sockInt < 0)
    {
      debug_printf(DEBUG_NORMAL, 
		   "Couldn't initialize raw socket for interface %s!\n",
		   ctx->intName);
      return XENOSOCK;
    }        

  // Build our link layer socket struct, so we can bind it to a specific
  // interface.
  sockData->sll.sll_family = PF_PACKET;
  sockData->sll.sll_ifindex = if_nametoindex(ctx->intName);
  sockData->sll.sll_protocol = htons(ETH_P_EAPOL);

  // Bind to the interface.
  retval = bind(sockData->sockInt, (const struct sockaddr *)&sockData->sll, 
		sizeof(struct sockaddr_ll));
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error binding raw socket to interface %s!\n",
		   ctx->intName);
      return XESOCKOP;
    }

  memset(&ifr, 0x00, sizeof(ifr));

  if (strlen(ctx->intName) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
                   __FUNCTION__, __LINE__);
      return XEGENERROR;
    }

  ifr.ifr_ifindex = if_nametoindex(ctx->intName);

  // Tell the ifreq struct which interface we want to use.
  Strncpy((char *)&ifr.ifr_name, sizeof(ifr.ifr_name), ctx->intName, 
	  strlen(ctx->intName)+1);

  // Get our MAC address.  (Needed for sending frames out correctly.)
  retval = ioctl(sockData->sockInt, SIOCGIFHWADDR, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting hardware (MAC) address for interface %s!\n",
		   ctx->intName);
      debug_printf(DEBUG_NORMAL, "Error was (%d) : %s\n", errno, strerror(errno)); 
      return XENOTINT;
    }

  // Store a copy of our source MAC for later use.
  memcpy((char *)&ctx->source_mac[0], (char *)&ifr.ifr_hwaddr.sa_data[0], 6);

  // Check if we want ALLMULTI mode, and enable it.
  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ALLMULTI))
    {
      if (strlen(ctx->intName) == 0)
        {
          debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
                       __FUNCTION__, __LINE__);
          return XEGENERROR;
        }

      // Tell the ifreq struct which interface we want to use.
      Strncpy((char *)&ifr.ifr_name, sizeof(ifr.ifr_name), ctx->intName, 
	      strlen(ctx->intName)+1);

      if (ioctl(sockData->sockInt, SIOCGIFFLAGS, &ifr) < 0)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't determine if ALLMULTI is enabled!\n");
	} else {
	  if (ifr.ifr_flags & IFF_ALLMULTI)
	    {
	      debug_printf(DEBUG_INT, "Allmulti mode is already enabled on this device!\n");
	      ctx->flags |= ALLMULTI;
	    } else {
	      debug_printf(DEBUG_INT, "Allmulti is currently disabled on this device!\n");
	      ctx->flags &= ~ALLMULTI;
	    }
	}

      debug_printf(DEBUG_INT, "Turning on ALLMULTI mode.\n");
      ifr.ifr_flags |= IFF_ALLMULTI;
      if (ioctl(sockData->sockInt, SIOCSIFFLAGS, &ifr) < 0)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't set ALLMULTI mode on this interface!  We will continue anyway!\n");
	}
    }

  // Set up wireless card drivers.
  cardif_set_driver(driver,ctx);

  if (cardif_int_is_wireless(ctx) == TRUE)
    {
      debug_printf(DEBUG_INT, "Interface is wireless.\n");
      ctx->intType = ETH_802_11_INT;

      if (context_create_wireless_ctx((wireless_ctx **)&ctx->intTypeData, 0) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't create wireless context for "
		       "interface!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_CANT_CREATE_WIRELESS_CTX, ctx->desc);
	  return -1;
	}

      cardif_disassociate(ctx, 0);

      ctx->intType = ETH_802_11_INT;

      wctx = (wireless_ctx *) ctx->intTypeData;
      if (wctx != NULL) {
        wctx->pmkids_supported = 1;
        pmksa_cache_init(ctx);
      }

    }

  ctx->sendframe = Malloc(FRAMESIZE);
  if (ctx->sendframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store frames "
		   "to be sent.\n");
      return XEMALLOC;
    }

  cardif_linux_rtnetlink_set_linkmode(ctx, IF_LINK_MODE_DORMANT);

  event_core_register(cardif_get_socket(ctx), ctx, eapol_withframe,
                      LOW_PRIORITY, "frame handler");
	  
  return XENONE;
}

/**
 * \brief Tell the wireless card to start scanning for wireless networks.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  start scanning for networks.
 * @param[in] passive  TRUE if we want to do a passive scan.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success (or nothing to do)
 **/
int cardif_do_wireless_scan(context *ctx, char passive)
{
  wireless_ctx *wctx = NULL;
   int resval = 0;
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return XEMALLOC;

  if (wireless == NULL) 
    {
      debug_printf(DEBUG_INT, "No valid wireless calls struct! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

  if (wireless->scan == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No scan function defined!\n");
      return XEMALLOC;
    }

  wctx = (wireless_ctx *)ctx->intTypeData;

  // If we are already scanning, then we shouldn't get here, but go ahead 
  // and ignore it anyway.
  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING) )
    {
      debug_printf(DEBUG_INT, "Got a request to start a new scan when one is"
		   " already in progress!  Ignoring!\n");
      return XENONE;
    }

  SET_FLAG(wctx->flags, WIRELESS_SCANNING);
  //This is moved to cardif_linux_rtnetlink_check_nets() to allow the cache to be used till
  //we actually get the data from scanning
  //config_ssid_clear(wctx);

 resval = wireless->scan(ctx, passive);

  if (resval != XENONE)
  {
          // We had an error trying to scan, so clear the scanning flag.
          UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);
  }

  return resval;
}

/**
 * \brief Send a disassociate message.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to send a disassociate message with.
 * @param[in] reason_code   The reason for the disassociation. (Reason codes
 *                          are specified in the 802.11 standards.)
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_disassociate(context *ctx, int reason_code)
{
  wireless_ctx *wctx = NULL;
  wctx = (wireless_ctx *) ctx->intTypeData;
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if(TEST_FLAG(ctx->flags, INT_GONE)) 
	return XENONE;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->disassociate == NULL) return XEMALLOC;

  debug_printf(DEBUG_INT, "Called %s\n", __FUNCTION__);
  return wireless->disassociate(ctx, reason_code);
}

/**
 * \brief Return the socket number for functions that need it.
 *
 * @param[in] ctx   The context that contains the socket number we are
 *                  looking for.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_get_socket(context *ctx)
{
  struct lin_sock_data *sockData;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  return sockData->sockInt;
}

/**
 * \brief Clean up an interface.
 *
 * Clean up anything that was created during the initialization and operation
 * of the interface.  This will be called before the program terminates.
 *
 * @param[in] ctx   The context that contains the interface that we want to 
 *                  clean up.
 *
 * \retval XENONE on success
 * \retval XEGENERROR on general error
 **/
int cardif_deinit(context *ctx)
{
  struct ifreq ifr;
  uint16_t int16;
  struct lin_sock_data *sockData;
  uint8_t all0s[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_linux_rtnetlink_set_operstate(ctx, XIF_OPER_UP);
  if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_linux_rtnetlink_set_linkmode(ctx, XIF_LINK_MODE_DEFAULT);


  FREE(ctx->sendframe);
  FREE(ctx->recvframe);
  
  sockData = ctx->sockData;

  debug_printf(DEBUG_INT | DEBUG_DEINIT, "Cleaning up interface %s...\n",ctx->intName);

  if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_linux_rtnetlink_cleanup(ctx);

  if (ctx->intType == ETH_802_11_INT)
  {
    pmksa_cache_deinit(ctx);
    // Remove all of the keys that we have set.
    if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_linux_clear_keys(ctx);

    debug_printf(DEBUG_INT, "Turning off WPA support/state.\n");

    // Clear the WPA IE.
    if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_linux_wext_set_wpa_ie(ctx, NULL, 0);

    if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_disable_wpa_state(ctx);

    // Reset the MAC address to all 0s.  (This tells the driver to
    // scan for new associations.
    if (!TEST_FLAG(ctx->flags, INT_GONE)) cardif_setBSSID(ctx, all0s);
  }

  // Check if we want ALLMULTI mode, and enable it.
  if (TEST_FLAG(ctx->flags, ALLMULTI))
    {
      memset(&ifr, 0x00, sizeof(ifr));

      // Tell the ifreq struct which interface we want to use.
      Strncpy((char *)&ifr.ifr_name, sizeof(ifr.ifr_name), ctx->intName, 
	      strlen(ctx->intName)+1);

      if (strlen(ifr.ifr_name) == 0)
	{
	  debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
		       __FUNCTION__, __LINE__);
	  return XEGENERROR;
	}

      if (ioctl(sockData->sockInt, SIOCGIFFLAGS, &ifr) < 0)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't get interface flags!\n");
	} else {
	  // Check if allmulti was disabled when we started.  If it was,
	  // then disable it again, so everything is good.
	  if (!(ctx->flags & ALLMULTI))
	    {
	      debug_printf(DEBUG_INT, "Turning off ALLMULTI mode!\n");

	      int16 = ifr.ifr_flags;

	      // ANDing the flags with 0xfdff will turn off the ALLMULTI flag.
	      ifr.ifr_flags = (int16 & 0xfdff);
	      if (ioctl(sockData->sockInt, SIOCSIFFLAGS, &ifr) < 0)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't set ALLMULTI mode on this interface!  We will continue anyway!\n");
		}
	    }
	}
    }

  close(sockData->sockInt);

#ifndef DISABLE_LIBNL
  if (driver_nl80211_deinit(ctx) )
        {
                debug_printf(DEBUG_DEINIT,"nl80211 Driver De-init Failed\n");
        }
#endif  // DISABLE_LIBNL

  // Now clean up the memory.
  FREE(ctx->sockData);

  return XENONE;
}

/**
 * \brief Set a WEP key.  Also, based on the index, we may change the transmit
 *        key.
 *
 * @param[in] ctx   The context that contains the interface that we want to 
 *                  change the WEP key on.
 * @param[in] key   A pointer to a buffer that contains the key to be set.
 * @param[in] keylen   The amount of data in the buffer "key" that should be
 *                     used as a key.
 * @param[in] index   The key index to install the key in to.  If
 *                    (index & 0x80) then this is a transmit key, and the
 *                    transmit key index will be changed as well.
 *
 * \retval XEMALLOC on memory allocation error.
 * \retval XENONE on success
 **/
int cardif_set_wep_key(context *ctx, uint8_t *key, int keylen, int index)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((key != NULL), "key != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_wep_key == NULL) return XEMALLOC;

  return wireless->set_wep_key(ctx, key, keylen, index);
}

/**
 * \brief Set a freq.  *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  change the WEP key on.
 *
 * \retval XEMALLOC on memory allocation error.
 * \retval XENONE on success
 **/

int cardif_set_freq( context *ctx )
{
   if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
        return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_freq == NULL) return XEMALLOC;

  return wireless->set_freq(ctx);
}

/**
 * \brief Set a TKIP key. 
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  set the TKIP key on.
 * @param[in] addr   The BSSID of the AP that this key should be used with.
 *                   (Should be ff:ff:ff:ff:ff:ff for broadcast keys!)
 * @param[in] keyidx   Set to TRUE if this key should be used as a transmit
 *                     key.
 * @param[in] key   A pointer to a buffer that contains the key to be set.
 * @param[in] keylen   The amount of data in the buffer pointed to by "key"
 *                     that contains the key data.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_set_tkip_key(context *ctx, char *addr,  int keyidx, int settx, 
			char *key, int keylen)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_tkip_key == NULL) return XEMALLOC;

  return wireless->set_tkip_key(ctx, (uint8_t *) addr, keyidx, settx, 
				key, keylen);
}

/**
 * \brief Set a CCMP (AES) key
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  set the CCMP key on.
 * @param[in] addr   The BSSID of the AP that this key should be used with.
 *                   (Should be ff:ff:ff:ff:ff:ff for broadcast keys!)
 * @param[in] keyidx   The index that this key should be installed in to.
 * @param[in] settx   Set to TRUE if this key should be used as a transmit key.
 * @param[in] key   A pointer to a buffer that contains the key to be set.
 * @param[in] keylen   The amount of data in the buffer pointed to by "key" 
 *                     that contains the key data.
 *
 * \retval XEMALLOC on memory allocation error.
 * \retval XENONE on success
 **/
int cardif_set_ccmp_key(context *ctx, char *addr, int keyidx,
			int settx, char *key, int keylen)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->set_ccmp_key == NULL) return XEMALLOC;

  return wireless->set_ccmp_key(ctx, (uint8_t *) addr, keyidx, settx,
				key, keylen);
}

/**
 * \brief Delete a key
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  delete a key from.
 * @param[in] key_idx   The index for the key that we want to delete.
 * @param[in] set_tx   TRUE if the key is a transmit key, FALSE if it isn't.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_delete_key(context *ctx, int key_idx, int set_tx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->delete_key == NULL) return XEMALLOC;

  return wireless->delete_key(ctx, key_idx, set_tx);
}

/**
 * \brief Attempt to associate to a non-WEP network.
 *
 * Do whatever we need to do in order to associate based on the flags in
 * the ssids_list struct.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  attempt an association on.
 **/
void cardif_associate(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (wireless == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Invalid wireless structure in %s() at %d.\n",
		   __FUNCTION__, __LINE__);
      return;
    }

  if (wireless->associate == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Attempted to associate using an invalid "
		   "wireless driver struct in %s() at %d.\n", __FUNCTION__,
		   __LINE__);
      return;
    }

  wireless->associate(ctx);
}

/**
 * \brief Request the current SSID from the driver/card.
 *
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 *
 * @param[in] ctx   The context that contains the interface that we are 
 *                  requesting the SSID for.
 *
 * @param[in,out] ssid_name   A pointer to a buffer that will contain the
 *                            SSID.  This should be at least 33 characters
 *                            long!
 * @param[in] ssid_buf_size   An integer that specifies the size of the 
 *                            buffer pointed to by "ssid_name".
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_GetSSID(context *ctx, char *ssid_name, unsigned int ssid_buf_size)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ssid_name != NULL), "ssid_name != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "No valid call to get SSID for this driver!"
		   "\n");
      return XEMALLOC;
    }

  if ((ctx == NULL) || (ssid_name == NULL)) 
  {
    debug_printf(DEBUG_INT, "NULL value passed to %s!\n", __FUNCTION__);
    return XEMALLOC;
  }

  return wireless->get_ssid(ctx, ssid_name, ssid_buf_size);
}

/******************************************
 *
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 ******************************************/
int cardif_GetBSSID(context *thisint, char *bssid_dest)
{
  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((bssid_dest != NULL), "bssid_dest != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return -1;

  if (thisint == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface data structure passed to %s!\n", __FUNCTION__);
      return -1;
    }

  if (bssid_dest == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid bssid_dest in %s!\n", __FUNCTION__);
      return -1;
    }

  return wireless->get_bssid(thisint, bssid_dest);
}

/**
 * \brief Determine the state of the interface.
 *
 * Set the flag in the state machine that indicates if this interface is up
 * or down.  If there isn't an interface, we should return an error.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  determine the up/down state for.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 * \retval XEGENERROR on general error
 **/
int cardif_get_if_state(context *ctx)
{
  int retVal;
  struct ifreq ifr;
  struct lin_sock_data *sockData;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  memset(&ifr, 0x00, sizeof(ifr));
  Strncpy(ifr.ifr_name, sizeof(ifr.ifr_name), ctx->intName, 
	  strlen(ctx->intName)+1);

  if (strlen(ifr.ifr_name) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
                   __FUNCTION__, __LINE__);
      return XEGENERROR;
    }

  retVal = ioctl(sockData->sockInt, SIOCGIFFLAGS, &ifr);
  if (retVal < 0)
    {
      debug_printf(DEBUG_NORMAL, "Interface %s not found!\n", ctx->intName);
      return FALSE;
    }
  if (ctx->intType == ETH_802_11_INT)
  {
	if ((ifr.ifr_flags & IFF_UP) == IFF_UP) 
	{
      	return TRUE;
    	} else {
      SET_FLAG(ctx->flags, WAS_DOWN);
      return FALSE;
    }
  }
  else
  {
  	if (((ifr.ifr_flags & IFF_UP) == IFF_UP) && (ctx->flag_link_state == 1))
    	{
      	return TRUE;
    	} else {
      	SET_FLAG(ctx->flags, WAS_DOWN);
      	return FALSE;
    	}
  }
  return XENONE;
}

/**
 * \brief Get the link state of an interface.
 *
 * @param[in] ctx   The context for the interface that we want to determine the link
 *                  state of an interface for.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval TRUE if link is up
 * \retval FALSE if link is down
 **/
int cardif_get_link_state(context *ctx)
{
  int result = 0;
  struct lin_sock_data *sockData = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (TEST_FLAG(ctx->flags, INT_GONE)) return FALSE;  // The interface isn't there, so it can't be up. ;)

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

#warning This is a stub.  Need to implement.

  if (result == 0)
    {
      return TRUE;
    }

  return FALSE;
}

/**
 * \brief Send a frame out a network card interface.
 *
 * Send a frame out of the network card interface.  If there isn't an 
 * interface, we should return an error.  We should return a different error
 * if we have a problem sending the frame.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  send a frame out.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on nothing to do
 * \retval XEGENERROR on general error
 * \retval >0 on success
 **/
int cardif_sendframe(context *ctx)
{
  char nomac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  int retval;
  struct lin_sock_data *sockData;
  uint16_t pad;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  if (ctx->send_size == 0) 
    {
      debug_printf(DEBUG_INT, "%s:%d -- Nothing to send!\n",
		   __FUNCTION__, __LINE__);
      return XENONE;
    }

  if (ctx->conn == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No connection information available!\n");
      return XENONE;
    }

  // The frame we are handed in shouldn't have a src/dest, so put it in.
  memcpy(&ctx->sendframe[0], &ctx->dest_mac[0], 6);
  memcpy(&ctx->sendframe[6], &ctx->source_mac[0], 6);

  if (ctx->conn == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No connection information available!  Can't"
		   " complete authentication!\n");
      return XEGENERROR;
    }

  if (memcmp(nomac, (char *)&ctx->conn->dest_mac[0], 6) != 0)
    {
      debug_printf(DEBUG_INT, "Static MAC address defined!  Using it!\n");
      memcpy(&ctx->sendframe[0], &ctx->conn->dest_mac[0], 6);
    }

  // Make sure the frame is large enough.
  if (ctx->send_size < 64)
    {
      pad = 64 - ctx->send_size;
      debug_printf(DEBUG_INT, "Padding frame to 64 bytes by adding %d byte"
		   "(s).\n", pad);
      memset(&ctx->sendframe[ctx->send_size+1], 0x00, pad);
      ctx->send_size += pad;
    }

  debug_printf(DEBUG_INT, "Frame to be sent (%d) : \n",
	       ctx->send_size);
  debug_hex_dump(DEBUG_INT, ctx->sendframe, ctx->send_size);

  snmp_dot1xSuppEapolFramesTx();

  retval = sendto(sockData->sockInt, ctx->sendframe, ctx->send_size, 0,
		  NULL, 0);
  if (retval <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't send frame! (%s)\n", strerror(errno));
    }

  memset(ctx->sendframe, 0x00, FRAMESIZE);
  ctx->send_size = 0;
  
  // Clear out the receive buffer so we don't accidently try to process it
  // again.
  if (ctx->recvframe != NULL)
    {
      memset(ctx->recvframe, 0x00, FRAMESIZE);
      ctx->recv_size = 0;
    }

  return retval;
}

/**
 * \brief Get a frame from a network interface.
 * 
 * Get a frame from the network.  Make sure to check the frame, to determine 
 * if it is something we care about, and act accordingly.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  get a frame from.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENOFRAMES if there are no frames to be had
 * \retval >0 if a frame was received
 **/
int cardif_getframe(context *ctx)
{
  int newsize=0;
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
  struct lin_sock_data *sockData;
  uint8_t *resultframe;
  int resultsize;
  struct config_globals *globals;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return XEMALLOC;

  sockData = ctx->sockData;

  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  errno = 0;
  resultsize = FRAMESIZE; /* overflows resultframe if too large, or should we increase resultframe instead? */

  FREE(ctx->recvframe);

  resultframe = Malloc(FRAMESIZE);
  if (resultframe == NULL)
    {
      debug_printf(DEBUG_INT, "Couldn't allocate memory for incoming frame!\n");
      return -1;
    }

  newsize = recvfrom(sockData->sockInt, resultframe, resultsize, 0, 0, 0);
  if (newsize <= 0)
    {
      if ((errno != EAGAIN) && (errno != ENETDOWN))
	{
	  debug_printf(DEBUG_NORMAL, "Error (%d) : %s  (%s:%d)\n", errno,
		       strerror(errno), __FUNCTION__, __LINE__);
	}
      return XENOFRAMES;
    } else {
      debug_printf(DEBUG_INT, "Got Frame (%d) : \n", newsize);
      debug_hex_dump(DEBUG_INT, resultframe, newsize);
    }

  snmp_dot1xSuppEapolFramesRx();

  // Make sure that the frame we got is for us..
  if ((memcmp(&ctx->source_mac[0], &resultframe[0], 6) == 0) ||
      ((memcmp(&resultframe[0], &dot1x_default_dest[0], 6) == 0) &&
       (memcmp(&resultframe[6], &ctx->source_mac[0], 6) != 0)))
    {
      // Since we now know this frame is for us, record the address it
      // came from.
      snmp_dot1xSuppLastEapolFrameSource((uint8_t *)&resultframe[6]);

      resultsize = newsize;

      switch (globals->destination)
	{
	case DEST_AUTO:
	  // If it is a wired interface, only change the destination if
	  // the recieved frame destination isn't the multicast address.
	  if (ctx->intType == ETH_802_11_INT)
	    {
	      if (memcmp(&resultframe[0], dot1x_default_dest, 6) == 0)
		{
		  break;
		}
	      // Otherwise, fall through.
	    }
	  else
	    {
	      break;
	    }

	case DEST_SOURCE:
	  if (memcmp(ctx->dest_mac, &resultframe[6], 6) != 0)
	    {
	      debug_printf(DEBUG_INT, "Changing destination mac to source.\n");
	    }
	  memcpy(ctx->dest_mac, &resultframe[6], 6);
	  break;

	case DEST_MULTICAST:
	  memcpy(ctx->dest_mac, dot1x_default_dest, 6);
	  break;

	case DEST_BSSID:
	  cardif_GetBSSID(ctx, ctx->dest_mac);
	  break;

	default:
	  debug_printf(DEBUG_NORMAL, "Unknown destination mode!\n");
	  break;
	}

      ctx->recv_size = newsize;

      ctx->recvframe = resultframe;
      return newsize;
    }

  // Otherwise it isn't for us. 
  debug_printf(DEBUG_INT, "Got a frame, not for us.\n");
  return XENOFRAMES;
}

/**
 * \brief Set the state needed to associate to a WPA enabled AP, and actually
 *        do a WPA authentication.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  enable WPA state on.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval XENONE on success
 **/
int cardif_enable_wpa_state(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->wpa_state == NULL) return XEMALLOC;

  debug_printf(DEBUG_INT, "WPA: Enabling WPA state on interface %s.\n",ctx->intName);

  return wireless->wpa_state(ctx, TRUE);
}

/**
 * \brief Clear the state needed to associate to a WPA enabled AP, and actually
 *        do a WPA authentication.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  clear WPA state from.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation failure
 **/
int cardif_disable_wpa_state(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->wpa_state == NULL) return XEMALLOC;

  return wireless->wpa_state(ctx, FALSE);
}

/**
 * \brief Enable WPA (if it is supported.)
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  enable WPA on.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation failure
 **/
int cardif_enable_wpa(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  debug_printf(DEBUG_INT, "WPA: Enabling WPA on interface %s.\n",ctx->intName);

  return wireless->wpa(ctx, TRUE);
}

/**
 * \brief Call this when we roam to a different AP, or disassociate from an AP.
 *
 * @param[in] ctx   The context that contains the interface that we want to 
 *                  associate with using WEP.
 * @param[in] zeros   TRUE if we should set all of the WEP keys to 0s, FALSE
 *                    if all of the WEP keys should just be cleared.
 * 
 * \retval XENONE on success, or not needed
 * \retval XEMALLOC on memory allocation failure
 **/
int cardif_wep_associate(context *ctx, int zeros)
{
  wireless_ctx *wctx;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!config_ssid_using_wep(wctx))
    {
      debug_printf(DEBUG_INT, "Doing WPA/WPA2 mode! Not "
		   "setting/unsetting keys.\n");
      return XENONE;
    }

  return wireless->wep_associate(ctx, zeros); 
}

/**
 * \brief Validate an interface, based on if it has a MAC address.
 *
 * @param[in] interface   The interface name to check.
 *
 * \retval FALSE if it isn't a valid interface
 * \retval TRUE if it is a valid interface
 **/
int cardif_validate(char *interface)
{
  int sd, res;
  struct ifreq ifr;

  if (!xsup_assert((interface != NULL), "interface != NULL", FALSE))
    return FALSE;

  memset(&ifr, 0x00, sizeof(ifr));
  Strncpy(ifr.ifr_name, sizeof(ifr.ifr_name), interface, strlen(interface)+1);

  if (strlen(ifr.ifr_name) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
                   __FUNCTION__, __LINE__);
      return FALSE;
    }

  sd = socket(PF_PACKET, SOCK_RAW, 0);
  if (sd < 0)
    return FALSE;

  res = ioctl(sd, SIOCGIFHWADDR, &ifr);
  close(sd);

  if (res < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't get information for interface %s!\n",interface);
    } else {
      switch (ifr.ifr_hwaddr.sa_family)
	{
	case ARPHRD_ETHER:
	case ARPHRD_IEEE80211:
	  return TRUE;
	}
    }

  return FALSE;
}

/**
 * \brief (en)/(dis)able countermeasures on this interface.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  enable countermeasures on.
 *
 * @param[in] endis  TRUE if we should enable countermeasures, FALSE if we
 *                   should disable countermeasures.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation failure
 **/
int cardif_countermeasures(context *ctx, char endis)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (wireless == NULL) return XEMALLOC;

  if (wireless->countermeasures == NULL) return XEMALLOC;

  return wireless->countermeasures(ctx, endis);
}

/**
 * \brief (en)/(dis)able receiving of unencrypted frames on this interface.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  enable "drop unencrypted frames" on.
 *
 * @param[in] endis TRUE if we should enable "drop unencrypted frames" FALSE
 *                  if we should disable it.
 *
 * \retval XEMALLOC on memory allocation error.
 * \retval XENONE on success
 **/
int cardif_drop_unencrypted(context *ctx, char endis)
{
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return XEMALLOC;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (wireless == NULL) return XEMALLOC;

  if (config_ssid_using_wep(wctx)) return XENONE;
  
  return wireless->drop_unencrypted(ctx, endis);
}

/**
 * \brief Attempt to determine if an interface is wireless.
 *
 * Check to see if an interface is wireless.  On linux, we look in
 * /proc/net/wireless to see if the interface is registered with the
 * wireless extensions.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  check to see if it is wireless.
 *
 * \retval -1 on error
 * \retval XENONE on success
 * \retval XEMALLOC on memory allocation error
 **/
#define PROC_WIRELESS_FILE  "/proc/net/wireless"

int cardif_int_is_wireless(context *ctx)
{
  FILE *fp;
  char line[1000], *lineptr=NULL;
  int done;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  done = FALSE;

  fp = fopen(PROC_WIRELESS_FILE, "r");
  if (fp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't access /proc/net/wireless!  (You probably don't have wireless extensions enabled!)\n");
      return -1;
    }

  memset(line, 0x00, 1000);

  while ((!done) && (fgets(line, 999, fp) != NULL))
    { 
      lineptr = strchr(line, ':');
      
      if (lineptr != NULL)
	{
	  
	  *lineptr = '\0';
	  lineptr = &line[0];
	  
	  while (*lineptr == ' ') lineptr++;  // Strip out blanks.
	  if (lineptr != NULL)
	    {
	      if (strcmp(lineptr, ctx->intName) == 0) done=TRUE;
	    }
	}
    }
  fclose(fp);
  
  if ((lineptr != NULL) && (strcmp(lineptr, ctx->intName) == 0))
    {
      debug_printf(DEBUG_INT, "Interface %s is wireless!\n", ctx->intName);
      return TRUE;
    } else {
      debug_printf(DEBUG_INT, "Interface %s is NOT wireless!\n", ctx->intName);
      return FALSE;
    }

  return XENONE;   // No errors.
}

int is_wireless(char *intname)
{
  FILE *fp;
  char line[1000], *lineptr=NULL;
  int done;

  if (!xsup_assert((intname != NULL), "intname != NULL", FALSE))
    return XEMALLOC;

  done = FALSE;

  fp = fopen(PROC_WIRELESS_FILE, "r");
  if (fp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't access /proc/net/wireless!  (You probably don't have wireless extensions enabled!)\n");
      return -1;
    }

  memset(line, 0x00, 1000);

  while ((!done) && (fgets(line, 999, fp) != NULL))
    {
      lineptr = strchr(line, ':');

      if (lineptr != NULL)
        {

          *lineptr = '\0';
          lineptr = &line[0];

          while (*lineptr == ' ') lineptr++;  // Strip out blanks.
          if (lineptr != NULL)
            {
              if (strcmp(lineptr, intname) == 0) done=TRUE;
            }
        }
    }
  fclose(fp);

  if ((lineptr != NULL) && (strcmp(lineptr, intname) == 0))
    {
      debug_printf(DEBUG_INT, "Interface %s is wireless!\n", intname);
      return TRUE;
    } else {
      debug_printf(DEBUG_INT, "Interface %s is NOT wireless!\n", intname);
      return FALSE;
    }

  return XENONE;   // No errors.
}

/***********************************************
 * Get the MAC address of an interface
 ***********************************************/
static int _getmac(char *dest, char *ifname) 
{
  struct ifreq ifr;
  int sock = -1;
  int retval;

  debug_printf(DEBUG_INT, "Looking for MAC address for %s!\n", ifname);

  sock = socket(PF_PACKET, SOCK_RAW, 0);
  if (sock < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't establish socket needed to query "
		   "interface %s for it's MAC address.\n", ifname);
      return FALSE;
    }

  memset(&ifr, 0x00, sizeof(ifr));

  if (strlen(ifname) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name in %s():%d\n",
                   __FUNCTION__, __LINE__);
      return FALSE;
    }

  ifr.ifr_ifindex = if_nametoindex(ifname);

  // Tell the ifreq struct which interface we want to use.
  Strncpy((char *)&ifr.ifr_name, sizeof(ifr.ifr_name), ifname,
          strlen(ifname)+1);
  printf("Interface : %s\n", ifr.ifr_name);

  // Get our MAC address.  (Needed for sending frames out correctly.)
  retval = ioctl(sock, SIOCGIFHWADDR, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting hardware (MAC) address for interface %s!\n", ifname);
      debug_printf(DEBUG_NORMAL, "Error was (%d) : %s\n", errno, strerror(errno));

      close(sock);
      return FALSE;
    }

  // Store a copy of our source MAC for later use.
  memcpy(dest, (char *)&ifr.ifr_hwaddr.sa_data[0], 6);

  close(sock);
  return TRUE;
}


/**
 * \todo Finish the documentation here!
 **/
int cardif_get_wpa_ie(context *ctx, char *iedata, int *ielen)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ielen != NULL), "ielen != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((wireless != NULL), "wireless != NULL", FALSE))
    return XEMALLOC;

  if (wireless->get_wpa_ie == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No function defined for wireless->get_wpa_ie()!\n");
      return XEMALLOC;
    }

  return wireless->get_wpa_ie(ctx, iedata, ielen);
}

int cardif_get_wpa2_ie(context *ctx, uint8_t *iedata, uint8_t *ielen) 
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ielen != NULL), "ielen != NULL", FALSE))
    return XEMALLOC;

  if (!wireless)
    {
      debug_printf(DEBUG_NORMAL, "Invalid wireless function pointers.\n");
      return XEMALLOC;
    }

  if (iedata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid memory for IE data! (%s:%d)\n",
		   __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

  if (!wireless->get_wpa2_ie)
    {
      debug_printf(DEBUG_NORMAL, "No valid function to get WPA2 IE!\n");
      return XEMALLOC;
    }

  return wireless->get_wpa2_ie(ctx, iedata, ielen);
}

/**
 * \brief Clear any keys that are in use on the interface.
 *
 * This function should clear out all keys that have been applied to the card.
 * It should be indepentant of the type (WEP/TKIP/CCMP) of key that was
 * applied.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  clear the keys for.
 *
 * \retval XENONE on success
 * \retval XEMALLOC on error
 **/
int cardif_clear_keys(context *ctx)
{
  int retVal = 0, i;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  // Clear the TX key.
  retVal = cardif_delete_key(ctx, 0, 1);
  if (retVal != XENONE) 
    {
      debug_printf(DEBUG_NORMAL, "Error clearing default TX key!\n");
      return retVal;
    }

  // Now, clear out the broadcast/multicast/group key(s).
  for (i=0;i<4;i++)
    {
      retVal = cardif_delete_key(ctx, i, 0);
      if (retVal != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Error clearing key %d!\n", i);
	  return retVal;
	}
    }

  return XENONE;
}

/**
 * \brief Attempt to reassociate to the network we were previously connected 
 *        to.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to reassociate on.
 * @param[in] reason   The reason code for a disassociation  as specified by 
 *                     the IEEE 802.11  standards documents.
 **/
void cardif_reassociate(context *ctx, uint8_t reason)
{
  wireless_ctx *wctx;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!config_ssid_using_wep(wctx))
    {
      debug_printf(DEBUG_NORMAL, "SSID '%s' is WPA/WPA2 capable. WPA/WPA2 is "
		   "enabled on this connection.\n", wctx->cur_essid);
      
      // Since we are doing WPA/WPA2, we need to disassociate from 
      // the network, and reassociate with WPA/WPA2 set up.
      cardif_enable_wpa(ctx);
      cardif_enable_wpa_state(ctx);

      cardif_clear_keys(ctx);
    }

  cardif_associate(ctx);  
}

/**
 * \brief Disable encryption on the card.  (Set the interface to open mode.)
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  disable encryption on.
 *
 * \retval XENONE on success
 * \retval !XENONE on error
 **/
int cardif_enc_disable(context *ctx)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  return wireless->enc_disable(ctx);
}

/**
 * \brief Determine what abilities this card has.  (WPA, WPA2, TKIP, CCMP, 
 *        WEP40, etc.)
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  get the abilities for.
 **/
void cardif_get_abilities(context *ctx)
{
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!wireless->enc_capabilities)
    {
      wctx->enc_capa = 0;
      return;
    }

  wireless->enc_capabilities(ctx);
}

/**
 * \brief Change the BSSID that we are currently connected to.
 *
 * @param[in] ctx   The context that contains the interface that we want to
 *                  get the BSSID for.
 * @param[in,out] new_bssid   A pointer to a buffer of at least 6 bytes that
 *                            will return the BSSID of the AP.
 **/
void cardif_setBSSID(context *ctx, uint8_t *new_bssid)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((new_bssid != NULL), "new_bssid != NULL", FALSE))
    return;

  if (!wireless->setbssid)
    {
      return;
    }

  wireless->setbssid(ctx, new_bssid);
}

/**
 * \brief Change the operstate of the interface.
 *
 * @param[in] ctx   The context that contains the interface that we want
 *                  to update the operstate for.
 * @param[in] newstate   The new operstate for the interface pointed to by
 *                       "ctx".
 **/
void cardif_operstate(context *ctx, uint8_t newstate)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!wireless->set_operstate)
    {
      debug_printf(DEBUG_INT, "No function defined to set operstate. (This "
		   "is probably nothing to worry about.\n");
      return;
    }

  wireless->set_operstate(ctx, newstate);
}

/******************************************************************
 *
 * Wait for an interface to be "attached" to the system before starting to
 * attempt authentication with it.  This is a blocking call that should
 * *ONLY* return when the interface is available.  (Note : 'available'
 * does not mean that the interface is UP.  The 802.1X state machine will
 * deal with the interface if it is down.  We just need to wait for an
 * interface to exist so that we can use it.
 *
 ******************************************************************/
void cardif_wait_for_int(char *intname)
{
  int idx = -1;

  if (!xsup_assert((intname != NULL), "intname != NULL", FALSE))
    return;

  idx = if_nametoindex(intname);
  if (idx < 1)
    {
      debug_printf(DEBUG_NORMAL, "Waiting for interface to be inserted, or "
		   "driver to be loaded.\n");
      while (if_nametoindex(intname) < 1)
	{
	  sleep(1);
	}
    }
}

/**
 * \brief Called when the passive scan timer times out.
 *
 * The passive scan timer expried.  So, we need to issue a scan request,
 * and reset our timer to recheck the scan results periodically.
 *
 * @param[in] ctx   A pointer to the context that contains the interface
 *                  that the passive scan timer timed out on.
 **/
void cardif_passive_scan_timeout(context *ctx)
{
  struct config_globals *globals;
  uint8_t *mac;
  char *ssid;
  wireless_ctx *wctx;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (!TEST_FLAG(wctx->flags, WIRELESS_PASV_SCANNING))
    {
     if (!TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
	{
	  timer_reset_timer_count(ctx, PASSIVE_SCAN_TIMER, 5);
	  cardif_do_wireless_scan(ctx, 1);
	  SET_FLAG(wctx->flags, WIRELESS_PASV_SCANNING);
	}
      else
	{
	  debug_printf(DEBUG_NORMAL, "Got a request to start a new passive scan "
		       "when a previous one has not completed!\n");
	}
    }
  else
    {
      // If the scanning flag is no longer set, then we need to make a decision
      // about how to associate.
      debug_printf(DEBUG_NORMAL, "Looking for the best network to connect to.\n");
      // Clear the passive scanning flag.
      UNSET_FLAG(ctx->flags, WIRELESS_PASV_SCANNING);

      // Reset the timer so that we scan again.
      
      globals = config_get_globals();
      
      if (!globals)
	{
	  debug_printf(DEBUG_NORMAL, "No global data!  Passive scanning will"
		       " be broken until the next time an authentication "
		       "completes.\n");
	}
      else
	{
	  debug_printf(DEBUG_INT, "Resetting passive scan timer.\n");
	  timer_reset_timer_count(ctx, PASSIVE_SCAN_TIMER, globals->passive_timeout);
	  
	}

      ssid = config_ssid_get_desired_ssid(ctx);

      if (ssid == NULL)
        {
          debug_printf(DEBUG_NORMAL, "No valid SSID was returned.  Either "
                       "there is something wrong with your configuration, or"
                       " the passive scan didn't find a network that is "
                       "currently configured.\n");
          return;
        }

      if (strcmp(ssid, wctx->cur_essid) != 0)
	{
	  debug_printf(DEBUG_NORMAL, "The best AP to connect to appears to be"
		       " in a different ESSID!  It is likely that your card"
		       " doesn't support the needed passive scanning flags."
		       "\n");
	  // Don't do anything with the result.
	} 
      else
	{
	  // We got a valid result.  So, see if it is a different AP.  If it
	  // is, then jump to it.
	  mac = config_ssid_get_mac(wctx);

          if (mac == NULL)
            {
              debug_printf(DEBUG_NORMAL, "Couldn't determine the MAC "
                           "address for the desired SSID found in a passive "
                           "scan.  You may not be associated to the best AP, "
                           "but your network should continue to work.\n");
              return;
            }

	  if (memcmp(ctx->dest_mac, mac, 6) != 0)
	    {
	      debug_printf(DEBUG_INT, "Jumpping to a BSSID with a better "
			   "signal.  (BSSID : ");
	      debug_hex_printf(DEBUG_INT, mac, 6);
	      debug_printf_nl(DEBUG_INT, ")\n");

	      // Then change our BSSIDs.
	      cardif_setBSSID(ctx, mac);
	    }
	  else
	    {
	      debug_printf(DEBUG_INT, "We are connected to the best "
			   "BSSID already.\n");
	    }
	}
    }
}

/*
    this function is called when UI request for signal strength
    ctx:  A pointer to the context that contains the interface 
    
    returns the singnal strength of the interface. 
*/

int cardif_get_signal_strength_percent(context *ctx)
{
 wireless_ctx *wctx = NULL;
  struct found_ssids *working = NULL;
  int signalStr = 0;

  wctx = (wireless_ctx *) ctx->intTypeData;
  working = config_ssid_find_by_name(wctx, wctx->cur_essid);

  if (working)
  {
    signalStr = working->strength;
  }
  return signalStr;

}
/*
        This is function called when UI request for IPAddress.
        
        ctx: A pointer to the ctx of the interface.
        
        returns the pointer to the IPaddress or NULL. 
*/
char *cardif_get_ip(context *ctx)
{

 char *ipaddress = NULL;
  char *tmpaddr = NULL;
  int sock;
  struct ifreq ifr;
  struct sockaddr_in *ifaddr;

 if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return NULL;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, ctx->intName, IF_NAMESIZE);

 if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
  {
    debug_printf(DEBUG_NORMAL, "Failed to get IP Address of %s returning NULL\n", ctx->intName);
  }
 {
    ifaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    close(sock);
    ipaddress = Malloc(20);
    if (ipaddress != NULL)
    {
      tmpaddr = inet_ntoa(ifaddr->sin_addr);
      memcpy(ipaddress, tmpaddr, 20);
    }
    debug_printf(DEBUG_NORMAL, "Got IP Address of %s = %s\n", ctx->intName, ipaddress);
  }
  return ipaddress;
}


char *cardif_get_netmask(context *ctx)
{
  // XXX  FINISH!
  return NULL;
}

char *cardif_get_gw(context *ctx)
{
  // XXX  FINISH!
  return NULL;
}

char *cardif_get_dns1(context *ctx)
{
  // XXX FINISH!
  return NULL;
}

char *cardif_get_dns2(context *ctx)
{
  // XXX FINISH!
  return NULL;
}

char *cardif_get_dns3(context *ctx)
{
  // XXX FINISH!
  return NULL;
}

/**
 * \brief Add given interface to interface cache
 **/
void cardif_add_interface(char *ifname, int ifindex)
{
  char mac[6];

  // Make sure we aren't looking at any loopback interfaces.
  if( is_wireless(ifname ) == TRUE )
  {
    if(_getmac(( char *)&mac, ifname ) == TRUE )
    {
      debug_printf(DEBUG_INT, "Wireless Interface %d named %s.\n", ifindex, ifname);
      interfaces_add (ifname, ifname, mac, is_wireless (ifname));
    }
  }
  else if (strncasecmp (ifname, "eth", 3 ) == 0 )
  {
    if(_getmac(( char *)&mac,ifname ) == TRUE )
    {
      debug_printf(DEBUG_INT, "Wired Interface %d named %s.\n", ifindex, ifname);
      interfaces_add (ifname, ifname, mac, is_wireless (ifname));
    }
  }
}

/**
 * \brief Enumerate all of the interfaces that are on the machine, and put
 *        them in the interface cache.
 **/
void cardif_enum_ints()
{
  struct if_nameindex *ifnames;
  int i = 0;

  ifnames = if_nameindex();
  if (ifnames == NULL)
  {
    debug_printf(DEBUG_NORMAL, "Got an error with if_nameindex() call!\n");
    debug_printf(DEBUG_NORMAL, "Are there no interfaces on this machine?\n");
    return;
  }

  while ((ifnames[i].if_index != 0) && (ifnames[i].if_name != NULL))
  {
    cardif_add_interface(ifnames[i].if_name, ifnames[i].if_index);
    i++;
  }

  if_freenameindex(ifnames);
}

/**
 * \brief Determine the device description based on the OS specific interface
 *        name.  For Linux, the OS specific interface name, and the 
 *        device description will be the same.
 *
 * @param[in] intname   The OS specific interface name to search for.
 *
 * \retval NULL on error, or interface not found.
 * \retval ptr to the interface description
 **/
char *cardif_find_description(char *intname)
{
  return strdup(intname);
}

/**
 * \brief Get a string representation of an interface's MAC address based on the
 *        OS specific interface name.
 *
 * @param[in] intname   The OS specific interface name for the interface we want to
 *                      get information on.
 *
 * \retval NULL on error
 * \retval ptr to MAC address string on success
 **/
char *cardif_get_mac_str(char *intname)
{
  uint8_t mac[6];
  char *resmac = NULL;

  if (get_mac_by_name(intname, (char *)&mac) != 0) return NULL;

  resmac = Malloc(25);
  if (resmac == NULL) return NULL;

  sprintf(resmac, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2]\
	  , mac[3],
	  mac[4], mac[5]);

  return resmac;
}

/**
 * \brief Determine in an interface is wireless based on it's OS specific
 *        interface name.
 *
 * @param[in] intname   The OS specific interface name that we want to check
 *                      to see if it is wireless.
 *
 * \retval TRUE if the interface is wireless
 * \retval FALSE if the interface is *NOT* wireless
 **/
int cardif_is_wireless_by_name(char *intname)
{
  return is_wireless(intname);
}

/**
 * \brief Determine the system uptime in seconds.
 *
 * @param[out] uptime   A 64 bit number that indicates the uptime of the system in seconds.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int cardif_get_uptime(uint64_t *uptime)
{
  struct utmp intEnt;
  struct timeval curTime;
  struct utmp *bTimePtr;

  bTimePtr = NULL;
  setutent();
  intEnt.ut_type = BOOT_TIME;
  bTimePtr = getutid( &intEnt );

  if( bTimePtr == NULL )
  {
      return -1;
  }

  if( gettimeofday( &curTime, NULL ) != 0 )
  {
        return -1;
  }

  *uptime = ( curTime.tv_sec ) - ( bTimePtr->ut_tv.tv_sec );
  return 0;
}

int cardif_get_freq(context *ctx, uint32_t *freq) 
{
        return 0;
}

int cardif_apply_pmkid_data(context *ctx, pmksa_list *list)
{
        if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return FALSE;



  if (wireless == NULL) return XEMALLOC;



  if (wireless->apply_pmkid_data == NULL) return XEMALLOC;



  return wireless->apply_pmkid_data(ctx, list);

}
int cardif_validate_connection( context *intdata )
{
	     wireless_ctx * wctx;
         uint16_t abilities;
         int retVal = FALSE;

            if ( !xsup_assert(( intdata != NULL ), "intdata != NULL ", FALSE )) return FALSE;
            wctx =( wireless_ctx * ) intdata->intTypeData;


	    if( !xsup_assert(( wctx != NULL ), "wctx != NULL ", FALSE ) ) return FALSE;	
           
		abilities = config_ssid_get_ssid_abilities ( wctx );

            switch (intdata->conn->association.auth_type)
            {
                case AUTH_NONE:
                     if( ( abilities  & ABIL_ENC)  && ( intdata->conn != NULL ))
                     {
					  if( intdata->conn->association.txkey != 0)
					  {
                                	debug_printf(DEBUG_NORMAL,"WEP  Connection \n" );
                                	retVal = TRUE;
					  }
                         	
                     }
                     else if(  ( config_ssid_get_ssid_abilities ( wctx ) == 0 ) && ( intdata->conn != NULL ))
                     {
				if( intdata->conn->association.txkey == 0 )
				{
                                	debug_printf(DEBUG_NORMAL,"OPEN  Connection \n" );
                                	retVal = TRUE;
                                	
				}
                     }
                    break;
               case AUTH_PSK:
                       if( ( abilities & ABIL_WPA_PSK ) && ( abilities & ABIL_WPA_IE ) )
                       {
                                debug_printf(DEBUG_NORMAL, " WPA_PSK connection with WPA or WPA1 \n");
                                retVal = TRUE;
			
                       }
                      else if( ( abilities & ABIL_RSN_PSK ) && ( abilities & ABIL_RSN_IE ) )
                      {
                                debug_printf(DEBUG_NORMAL, " WPA_PSK connection with WPA2\n");
                                retVal = TRUE;
                                
                      }
		      break;

               case AUTH_EAP: /* here i'm checking it for enterprise  and dynamic wep */
               case AUTH_UNKNOWN:
                   
                       if( ( abilities & ABIL_WPA_DOT1X ) && ( abilities & ABIL_WPA_IE ) )
                       {
                                debug_printf(DEBUG_NORMAL, " WPA_DOT1X connection with WPA or WPA1 \n");
                                retVal = TRUE;
                                
                       }
                      else if( ( abilities & ABIL_RSN_DOT1X ) && ( abilities & ABIL_RSN_IE ) )
                      {
                                debug_printf(DEBUG_NORMAL, " WPA_DOT1X connection with WPA2\n");
                                retVal = TRUE;
                      }
                     else if(( abilities & ABIL_ENC ) && ( intdata->prof != NULL ))
                     {		
					if( intdata->prof->name != NULL )
					{
			       	     	debug_printf(DEBUG_NORMAL,"DYNAMIC WEP Connection \n" );
                               	retVal = TRUE;	
					}
                               
                     }
		      break;

              default:
                   break;
             }

 return retVal;
}


