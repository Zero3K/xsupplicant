/**
 * File: cardif_linux_rtnetlink.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * Authors: Chris.Hessing@utah.edu
 *
 **/

#include <unistd.h>
#include <sys/socket.h>
#include <iwlib.h>
#include <sys/ioctl.h>
#include "netlink.h"
#include "rtnetlink.h"
#include <net/if.h>
#include <linux/if_packet.h>
#include <math.h>

#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "wireless_sm.h"
#include "cardif_linux.h"
#include "statemachine.h"
#include "platform/cardif.h"
#include "wpa.h"
#include "wpa2.h"
#include "eap_sm.h"
#include "eap_types/mschapv2/mschapv2.h"
#include "config_ssid.h"
#include "eapol_key_type254.h"
#include "timer.h"
#include "mic.h"
#include "event_core.h"
#include "cardif_linux_wext.h"
#include "cardif_linux_rtnetlink.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

// Define this, so the compiler doesn't complain.
extern char *if_indextoname(unsigned int, char *);

#define INT_DEL    0
#define INT_NEW    1

static int rtnl_sock=-1;
static struct sockaddr_nl rtnl_data;

#ifndef IWEVCUSTOM
#warning IWEVCUSTOM is not defined!  We will define it, and try to continue!
#define IWEVCUSTOM   0x8C02
#endif

#ifndef IW_CUSTOM_MAX
#warning IW_CUSTOM_MAX is not defined!  You should upgrade to a more current version of wireless extensions.  We will attempt to define it ourselves, but the results may not be good.
#define IW_CUSTOM_MAX  256  // In bytes, matches current WE versions. (11/14/05)
#endif

// Forward defs to avoid compiler warnings.
void cardif_linux_rtnetlink_process_token(context *ctx,
					  struct iw_event *iwe);

extern unsigned int if_nametoindex(const char *);

/********************************************************
 *
 * Do whatever is needed to establish a netlink socket so that we can
 * catch events, and take action.
 *
 ********************************************************/
void cardif_linux_rtnetlink_init()
{
  rtnl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  
  if (rtnl_sock < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't establish an rtnetlink socket!  Some functionality won't be available!\n");
      return;
    }

  memset((char *)&rtnl_data, 0x00, sizeof(rtnl_data));

  rtnl_data.nl_family = AF_NETLINK;
  rtnl_data.nl_groups = RTMGRP_LINK;

  if (bind(rtnl_sock, (struct sockaddr *)&rtnl_data, sizeof(rtnl_data)) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't bind netlink socket!  Some functionality won't be available!\n");
      close(rtnl_sock);
      return;
    }

  event_core_register(rtnl_sock, NULL, cardif_linux_rtnetlink_check_event, 
		      HIGH_PRIORITY, "rtnetlink handler");
}

/********************************************************
 *
 * Do whatever is needed to shutdown the netlink socket that we set up.
 *
 ********************************************************/
void cardif_linux_rtnetlink_cleanup(context *ctx)
{
  debug_printf(DEBUG_INT, "Called cardif_linux_rtnetlink_cleanup()!\n");

  // Close the rtnetlink socket.
  close(rtnl_sock);
}

/*********************************************************************
 *
 * Get the wireless extensions version that this driver was built with.
 *
 *********************************************************************/
int cardif_linux_rtnetlink_get_we_ver(context *intdata)
{
  struct iwreq iwr;
  struct iw_range *range = NULL;
  char buffer[sizeof(iwrange)*2];
  int sock;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  memset(buffer, 0x00, (sizeof(iwrange)*2));

  iwr.u.data.pointer = (caddr_t) buffer;
  iwr.u.data.length = sizeof(buffer);
  iwr.u.data.flags = 0;

  sock = cardif_get_socket(intdata);
  if (iw_get_ext(sock, intdata->intName, SIOCGIWRANGE, &iwr) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error with ioctl SIOCGIWRANGE (Error: %s)\n",
		   strerror(errno));
      return -1;
    }

  range = (struct iw_range *)buffer;

  return range->we_version_compiled;
}

/********************************************************
 *
 * Gather the data that was returned from a scan.
 *
 ********************************************************/
void cardif_linux_rtnetlink_reap(context *intdata, char *data, int len)
{
  struct stream_descr stream;
  struct iw_event iwe;
  int retval;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((data != NULL), "data != NULL", FALSE))
    return;

  xsup_assert((len >= 0), "len >= 0", TRUE);
  xsup_assert((len < 65001), "len < 65001", TRUE);

  iw_init_event_stream(&stream, data, len);
  do
    {
#ifdef OLD_IWLIB
      retval = iw_extract_event_stream(&stream, &iwe);
#else
      retval = iw_extract_event_stream(&stream, &iwe, 
				       cardif_linux_rtnetlink_get_we_ver(intdata));
#endif

      if (retval == 1)  // Then we got something
	{
	  cardif_linux_rtnetlink_process_token(intdata, &iwe);
	} else {
	  switch (retval)
	    {
	    case 0:
	      // No error.
	      break;

	    case -1:debug_printf(DEBUG_NORMAL, "Invalid event!\n");
	      break;

	    case 2:debug_printf(DEBUG_NORMAL, "Unknown event found. Skipping."
				"(Event %04X) (Not supported in wireless "
				"extensions %d?)\n", iwe.cmd, WIRELESS_EXT);
	      break;

	    case -2:debug_printf(DEBUG_NORMAL, "Invalid event data. Skipping."
				 "\n");
	      break;

	    default:debug_printf(DEBUG_NORMAL, "Unknown result code from "
				 "iw_extract_event_stream(). (Result was %d)"
				 "\n", retval);
	      break;
	    }
	}
    }
  while (retval > 0);
}

/*******************************************************
 *
 * Check to see if we have data in the returned scan buffer, even if 
 * we didn't get a scan complete event.  (Some cards may not send the
 * scan complete event.)
 *
 *******************************************************/
uint8_t cardif_linux_rtnetlink_check_nets(context *idata)
{
  struct lin_sock_data *sockData = NULL;
  struct iwreq iwr;
  char *buffer = NULL;
  uint16_t buf_size = 8192;
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((idata != NULL), "idata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((idata->intTypeData != NULL), "idata->intTypeData != NULL",
		   FALSE))
    return XEMALLOC;

  wctx = (wireless_ctx *)idata->intTypeData;

  if (!TEST_FLAG(wctx->flags, WIRELESS_SCANNING)) 
    {
      return XENONE;
    }

  debug_printf(DEBUG_INT, "Checking for returned SSID information....\n");

  sockData = idata->sockData;

  if (!xsup_assert((buf_size != 0), "buf_size != 0", TRUE))
      return XEMALLOC;
  
  if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
    return XEMALLOC;

  buffer = (char *)Malloc(buf_size);
  if (buffer == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for scan buffer!"
		   "\n");
      return XEMALLOC;
    }

  iwr.u.data.pointer = buffer;
  iwr.u.data.flags = 0;
  iwr.u.data.length = buf_size;

  strcpy(iwr.ifr_name, idata->intName);
  
  if (ioctl(sockData->sockInt, SIOCGIWSCAN, &iwr) < 0)
    {
      if (errno == E2BIG)
	{
	  // Our return results are too big for our default buffer.  So,
	  // allocate more and try again!
	  
	  FREE(buffer);
	  buf_size *= 2;

	  buffer = (char *)Malloc(buf_size);
	  if (!buffer)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for scan "
			   "buffer!\n");
	      return XEMALLOC;
	    }

	  iwr.u.data.pointer = buffer;
	  iwr.u.data.length = buf_size;

	  while (ioctl(sockData->sockInt, SIOCGIWSCAN, &iwr) < 0)
	    {
	      FREE(buffer);
	      
	      if (buf_size > 60000)
		{
		  debug_printf(DEBUG_NORMAL, "Buffer size to allocate has "
			       "become unreasonable!  (If you really have "
			       "that many SSIDs, you won't get much data "
			       "across the network anyway!)\n");
		  return -1;
		}

	      buf_size *= 2;

	      buffer = (char *)Malloc(buf_size);
	      if (!buffer)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for scan buffer!\n");
		  return XEMALLOC;
		}

	      iwr.u.data.pointer = buffer;
	      iwr.u.data.length = buf_size;
	    }
	}
      else
	{
	  if (errno == EAGAIN)
	    {
	      debug_printf(DEBUG_INT, "No data available! (%s)\n", 
			   strerror(errno));
	      return XENONE;
	    }
	  else
	    {
	      debug_printf(DEBUG_NORMAL, "Error with scan results!\n");
	      debug_printf(DEBUG_NORMAL, "Error was : %s\n", strerror(errno));
	      UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);
	      return -1;
	    }
	}
    }

  debug_printf(DEBUG_NORMAL, "Scan complete.\n");

  // Cancel the scancheck timer, so it doesn't continue to fire.
  timer_cancel(idata, SCANCHECK_TIMER);

  if (iwr.u.data.length <= 0) 
    {
      FREE(buffer);
      return XENONE;
    }

  // Then harvest the data.
  debug_printf(DEBUG_INT, "Reaping data. (Size : %d)\n", iwr.u.data.length);
  debug_hex_dump(DEBUG_INT, (uint8_t *)buffer, iwr.u.data.length);
  cardif_linux_rtnetlink_reap(idata, (char *)buffer, iwr.u.data.length);
      
  UNSET_FLAG(wctx->flags, WIRELESS_SCANNING);

  // Clean up after ourselves.
  FREE(buffer);

  return XDATA;
}

/***********************************************************
 *
 * Check the MAC that we were given.  If it is all 0s, 4s, or Fs then the
 * event is a disassociation.  If it isn't then it is an association.
 *
 ***********************************************************/
int cardif_linux_rtnetlink_validate(context *idata, uint8_t *mac)
{
  char newmac[6];

  if (!xsup_assert((idata != NULL), "idata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((mac != NULL), "mac != NULL", FALSE))
    return XEMALLOC;

  // Is it a disassociation?
  memset(newmac, 0x00, 6);
  if (memcmp(newmac, mac, 6) == 0)
    {
      return FALSE;
    }

  memset(newmac, 0x44, 6);
  if (memcmp(newmac, mac, 6) == 0)
    {
      return FALSE;
    }

  memset(newmac, 0xff, 6);
  if (memcmp(newmac, mac, 6) == 0)
    {
      return FALSE;
    }
  
  // Otherwise, it was an association
  return TRUE;
}


/**********************************************************************
 *
 * Process a SIOCGIWAP event.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_SIOCGIWAP(context *idata,
					      struct iw_event *iwe)
{
  char mac[6];
  int assoc;
  struct config_globals *globals = NULL;
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((idata != NULL), "idata != NULL", FALSE))
    return;

  if (!xsup_assert((idata->intTypeData != NULL), "idata->intTypeData != NULL",
		   FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)idata->intTypeData;

  memcpy(mac, iwe->u.ap_addr.sa_data, 6);
  debug_printf(DEBUG_INT, "AP MAC : ");
  debug_hex_printf(DEBUG_INT, (uint8_t *)mac, 6);

#warning Check this!
  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
    {
      config_ssid_add_bssid(wctx, mac);
    } else {
      globals = config_get_globals();

      if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
	return;

      assoc = cardif_linux_rtnetlink_validate(idata, (uint8_t *)&mac);
      if (assoc)
	{
	  // We have changed to associated mode.  Populate the destination
	  // MAC with the BSSID, as long as we are in auto mode.
	  
	  SET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);
	  UNSET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);
	  
	  if (globals->destination == DEST_AUTO)
	    memcpy(idata->dest_mac, mac, 6);
	  
	} else {
	  UNSET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);
	  UNSET_FLAG(wctx->flags, WIRELESS_SM_STALE_ASSOCIATION);
	}
    }
}

/**********************************************************************
 *
 * Process a SIOCGIWESSID event.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_SIOCGIWESSID(context *ctx,
						 struct iw_event *iwe)
{
  char essid[IW_ESSID_MAX_SIZE+1];
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  memset(essid, 0x00, IW_ESSID_MAX_SIZE+1);
  
  memcpy(essid, iwe->u.essid.pointer, iwe->u.essid.length);
  essid[iwe->u.essid.length] = '\0';

#warning Check this!
  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
    {
      debug_printf(DEBUG_INT, "ESSID : %s\n", essid);
      
      config_ssid_add_ssid_name(wctx, essid);
    } else {
      debug_printf(DEBUG_NORMAL, "Got a get SSID event!? "
		   "Notify your wireless driver maintainer.\n");
    }
}

/*****************************************************************
 *
 * Process an SIOCSIWESSID.
 *
 *****************************************************************/
void cardif_linux_rtnetlink_process_SIOCSIWESSID(context *ctx,
						 struct iw_event *iwe)
{
  char essid[IW_ESSID_MAX_SIZE+1];
  wireless_ctx *wctx = NULL;
  char wpaie[24];

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  memset(essid, 0x00, IW_ESSID_MAX_SIZE+1);
  
  memcpy(essid, iwe->u.essid.pointer, iwe->u.essid.length);
  essid[iwe->u.essid.length] = '\0';

  /*
#warning Check this!
  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
    {
      debug_printf(DEBUG_NORMAL, "Got an SSID set request from a scan!? "
		   "Notify your driver maintainer!\n");
    } else {
  */
      debug_printf(DEBUG_INT, "ESSID set .. name : %s\n", essid);
      
      if ((essid == NULL) || (wctx->cur_essid == NULL) ||
	  (strcmp(essid, wctx->cur_essid) != 0))
	{
	  if (config_ssid_ssid_known(wctx, essid) != TRUE)
	    {
	      // We only want to set this to TRUE if we don't already know
	      // something about the SSID we connected to.
	      SET_FLAG(wctx->flags, WIRELESS_SM_SSID_CHANGE);
	    }
	  
	  if (config_build(ctx, essid) == FALSE)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't build a valid configuration"
			   " for ESSID %s!\n", essid);

	      // If we didn't initiate the set, then clear keys.
	      if (!TEST_FLAG(wctx->flags, WIRELESS_SM_SSID_CHANGE))
		{
		  cardif_clear_keys(ctx);

		  memset(wpaie, 0x00, sizeof(wpaie));

		  // We will also need to clear the WPA IE.
		  if (cardif_linux_wext_set_wpa_ie(ctx, (unsigned char *)wpaie,
						   0) < 0)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't clear WPA IE!  You "
				   "may not be able to associate.\n");
		    }
		}
	    }
	  
	  // We changed ssids, so record the new one.
	  if (wctx->cur_essid != NULL)
	    {
	      FREE(wctx->cur_essid);

	      wctx->cur_essid = strdup(essid);
	    }
	}
      //    }
  // Unset the SSID_SET flag, if we set it.
  UNSET_FLAG(wctx->flags, WIRELESS_SM_SSID_CHANGE);
}

/**********************************************************************
 *
 * Scan through whatever was returned by the IWEVGENIE event, and pull
 * out any interesting IEs.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_parse_ies(context *ctx,
				      uint8_t *iedata, int ielen)
{
  int i = 0;
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return;

  if (!xsup_assert((ielen > 0), "ielen > 0", FALSE))
    return;

  if (!xsup_assert((ielen < 256), "ielen < 256", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  while (i < ielen)
    {
      if (iedata[i] == WPA_EID)
	{
	  if (wpa_parse_ie((char *)&iedata[i]) > 0)
	    {
	      // We have a valid IE, save it.
	      config_ssid_update_abilities(wctx, WPA_IE);
	      config_ssid_add_wpa_ie(wctx, (uint8_t *)&iedata[i], iedata[i+1]+2);
	    }
	}

      if (iedata[i] == WPA2_EID)
	{
	  if (wpa2_parse_ie((char *)&iedata[i]) > 0)
	    {
	      // We have a valid IE, save it.
	      config_ssid_update_abilities(wctx, RSN_IE);
	      config_ssid_add_rsn_ie(wctx, (uint8_t *)&iedata[i], iedata[i+1]+2);
	    }
	}
      i += (iedata[i+1]+2);
    }
}

/**********************************************************************
 *
 * Process an IWEVGENIE event.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_IWEVGENIE(context *ctx,
					      struct iw_event *iwe)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  debug_printf(DEBUG_INT, "IWEVGENIE (%d)\n", iwe->u.data.length);
  debug_printf_nl(DEBUG_INT, "IE : ");
  debug_hex_printf(DEBUG_INT, iwe->u.data.pointer, iwe->u.data.length);
  cardif_linux_rtnetlink_parse_ies(ctx, iwe->u.data.pointer, 
				   iwe->u.data.length);
}

/**********************************************************************
 *
 * Process an IWEVCUSTOM event.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_IWEVCUSTOM(context *ctx,
					       struct iw_event *iwe)
{
  char custom[IW_CUSTOM_MAX+1];
  char temp[IW_CUSTOM_MAX+1];
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
    {
      Strncpy(custom, IW_CUSTOM_MAX+1, iwe->u.data.pointer, 
	      iwe->u.data.length);
      
      debug_printf(DEBUG_INT, "IWEVCUSTOM : %s\n", custom);
      
      if (strncmp("wpa_ie=", custom, 7) == 0)
	{
	  config_ssid_update_abilities(wctx, WPA_IE);
	  debug_printf(DEBUG_INT, "AP appears to support WPA!\n");
	  
	  process_hex(&custom[7], (iwe->len -7), temp);
	  wpa_parse_ie(temp);
	  
	  config_ssid_add_wpa_ie(wctx, (uint8_t *)temp, 
				 ((iwe->u.data.length - 7)/2));
	}
      
      if (strncmp("rsn_ie=", custom, 7) == 0)
	{
	  config_ssid_update_abilities(wctx, RSN_IE);
	  debug_printf(DEBUG_INT, "AP appears to support WPA2/802.11i!\n");
	  
	  process_hex(&custom[7], (iwe->len -7), temp);
	  wpa2_parse_ie(temp);
	  
	  config_ssid_add_rsn_ie(wctx, (uint8_t *)temp, 
				 ((iwe->u.data.length - 7)/2));
	}
    } else {
      Strncpy(custom, IW_CUSTOM_MAX+1, iwe->u.data.pointer, 
	      iwe->u.data.length);

      memset(temp, 0x00, IW_CUSTOM_MAX+1);
      
      memcpy(temp, custom, iwe->u.data.length);
      temp[iwe->u.data.length] = '\0';
      debug_printf(DEBUG_INT, "Custom Data : \n");
      debug_hex_dump(DEBUG_INT, (uint8_t *)temp, iwe->u.data.length);
      cardif_linux_rtnetlink_check_custom(ctx, temp);
    }
}

/**********************************************************************
 *
 * Process an SIOCGIWSCAN event.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_SIOCGIWSCAN(context *ctx)
{
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
    {
      debug_printf(DEBUG_NORMAL, "Got an SIOCGIWSCAN in a scan result!? "
		   "Contact your wireless card driver maintainer!\n");
    } else {
      debug_printf(DEBUG_INT, "Wireless scan complete!\n");
      cardif_linux_rtnetlink_check_nets(ctx);
    }
}

/**********************************************************************
 *
 * Process an association request IE, if one is returned.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_IWEVASSOCREQIE(context *ctx, 
						   struct iw_event *iwe)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  if (iwe->u.data.length <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Got an IWEVASSOCREQIE, but it contains "
		   "no data?!\n");
      return;
    }

  debug_printf(DEBUG_INT, "IWEVASSOCREQIE returned : \n");
  debug_hex_printf(DEBUG_INT, iwe->u.data.pointer, iwe->u.data.length);
  cardif_linux_rtnetlink_parse_ies(ctx, iwe->u.data.pointer, 
				   iwe->u.data.length);
}

/**********************************************************************
 *
 * Process a response IE if one is returned.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_IWEVASSOCRESPIE(context *ctx,
						    struct iw_event *iwe)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  if (iwe->u.data.length <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Got an IWEVASSOCRESPIE, but it contains "
		   "no data?!\n");
      return;
    }
  debug_printf(DEBUG_INT, "IWEVASSOCRESPIE returned : \n");
  debug_hex_printf(DEBUG_INT, iwe->u.data.pointer, iwe->u.data.length);
  cardif_linux_rtnetlink_parse_ies(ctx, iwe->u.data.pointer,
				   iwe->u.data.length);
}

/***************************************************************************
 *
 * Handle a Michael MIC failure.
 *
 ***************************************************************************/
void cardif_linux_rtnetlink_process_IWEVMICHAELMICFAILURE(context *ctx,
							  struct iw_event *iwe)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

#ifdef IW_MICFAILURE_KEY_ID
  struct iw_michaelmicfailure *mic;

  // TODO : Double check this implementation.

  if (iwe->u.data.length <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Got a MIC failure, but it contained no "
		   "data!  Ignoring! (This may be dangerous.)\n");
      return;
    }

  mic = iwe->u.data.pointer;

  debug_printf(DEBUG_INT, "MIC failure :\n");
  debug_printf(DEBUG_INT, "  Key ID   : %d\n", mic->flags & IW_MICFAILURE_KEY_ID);
  
  if (mic->flags & IW_MICFAILURE_GROUP)
    {
      debug_printf(DEBUG_INT, "  Key Type : Group\n");
      debug_printf(DEBUG_NORMAL, "MIC failure on group key!\n");
      eapol_key_type254_request_new_key(ctx, 0);
      ctx->send_size = 0;
    } 

  if (mic->flags & IW_MICFAILURE_PAIRWISE)
    {
      debug_printf(DEBUG_INT, "  Key Type : Pairwise\n");
      debug_printf(DEBUG_NORMAL, "MIC failure on pairwise key!\n");
      eapol_key_type254_request_new_key(ctx, 1);
      ctx->send_size = 0;
    }

  if (mic->flags & IW_MICFAILURE_STAKEY)
    {
      debug_printf(DEBUG_INT, "  STAKEY\n");
    }

  // Some wireless cards may also return a count.  But we maintain our own
  // internal counter, so it isn't relevant.
  
  ctx->statemachine->MICfailures++;
  debug_printf(DEBUG_NORMAL, "MIC failure #%d!\n",
	       ctx->statemachine->MICfailures);
      
  if (ctx->statemachine->MICfailures >= 2)
    {
      // The WPA/802.11i standard requires we assert countermeasures 
      // for 60 seconds.
      if (timer_check_existing(ctx, COUNTERMEASURE_TIMER))
	{
	  debug_printf(DEBUG_NORMAL, "For some reason, we already have "
		       "a countermeasure timer in the queue!  Resetting "
		       "the timer!\n");
	  timer_reset_timer_count(ctx, COUNTERMEASURE_TIMER, 
				  MIC_COUNTERMEASURE_TIMEOUT);
	} else {
	  debug_printf(DEBUG_NORMAL, "Enabling MIC countermeasures!\n");
	  timer_add_timer(ctx, COUNTERMEASURE_TIMER, 
			  MIC_COUNTERMEASURE_TIMEOUT,
			  NULL, &mic_disable_countermeasures);
	}
      cardif_countermeasures(ctx, TRUE);
    }
#else
  debug_printf(DEBUG_NORMAL, "MIC failure support is not enabled in the "
	       "version of wireless extensions on your platform.  You should"
	       " consider upgrading to a more current version!\n");
#endif
}

/**********************************************************************
 *
 * Given a wireless event, process it.  If *state is NULL, then the event
 * is the result of a requested scan, so it needs to be added to the
 * SSID list.  If *state is not NULL, then this is an event generated by
 * the wireless interface.
 *
 **********************************************************************/
void cardif_linux_rtnetlink_process_token(context *ctx,
					  struct iw_event *iwe)
{
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((iwe != NULL), "iwe != NULL", FALSE))
    return;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  switch (iwe->cmd)
    {
    case SIOCGIWAP:
      cardif_linux_rtnetlink_process_SIOCGIWAP(ctx, iwe);
      break;
      
    case SIOCGIWFREQ:
      // Don't care.
      break;
      
    case SIOCGIWMODE:
      // Don't care.
      break;
      
    case SIOCGIWESSID:
      cardif_linux_rtnetlink_process_SIOCGIWESSID(ctx, iwe);
      break;

    case SIOCSIWESSID:
      cardif_linux_rtnetlink_process_SIOCSIWESSID(ctx, iwe);
      break;
      
    case SIOCGIWNAME:
      // Don't care.
      break;

    case SIOCGIWSCAN:
      cardif_linux_rtnetlink_process_SIOCGIWSCAN(ctx);
      break;

#ifdef IWEVTXDROP
      // This is mostly for the gee-whiz factor.
    case IWEVTXDROP:
      debug_printf(DEBUG_INT, "Wireless TX Drop\n");
      break;
#endif
      
#if WIRELESS_EXT > 17
    case IWEVASSOCREQIE:
      debug_printf(DEBUG_INT, "IWEVASSOCREQIE\n");
      debug_hex_printf(DEBUG_INT, iwe->u.data.pointer, iwe->u.data.length);
      cardif_linux_rtnetlink_process_IWEVASSOCREQIE(ctx, iwe);
      break;
      
    case IWEVASSOCRESPIE:
      debug_printf(DEBUG_INT, "IWEVASSOCRESPIE\n");
      cardif_linux_rtnetlink_process_IWEVASSOCRESPIE(ctx, iwe);
      break;
      
    case IWEVGENIE:
#warning Check this!
      if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
	{
	  cardif_linux_rtnetlink_process_IWEVGENIE(ctx, iwe);
	}
      break;

    case IWEVMICHAELMICFAILURE:
      debug_printf(DEBUG_INT, "MIC Failure!\n");
      cardif_linux_rtnetlink_process_IWEVMICHAELMICFAILURE(ctx, iwe);
      break;
      
    case IWEVPMKIDCAND:
      debug_printf(DEBUG_INT, "IWEVPMKIDCAND\n");
      break;
#endif
    case SIOCGIWENCODE:
      if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
	{
	  if (!(iwe->u.data.flags & IW_ENCODE_DISABLED))
	    {
	      config_ssid_update_abilities(wctx, ENC);
	    }
	}
      break;
      
    case SIOCGIWRATE:
      // Don't care.
      break;
      
    case IWEVQUAL:
      debug_printf(DEBUG_INT, "Quality : %d  Signal : %d   Noise : %d\n",
		   iwe->u.qual.qual, (iwe->u.qual.level - 0x100), 
		   (iwe->u.qual.noise - 0x100));
      config_ssid_add_qual(wctx, iwe->u.qual.qual, (iwe->u.qual.level - 0x100), 
			   (iwe->u.qual.noise - 0x100));
      break;
      
    case IWEVCUSTOM:
      cardif_linux_rtnetlink_process_IWEVCUSTOM(ctx, iwe);
      break;

    case SIOCSIWENCODE:
      debug_printf(DEBUG_INT, "Encryption key set\n");
      break;

    default:
      debug_printf(DEBUG_INT, "Unknown event (%04X)  (Unknown in wireless "
		   "extensions %d?)\n", iwe->cmd, WIRELESS_EXT);
    }
}

/*******************************************************
 *
 * Check to see if we have any events, and act on them if we do.
 *
 *******************************************************/
int cardif_linux_rtnetlink_check_event(context *ctx, int sock)
{
  int rtnl_data_size, remain, length;
  char buf[8192];
  struct nlmsghdr *nlhead = NULL;

  // The context passed in to this function is a place holder value.  If
  // it is anything but NULL, then something is broken!
  if (!xsup_assert((ctx == NULL), "ctx == NULL", FALSE))
    return XEMALLOC;

  // Grab the next message off the rtnetlink socket.
  rtnl_data_size = sizeof(rtnl_data);
  if (rtnl_sock < 0)
    {
      debug_printf(DEBUG_NORMAL, "RTnetlink socket not available!\n");
      return XENOSOCK;
    }

  remain = recvfrom(rtnl_sock, buf, sizeof(buf), MSG_DONTWAIT,
		    (struct sockaddr *)&rtnl_data, 
		    (u_int *) &rtnl_data_size);
  if (remain >= 0)
    {
      // We need a pointer to the buffer to work with.
      nlhead = (struct nlmsghdr *)buf;

      // There may be more than one message in the packet.  So, loop through!
      while (remain >= sizeof(struct nlmsghdr))
	{
	  // Make sure we have enough data for a real message.
	  if ((nlhead->nlmsg_len > remain) || 
	      ((nlhead->nlmsg_len - sizeof(struct nlmsghdr)) < 0))
	    {
	      debug_printf(DEBUG_NORMAL, "Invalid netlink message!\n");
	      break;
	    }
	  
	  // See what kind of message it is.
	  switch (nlhead->nlmsg_type)
	    {
	    case RTM_NEWLINK:
	      debug_printf(DEBUG_INT, "Got an RTM_NEWLINK!\n");
	      cardif_linux_rtnetlink_do_link(nlhead,
					     nlhead->nlmsg_len, INT_NEW);
	      break;
	      
	    case RTM_DELLINK:
	      debug_printf(DEBUG_INT, "Got an RTM_DELLINK!\n");
	      cardif_linux_rtnetlink_do_link(nlhead, 
					     nlhead->nlmsg_len, INT_DEL);
	      break;
	    }

	  // Find the aligned length of the message, so we can skip
	  // to the next message.
	  length = NLMSG_ALIGN(nlhead->nlmsg_len);

	  remain -= length;
	  
	  nlhead = (struct nlmsghdr *) ((char *)nlhead + length);
	}

      // If we have anything left, then there may be a problem.  So, report
      // the we may have a problem.
      if (remain > 0)
	{
	  debug_printf(DEBUG_NORMAL, "Extra bytes at the end of the netlink message.\n");
	}
    }

  return XENONE;
}

/************************************************************
 *
 *  We got an RTM_NEWLINK or RTM_DELLINK message, so process it, and 
 *  decide how to proceed.
 *
 ************************************************************/
void cardif_linux_rtnetlink_do_link(struct nlmsghdr *msg, int len, int type)
{
  struct ifinfomsg *ifinfo = NULL;
  int nlmsg_len, rtalen, rtlen;
  struct rtattr *rtattr = NULL;

  if (!xsup_assert((msg != NULL), "msg != NULL", FALSE))
    return;

  if (len < sizeof(struct ifinfomsg))
    {
      debug_printf(DEBUG_NORMAL, "Netlink message too short!\n");
      return;
    }

  // Get the actual message from the block.
  ifinfo = NLMSG_DATA(msg);

  // Find out how big the message is.
  nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

  if ((msg->nlmsg_len - nlmsg_len) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Message inside newlink isn't valid!\n");
      return;
    }

  rtattr = (struct rtattr *)(((char *)ifinfo) + nlmsg_len);

  rtalen = RTA_ALIGN(sizeof(struct rtattr));
  
  // Validate the attribute we have, and determine if it is for wireless,
  // or wired.
  while (RTA_OK(rtattr, (msg->nlmsg_len - nlmsg_len)))
    {
      switch (rtattr->rta_type)
	{
	case IFLA_UNSPEC:
	  debug_printf(DEBUG_INT, "IFLA_UNSPEC event.\n");
	  break;

	case IFLA_ADDRESS:
	  debug_printf(DEBUG_INT, "IFLA_ADDRESS event.\n");
	  break;

	case IFLA_BROADCAST:
	  debug_printf(DEBUG_INT, "IFLA_BROADCAST event.\n");
	  break;

	case IFLA_IFNAME:
	  // This is a non-wireless event. (Ignore it.)
	  debug_printf(DEBUG_INT, "IFLA_IFNAME event.\n");
	  break;

	case IFLA_MTU:
	  debug_printf(DEBUG_INT, "IFLA_MTU event.\n");
	  break;

	case IFLA_LINK:
	  debug_printf(DEBUG_INT, "IFLA_LINK event.\n");
	  break;

	case IFLA_WIRELESS:
	  // This is a wireless event.
	  cardif_linux_rtnetlink_ifla_wireless(ifinfo->ifi_index,
					       ((char *) rtattr)+rtalen,
					       rtattr->rta_len - rtalen);
	  break;

	case IFLA_OPERSTATE:
	  cardif_linux_rtnetlink_ifla_operstate(ifinfo->ifi_index,
						((char *) rtattr)+rtalen,
						rtattr->rta_len - rtalen);
	  break;

	default:
	  debug_printf(DEBUG_INT, "RTNetlink Event type %d\n", 
		       rtattr->rta_type);
	  break;
	}

      rtlen = msg->nlmsg_len - nlmsg_len;

      // Get the next attribute
      rtattr = RTA_NEXT(rtattr, rtlen);
    }
}

/***********************************************************
 *
 * Check the string that identifies the custom event that we got. And
 * act on it.
 *
 ***********************************************************/
void cardif_linux_rtnetlink_check_custom(context *intdata,
					 char *str)
{
  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((str != NULL), "str != NULL", FALSE))
    return;

  if (strncmp(str, "MLME-MICHAELMICFAILURE.indication", 33) == 0)
    {
      intdata->statemachine->MICfailures++;
      debug_printf(DEBUG_NORMAL, "MIC failure #%d!\n",
		   intdata->statemachine->MICfailures);
      
      if (strstr(str, " unicast ") != NULL)
	{
	  // The attempted attack was probably against the unicast key.
	  debug_printf(DEBUG_NORMAL, "MIC failure on unicast key!\n");
	  eapol_key_type254_request_new_key(intdata, 1);
	  intdata->send_size = 0;
	} else {
	  // The attempted attack was probably against the group key.
	  debug_printf(DEBUG_NORMAL, "MIC failure on group key!\n");
	  eapol_key_type254_request_new_key(intdata, 0);
	  intdata->send_size = 0;
	}

      if (intdata->statemachine->MICfailures >= 2)
	{
	  // The WPA/802.11i standard requires we assert countermeasures 
	  // for 60 seconds.
	  if (timer_check_existing(intdata, COUNTERMEASURE_TIMER))
	    {
	      debug_printf(DEBUG_NORMAL, "For some reason, we already have "
			   "a countermeasure timer in the queue!  Resetting "
			   "the timer!\n");
	      timer_reset_timer_count(intdata, COUNTERMEASURE_TIMER, 
				      MIC_COUNTERMEASURE_TIMEOUT);
	    } else {
	      debug_printf(DEBUG_NORMAL, "Enabling MIC countermeasures!\n");
	      timer_add_timer(intdata, COUNTERMEASURE_TIMER, 
			      MIC_COUNTERMEASURE_TIMEOUT,
			      NULL, &mic_disable_countermeasures);
	    }
	  cardif_countermeasures(intdata, TRUE);
	}
    }
}

/***********************************************************
 *
 * Check to see if we have become disassociated before the rekey_prob_timer
 * (found in profile.h) reaches 0.  If we have, it may indicate that we
 * have a card driver that resets the card on a key set.  This should only be
 * a problem with WEP and older card drivers.
 *
 ***********************************************************/
void cardif_linux_rtnetlink_check_key_prob(context *idata)
{
  struct config_globals *globals = NULL;

  if (!xsup_assert((idata != NULL), "idata != NULL", FALSE))
    return;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return;

  if (timer_check_existing(idata, REKEY_PROB_TIMER))
    {
      if (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
	{
	  debug_printf(DEBUG_NORMAL, "** WARNING! ** You were disassocated "
		       "within a short time of setting a key!\nThis usually "
		       "means there is a problem with the card driver.\n"
		       "Please e-mail the developers for more information on "
		       "what this means. Be sure to include the type of card, "
		       "driver in use, and driver version number.\n");
	}
    }
}

/***********************************************************
 *
 * Process operstate events.
 *
 ***********************************************************/
void cardif_linux_rtnetlink_ifla_operstate(int ifindex, char *data, int len)
{
  if (!xsup_assert((data != NULL), "data != NULL", FALSE))
    return;

  debug_printf(DEBUG_INT, "Got a netlink OPERSTATE event!\n");

  debug_printf(DEBUG_INT, "OPERSTATE event on interface %d\n", ifindex);

  debug_printf(DEBUG_INT, "Event dump (%d) : \n", len);
  debug_hex_dump(DEBUG_INT, data, len);

  switch(data[0])
    {
    case XIF_OPER_UNKNOWN:
      debug_printf(DEBUG_INT, "Interface is in unknown state.\n");
      break;

    case XIF_OPER_NOTPRESENT:
      debug_printf(DEBUG_INT, "Interface is not present.\n");
      break;

    case XIF_OPER_DOWN:
      debug_printf(DEBUG_INT, "Interface is down.\n");
      break;

    case XIF_OPER_LOWERLAYERDOWN:
      debug_printf(DEBUG_INT, "Interface lower layer is down.\n");
      break;

    case XIF_OPER_DORMANT:
      debug_printf(DEBUG_INT, "Interface is dormant.\n");
      break;

    case XIF_OPER_UP:
      debug_printf(DEBUG_INT, "Interface is up.\n");
      break;

    default:
      debug_printf(DEBUG_INT, "Unknown interface state %d.\n", data[0]);
      break;
    }
}

/***********************************************************
 *
 * Process wireless events.
 *
 ***********************************************************/
void cardif_linux_rtnetlink_ifla_wireless(int ifindex, char *data, int len)
{
  struct iw_event iwe;
  struct config_globals *globals = NULL;
  struct stream_descr stream;
  wireless_ctx *wctx = NULL;
  context *ctx = NULL;
  char intName[128];
  int intIndex = 0;
  int ret = 0;

  if (!xsup_assert((data != NULL), "data != NULL", FALSE))
    return;

  // Determine the name of the interface that generated the event.
  if (if_indextoname(ifindex, intName) == NULL) return;

  // Locate the context that matches the ifindex.
  event_core_reset_locator();
  ctx = event_core_get_next_context();

  if(ctx != NULL)
    {
      debug_printf(DEBUG_NORMAL, "Checking '%s = %s'.\n", intName, ctx->intName);
    }

  while (((ctx != NULL) && (strcmp(intName, ctx->intName) != 0)))
    {
      ctx = event_core_get_next_context();
      if(ctx != NULL)
	{ 
	  debug_printf(DEBUG_NORMAL, "Checking '%s = %s'.\n", intName, ctx->intName);
	}
      else 
	{
	  debug_printf(DEBUG_NORMAL, "ctx is NULL in %s:%d\n", __FUNCTION__, __LINE__);
	}
    }

  if (ctx == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Unable to locate interface '%s' with index '%d' in %s.\n", intName, ifindex, __FUNCTION__);
      return;
    }

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (wctx == NULL)
    {
      if (ctx->intType == ETH_802_11_INT)
	{
	  debug_printf(DEBUG_NORMAL, "Got a wireless event, but the context for '%s' doesn't have a wireless subcontext!?\n");
	  return;
	}

      debug_printf(DEBUG_NORMAL, "Got a wireless event on non-wireless interface '%s'.\n");
    }

  if ((data == NULL) || (len == 0))
    {
      debug_printf(DEBUG_NORMAL, "No data available in event!\n");
      return;
    }

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return;

  iw_init_event_stream(&stream, data, len);
  do
    {
#ifdef OLD_IWLIB
      ret = iw_extract_event_stream(&stream, &iwe);
#else
      ret = iw_extract_event_stream(&stream, &iwe, 
				    cardif_linux_rtnetlink_get_we_ver(ctx));
#endif

      if (ret <= 0) return;

      intIndex = if_nametoindex(ctx->intName);

      if ((ifindex != intIndex) &&
	  (!(TEST_FLAG(wctx->flags, WIRELESS_ONEDOWN))))
	{
	  debug_printf(DEBUG_INT, "Got a wireless event!  Interface index is %d, "
		       "we are using index %d!\n", ifindex, intIndex);
	  debug_printf(DEBUG_INT, "Ignoring!\n");
	  return;
	}
 
      if (TEST_FLAG(wctx->flags, WIRELESS_ONEDOWN))
	{
	  if ((ifindex < (intIndex - 1)) || (ifindex > (intIndex)))
	    {
	      debug_printf(DEBUG_INT, "Got a wireless event! Interface index is "
			   "%d, we are using indexes %d & %d!\n", ifindex,
			   intIndex-1, intIndex);
	      return;
	    }
	}

      // Process the event.
      cardif_linux_rtnetlink_process_token(ctx, &iwe);
    } while (ret > 0);
}

/*************************************************************************
 *
 *  Manually check and see if we have scan data to return.  This is needed
 * for devices that don't return scan complete events.
 *
 *************************************************************************/
uint8_t cardif_linux_rtnetlink_scancheck(context *ctx)
{
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
      return 0;

  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
		   FALSE))
    return 0;

  wctx = (wireless_ctx *)ctx->intTypeData;
  
  if (ctx->intType == ETH_802_11_INT)
    {
      if (TEST_FLAG(wctx->flags, WIRELESS_SCANNING))
	{
	  // It is okay to set a socket of -1 to rtnetlink_check_event.  It
	  // uses an internal variable to keep track of it's socket anyway.
	  if (cardif_linux_rtnetlink_check_nets(ctx) != XDATA)
	    {
	      debug_printf(DEBUG_INT, "Waiting for SSID information...\n");
	    }
	  else
	    {
	      // We got data, and canceled our timer, so let the caller know.
#warning Update caller to use the proper value!
	      return 0xff;
	    }
	}
    }
  return 0;
}

/*************************************************************************
 *
 *  Add an attribute to our packet that we are going to send to the kernel.
 *
 *************************************************************************/
int cardif_linux_rtnetlink_add_attr(int type, struct nlmsghdr *nldr,
				    int bufsize, uint8_t *data, int attrlen)
{
  struct rtattr *rtattr = NULL;
  int len = 0;

  // Determine the total length of the message.
  len = RTA_LENGTH(attrlen);

  if (NLMSG_ALIGN(nldr->nlmsg_len)+len > bufsize)
    {
      debug_printf(DEBUG_NORMAL, "Not enough buffer space to create netlink "
		   "request.  Buffer size is %d, but required buffer size "
		   "is %d.\n", bufsize, NLMSG_ALIGN(nldr->nlmsg_len));
      return -1;
    }

  rtattr = (struct rtattr *)(((char *)nldr) + NLMSG_ALIGN(nldr->nlmsg_len));
  rtattr->rta_type = type;
  rtattr->rta_len = len;
  memcpy(RTA_DATA(rtattr), data, attrlen);

  // Update our length to account for everything.
  nldr->nlmsg_len = NLMSG_ALIGN(nldr->nlmsg_len) + len;

  return 0;
}

/*************************************************************************
 *
 *  On init, we need to tell the OS to put interfaces that are "UP" in to
 * dormant mode.  See http://www.flamewarmaster.de/software/operstates.txt
 * for information on how this should all work.
 *
 *************************************************************************/
void cardif_linux_rtnetlink_set_linkmode(context *ctx, uint8_t newstate)
{
  struct {
    struct nlmsghdr nlmsg;
    struct ifinfomsg ifi;
    uint8_t data[sizeof(struct rtattr)+1];
  } state;

  static int seq;

  debug_printf(DEBUG_INT, "Setting Linkmode to %d.\n", newstate);

  memset(&state, 0x00, sizeof(state));

  state.nlmsg.nlmsg_type = RTM_SETLINK;
  state.nlmsg.nlmsg_seq = ++seq;
  state.nlmsg.nlmsg_flags = NLM_F_REQUEST;
  state.nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

  state.ifi.ifi_family = AF_UNSPEC;
  state.ifi.ifi_index = if_nametoindex(ctx->intName);

  if (cardif_linux_rtnetlink_add_attr(IFLA_LINKMODE, &state.nlmsg, 
				      sizeof(state), &newstate, 1) != 0)
    {
      // Couldn't do anything.
      return;
    }

  // Otherwise, send the packet.
  send(rtnl_sock, (void *)&state, sizeof(state), 0);
}

/*************************************************************************
 *
 *  Send an RTNETLINK message that indicates that the interface is now 
 *  fully up.  This will allow things such as DHCP to happen.
 *
 *  See http://www.flamewarmaster.de/software/operstates.txt for information
 *  on how this should all work.
 *
 *************************************************************************/
void cardif_linux_rtnetlink_set_operstate(context *ctx, uint8_t newstate)
{
  struct operstaterequest {
    struct nlmsghdr nlmsg;
    struct ifinfomsg ifi;
    uint8_t data[sizeof(struct rtattr)+1];
  };

  static uint32_t seq;
  
  struct operstaterequest opstate;

  debug_printf(DEBUG_INT, "Setting operstate to %d\n", newstate);

  memset(&opstate, 0x00, sizeof(opstate));

  opstate.nlmsg.nlmsg_type = RTM_SETLINK;
  opstate.nlmsg.nlmsg_seq = ++seq;
  opstate.nlmsg.nlmsg_flags = NLM_F_REQUEST;
  opstate.nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

  opstate.ifi.ifi_family = AF_UNSPEC;
  opstate.ifi.ifi_index = if_nametoindex(ctx->intName);

  if (cardif_linux_rtnetlink_add_attr(IFLA_OPERSTATE, &opstate.nlmsg,
                                      sizeof(opstate), &newstate, 1) != 0)
    {
      // Couldn't do anything.
      return;
    }

  // Otherwise, send the packet.
  send(rtnl_sock, (void *)&opstate, sizeof(opstate), 0);
}
