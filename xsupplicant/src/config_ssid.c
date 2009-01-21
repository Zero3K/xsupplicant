/**
 * Implementation for handling SSID related config pieces.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file config_ssid.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#ifndef WINDOWS
#include <unistd.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "xsup_err.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "libxsupconfcheck/xsupconfcheck_conn.h"
#include "liblist/liblist.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 * \brief Search through our list of known SSIDs, and see if we know the one
 *        specified in the wireless context.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the SSID
 *                   cache we want to search through.
 *
 * \retval NULL on error
 * \retval ptr to the structure that contains the information about 
 *         \c ssid_name.
 **/
struct found_ssids *config_ssid_find_by_wctx(wireless_ctx *wctx)
{
  struct found_ssids *cur = NULL;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return NULL;

  if (wctx->cur_essid == NULL) return NULL;  // If we don't have an SSID, then we won't find the SSID. :)

  // Start at the top of the list.
  cur = wctx->ssid_cache;

  while ((cur != NULL) && (strcmp(wctx->cur_essid, cur->ssid_name) != 0) && (memcmp(wctx->cur_bssid, cur->mac, 6) != 0))
    {
      cur = cur->next;
    }

  return cur;
}

/**
 * \brief Determine the best SSID based on the information given about the
 *        signal.
 *
 * Determine which SSID structure is the better choice based on the signal
 * quality information that we get from a scan.  We want to rely first on 
 * the signal and noise measurements, and then on the quality measurement.
 *
 * @param[in] one   The first structure to compare.
 * @param[in] two   The second structure to compare.
 *
 * \retval NULL on error
 * \retval ptr to the better choice of \c one, and \c two.
 **/
struct found_ssids *config_ssid_best_signal(struct found_ssids *one,
					    struct found_ssids *two)
{
  uint8_t one_lb = 0, two_lb = 0;

  if (!xsup_assert((one != NULL), "one != NULL", FALSE))
    return NULL;

  if (!xsup_assert((two != NULL), "two != NULL", FALSE))
    return NULL;

  if ((one->noise != 0) && (two->noise != 0))
    {
      one_lb = one->noise - one->signal;
      two_lb = two->noise - two->signal;
    }
  else if ((one->noise == 0) && (two->noise != 0))
    {
      return two;
    }
  else if ((one->noise == 0) && (two->noise == 0))
    {
      // We will have to rely on the quality value.
      if ((one->quality != 0) && (two->quality != 0))
	{
	  if (one->quality > two->quality)
	    {
	      return one;
	    }
	  else
	    {
	      return two;
	    }
	}
    }

  // If we get here, then we aren't sure which one is better.  So, return
  // nothing.
  return NULL;
}

/**
 * \brief Init a new node in the ESSID list.
 *
 * @param[in] wctx   A pointer to the wireless context that we want to create
 *                   a new cache node in.
 *
 * \retval NULL on error
 * \retval ptr to the structure that was just created.
 **/
struct found_ssids *config_ssid_init_new_node(wireless_ctx *wctx)
{
	struct found_ssids *working = NULL;

	working = (struct found_ssids *)Malloc(sizeof(struct found_ssids));
	if (working == NULL) return NULL;

	liblist_add_to_tail((genlist **)&wctx->ssid_cache, (genlist *)working);

	return working;
}
 
/**
 * \brief Add a newly discovered SSID.
 *
 * @param[in] wctx   A pointer to the wireless context that we want to add
 *                   the new SSID to.
 * @param[in] newssid   A pointer to the new SSID that we want to add.
 **/
void config_ssid_add_ssid_name(wireless_ctx *wctx, char *newssid)
{
	struct found_ssids *working = NULL;

	working = wctx->temp_ssid;

  if ((!working) || (working->ssid_name))
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Found new ESSID (%s), adding...\n", newssid);
	  wctx->temp_ssid = config_ssid_init_new_node(wctx);
	  working = wctx->temp_ssid;
    }

  // We need to make a copy.  We can't assume that the allocated memory
  // will always be there!
  working->ssid_name = _strdup(newssid);
}

/**
 * \brief Add a discovered WPA IE to an SSID node.
 *
 * @param[in] wctx   A pointer to the wireless context that we want to add
 *                   a newly discovered WPA IE to.
 * @param[in] wpa_ie   A pointer to the string of octets that make up the
 *                     WPA IE that we want to store.
 * @param[in] len   The length of the wpa_ie that we want to store.
 **/
void config_ssid_add_wpa_ie(wireless_ctx *wctx, uint8_t *wpa_ie, uint8_t len)
{
	struct found_ssids *working = NULL;

	working = wctx->temp_ssid;

  if ((!working) || (working->wpa_ie))
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Found new ESSID block, adding...\n");
      wctx->temp_ssid = config_ssid_init_new_node(wctx);
	  working = wctx->temp_ssid;
    }

  working->wpa_ie = (uint8_t *)Malloc(len);
  if (!working->wpa_ie)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store the WPA "
		   "IE!  Xsupplicant will not be able to use this ESSID! "
		   "(%s:%d)\n", __FUNCTION__, __LINE__);
      return;
    }

  memcpy(working->wpa_ie, wpa_ie, len);
  working->wpa_ie_len = len;
}

/**
 * \brief Add a newly discovered RSN IE to a SSID node.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the 
 *                   structure that we want to add this RSN IE to.
 * @param[in] rsn_ie   A pointer to a string of octets that make up the 
 *                     RSN IE to store.
 * @param[in] len   The length of the RSN IE that we want to store.
 **/
void config_ssid_add_rsn_ie(wireless_ctx *wctx, uint8_t *rsn_ie, uint8_t len)
{
	struct found_ssids *working = NULL;

	working = wctx->temp_ssid;

  if ((!working) || (working->rsn_ie))
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Found new ESSID block, adding...\n");
	  wctx->temp_ssid = config_ssid_init_new_node(wctx);
	  working = wctx->temp_ssid;
    }

  working->rsn_ie = (uint8_t *)Malloc(len);
  if (!working->rsn_ie)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store the RSN "
		   "IE!  Xsupplicant will not be able to use this ESSID! "
		   "(%s:%d)\n", __FUNCTION__, __LINE__);
	  ipc_events_malloc_failed(NULL);
      return;
    }

  memcpy(working->rsn_ie, rsn_ie, len);
  working->rsn_ie_len = len;
}

/**
 * \brief Add the BSSID to the ESSID node.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the 
 *                   structure that we want to add the BSSID to.
 * @param[in] newmac   A pointer to the new MAC address that we want to 
 *                     become the BSSID.
 **/
void config_ssid_add_bssid(wireless_ctx *wctx, char *newmac)
{
  char empty_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  struct found_ssids *working = NULL;

  if (!xsup_assert((newmac != NULL), "newmac != NULL", FALSE))
    return;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  working = wctx->temp_ssid;

  if (!working) 
    {
		wctx->temp_ssid = config_ssid_init_new_node(wctx);
		working = wctx->temp_ssid;
    }
  else
    {
      if (memcmp(working->mac, empty_mac, 6) != 0)
	{
	  debug_printf(DEBUG_PHYSICAL_STATE, "Found new ESSID block, adding...\n");
	  wctx->temp_ssid = config_ssid_init_new_node(wctx);
	  working = wctx->temp_ssid;
	}
    }

  memcpy(working->mac, newmac, 6);
}

/**
 * \brief Add flags to the ESSID node.
 *
 * @param[in] wctx   The wireless context that contains the structure that we
 *                   want to add the flags to.
 * @param[in] newabil   The new value for the flags byte in the structure.
 **/
void config_ssid_update_abilities(wireless_ctx *wctx, uint16_t newabil)
{
	struct found_ssids *working = NULL;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

	working = wctx->temp_ssid;

  // If we get here, and don't have a valid structure, then we are doomed.
  xsup_assert((working != NULL), "working != NULL", TRUE);

  working->abilities |= newabil;
}

/**
 * \brief Add the frequency to the ESSID node.
 *
 * @param[in] wctx  The wireless context that contains the structure that we 
 *                  want to update the frequency for.
 * @param[in] newfreq   The new value for the frequency.
 **/
void config_ssid_add_freq(wireless_ctx *wctx, unsigned int newfreq)
{
	struct found_ssids *working = NULL;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

	working = wctx->temp_ssid;

  if ((!working) || (working->freq != 0))
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Found new ESSID block, adding...\n");
	  wctx->temp_ssid = config_ssid_init_new_node(wctx);
	  working = wctx->temp_ssid;
    }

  working->freq = newfreq;
}

/**
 * \brief Add signal quality information to the ESSID node.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the 
 *                   structure whose values we need to update.
 * @param[in] qual   The new value for "quality" (Should be 0..100%)
 * @param[in] signal   The signal strength.
 * @param[in] noise   The amount of noise.
 **/
void config_ssid_add_qual(wireless_ctx *wctx, unsigned char qual, char signal, char noise, uint8_t percentage)
{
	struct found_ssids *working = NULL;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

	working = wctx->temp_ssid;

  if ((!working) || (working->quality != 0) || (working->signal != 0) ||
      (working->noise != 0))
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Found new ESSID block, adding...\n");
	  wctx->temp_ssid = config_ssid_init_new_node(wctx);
	  working = wctx->temp_ssid;
    }

  working->quality = qual;
  working->signal = signal;
  working->noise = noise;
  working->strength = percentage;
}

/**
 * \brief Dump all of the information about the SSIDs we are looking at.
 *
 * @param[in] wctx   The wireless context whose SSID cache we want to dump.
 **/
void config_ssid_dump(wireless_ctx *wctx)
{
  struct found_ssids *cur = NULL;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  cur = wctx->ssid_cache;

  debug_printf(DEBUG_PHYSICAL_STATE, "\n\n\nDumpping SSIDs:\n\n");

  while (cur != NULL)
    {
      if (cur == NULL)
	{
	  debug_printf(DEBUG_PHYSICAL_STATE, "NO VALID SSID INFORMATION AVAILABLE "
		       "TO DUMP!!\n");
	  return;
	}
      
      if (cur->ssid_name != NULL)
	{
	  debug_printf(DEBUG_PHYSICAL_STATE, "ESSID : %s\n", cur->ssid_name);
	  debug_printf(DEBUG_PHYSICAL_STATE, "Abilities : %02X\n", cur->abilities);
	  debug_printf(DEBUG_PHYSICAL_STATE, "Quality : %d     ", cur->quality);
	  if (cur->signal > 0)
	    {
	      debug_printf_nl(DEBUG_PHYSICAL_STATE, "Signal level : %d dBm",
			      cur->signal);
	    }

	  if (cur->noise > 0)
	    {
	      debug_printf_nl(DEBUG_PHYSICAL_STATE, "Noise level : %d dBm",
			      cur->noise);
	    }

	  debug_printf_nl(DEBUG_PHYSICAL_STATE, "\n");

	  if ((cur->wpa_ie != NULL) && ((cur->wpa_ie_len > 0) && (cur->wpa_ie_len < 255)))
	    {
	      debug_printf(DEBUG_PHYSICAL_STATE, "WPA IE (%d) : ", cur->wpa_ie_len);
	      debug_hex_printf(DEBUG_PHYSICAL_STATE, cur->wpa_ie, cur->wpa_ie_len);
	      debug_printf(DEBUG_PHYSICAL_STATE, "\n");
	    }
	  
	  if ((cur->rsn_ie != NULL) && ((cur->rsn_ie_len > 0) && (cur->rsn_ie_len < 255)))
	    {
	      debug_printf(DEBUG_PHYSICAL_STATE, "RSN IE (%d) : ", cur->rsn_ie_len);
	      debug_hex_printf(DEBUG_PHYSICAL_STATE, cur->rsn_ie, cur->rsn_ie_len);
		  debug_printf(DEBUG_PHYSICAL_STATE, "\n");
	    }
	}
      cur = cur->next;
    }
}

/**
 * \brief Free the memory used in a single node.
 *
 * @param[in] node   A pointer to the node that has the data we want to free.
 **/
void config_ssid_free_node(void **inptr)
{
	struct found_ssids *node = (*inptr);

	if (inptr == NULL) return;

    FREE(node->ssid_name);
    FREE(node->wpa_ie);
    FREE(node->rsn_ie);

	FREE((*inptr));
}

/**
 * \brief Free the SSID cache.
 *
 * Clear out the list of SSIDs that we know about.  This will usually be 
 * called at the time that a scan is started.  To allow for new data to
 * be compiled.
 *
 * @param[in] wctx   The wireless context whose SSID cache we want to clear.
 **/
void config_ssid_clear(wireless_ctx *wctx)
{
  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  liblist_delete_list((genlist **)&wctx->ssid_cache, config_ssid_free_node);

  wctx->ssid_cache = NULL;
}

/**
 * \brief Search through our list of known SSIDs, and see if we know the one
 *        specified in ssid_name.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the SSID
 *                   cache we want to search through.
 * @param[in] ssid_name   A pointer to the SSID name that we are attempting to 
 *                        locate in the SSID cache.
 *
 * \retval NULL on error
 * \retval ptr to the structure that contains the information about 
 *         \c ssid_name.
 **/
struct found_ssids *config_ssid_find_by_name(wireless_ctx *wctx, char *ssid_name)
{
  struct found_ssids *cur = NULL;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return NULL;

  if (!xsup_assert((ssid_name != NULL), "ssid_name != NULL", FALSE))
    return NULL;

  // Start at the top of the list.
  cur = wctx->ssid_cache;

  while (cur != NULL) 
    {
		if ((cur->ssid_name != NULL) && (strcmp(ssid_name, cur->ssid_name) != 0))
		{
			cur = cur->next;
		}
		else
		{
			break;
		}
    }

  if (cur != NULL)
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Found SSID with name of '%s'!\n",
		   cur->ssid_name);
    }

  return cur;
}

/**
 * \brief Given an SSID name, set the pointer to the active SSID configuration.
 *
 * \note If there is more than one AP visible, this won't necessarily find
 * the one that we are really connected to.  We mostly need this to have useful
 * information about the SSID, which should be the same between APs.
 *
 * @param[in] wctx   The wireless context that we want to update the active
 *                   SSID pointer for.
 * @param[in] ssid_name   The SSID name that we want to become the active 
 *                        SSID.
 *
 * \warning If the requested SSID is unavailable, the active SSID will be
 *          set to NULL!
 **/
/*
void config_ssid_set_active_ssid(wireless_ctx *wctx, char *ssid_name)
{
  if (!xsup_assert((ssid_name != NULL), "ssid_name != NULL", FALSE))
    return;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

  wctx->active_ssid = config_ssid_find_by_name(wctx, ssid_name);
}
*/

/**
 * \brief See if the ESSID requested is one that we know about in our list.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the SSID
 *                   cache that we want to search to see if we know about it.
 * @param[in] ssid   The name of the SSID that we want to search for.
 *
 * \retval FALSE if the SSID isn't in the cache
 * \retval TRUE if the SSID is in the cache
 **/
int config_ssid_ssid_known(wireless_ctx *wctx, char *ssid)
{
	if (ssid == NULL) return FALSE;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return FALSE;

  if (config_ssid_find_by_name(wctx, ssid) != NULL)
    {
      return TRUE;
    } else {
      return FALSE;
    }
}

/**
 * \brief Attempt to locate the "best" SSID in the cache.
 *
 * Go through the list of SSIDs that we found in the scan, and see which one
 * is the "best" based on the priority.  If there are two SSIDs with the same
 * priority, then we will return the first one that was found.
 *
 * @param[in] wctx   The wireless context that contains the SSID cache that we
 *                   want to find the "best" SSID in.
 *
 * \retval NULL if there are no SSIDs in the cache
 * \retval ptr to the "best" SSID to use.  (The one the supplicant believes
 *             has the highest chance of forming a useful connection.)
 **/
struct found_ssids *config_ssid_find_best_ssid(context *ctx)
{
  struct found_ssids *cur = NULL, *best = NULL, *temp = NULL;
  uint8_t best_pri = 0xff, cur_pri = 0;
  config_connection *conf = NULL;
  wireless_ctx *wctx = NULL;
  int retval = 0;
  struct config_globals *globals = NULL;
  struct config_connection *conn = NULL;
  char *machineAuth_wireless = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return NULL;
  
  if (ctx->intType != ETH_802_11_INT) 
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to find the 'best' SSID using an interface that isn't wireless!\n");
	  return NULL;
  }

  globals = config_get_globals();

#ifdef WINDOWS
	if ((globals != NULL) && (globals->wirelessMachineAuthConnection != NULL) &&
		(win_impersonate_is_user_on_console() == FALSE)) 
	{
		conn = config_find_connection(CONFIG_LOAD_GLOBAL, globals->wirelessMachineAuthConnection);
		if (conn != NULL)
		{
			machineAuth_wireless = _strdup(conn->ssid);
		}
	}
#endif	

  wctx = (wireless_ctx *)ctx->intTypeData;

  // Start at the top of our list of SSIDs.
  cur = wctx->ssid_cache;

  // We want to go through every single SSID we have in the list.
  while (cur != NULL)
    {
		retval = 0;

		if ((machineAuth_wireless != NULL) && (cur->ssid_name != NULL) &&
			(strcmp(machineAuth_wireless, cur->ssid_name) == 0))
		{
			cur_pri = 0;  // Force it lower than the lowest. ;)
		}
		else
		{
			cur_pri = config_get_network_priority(cur->ssid_name);
		}

		debug_printf(DEBUG_PHYSICAL_STATE, "Checking %s with Priority %d\n",
		   cur->ssid_name, cur_pri);

	  conf = config_find_connection_from_ssid(CONFIG_LOAD_GLOBAL, cur->ssid_name);
	  if (conf == NULL)
	  {
		  conf = config_find_connection_from_ssid(CONFIG_LOAD_USER, cur->ssid_name);
	  }

	  if (conf != NULL)
	  {
		if ((best != NULL) && (strcmp(cur->ssid_name, best->ssid_name) == 0))
			{
				if ((temp = config_ssid_best_signal(best, cur)) != NULL)
				{
					// We found the same SSID with a better signal, so select that
					// one.
					best = temp;
				}
				// Otherwise, we were unable to determine which one was better, so
				// just use the first one that showed up.
			}
	   else if (cur_pri < best_pri)
			{
				best = cur;
				best_pri = cur_pri;
			}
	  }

      cur = cur->next;
    }

  if (best)
    {
      debug_printf(DEBUG_PHYSICAL_STATE, "Best SSID appears to be '%s'\n",
		   best->ssid_name);
      debug_printf(DEBUG_PHYSICAL_STATE, "    Signal : %d   Noise : %d   Quality : "
		   "%d\n", best->signal, best->noise, best->quality);

	  conf = config_find_connection_from_ssid(CONFIG_LOAD_GLOBAL, best->ssid_name);
	  if (conf == NULL)
	  {
		  conf = config_find_connection_from_ssid(CONFIG_LOAD_USER, best->ssid_name);
	  }

	  if (conf != NULL)
	  {
		  retval = xsupconfcheck_conn_check(ctx, conf, FALSE);

		  if (retval > 0)   
		  {
			  // We need to ask the user for information.
			  ipc_events_ui(ctx, IPC_EVENT_UI_NEED_UPW, conf->name);

			  // If we return a value when we have less than all the info, we end up associating and not doing
			  // anything useful.  So wait until we have enough data to complete the auth before returning a value.
			  best = NULL;
		  } else if (retval < 0)
		  {
			  // We got an error.
			  best = NULL;
		  }
	  }
    }

  return best;
}

/**
 * \brief Locate an SSID in the SSID cache by means of the BSSID.
 *
 * By the time this function is called, we should have already selected the
 * SSID name we want to connect to.  But, it is possible that the user
 * specified a 'forced' MAC address in the configuration file.  If they did,
 * then we need to attempt to find the record for that specific MAC.  If we
 * can't, then we run the risk of having mismatched IEs, and we wouldn't be
 * able to connect.
 *
 * @param[in] ctx   The context that contains the information that we need to
 *                  use to locate the SSID.
 * @param[in] forced_mac   The MAC address that we are looking for.
 **/
void config_ssid_get_by_mac(context *ctx, uint8_t *forced_mac)
{
  struct found_ssids *cur = NULL;
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  if (!xsup_assert((forced_mac != NULL), "forced_mac != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)ctx->intTypeData;

  if (wctx == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Invalid wireless context in %s()!  Cannot use forced MAC address!\n",
			__FUNCTION__);
	  return;
  }

  cur = wctx->ssid_cache;

  while ((cur != NULL) && (memcmp(cur->mac, forced_mac, 6) != 0))
    {
      cur = cur->next;
    }

  if (cur == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find an SSID that matched the "
		   "static MAC address configured for this SSID.  We will "
		   "use the best detected MAC instead.\n");
      return;
    }

//  wctx->active_ssid = cur;
}

/**
 * \brief Return the SSID name for the SSID we want to connect to.
 *
 * @param[in] ctx   The context that contains the information about the SSID
 *                  we want to connect to.
 *
 * \retval NULL on error
 * \retval ptr to the name of the SSID we want to attempt to connect to.
 **/
char *config_ssid_get_desired_ssid(context *ctx)
{
  struct config_globals *globals = NULL;
  char cur_ssid[33];
  wireless_ctx *wctx = NULL;
  struct found_ssids *ssid = NULL;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return NULL;

  wctx = (wireless_ctx *)ctx->intTypeData;

  xsup_assert((wctx != NULL), "wctx != NULL", TRUE);

  // If the user has sent us a message to associate to a specific network,
  // then we should *ALWAYS* return that network!
  if (TEST_FLAG(ctx->flags, FORCED_CONN))
  {
	  if (ctx->conn == NULL)
	  {
		  debug_printf(DEBUG_NORMAL, "The flag to set a forced connection is set, "
					"but there isn't a connection configured?  Try setting the "
					"connection again!\n");
		  return NULL;
	  }

	  return ctx->conn->ssid;
  }

  // We don't know anything about the current SSID, so see if
  // we are in auto associate mode, and if so, find the SSID that the user
  // has specified with the highest priority.
  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return NULL;

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ASSOC_AUTO))
    {
      ssid = config_ssid_find_best_ssid(ctx);

      if (ssid == NULL) return NULL;

      return ssid->ssid_name;
    } else {
      memset(cur_ssid, 0x00, 33);

      // Get our current SSID
      if ((cardif_GetSSID(ctx, cur_ssid, 33) == XENONE) && (strlen(cur_ssid) > 0))
	{
	  ssid = config_ssid_find_by_name(wctx, cur_ssid);
	  
	  if (ssid != NULL) 
	    {
	      debug_printf(DEBUG_PHYSICAL_STATE, "Returning SSID '%s'\n", 
			   ssid->ssid_name);
	      return ssid->ssid_name;
	    } else {
	      debug_printf(DEBUG_NORMAL, "You are in manual association mode"
			   ", and the current ESSID was not found.  Will"
			   " scan again.\n");
	    }
	}
    }

  return NULL;
}

/**
 * \brief Return an unsigned char with bitflags that indicate what capabilities 
 * this SSID has. (Supporting of WEP, WPA, 802.11i, etc.)
 *
 * @param[in] wctx   The wireless context that contains the information that 
 *                   we need to return.
 *
 * \retval uint8_t A byte containing flags that indicate the capabilities of
 *                 the active SSID.
 **/
uint8_t config_ssid_get_ssid_abilities(wireless_ctx *wctx)
{
	struct found_ssids *ssid = NULL;

	xsup_assert((wctx != NULL), "wctx != NULL", TRUE);

	ssid = config_ssid_find_by_wctx(wctx);

  if (ssid == NULL) return 0x00;

  return ssid->abilities;
}

/**
 * \brief Return if we are using WEP or not.
 *
 * @param[in] wctx   The wireless context that contains the information needed
 *                   to know if this is a WEP enabled connection, or not.
 *
 * \retval TRUE if the connection uses WEP
 * \retval FALSE if the connection does not use WEP
 **/
int config_ssid_using_wep(wireless_ctx *wctx)
{
  int abil = 0;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return FALSE;

  abil = config_ssid_get_ssid_abilities(wctx);

  if ((abil & ABIL_WPA_IE) || (abil & ABIL_RSN_IE)) return FALSE;

  return TRUE;
}

/**
 * \brief Return the wpa_ie and the wpa_ie_len for the selected SSID.
 *
 * @param[in] wctx   A pointer to the wireless context that contains the WPA IE
 *                   information that we want to know about.
 * @param[out] wpa_ie   A pointer to the octet string that makes up the WPA IE.
 * @param[out] wpa_ie_len   A pointer to a value that indicates the length of 
 *                          the WPA IE.
 *
 * \warning The caller is expected to free the memory allocated by wpa_ie.
 **/
void config_ssid_get_wpa_ie(wireless_ctx *wctx, uint8_t **wpa_ie, uint8_t *wpa_ie_len)
{
	struct found_ssids *ssid = NULL;

  if (!xsup_assert((wpa_ie != NULL), "wpa_ie != NULL", FALSE))
    return;

  xsup_assert((wctx != NULL), "wctx != NULL", TRUE);

  ssid = config_ssid_find_by_wctx(wctx);

  if (ssid == NULL) 
    {
      *wpa_ie = NULL;
      (*wpa_ie_len) = 0;
      return;
    }

  (*wpa_ie) = ssid->wpa_ie;
  (*wpa_ie_len) = ssid->wpa_ie_len;
}

#define MACADDR(x)  x[0],x[1],x[2],x[3],x[4],x[5]
/**
 * \brief Return the rsn_ie and the rsn_ie_len for the selected SSID.
 *
 * @param[in] wctx   The wireless context that contains the information needed
 *                   to return the RSN IE for the active SSID.
 * @param[out] rsn_ie   A pointer to the return RSN IE value.
 * @param[out] rsn_ie_len   A pointer to a value that indicates the length of
 *                          the resulting RSN IE.
 **/
void config_ssid_get_rsn_ie(wireless_ctx *wctx, uint8_t **rsn_ie, uint8_t *rsn_ie_len)
{
	struct found_ssids *ssid = NULL;

  if (!xsup_assert((rsn_ie != NULL), "rsn_ie != NULL", FALSE))
    return;

  xsup_assert((wctx != NULL), "wctx != NULL", TRUE);

  ssid = config_ssid_find_by_wctx(wctx);

  if (ssid == NULL)
    {
      *rsn_ie = NULL;
      rsn_ie_len = 0;
      return;
    }

  if (ssid->rsn_ie == NULL)
  {
	  debug_printf(DEBUG_INT, "SSID : %s\n", ssid->ssid_name);
	  debug_printf(DEBUG_INT, "MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", MACADDR(ssid->mac));
	  debug_printf(DEBUG_INT, "Abilities : %d\n", ssid->abilities);
  }

  *rsn_ie = ssid->rsn_ie;
  *rsn_ie_len = ssid->rsn_ie_len;
}

/**
 * \brief Return the frequency that this AP is on.
 *
 * @param[in] wctx   The wireless context that contains the frequency for
 *                   the active AP.
 * 
 * \retval 0 if unknown
 * \retval u_int The frequency in use by the AP.
 **/
unsigned int config_ssid_get_freq(wireless_ctx *wctx)
{
	struct found_ssids *ssid = NULL;

	if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return 0;

	ssid = config_ssid_find_by_wctx(wctx);

	if (ssid == NULL) return 0;

	return ssid->freq;
}

/**
 * \brief Return the MAC address of the AP for this SSID.
 *
 * @param[in] wctx   The wireless context that contains the MAC address for the
 *                   active SSID.
 *
 * \retval NULL on error
 * \retval ptr to the MAC address of the AP.
 **/
uint8_t *config_ssid_get_mac(wireless_ctx *wctx)
{
	struct found_ssids *ssid = NULL;

	xsup_assert((wctx != NULL), "wctx != NULL", TRUE);

	ssid = config_ssid_find_by_wctx(wctx);

	if (ssid == NULL)
    {
      // This may not actually be a problem.  Rather, it could be that the
      // user wanted to use an SSID that we didn't find in a scan.
      debug_printf(DEBUG_PHYSICAL_STATE, "Invalid SSID struct!  (%s:%d)\n", 
		   __FUNCTION__, __LINE__);
      return NULL;
    }

  return (uint8_t *)&ssid->mac;
}
