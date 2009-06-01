/**
 * \file pmksa.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/  
  
#ifdef WINDOWS
#include <windows.h>
  
#include "stdintwin.h"
#else	
#include <string.h>
#endif // WINDOWS
  
#include <openssl/hmac.h>
#include <openssl/sha.h>
  
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "context.h"
#include "pmksa.h"
#include "timer.h"
#include "config_ssid.h"
#include "liblist/liblist.h"
#include "platform/cardif.h"
  
#define MAX_PMKSA_CACHE_DEPTH    32	///< The maximum number of entries that should ever be allowed in the cache.  (Per interface.)
  
/**
 * \brief Initalize our PMK cache.  
 **/ 
void
pmksa_cache_init (context * ctx) 
{
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;

  wctx = (wireless_ctx *) ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return;
  
  wctx->pmksa_cache = NULL;
  pmksa_init_cache_update (ctx);
  debug_printf (DEBUG_INT, "PMKSA cache inited.\n");
}


/**
 * \brief Dump the key cache to the log file for debugging.
 *
 * @param[in] ctx   The context of the interface we want to dump the cache for.
 **/ 
  void
pmksa_dump_cache (context * ctx) 
{
  pmksa_cache_element * cur = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  if (!xsup_assert 
	 ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return;
  
  wctx = ctx->intTypeData;
  cur = wctx->pmksa_cache;
  debug_printf (DEBUG_INT,
		   "---------------- PMKSA Cache Dump ---------------\n");

  while (cur != NULL)
    {
      debug_printf (DEBUG_INT, "PMKID : ");
      debug_hex_printf (DEBUG_INT, cur->pmkid, 16);
      debug_printf (DEBUG_INT, "AMAC : ");
      debug_hex_printf (DEBUG_INT, cur->authenticator_mac, 6);
      debug_printf (DEBUG_INT, "SSID : %s\n", cur->ssid);
      debug_printf (DEBUG_INT, "Remaining Lifetime :%d\n", cur->lifetime);
      cur = cur->next;
    }
  debug_printf (DEBUG_INT,
		  "------------------------------------------------\n");
}


/**
 * \brief Free the data from a single PMKSA cache entry
 *
 * @param[in] elem   The PMKSA cache entry that we want to be freed.
 **/ 
void
pmksa_free_cache_entry (void **data) 
{
  pmksa_cache_element * elem = (*data);
  
  if (!xsup_assert ((elem != NULL), "elem != NULL", FALSE))
    return;

    // Most of the data in our current cache entry will be freed when we free the base
    // pointer.  The things below are the exception.
    FREE (elem->pmk);
    FREE (elem->ssid);
    FREE ((*data));
}


/**
 * \brief Clear out all of the PMKSA cache entries that we currently know about.
 **/ 
void
pmksa_cache_clear (context * ctx) 
{
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  wctx = (wireless_ctx *) ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return;
  
  liblist_delete_list ((genlist **) & wctx->pmksa_cache,
			  pmksa_free_cache_entry);
  wctx->pmksa_cache = NULL;
}


/**
 * \brief Create a PMKID from the PMK, SPA, and AA.
 *
 * @param[in] pmk   The PMK ID to be used to generate a PMKID
 * @param[in] spa   The MAC address of the interface this PMKID will be part of.
 * @param[in] aa   The authenticator MAC address this PMKID will map to.
 *
 * \retval NULL   if a PMKID couldn't be created.
 * \retval PMKID   if a PMKID was created.
 **/ 
uint8_t * pmksa_create_pmkid (uint8_t * pmk, uint8_t * spa, uint8_t * aa) 
{
  uint8_t * pmkid = NULL;
  uint8_t * tohash = NULL;
  char *strhash = "PMK Name";
  unsigned int ressize = 0;
  
  tohash = Malloc (strlen (strhash) + 6 + 6);	// length of 'PMK Name' + sizeof(spa) + sizeof(aa) -- (Can't use sizeof on spa or aa because they are pointers.  But, you get the idea. ;)
  if (tohash == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to allocate memory to create the PMKID hash string.\n");
      return NULL;
    }
  
  strcpy ((char *) tohash, strhash);
  memcpy (&tohash[strlen (strhash)], aa, 6);
  memcpy (&tohash[strlen (strhash) + 6], spa, 6);
  pmkid = Malloc (32);	// The resulting hash should be 16 bytes.
  if (pmkid == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to allocate memory to create PMKID!\n");
      FREE (tohash);
      return NULL;
    }
  
  debug_printf (DEBUG_INT, "Hashing :\n");
  debug_hex_dump (DEBUG_INT, tohash, (strlen (strhash) + 12));
  HMAC (EVP_sha1 (), pmk, 32, tohash, (strlen (strhash) + 12), pmkid,
	  &ressize);
  FREE (tohash);
  return pmkid;
}


/**
 * \brief Check the cache depth to be sure it isn't too deep.  If it is, then age out the
 *        oldest entry.
 *
 * @param[in] ctx   The context that contains the cache we want to check.
 **/ 
void
pmksa_check_cache_depth (context * ctx) 
{
  pmksa_cache_element * cur = NULL, *oldest = NULL;
  wireless_ctx * wctx = NULL;
  int i = 0;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;

  wctx = ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return;
  
    // The first entry in the list probably is one of the newest ones, but we will start
    // by assuming it is the one we need to remove.  (If we are >= MAX_PMKSA_CACHE_DEPTH)
    cur = oldest = wctx->pmksa_cache;
  while (cur != NULL)
    {
      if (cur->lifetime < oldest->lifetime)
	oldest = cur;
      cur = cur->next;
      i++;
    }

  if (i >= MAX_PMKSA_CACHE_DEPTH)
    {
	// We need to age out an entry.
	pmksa_delete (ctx, oldest);
    }
}


/**
 * \brief Validate that we don't already have the PMK in the cache.
 *
 * @param[in] ctx   The context for the interface that we are checking the PMK on.
 * @param[in] pmkid   The PMKID that we want to search for.
 *
 * \retval NULL if the PMK cache entry doesn't exist yet.
 **/ 
pmksa_cache_element * pmksa_pmkid_exists (context * ctx, uint8_t * pmkid) 
{
  pmksa_cache_element * cur = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return NULL;
  
  if (!xsup_assert ((pmkid != NULL), "pmkid != NULL", FALSE))
    return NULL;
  
  if (!xsup_assert 
	 ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return NULL;
  
  wctx = ctx->intTypeData;
  cur = wctx->pmksa_cache;
  while (cur != NULL)
    {
	// See if this is our PMKID.
	if (memcmp (pmkid, cur->pmkid, 16) == 0)
	{
	  return cur;
	}

        cur = cur->next;
    }

  return NULL;
}


/**
 * \brief Determine if an SA already exists in the cache for this authenticator MAC.
 *        If it does, return it.
 *
 * @param[in] ctx   The context for the interface whose PMKSA cache we want to check.
 * @param[in] aMac   The authenticator MAC address that we want to check for an SA with.
 *
 * \retval NULL if the entry isn't found.
 **/ 
pmksa_cache_element * pmksa_sa_exists (context * ctx, uint8_t * aMac) 
{
  pmksa_cache_element * cur = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return NULL;
  
  if (!xsup_assert ((aMac != NULL), "aMac != NULL", FALSE))
    return NULL;

  if (!xsup_assert 
	 ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return NULL;

  wctx = ctx->intTypeData;
  cur = wctx->pmksa_cache;
  while (cur != NULL)
    {
	// See if this is our PMKID.
	if (memcmp (aMac, cur->authenticator_mac, 6) == 0)
	{
	  return cur;
	}
	cur = cur->next;
    }
  return NULL;
}


/**
 * \brief Create a PMKSA in our cache.
 *
 * @param[in] ctx   The context that we want to add a PMKSA to.
 * @param[in] aMac   The authenticator MAC address we want to add a PMKSA for.
 *
 * \retval 0 on success
 * \retval 1 on success, but no interface cache update is needed.
 * \retval -1 on error
 **/ 
int
pmksa_add (context * ctx, uint8_t * aMac) 
{
  uint8_t * pmkid = NULL;
  pmksa_cache_element * newElem = NULL;
  config_globals * globals = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return -1;
  
  if (!xsup_assert ((aMac != NULL), "aMac != NULL", FALSE))
    return -1;
  
  wctx = ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return -1;
  
  if (!xsup_assert 
	 ((ctx->statemachine != NULL), "ctx->statemachine != NULL", FALSE))
    return -1;
 
    // If there is no PMK available, then ignore this request.
  if (ctx->statemachine->PMK == NULL)
    return 1;
  
  pmkid = pmksa_create_pmkid (ctx->statemachine->PMK, 
				  (unsigned char *) ctx->source_mac, aMac);
  if (pmkid == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to create PMKID for interface '%s'.  This key will not be cached.\n",
		      ctx->desc);
      return -1;
    }
  
  newElem = pmksa_pmkid_exists (ctx, pmkid);
  if (newElem != NULL)
    {
	// Our cache entry already exists, so leave it alone.
	debug_printf (DEBUG_INT, "Cache entry already exists.  Ignoring.\n");
	FREE (pmkid);
	return 1;
    }
  newElem = pmksa_sa_exists (ctx, aMac);
  if (newElem != NULL)
    {
	// Our cache entry exists, but we have a newer one.  Delete the old one.  And then move on to add
	// the new one.
	debug_printf (DEBUG_INT, "Clearing stale cache entry.\n");
	pmksa_delete (ctx, newElem);
    }
  pmksa_check_cache_depth (ctx);
  newElem = Malloc (sizeof (pmksa_cache_element));
  if (newElem == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to allocate memory to create new PMKSA cache entry.  This key will not be cached.\n");
      FREE (pmkid);
      return -1;
    }
  globals = config_get_globals ();
  newElem->akmp = 1;		// 802.1X
  memcpy (newElem->authenticator_mac, aMac, 6);
  if (globals->pmksa_age_out == 0)
    {
      newElem->lifetime = PMKSA_DEFAULT_AGEOUT_TIME;
    }
  else
    {
      newElem->lifetime = globals->pmksa_age_out;
    }
  newElem->pmk = Malloc (32);
  if (newElem->pmk == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to allocate memory to cache the PMK.\n");
      FREE (pmkid);
      return -1;
    }
  memcpy (newElem->pmk, ctx->statemachine->PMK, 32);
  memcpy (&newElem->pmkid, pmkid, 16);
  debug_printf (DEBUG_INT, "PMKID : \n");
  debug_hex_dump (DEBUG_INT, pmkid, 16);
  FREE (pmkid);
  newElem->ssid = _strdup (wctx->cur_essid);
  
    // Then, add it to the list.
  newElem->next = wctx->pmksa_cache;
  wctx->pmksa_cache = newElem;
  debug_printf (DEBUG_INT, "Added PMKID to our cache.\n");
  return 0;
}


/**
 * \brief Delete a PMKSA from the cache.
 *
 * @param[in] ctx   The context that contains the cache element we want to delete.
 * @param[in] toDelete   A pointer to the element we want to delete.
 **/ 
void
pmksa_delete (context * ctx, pmksa_cache_element * toDelete) 
{
  pmksa_cache_element * cur = NULL, *last = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  if (!xsup_assert ((toDelete != NULL), "toDelete != NULL", FALSE))
    return;
  
  debug_printf (DEBUG_KEY_STATE,
		   "Deleting PMKID %x from the PMKSA cache on %s.\n",
		   toDelete->pmkid, ctx->desc);
  wctx = ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return;
  if (toDelete == wctx->pmksa_cache)
    {
	// We want to delete the first node in our list.
      cur = wctx->pmksa_cache;
      wctx->pmksa_cache = wctx->pmksa_cache->next;
      pmksa_free_cache_entry ((void **) &cur);
      FREE (cur);
    }
  else
    {
	// We want to delete a node later in the list.
      last = wctx->pmksa_cache;
      cur = last->next;
      while (cur != NULL)
	{
	  if (cur == toDelete)
	    {
		// Delete this entry.
	      last->next = cur->next;	// Remove the node from the list.
	      pmksa_free_cache_entry ((void **) &cur);	// Free the memory of the removed node.
	      FREE (cur);
	      return;		// Jump out.
	    }
	  cur = cur->next;
	  last = last->next;
	}
    }
  debug_printf (DEBUG_KEY_STATE,
		   "Unable to locate PMKID %x on interface %s!\n",
		   toDelete->pmkid, ctx->desc);
}


/**
 * \brief Check out PMKSA cache, decrement the lifetime values, and if we find any cache entries that have expired,
 *        delete them.
 *
 * @param[in] ctx   The context to age out the cache entries on.
 * @param[in] secs_elapsed   The amount of time that has elapsed since we last checked the cache.  (This value is
 *                           decremented from the lifetime value in the cache.
 **/ 
void
pmksa_age_out (context * ctx, uint8_t secs_elapsed) 
{
  pmksa_cache_element * cur = NULL, *next = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  if (!xsup_assert ((secs_elapsed > 0), "secs_elapsed > 0", FALSE))
    return;
  
  debug_printf (DEBUG_KEY_STATE,
		   "PMKSA cache update for interface '%s'.  (%d secs elapsed)\n",
		   ctx->desc, secs_elapsed);
  wctx = ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return;
  cur = wctx->pmksa_cache;
  while (cur != NULL)
    {
      if ((cur->lifetime - secs_elapsed) <= 0)
	{
	  debug_printf (DEBUG_NORMAL,
			  "Aging out PMKSA entry for %02x:%02x:%02x:%02x:%02x:%02x on interface '%s'.\n",
			  cur->authenticator_mac[0],
			  cur->authenticator_mac[1],
			  cur->authenticator_mac[2],
			  cur->authenticator_mac[3],
			  cur->authenticator_mac[4],
			  cur->authenticator_mac[5], ctx->desc);
	  next = cur->next;
	  pmksa_delete (ctx, cur);
	  cur = next;
	}
      else
	{
	  cur->lifetime -= secs_elapsed;
	  cur = cur->next;
	}
    }
}


/**
 * \brief This function will be called against all SSIDs that are found during a passive scan.  It should check
 *        the scan cache, and if a PMKSA exists, it should reset the age out timer for the entry.
 *
 * @param[in] ctx   The context that the PMKSA cache is tied to.
 * @param[in] aMac   The authenticator's MAC address.
 * @param[in] ssid   The SSID that the authenticator's MAC address is tied to.
 **/ 
void
pmksa_seen (context * ctx, uint8_t * aMac, char *ssid) 
{
  wireless_ctx * wctx = NULL;
  pmksa_cache_element * cur = NULL;
  config_globals * globals = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  if (!xsup_assert ((aMac != NULL), "aMac != NULL", FALSE))
    return;

  if (!xsup_assert ((ssid != NULL), "ssid != NULL", FALSE))
    return;

  wctx = ctx->intTypeData;
  if (!xsup_assert ((wctx != NULL), "wctx != NULL", FALSE))
    return;
  
  globals = config_get_globals ();
  cur = wctx->pmksa_cache;
  while (cur != NULL)
    {
      if ((cur != NULL) 
	    &&(memcmp (cur->authenticator_mac, aMac, 6) == 0) 
	    &&(strcmp (cur->ssid, ssid) == 0))
	{
	    // This entry has been seen.  Reset it's lifetime.
	    debug_printf (DEBUG_INT,
			   "Resetting ageout counter for %02x:%02x:%02x:%02x:%02x:%02x\n",
			   aMac[0], aMac[1], aMac[2], aMac[3], aMac[4],
			   aMac[5]);
	  if (globals->pmksa_age_out == 0)
	    {
	      cur->lifetime = PMKSA_DEFAULT_AGEOUT_TIME;
	      break;
	    }
	  else
	    {
	      cur->lifetime = globals->pmksa_age_out;
	      break;
	    }
	}
      cur = cur->next;
    }
  if (cur == NULL)
    {
	// This entry is new.  Add it.
	debug_printf (DEBUG_NORMAL,
		      "Creating OKC entry for new AP %02x:%02x:%02x:%02x:%02x:%02x on interface '%s'.\n",
		      aMac[0], aMac[1], aMac[2], aMac[3], aMac[4], aMac[5],
		      ctx->desc);
      pmksa_add (ctx, aMac);
    }
}


/**
 * \brief Deinit the cache.
 **/ 
void
pmksa_cache_deinit (context * ctx) 
{
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  debug_printf (DEBUG_INT | DEBUG_DEINIT,
		   "Clearing PMKSA cache for interface '%s'.\n", ctx->desc);
  pmksa_cache_clear (ctx);
}


/**
 * \brief Our timer callback to handle PMKSA maintenance on the cache.
 *
 * @param[in] ctx   This value should always be NULL in this call.  It is required by the prototype,
 *                  but isn't used.
 **/ 
void
pmksa_cache_update (context * ctx) 
{
  config_globals * confdata = NULL;
  uint8_t secs_elapsed;
  
  confdata = config_get_globals ();
  if (confdata->pmksa_cache_check == 0)
    {
      secs_elapsed = PMKSA_CACHE_REFRESH;
    }
  else
    {
      secs_elapsed = confdata->pmksa_cache_check;
    }
  pmksa_age_out (ctx, secs_elapsed);
  
//      pmksa_dump_cache(ctx);
    
    // Reset the timer so we do this again when we are ready.
    timer_reset_timer_count (ctx, PMKSA_CACHE_MGMT_TIMER, secs_elapsed);
}


/**
 * \brief Init the PMKSA cache maintenance timer.
 *
 * @param[in] ctx   The context we want to start the timer on.
 **/ 
void
pmksa_init_cache_update (context * ctx) 
{
  config_globals * confdata = NULL;
  uint8_t secs_elapsed = 0;
  
  confdata = config_get_globals ();
  if (confdata == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to get configuration information needed to enable the PMKSA cache maintenance.  Will use the default.\n");
      secs_elapsed = PMKSA_CACHE_REFRESH;
    }
  else
    {
      if (confdata->pmksa_cache_check == 0)
	{
	  secs_elapsed = PMKSA_CACHE_REFRESH;
	}
      else
	{
	  secs_elapsed = confdata->pmksa_cache_check;
	}
    }
  
    // Enable our PMKSA cache maintenance timer.
    timer_add_timer (ctx, PMKSA_CACHE_MGMT_TIMER, secs_elapsed, NULL,
		     pmksa_cache_update);
}


/**
 * \brief Populate the PMK based on the PMKID provided.
 *
 * @param[in] ctx   The context for the interface that we want to apply the PMKSA entry to.
 * @param[in] pmkid   The PMKID that we want to locate, and use.
 *
 * \retval 0 on success
 **/ 
int
pmksa_populate_keydata (context * ctx, uint8_t * pmkid) 
{
  pmksa_cache_element * cur = NULL;
  wireless_ctx * wctx = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return -1;
  
  if (!xsup_assert ((pmkid != NULL), "pmkid != NULL", FALSE))
    return -1;
  
  if (!xsup_assert 
	 ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return -1;
  
  wctx = ctx->intTypeData;
  cur = wctx->pmksa_cache;
  while (cur != NULL)
    {
	// See if this is our PMKID.
	if (memcmp (pmkid, cur->pmkid, 16) == 0)
	{
	  if (ctx->statemachine->PMK != NULL)
	    FREE (ctx->statemachine->PMK);
	  
	  ctx->statemachine->PMK = Malloc (32);
	  if (ctx->statemachine->PMK == NULL)
	    {
	      debug_printf (DEBUG_NORMAL,
			      "Unable to allocate memory to store the PMK for interface '%s'!\n",
			      ctx->desc);
	      return -1;
	    }
	  memcpy (ctx->statemachine->PMK, cur->pmk, 32);
	  return 0;
	}
      cur = cur->next;
    }
  return -1;
}


/**
 * \brief Generate PMKIDs for Opportunistic Key Caching
 *
 * @param[in] ctx   The context that we want to use to create key cache entries for.
 **/ 
void
pmksa_generate_okc_data (context * ctx) 
{
  wireless_ctx * wctx = NULL;
  struct found_ssids *ssids = NULL;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return;
  if (!xsup_assert 
	 ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return;
  
  wctx = ctx->intTypeData;
  ssids = wctx->ssid_cache;
  while (ssids != NULL)
    {
	// We don't want cache entries for NULL (Hidden) SSIDs.
	if ((ssids->ssid_name != NULL) 
	    &&(strcmp (ssids->ssid_name, wctx->cur_essid) == 0))
	{
	    // Make sure this is an IEEE 802.11i/WPA2 network.
	    if (ssids->rsn_ie != NULL)
	    {
	      pmksa_add (ctx, ssids->mac);
	    }
	}
      ssids = ssids->next;
    }
}


/**
 * \brief Add a new cache entry to our 'short list'.
 *
 * @param[in] ctx   The context we are working with.
 * @param[in] ssid   The SSID scan entry that we want to add to the apply_list.
 * @param[in] apply_list   The resulting list of scan entries.
 * @param[in] entries   The number of entries that apply_list holds.
 *
 * \warning This function assumes that there is a PMKSA that is valid, and in the list for
 *          the SSID/BSSID combination that the parameter 'ssid' points to!
 *
 * \retval ptr  to the new lowest strength SSID in the list.
 **/ 
struct found_ssids *
pmksa_add_to_int_cache_list (context * ctx, struct found_ssids *ssid,
			     pmksa_list * apply_list, int entries) 
{
  int i = 0;
  int x = 0;
  
  if (!xsup_assert ((ctx != NULL), "ctx != NULL", FALSE))
    return NULL;
  
  if (!xsup_assert ((ssid != NULL), "ssid != NULL", FALSE))
    return NULL;
  
  if (!xsup_assert ((apply_list != NULL), "apply_list != NULL", FALSE))
    return NULL;
  
  if (!xsup_assert ((entries > 0), "entries > 0", FALSE))
    return NULL;
  
    // Start at the most likely value, and work down.
    for (i = (entries - 1); i >= 0; i--)
    {
	// If our new value is better than the one we are looking at, then we need to
	// insert it in to our list.
	if ((apply_list[i].ssid_element == NULL) 
	    ||
	    (config_ssid_best_signal 
	     (ssid, apply_list[i].ssid_element) == ssid))
	{
	    // Move each entry down one in the list.  Except for the lowest entry, which
	    // should be overwritten.
	    for (x = i; x >= 1; x--)
	    {
	      apply_list[x - 1].cache_element =
	      apply_list[x].cache_element;
	      apply_list[x - 1].ssid_element = apply_list[x].ssid_element;
	    }
	  apply_list[i].ssid_element = ssid;
	  apply_list[i].cache_element = pmksa_sa_exists (ctx, ssid->mac);
	  break;		// Stop the loop.
	}
    }
  
    // If we have any NULL entries in the list, the 'lowest' value should be NULL.
    for (i = 0; i < entries; i++)
    {
      if (apply_list[i].ssid_element == NULL)
	return NULL;
    }
  
    // Otherwise, it should be the one at element 0.
    return apply_list[0].ssid_element;
}


/**
 * \brief Figure out the best set of cache entries to push down to the card.
 *
 * @param[in] ctx   The context for the interface that we want to set the cache on.
 **/ 
void
pmksa_apply_cache (context * ctx) 
{
  wireless_ctx * wctx = NULL;
  struct found_ssids *ssids = NULL;
  struct found_ssids *lowest = NULL;
  pmksa_list * apply_list = NULL;
  int retval = 0;
  
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;
  
  if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
    return;
  
  wctx = (wireless_ctx *) ctx->intTypeData;
  ssids = wctx->ssid_cache;
  if (wctx->pmkids_supported <= 0)
    {
      debug_printf (DEBUG_INT,
		      "No PMKIDs are supported on this interface!  Won't attempt to set any.\n");
      return;
    }
  apply_list = Malloc(sizeof (pmksa_list) * wctx->pmkids_supported);
  if (apply_list == NULL)
    {
      debug_printf (DEBUG_NORMAL,
		      "Unable to allocate memory to store our PMK cache list.\n");
      return;
    }
  if (wctx->cur_essid == NULL)
    {
      debug_printf(DEBUG_NORMAL,
		      "Our current SSID is unknown on interface '%s'!  Can't generate PMKID list!\n",
		      ctx->desc);
      return;
    }
  
  while (ssids != NULL)
    {
	// If the SSID matches our current list.
	if ((ssids->ssid_name != NULL) 
	    &&(strcmp (wctx->cur_essid, ssids->ssid_name) == 0))
	{
	    // We only care about SSIDs we have a PMKID for. Ignore the rest.
	    if (pmksa_sa_exists (ctx, ssids->mac) != NULL)
	    {
	      if ((lowest == NULL) 
		    ||(config_ssid_best_signal (ssids, lowest) == ssids))
		{
		  lowest = pmksa_add_to_int_cache_list (ctx, ssids, apply_list,
						  wctx->pmkids_supported);
		}
	    }
	}
      ssids = ssids->next;
    }
  
#ifdef WINDOWS
	cardif_apply_pmkid_data(ctx, apply_list);   
#elif !defined(__APPLE__)
	if ( wctx->pmksa_add_ioctl_supported == TRUE )
        {
                retval = cardif_apply_pmkid_data(ctx, apply_list);
                if ( retval == 0)
                        wctx->pmksa_add_ioctl_supported = TRUE;
                else if ( retval == SIOCSIWPMKSA_NOT_SUPPORTED)
                        wctx->pmksa_add_ioctl_supported = FALSE;
        }
#else
#warning Need to implement for OS X!
#endif
//      pmksa_dump_cache(ctx);
    
    // All of the pointers in apply_list are referential pointers.  So we don't want to free them, just
    // the memory that was allocated for the list.
    FREE (apply_list);
}


