/**
 * Handle keying for type 1 (RC4, non-TKIP) EAPOL Keys
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * \file eapol_key_type1.c
 *
 **/

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <string.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "eap_sm.h"
#include "wpa_common.h"
#include "frame_structs.h"
#include "platform/cardif.h"
#include "key_statemachine.h"
#include "eapol_key_type1.h"
#include "xsup_common.h"
#include "timer.h"
#include "ipc_events.h"
#include "ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 *  Write keydata into a logfile
 */
int eapol_dump_keydata(char *inframe, int framesize)
{
  struct key_packet *keydata;
  uint16_t length;

  if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
    return XEMALLOC;

  keydata = (struct key_packet *)inframe;

  debug_printf(DEBUG_KEY, "Key Descriptor   = %d\n",keydata->key_descr);

  memcpy(&length, keydata->key_length,2);
  debug_printf(DEBUG_KEY, "Key Length       = %d\n",ntohs(length));
  debug_printf(DEBUG_KEY, "Replay Counter   = ");
  debug_hex_printf(DEBUG_KEY, keydata->replay_counter, 8);
  debug_printf(DEBUG_KEY, "Key IV           = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_iv, 16);
  debug_printf(DEBUG_KEY, "Key Index (RAW)  = %02X\n",keydata->key_index);
  debug_printf(DEBUG_KEY, "Key Signature    = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_signature, 16);

  return XENONE;
}

/**
 * Check the HMAC on the key packet we got.  If we can't validate the
 * HMAC, then we return FALSE, indicating an error.
 **/
int eapol_key_type1_check_hmac(context *thisint, char *inframe,
			       int framesize)
{
  struct key_packet *keydata = NULL;
  char *framecpy = NULL;
  char *calchmac = NULL;
  int outlen = 0;
  int retVal = 0;
  int length = 0;

  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
    return XEMALLOC;

  if (thisint->eap_state->eapKeyData == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No keying material available!  Ignoring "
		   "key frame!\n");
      return XEMALLOC;
    }

  // First, make a copy of the frame.
  framecpy = (char *)Malloc(framesize);
  if (framecpy == NULL) 
  {
	  ipc_events_malloc_failed(thisint);
	  return XEMALLOC;
  }

  memcpy(framecpy, inframe, framesize);

  // Now, we want to zero out the HMAC.
  keydata = (struct key_packet *)&framecpy[4];

  memcpy(&length, keydata->key_length, 2);

  memset((char *)&keydata->key_signature, 0x00, 16);

  // Once we have done that, we need to calculate the HMAC.
  calchmac = (char *)Malloc(16);   // The resulting MAC is 16 bytes long.
  if (calchmac == NULL) 
  {
	  ipc_events_malloc_failed(thisint);
	  return XEMALLOC;
  }

  HMAC(EVP_md5(), thisint->eap_state->eapKeyData+32, 
       thisint->eap_state->eapKeyLen, (uint8_t *) framecpy, framesize, 
       (uint8_t *) calchmac, (unsigned int *) &outlen);

  // Now, we need to compare the calculated HMAC to the one sent to us.
  keydata = (struct key_packet *)&inframe[4];

  eapol_dump_keydata((char *)keydata, framesize);

  if (memcmp(calchmac, keydata->key_signature, 16) == 0)
    {
      // The HMAC is valid.
      retVal = TRUE;
    } else {
      retVal = FALSE;
    }

  // Clean up after ourselves.
  FREE(framecpy);
  FREE(calchmac);

  return retVal;
}

int eapol_key_type1_get_rc4(context *thisint, uint8_t *enckey, 
			    uint8_t *deckey, int keylen, uint8_t *iv, int ivlen)
{
  uint8_t *wholekey = NULL;
  RC4_KEY key;

  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((enckey != NULL), "enckey != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((deckey != NULL), "deckey != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iv != NULL), "iv != NULL", FALSE))
    return XEMALLOC;

  wholekey = (uint8_t *)Malloc(sizeof(uint8_t) * 
			       (ivlen + thisint->eap_state->eapKeyLen));
  if (wholekey == NULL) 
  {
	  ipc_events_malloc_failed(thisint);
	  return XEMALLOC;
  }

  memcpy(wholekey, iv, ivlen);

  if (!thisint->eap_state->eapKeyData)
    {
      debug_printf(DEBUG_NORMAL, "Invalid keying material!  Keys will not be "
		   "handled correctly!\n");
      FREE(wholekey);
      return XEMALLOC;
    }

  memcpy(wholekey + ivlen, thisint->eap_state->eapKeyData, 
	 thisint->eap_state->eapKeyLen);

  RC4_set_key(&key, ivlen + thisint->eap_state->eapKeyLen, wholekey);
  RC4(&key, keylen, enckey, deckey);

  FREE(wholekey);

  return XENONE;
}

/**
 * If our rekey timer expires, we should quietly remove it.  In the case of
 * this timer, we WANT it to expire with no events!  (Otherwise, the card
 * in use may have issues.)
 **/
void eapol_key_type1_clear_timer(context *ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  debug_printf(DEBUG_KEY, "Clearing rekey problem timer.  (This is "
	       "harmless!)\n");
  timer_cancel(ctx, REKEY_PROB_TIMER);
}

/**
 * Set up our timer to warn if the driver may have the card reset issue.
 */
void eapol_key_type1_set_rekey_prob_timer(context *ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  if (timer_check_existing(ctx, REKEY_PROB_TIMER))
    {
      debug_printf(DEBUG_NORMAL, "Less than %d seconds have elapsed since the "
		   "last key was set!  Either your AP has the rekey interval "
		   "set dangerously low, or your card may reset everytime new "
		   "keys are set!  Please check the rekey interval time on "
		   "your AP and report your card type, driver, and driver "
		   "version number to the list!\n", REKEY_PROB_TIMEOUT);
      timer_reset_timer_count(ctx, REKEY_PROB_TIMER, REKEY_PROB_TIMEOUT);
    } else {
      // There isn't an existing counter, so set up a new one.
      timer_add_timer(ctx, REKEY_PROB_TIMER, REKEY_PROB_TIMEOUT, NULL,
		      &eapol_key_type1_clear_timer);
    }
}

/**
 * Display the stale key warning, and disable the timer that was running.
 **/
void eapol_key_type1_stale_key_warn(context *ctx)
{
  struct config_globals *globals;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return;

  debug_printf(DEBUG_NORMAL, "Your unicast key has been in use for %d "
	       "minute(s).  Given the time it takes to crack WEP keys, your "
	       "data is now less secure than it was.  You should consider "
	       "asking your network administrator to lower the rekey interval"
	       " for your wireless network.\n\n"
	       " *** PLEASE NOTE ***  This is just a warning message, and does"
	       " not indicate that your WEP key has been broken!\n", 
	       (globals->stale_key_timeout/60));
  timer_cancel(ctx, STALE_KEY_WARN_TIMER);
}

/**
 * Set a timer that watches how long a key has been in use.  (Should only
 * be used for unicast keys, since broadcast keys aren't very secure to
 * begin with!)  If the timer expires, then we need to warn the user that
 * their security may be weaker than it used to be.
 */
void eapol_key_type1_set_stale_key_warn_timer(context *ctx)
{
  struct config_globals *globals;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return;

  if (timer_check_existing(ctx, STALE_KEY_WARN_TIMER))
    {
      timer_reset_timer_count(ctx, STALE_KEY_WARN_TIMER, 
			      globals->stale_key_timeout);
    } else {
      // Set up a new warning counter.
      timer_add_timer(ctx, STALE_KEY_WARN_TIMER, globals->stale_key_timeout, 
		      NULL, &eapol_key_type1_stale_key_warn);
    }
}

/**
 * Decrypt the key, and set it on the interface.  If there isn't a key to
 * decrypt, then use the peer key.
 **/
int eapol_key_type1_decrypt(context *thisint, char *inframe,
			    int framesize)
{
  struct key_packet *keydata = NULL;
  int keylen, rc=0;
  uint16_t length;
  uint8_t *newkey = NULL, *enckey = NULL;
  struct config_globals *globals;
  wireless_ctx *wctx;

  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((inframe != NULL), "inframe != NULL", FALSE))
    return XEMALLOC;

  wctx = (wireless_ctx *)thisint->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return FALSE;

  keydata = (struct key_packet *)&inframe[0];

  memcpy(&length, keydata->key_length, 2);
  keylen = ntohs(length);

  debug_printf(DEBUG_KEY_STATE, "EAPoL Key Processed: %s [%d] %d bytes.\n",
	       keydata->key_index & UNICAST_KEY ? "unicast" : "broadcast",
	       (keydata->key_index & KEY_INDEX)+1, keylen);

  if ((keylen != 0) && ((framesize)-sizeof(*keydata) >= keylen))
    {
      newkey = (uint8_t *)Malloc(sizeof(uint8_t) * keylen);
      if (newkey == NULL) 
	  {
		  ipc_events_malloc_failed(thisint);
		  return XEMALLOC;
	  }

      enckey = (uint8_t *)&inframe[sizeof(struct key_packet)];

      debug_printf(DEBUG_KEY, "Key before decryption : ");
      debug_hex_printf(DEBUG_KEY, enckey, keylen);

      if (eapol_key_type1_get_rc4(thisint, enckey, newkey, keylen, 
				  keydata->key_iv, 16) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't decrypt new key!\n");
	  return XEBADKEY;
	}

      debug_printf(DEBUG_KEY, "Key after decryption : ");
      debug_hex_printf(DEBUG_KEY, newkey, keylen);

      if (cardif_set_wep_key(thisint, newkey, keylen, keydata->key_index)
	  != 0)
	{
	  rc = FALSE;
	} else {

	  //  If the unicast flag is set, start the warning timer.
	  if (keydata->key_index & 0x80)
	    {
	      debug_printf(DEBUG_NORMAL, "Set unicast WEP key. (%d bits)\n",
			   (keylen * 8));
	      eapol_key_type1_set_rekey_prob_timer(thisint);
	      eapol_key_type1_set_stale_key_warn_timer(thisint);

		  if ((keylen * 8) == 104)
		  {
			  wctx->pairwiseKeyType = CIPHER_WEP104;
		  }
		  else
		  {
			  wctx->pairwiseKeyType = CIPHER_WEP40;
		  }
	    }
	  else
	    {
	      debug_printf(DEBUG_NORMAL, "Set broadcast/multicast WEP key. "
			   "(%d bits)\n", (keylen * 8));

		  if ((keylen * 8) == 104)
		  {
			  wctx->groupKeyType = CIPHER_WEP104;
		  }
		  else
		  {
			  wctx->groupKeyType = CIPHER_WEP40;
		  }
	    }

	  rc = TRUE;

	  UNSET_FLAG(wctx->flags, WIRELESS_ROAMED);
	}

      FREE(newkey);
    } else {
      debug_printf(DEBUG_KEY, "Using peer key!\n");

      debug_printf(DEBUG_NORMAL, "Set unicast WEP key. (%d bits)\n",
			   (keylen * 8));

      globals = config_get_globals();

      if (globals)
	{
	  if (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
	    {
	      debug_printf(DEBUG_NORMAL, "*WARNING* This AP uses the key "
			   "generated during the authentication\nprocess.  If "
			   "reauthentication doesn't happen frequently enough "
			   "your connection\nmay not be very secure!\n");
	    }
	}

      if (cardif_set_wep_key(thisint, thisint->eap_state->eapKeyData, keylen, 
			     keydata->key_index) != 0)
	{
	  rc = FALSE;
	} else {
	  rc = TRUE;

	  //  If the unicast flag is set, start the warning timer.
	  if (keydata->key_index & 0x80)
	    {
	      eapol_key_type1_set_rekey_prob_timer(thisint);
	      eapol_key_type1_set_stale_key_warn_timer(thisint);
	    }
	}
    }

  // If we reach this point, then we should remember the length of the
  // keys for later comparison.
  if (keydata->key_index & UNICAST_KEY)
    {
		wctx->unicastKeyLen = keylen;
    } else {
		wctx->broadcastKeyLen = keylen;
    }

  return rc;
}

/**
 * We are handed in an EAPoL key frame.  From that frame, we check the frame
 * to make sure it hasn't been changed in transit.  We then determine the 
 * correct key, and make the call to set it.
 **/
void eapol_key_type1_process(context *thisint)
{
  struct key_packet *keydata;
  struct eapol_header *eapolheader;
  uint8_t *inframe;
  int framesize;
  int framelen;
  struct config_globals *globals;
  wireless_ctx *wctx;

  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return;

  wctx = (wireless_ctx *)thisint->intTypeData;

  if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE))
	  return;

  globals = config_get_globals();

  if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
    return;

  inframe = thisint->recvframe;
  framesize = thisint->recv_size;

  eapolheader = (struct eapol_header *)&inframe[OFFSET_PAST_MAC];

  framelen = ntohs(eapolheader->eapol_length);

  keydata = (struct key_packet *)&inframe[OFFSET_TO_EAPOL+4];

  if (keydata->key_descr != RC4_KEY_TYPE)
    {
      debug_printf(DEBUG_NORMAL, "Key type isn't RC4!\n");
      return;
    }

  if (eapol_key_type1_check_hmac(thisint, (char *)&inframe[OFFSET_TO_EAPOL], framelen+4)==FALSE)
    {
      debug_printf(DEBUG_NORMAL, "HMAC failed on key data!  This key will be discarded.\n");
      return;
      }

  if (eapol_key_type1_decrypt(thisint, (char *)&inframe[OFFSET_TO_EAPOL+4],
			      (framelen)) != TRUE)
    {
      debug_printf(DEBUG_NORMAL, "Failed to set wireless key!\n");
      return;
    }

  if ((wctx->unicastKeyLen != 0) && (wctx->broadcastKeyLen != 0) &&
      (wctx->unicastKeyLen != wctx->broadcastKeyLen))
    {

      if (!TEST_FLAG(globals->flags, CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS))
	{
	  debug_printf(DEBUG_NORMAL, "[WARNING] Unicast and broadcast keys "
		       "are different lengths!  Some cards/drivers/APs do "
		       "not like this combination!\n");
	}
    }
  thisint->recv_size = 0;
}
