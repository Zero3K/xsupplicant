/**
 * Handle keying for WPA keys.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol_key_type254.c
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#ifdef WINDOWS
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "key_statemachine.h"
#include "eapol_key_type254.h"
#include "eapol.h"
#include "frame_structs.h"
#include "wpa.h"
#include "wpa_common.h"
#include "xsup_common.h"
#include "psk.h"
#include "mic.h"
#include "snmp.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "eap_types/mschapv2/mschapv2.h"
#include "eap_sm.h"
#include "statemachine.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "timer.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

uint8_t group_key_ver = 0, pairwise_key_ver = 0;

/**
 * Given a frame, parse all of the data that is contained in it, and
 * provide a human readable output that is useful for debugging.
 */
void eapol_key_type254_dump(char *framedata)
{
  uint16_t value16=0;
  int need_comma = 0;
  struct wpa_key_packet *keydata;

  if (!xsup_assert((framedata != NULL), "framedata != NULL", FALSE))
    return;

  keydata = (struct wpa_key_packet *)&framedata[OFFSET_TO_EAPOL+4];

  debug_printf(DEBUG_KEY, "Key Descriptor      = %d\n", keydata->key_descriptor);
  memcpy(&value16, keydata->key_information, 2);
  debug_printf(DEBUG_KEY, "Key Information     = %04X  (Flags : ", ntohs(value16));
  if (ntohs(value16) & WPA_PAIRWISE_KEY)
    {
      debug_printf_nl(DEBUG_KEY, "Pairwise Key");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA_INSTALL_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Install Key");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA_KEY_ACK_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Key Ack");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA_KEY_MIC_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "MIC");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA_SECURE_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Secure");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA_ERROR_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Error");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA_REQUEST_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Request");
      need_comma = 1;
    }

  debug_printf_nl(DEBUG_KEY, ")\n");

  switch (ntohs(value16) & WPA_KEYTYPE_MASK)
    {
    case 1:
      debug_printf(DEBUG_KEY, "Key Descriptor Version : HMAC-MD5 for MIC and RC4 for encryption.\n");
      break;

    case 2:
      debug_printf(DEBUG_KEY, "Key Descriptor Version : HMAC-SHA1-128 for MIC and AES for encryption.\n");
      break;
    }

  debug_printf(DEBUG_KEY, "Key Length          = %d\n", 
	       ntohs(keydata->key_length));

  debug_printf(DEBUG_KEY, "Key Replay Counter  = ");  
  debug_hex_printf(DEBUG_KEY, keydata->key_replay_counter, 8);

  debug_printf(DEBUG_KEY, "Key NONCE           = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_nonce, 32);

  debug_printf(DEBUG_KEY, "Key IV              = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_iv, 16);
  
  debug_printf(DEBUG_KEY, "Key RSC             = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_rsc, 8);
  
  debug_printf(DEBUG_KEY, "Key ID              = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_id, 8);

  debug_printf(DEBUG_KEY, "Key MIC             = ");
  debug_hex_printf(DEBUG_KEY, keydata->key_mic, 16);

  value16 = ntohs(keydata->key_material_len);
  debug_printf(DEBUG_KEY, "Key Material Length = %d\n", value16);

  if (value16 > 0)
    {
      debug_printf(DEBUG_KEY, "Key Data : (%d)\n", value16);
      debug_hex_dump(DEBUG_KEY, keydata->keydata, value16);
    }
}

/*******************************************************
 *
 * Generate the pre-Temporal key. (PTK) Using the authenticator, and 
 * supplicant nonces.  (Anonce, and Snonce.)  The PTK is used for keying
 * when we are ready.
 *
 *******************************************************/
char *eapol_key_type254_gen_ptk(context *intdata, char *Anonce)
{
  char prfdata[76];  // 6*2 (MAC addrs) + 32*2 (nonces)
  char *retval;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((Anonce != NULL), "Anonce != NULL", FALSE))
    return NULL;

  memset((char *)&prfdata, 0x00, 76);

  debug_printf(DEBUG_KEY, "Dest MAC: ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *)&intdata->dest_mac, 6);

  if (memcmp((char *)&intdata->source_mac, (char *)&intdata->dest_mac, 6) < 0)
    {
      memcpy((char *)&prfdata[0], (char *)&intdata->source_mac, 6);
      memcpy((char *)&prfdata[6], (char *)&intdata->dest_mac, 6);
    } else if (memcmp((char *)&intdata->source_mac, (char *)&intdata->dest_mac,
		      6) > 0)
      {
	memcpy((char *)&prfdata[0], (char *)&intdata->dest_mac, 6);
	memcpy((char *)&prfdata[6], (char *)&intdata->source_mac, 6);
      } else {
	debug_printf(DEBUG_NORMAL, "Source and Destination MAC addresses "
		     "match!  The PTK won't be valid!\n");
	ipc_events_error(intdata, IPC_EVENT_ERROR_INVALID_PTK, intdata->desc);
	return NULL;
      }

  if (memcmp(intdata->statemachine->SNonce, Anonce, 32) < 0)
    {
      memcpy((char *)&prfdata[12], intdata->statemachine->SNonce, 32);
      memcpy((char *)&prfdata[44], Anonce, 32);
    } else if (memcmp(intdata->statemachine->SNonce, Anonce, 32) > 0)
      {
	memcpy((char *)&prfdata[12], Anonce, 32);
	memcpy((char *)&prfdata[44], intdata->statemachine->SNonce, 32);
      } else {
	debug_printf(DEBUG_NORMAL, "ANonce and SNonce match!  The PTK won't"
		     " be valid!\n");
	ipc_events_error(intdata, IPC_EVENT_ERROR_INVALID_PTK, intdata->desc);
	return NULL;
      }
  
  retval = (char *)Malloc(80);
  if (retval == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for retval in %s "
		   "at %d!\n", __FUNCTION__, __LINE__);
	  ipc_events_malloc_failed(intdata);
      return NULL;
    }

  debug_printf(DEBUG_KEY, "PMK : ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *) intdata->statemachine->PMK, 32);
  wpa_PRF((uint8_t *) intdata->statemachine->PMK, 32, (uint8_t *) "Pairwise key "
	  "expansion", 22, (uint8_t *)&prfdata, 76, (uint8_t *) retval, 64);

  debug_printf(DEBUG_KEY, "PTK : ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *) retval, 64);

  return retval;
}

/*****************************************************************
 *
 * When a MIC failure occures, we need to send the AP a request for
 * a new key. (Reference 802.11i-D3.0.pdf page 43, line 8)
 *
 *****************************************************************/
void eapol_key_type254_request_new_key(context *intdata, char unicast)
{
  struct wpa_key_packet *outkeydata;
  uint16_t value16, keyindex, len;
  char key[16];

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  outkeydata = (struct wpa_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

  // Clear everything out.
  memset(&intdata->sendframe[OFFSET_TO_EAPOL+4], 0x00,
	 sizeof(struct wpa_key_packet));

  outkeydata->key_descriptor = WPA_KEY_TYPE;

  value16 = (WPA_REQUEST_FLAG | WPA_ERROR_FLAG);

  if (unicast == 1)
    {
      // Set the key flags to indicate this is a pairwise key, with an
      // index of 0.
      keyindex = (WPA_PAIRWISE_KEY | pairwise_key_ver);
    } else {
      // Set the key flags to indicate this is a group key. We don't know the
      // index, so for now we will use 1.
      keyindex = ((1 << 4) | group_key_ver);
    }

  value16 = (value16 | keyindex);

  memcpy(outkeydata->key_information, &value16, 2);

  // Build the response.
  len = sizeof(struct wpa_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe); 
  
  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "No valid PTK available!  We will not be "
		   "able to request a new key!\n");
      return;
    }

  memcpy(key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);

  cardif_sendframe(intdata);
  intdata->statemachine->eapolEap = FALSE;
}

/****************************************************************
 *
 * When we have completed the PTK piece, and the pairwise key has been
 * applied to the interface, we need to get the group key.  The authenticator
 * will send us a group key that is encrypted.  We should decrypt it, apply
 * it to our interface, and send the authenticator a message to let it know
 * that we have a group key.
 *
 ****************************************************************/
void eapol_key_type254_do_gtk(context *intdata)
{
  struct wpa_key_packet *inkeydata = NULL, *outkeydata = NULL;
  uint16_t value16 = 0, keyflags = 0, version = 0, keyindex = 0, len = 0;
  unsigned char *keydata = NULL;
  char key[32], rc4_ek[32];
  char zeros[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  xsup_assert((intdata->statemachine != NULL), "intdata->statemachine != NULL",
	      TRUE);

  if (!xsup_assert((intdata->intType == ETH_802_11_INT), "intdata->intType == ETH_802_11_INT", FALSE))
	  return;

  if (!xsup_assert((intdata->intTypeData != NULL), "intdata->intTypeData != NULL", FALSE))
	  return;

  wctx = intdata->intTypeData;

  inkeydata = (struct wpa_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];
  outkeydata = (struct wpa_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

  // First, make sure that the inkeydata replay counter is higher than
  // the last counter we saw.
  if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <= 0) &&
      (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0))
    {
      debug_printf(DEBUG_NORMAL, "Invalid replay counter!  Discarding!\n");
      debug_printf(DEBUG_KEY, "Recieved counter : ");
      debug_hex_printf(DEBUG_KEY, inkeydata->key_replay_counter, 8);
      debug_printf(DEBUG_KEY, "Our counter : ");
      debug_hex_printf(DEBUG_KEY, wctx->replay_counter, 8);
      intdata->recv_size = 0;
      return;
    }

  // Clear everything out.
  memset(&intdata->sendframe[OFFSET_TO_EAPOL+4], 0x00,
	 sizeof(struct wpa_key_packet));

  outkeydata->key_descriptor = WPA_KEY_TYPE;

  memcpy(&value16, inkeydata->key_information, 2);
  value16 = ntohs(value16);

  keyflags = 0;
  keyflags = (value16 & WPA_KEYTYPE_MASK);
  version = keyflags;
  group_key_ver = version;
  keyindex = ((value16 & WPA_KEY_INDEX) >> 4);

  // Verify that our flags are correct.  (We don't check for the install flag,
  // for now.  Since the WPA spec doesn't explicitly require that the install
  // flag be set.)
  if (!((value16 & WPA_KEY_ACK_FLAG) &&
	(value16 & WPA_KEY_MIC_FLAG) && (value16 & WPA_SECURE_FLAG)))
    {
      debug_printf(DEBUG_NORMAL, "Invalid flags in GTK message 1!\n");
      return;
    }

  value16 = ntohs(inkeydata->key_material_len);

  keydata = (unsigned char *)Malloc(value16+8);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for key data!\n");
      return;
    }

  memcpy(keydata, 
	 &intdata->recvframe[OFFSET_TO_EAPOL+4+sizeof(struct wpa_key_packet)],
	 value16);

  debug_printf(DEBUG_KEY, "Setting GTK! (Version : %d  Length : %d  Slot : %d)"
	       "\n", version, value16, keyindex);

  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "No valid PTK available!  You will probably"
		   " not be able to pass data.\n");
      FREE(keydata);
      return;
    }

  switch (version)
    {
    case 1:
      // Decrypt the GTK.
		if (intdata->statemachine->PTK == NULL)
		{
			debug_printf(DEBUG_NORMAL, "The PTK for this connection is NULL!\n");
			cardif_disassociate(intdata, DISASSOC_CIPHER_REJECT);  
			return;
		}

      memset(rc4_ek, 0x00, 32);
      memcpy(rc4_ek, inkeydata->key_iv, 16);
      memcpy(&rc4_ek[16], &intdata->statemachine->PTK[16], 16);
      rc4_skip((uint8_t *) rc4_ek, 32, 256, keydata, value16);
      
      debug_printf_nl(DEBUG_KEY, "GTK (%d) : ", value16);
      debug_hex_printf(DEBUG_KEY, keydata, value16);


      wpa_common_set_key(intdata, NULL, keyindex, FALSE, (char *)keydata,
			 value16);
      break;

    case 2:
      // First, decrypt the GTK
      memset(key, 0x00, 32);
      if (aes_unwrap((uint8_t *) &intdata->statemachine->PTK[16], (value16-8)/8, 
		 keydata, (uint8_t *) key) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Failed AES unwrap.\n");
		  if (intdata->statemachine->PTK == NULL) debug_printf(DEBUG_NORMAL, "Unwrap failed because PTK is NULL!\n");
		  ipc_events_error(intdata, IPC_EVENT_ERROR_FAILED_AES_UNWRAP, intdata->desc);
		  cardif_disassociate(intdata, DISASSOC_CIPHER_REJECT);  
		  return;
	  }
      
      wpa_common_set_key(intdata, NULL, keyindex, FALSE, (char *)keydata, (value16 -8));
     
      break;
    }

  debug_printf(DEBUG_NORMAL, "Interface '%s' set new group WPA key.\n", intdata->desc);

  // Build the response.
  len = sizeof(struct wpa_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  value16 = ((version | (keyindex << 4)) | WPA_KEY_MIC_FLAG | WPA_SECURE_FLAG);
  value16 = htons(value16);
  memcpy(&outkeydata->key_information, &value16, 2);

  outkeydata->key_length = inkeydata->key_length;
  memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter, 8);

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe); 
  
  memcpy(&key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);

  // Dump what we built.
  eapol_key_type254_dump((char *) intdata->sendframe);

  if (intdata->conn->association.auth_type == AUTH_PSK)
    {
      // If we are using PSK, and we made it here, then we are in 
      // S_FORCE_AUTH state.
	  statemachine_change_state(intdata, S_FORCE_AUTH);
    }

  // Drop unencrypted frames.
  cardif_drop_unencrypted(intdata, 1);

  FREE(keydata);
}

/***************************************************************
 *
 * Handle the first packet in the four-way handshake.
 *
 ***************************************************************/
void eapol_key_type254_do_type1(context *intdata)
{
  struct wpa_key_packet *inkeydata, *outkeydata;
  uint16_t keyflags, len, value16;
  int i, version, ielen;
  char key[16], wpa_ie[26];
  char zeros[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((intdata->intType == ETH_802_11_INT), "intdata->intType == ETH_802_11_INT", FALSE))
	  return;

  if (!xsup_assert((intdata->intTypeData != NULL), "intdata->intTypeData != NULL", FALSE))
	return;

  wctx = intdata->intTypeData;

  inkeydata = (struct wpa_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];
  outkeydata = (struct wpa_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

  // First, make sure that the inkeydata replay counter is higher than
  // the last counter we saw.
  if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <= 0) &&
      (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0))
    {
      debug_printf(DEBUG_NORMAL, "Invalid replay counter!  Discarding!\n");
      intdata->recv_size = 0;
      return;
    }

  // Clear everything out.
  memset(&intdata->sendframe[OFFSET_TO_EAPOL+4], 0x00,
	 sizeof(struct wpa_key_packet));

  // XXX Need to do this better.  Tie it in with Nonce code from SIM/AKA.
  for (i=0;i<32;i++)
    {
      outkeydata->key_nonce[i] = rand();
    }

  intdata->statemachine->SNonce = (uint8_t *)malloc(32);
  if (intdata->statemachine->SNonce == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for SNonce in "
		   "%s at %d!\n", __FUNCTION__, __LINE__);
	  ipc_events_malloc_failed(intdata);
      return;
    }
  memcpy(intdata->statemachine->SNonce, (char *)&outkeydata->key_nonce[0],
	 32);

  // Calculate the PTK.
  FREE(intdata->statemachine->PTK);

  intdata->statemachine->PTK = (uint8_t *)eapol_key_type254_gen_ptk(intdata,
							 (char *)&inkeydata->key_nonce);

  outkeydata->key_descriptor = WPA_KEY_TYPE;

  memcpy(&value16, inkeydata->key_information, 2);
  value16 = ntohs(value16);

  keyflags = 0;
  keyflags = (value16 & WPA_KEYTYPE_MASK);
  version = keyflags;
  pairwise_key_ver = version;
  keyflags |= (WPA_PAIRWISE_KEY | WPA_KEY_MIC_FLAG);
  keyflags = htons(keyflags);

  memcpy(&outkeydata->key_information, &keyflags, 2);
  
  len = sizeof(struct wpa_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  outkeydata->key_length = inkeydata->key_length;

  memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter, 8);

  cardif_get_wpa_ie(intdata, wpa_ie, &ielen);

  memcpy(&intdata->sendframe[OFFSET_TO_EAPOL+4+sizeof(struct wpa_key_packet)], 
	 &wpa_ie, ielen);
  value16 = ielen;
  value16 = htons(value16);
  intdata->send_size += ielen;

  outkeydata->key_material_len = value16;

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe);

  memcpy(key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);

  // Dump what we built.
  eapol_key_type254_dump((char *) intdata->sendframe);
}

/********************************************************
 *
 * Compare the IE that we got from a key packet to the IE that we got from
 * the AP, to see if they match.
 *
 ********************************************************/
char eapol_key_type254_cmp_ie(context *intdata, uint8_t *wpaie, char wpaielen)
{
  uint8_t *apie, apielen;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((wpaie != NULL), "wpaie != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((intdata->conn != NULL), "intdata->conn != NULL", FALSE))
	  return XEMALLOC;

  if (intdata->conn->flags & CONFIG_NET_IS_HIDDEN)
  {
	  debug_printf(DEBUG_NORMAL, "Interface '%s' connected to a hidden SSID.  We don't know the IE that was used, so we won't check.  (Man-in-the-middle checks have been weakened.)\n", intdata->desc);
	  return 0;
  }

  debug_printf(DEBUG_KEY, "WPA IE from Key Packet (%d) : ", wpaielen);
  debug_hex_printf(DEBUG_KEY, wpaie, wpaielen);

  // Don't free apie, as it is a reference pointer only!!
  config_ssid_get_wpa_ie(intdata->intTypeData, &apie, &apielen);
  debug_printf(DEBUG_KEY, "WPA IE from AP Scan (%d)    : ", apielen);
  debug_hex_printf(DEBUG_KEY, apie, apielen);
  
  if (wpaielen != apielen)
    {
      debug_printf(DEBUG_NORMAL, "IE from the AP and IE from the key messages"
		   " are different lengths!\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_IES_DONT_MATCH, intdata->desc);
      return -1;
    }

  if (memcmp(wpaie, apie, apielen) != 0)
    {
      debug_printf(DEBUG_NORMAL, "IE from the AP and IE from the key messages"
		   " do not match!\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_IES_DONT_MATCH, intdata->desc);
      return -1;
    }

  return XENONE;
}

/**
 * \brief Clear our "bad PSK" flag.
 **/
int8_t eapol_key_type254_psk_timeout(context *ctx)
{
	debug_printf(DEBUG_INT, "Clearing bad PSK flag.\n");
	UNSET_FLAG(((wireless_ctx *)ctx->intTypeData)->flags, WIRELESS_SM_DOING_PSK);

	timer_cancel(ctx, PSK_DEATH_TIMER);

	return 0;
}

/********************************************************
 *
 * Handle the third packet in the 4 way handshake.  We should be able to
 * generate the pairwise key at this point.
 *
 ********************************************************/
void eapol_key_type254_do_type3(context *intdata)
{
  struct wpa_key_packet *inkeydata, *outkeydata;
  uint16_t keyflags, len, value16, keyindex;
  int version;
  char key[32];
  char zeros[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((intdata->intType == ETH_802_11_INT), "intdata->intType == ETH_802_11_INT", FALSE))
	  return;

  if (!xsup_assert((intdata->intTypeData != NULL), "intdata->intTypeData != NULL", FALSE))
	  return;

  wctx = intdata->intTypeData;

  memset(key, 0x00, 32);

  inkeydata = (struct wpa_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];
  outkeydata = (struct wpa_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

  // First, make sure that the inkeydata replay counter is higher than
  // the last counter we saw.
  if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <= 0) &&
      (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0))
    {
      debug_printf(DEBUG_NORMAL, "Invalid replay counter!  Discarding!\n");
      intdata->recv_size = 0;
      return;
    }

  // Update our replay counter.
  memcpy(wctx->replay_counter, &inkeydata->key_replay_counter, 8);

  // Clear everything out.
  memset(&intdata->sendframe[OFFSET_TO_EAPOL], 0x00,
	sizeof(struct wpa_key_packet)+28);

  outkeydata->key_descriptor = WPA_KEY_TYPE;

  memcpy(&value16, inkeydata->key_information, 2);
  value16 = ntohs(value16);
  
  keyflags = 0;
  keyflags = (value16 & WPA_KEYTYPE_MASK);
  version = keyflags;  

  keyflags = 0;
  keyflags = (value16 & WPA_KEYTYPE_MASK);
  keyflags |= (WPA_PAIRWISE_KEY | WPA_KEY_MIC_FLAG);
  keyindex = ((value16 & WPA_KEY_INDEX) >> 4);

  // If the authenticator sets the secure flag, we need to do the same.
  if (value16 & WPA_SECURE_FLAG) keyflags |= WPA_SECURE_FLAG;
  keyflags = htons(keyflags);

  memcpy(&outkeydata->key_information, &keyflags, 2);
  
  len = sizeof(struct wpa_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  outkeydata->key_length = inkeydata->key_length;

  memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter, 8);
  memcpy(&outkeydata->key_nonce, intdata->statemachine->SNonce, 32);

  memcpy(outkeydata->key_nonce, intdata->statemachine->SNonce,
	 32);

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe); 

  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "No valid PTK available!  You will probably"
		   " not get valid keys!  (And traffic will probably not "
		   "flow correctly.)\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_INVALID_PTK, intdata->desc);
      return;
    }

  memcpy(key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);  

  // Dump what we built.
  eapol_key_type254_dump((char *) intdata->sendframe);

  if (eapol_key_type254_cmp_ie(intdata, inkeydata->keydata, 
			       ntohs(inkeydata->key_material_len)) != XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Error comparing IEs.  Possible attack in "
		   "progress!  Disconnecting.\n");
      cardif_disassociate(intdata, DISASSOC_INVALID_IE);
      return;
    }

  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "No valid PTK available.  We will not be "
		   "able to get valid keys.  (And traffic will not flow "
		   "properly.\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_INVALID_PTK, intdata->desc);
      return;
    }

  // Get TK1
  value16 = ntohs(inkeydata->key_length);
  memcpy(key, (char *)&intdata->statemachine->PTK[32], value16);
  
  debug_printf(DEBUG_KEY, "TK1 : ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *) key, value16);
  
  cardif_sendframe(intdata);
  intdata->statemachine->eapolEap = FALSE;
  intdata->send_size = 0;

  debug_printf(DEBUG_KEY, "Setting PTK1! (Index : %d Length : %d)\n", 
	       keyindex, value16);

  switch (version) 
    {
    case 1:
      wpa_common_set_key(intdata, intdata->dest_mac, keyindex, TRUE,
			 key, value16);
      break;

    case 2:
      wpa_common_set_key(intdata, intdata->dest_mac, keyindex, TRUE,
			 key, value16);
      break;
    }

  debug_printf(DEBUG_NORMAL, "Interface '%s' set new pairwise WPA key.\n", intdata->desc);

#ifdef WINDOWS
  // If we get here (and are doing PSK) we need to set a timer to let us know if the PSK is wrong.  The
  // *proper* way to handle this is to check the disassociate value from the AP to see if it indicates
  // that the PSK is wrong.  But, Windows doesn't give us access to that, so we will have to play with some
  // timer magic instead. :-/
  timer_add_timer(intdata, PSK_DEATH_TIMER, 5, NULL, eapol_key_type254_psk_timeout);
#endif
}

void eapol_key_type254_determine_key(context *intdata)
{
  struct wpa_key_packet *keydata;
  int keyflags;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((intdata->recvframe != NULL), "intdata->recvframe != NULL", FALSE))
	  return;

  keydata = (struct wpa_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];  
  memcpy(&keyflags, keydata->key_information, 2);

  keyflags = ntohs(keyflags);

  if (keyflags & WPA_KEY_MIC_FLAG)
    {
      if (mic_wpa_validate((char *) intdata->recvframe, intdata->recv_size, 
			   (char *)intdata->statemachine->PTK, 16) == FALSE)
	{
	  intdata->statemachine->MICVerified = TRUE;
	  intdata->statemachine->IntegrityFailed = TRUE;
	  debug_printf(DEBUG_KEY, "MIC failure!\n");
       	  return;   // Silently discard.
	} else {
	  intdata->statemachine->IntegrityFailed = FALSE;
	  intdata->statemachine->MICVerified = TRUE;
	}
    }

  if ((keyflags & WPA_PAIRWISE_KEY) && (keyflags & WPA_KEY_ACK_FLAG) &&
      (keyflags & WPA_KEY_MIC_FLAG) && (keyflags & WPA_INSTALL_FLAG))
    {
      debug_printf(DEBUG_KEY, "Key Packet #3 (response) :\n");
      eapol_key_type254_do_type3(intdata);
    } else if ((keyflags & WPA_PAIRWISE_KEY) && (keyflags & WPA_KEY_ACK_FLAG))
    {
      debug_printf(DEBUG_KEY, "Key Packet #1 (response) :\n");
      eapol_key_type254_do_type1(intdata);
    } else if ((keyflags & WPA_KEY_MIC_FLAG) && (keyflags & WPA_PAIRWISE_KEY))
    {
      debug_printf(DEBUG_NORMAL, "Got Key Packet #2 or #4!  (This shouldn't happen!)\n");
    } else if (!(keyflags & WPA_PAIRWISE_KEY))
      {
	// We have a group key packet.
	eapol_key_type254_do_gtk(intdata);
      }

  if (intdata->recv_size > 0)
    {
      eapol_build_header(intdata, EAPOL_KEY, (intdata->recv_size-OFFSET_TO_EAPOL-4), 
			 (char *) intdata->recvframe);
      cardif_sendframe(intdata);
      intdata->statemachine->eapolEap = FALSE;
    }      
}

/**
 *
 * Process a WPA frame that we get from the authenticator.
 *
 **/
void eapol_key_type254_process(context *intdata)
{
  uint8_t *inframe = NULL;
  int insize;
  char tpmk[254];
  wireless_ctx *wctx = NULL;
  char *pskptr = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  inframe = intdata->recvframe;
  insize = intdata->recv_size;

  debug_printf(DEBUG_KEY, "Processing WPA key message!\n");

  eapol_key_type254_dump((char *)inframe);

  if (intdata->conn == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Got a key message on '%s' when we don't have a valid configuration defined?  Make sure you don't have another supplicant running.\n", intdata->desc);
	  return;
  }

  if (intdata->conn->association.psk != NULL) pskptr = intdata->conn->association.psk;

  // Make sure the one below always comes last so that it if the user overrides it via the UI
  // that the one from the UI is the one used.
  if (intdata->conn->association.temp_psk != NULL) pskptr = intdata->conn->association.temp_psk;

	if (intdata->conn->association.auth_type == AUTH_PSK)
	{
		wctx = (wireless_ctx *)intdata->intTypeData;

		if (!xsup_assert((wctx != NULL), "wctx != NULL", FALSE)) return;

		SET_FLAG(wctx->flags, WIRELESS_SM_DOING_PSK);

		if (pskptr != NULL)
	    {
	      if (wctx->cur_essid == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Unknown SSID, checking!\n");
		  wctx->cur_essid = (char *)Malloc(33);
		  if (wctx->cur_essid == NULL)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory! "
				   "(%s:%d)\n", __FUNCTION__, __LINE__);
			  ipc_events_malloc_failed(intdata);
		      return;
		    }

		  if (cardif_GetSSID(intdata, wctx->cur_essid, 33) != XENONE)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't get ESSID!\n");
		      FREE(wctx->cur_essid);
		      return;
		    }
		}

	      // We have an ASCII password, so calculate it.
		  if (psk_wpa_pbkdf2(pskptr, (uint8_t *) wctx->cur_essid, 
				 strlen(wctx->cur_essid), (uint8_t *)&tpmk) 
		  == TRUE)
		{
		  FREE(intdata->statemachine->PMK);

		  intdata->statemachine->PMK = (uint8_t *)Malloc(32);
		  if (intdata->statemachine->PMK == NULL)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for"
				   " intdata->statemachine->PMK in %s:%d!\n",
				   __FUNCTION__, __LINE__);
			  ipc_events_malloc_failed(intdata);
		      return;
		    }
		  
		  memcpy(intdata->statemachine->PMK, (char *)&tpmk, 32);
		}
	    } else {
	      // We have a hex key, we need to convert it from ASCII to real
	      // hex.
			if (intdata->conn->association.psk_hex == NULL || strlen(intdata->conn->association.psk_hex) != 64)
		{
		  debug_printf(DEBUG_NORMAL, "Invalid HEX key defined for "
			       "WPA-PSK!\n");
		  return;
		}
			process_hex(intdata->conn->association.psk_hex, 
				strlen(intdata->conn->association.psk_hex), (char *)&tpmk);

	      FREE(intdata->statemachine->PMK);

	      intdata->statemachine->PMK = (uint8_t *)Malloc(32);
	      if (intdata->statemachine->PMK == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for "
			       "intdata->statemachine->PMK in %s:%d!\n",
			       __FUNCTION__, __LINE__);
		  ipc_events_malloc_failed(intdata);
		  return;
		}
	    }

  if (intdata->statemachine->PMK == NULL)
    {
	  debug_printf(DEBUG_NORMAL, "There is no PMK available!  WPA cannot"
		       " continue!\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_PMK_UNAVAILABLE, intdata->desc);
	  return;
	}
    } 

  eapol_key_type254_determine_key(intdata);

  if (intdata->send_size > 0)
    {
      cardif_sendframe(intdata);
      intdata->statemachine->eapolEap = FALSE;
    }

}
