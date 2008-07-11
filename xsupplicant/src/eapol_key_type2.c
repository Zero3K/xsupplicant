/**
 * Handle keying for WPA2/802.11i keys.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapol_key_type2.c
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
#include "eapol_key_type2.h"
#include "eapol.h"
#include "frame_structs.h"
#include "wpa_common.h"
#include "xsup_common.h"
#include "statemachine.h"
#include "wpa2.h"
#include "wpa.h"
#include "psk.h"
#include "mic.h"
#include "snmp.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "eap_types/mschapv2/mschapv2.h"
#include "eap_sm.h"
#include "ipc_events.h"
#include "ipc_events_index.h"
#include "timer.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

uint8_t wpa2_group_key_ver = 0, wpa2_pairwise_key_ver = 0;

/**
 * Given a frame, parse all of the data that is contained in it, and
 * provide a human readable output that is useful for debugging.
 **/
void eapol_key_type2_dump(context *intdata, char *framedata)
{
  int value16=0;
  int need_comma = 0, encdata = 0;
  uint16_t keylen, version = 0;
  struct wpa2_key_packet *keydata;
  uint8_t *keypayload = NULL;
  uint8_t *key = NULL;
  uint8_t rc4_ek[32];

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((framedata != NULL), "framedata != NULL", FALSE))
    return;

  keydata = (struct wpa2_key_packet *)&framedata[OFFSET_TO_EAPOL+4];

  debug_printf(DEBUG_KEY, "Key Descriptor      = %d\n", keydata->key_descriptor);
  memcpy(&value16, keydata->key_information, 2);
  debug_printf(DEBUG_KEY, "Key Information     = %04X  (Flags : ", ntohs(value16));

  if (ntohs(value16) & WPA2_PAIRWISE_KEY)
    {
      debug_printf_nl(DEBUG_KEY, "Pairwise Key");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_INSTALL_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Install Key");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_KEY_ACK_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Key Ack");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_KEY_MIC_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "MIC");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_SECURE_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Secure");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_ERROR_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Error");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_REQUEST_FLAG)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Request");
      need_comma = 1;
    }
  if (ntohs(value16) & WPA2_ENCRYPTED_DATA)
    {
      if (need_comma) debug_printf_nl(DEBUG_KEY, ", ");
      debug_printf_nl(DEBUG_KEY, "Encrypted Data");
      need_comma = 1;
      encdata = 1;
    }

  debug_printf_nl(DEBUG_KEY, ")\n");

  switch (ntohs(value16) & WPA2_KEYTYPE_MASK)
    {
    case 1:
      version = 1;
      debug_printf(DEBUG_KEY, "Key Descriptor Version : HMAC-MD5 for MIC and RC4 for encryption.\n");
      break;

    case 2:
      version = 2;
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

  // nothing to do!
  if (encdata == 0) return;

  keylen = value16;
  memcpy(&value16, keydata->key_information, 2);
  
  keypayload = (uint8_t *)Malloc(keylen);
  if (keypayload == NULL)
    {
      debug_printf(DEBUG_NORMAL, 
		   "Error with malloc of keypayload in %s()!\n", __FUNCTION__);
	  ipc_events_malloc_failed(intdata);
      return;
    }

  memcpy(keypayload, keydata->keydata, keylen);
  
  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "PTK is NULL!  Can't decrypt data!\n");
      FREE(keypayload);
      return;
    }

  switch (version)
    {
    case 1:
      memset(rc4_ek, 0x00, 32);
      memcpy(rc4_ek, keydata->key_iv, 16);
      memcpy(&rc4_ek[16], &intdata->statemachine->PTK[16], 16);
      rc4_skip(rc4_ek, 32, 256, keypayload, keylen);
      break;
      
    case 2:
      key = (uint8_t *)Malloc(keylen);
      if (key == NULL)
	{
	  debug_printf(DEBUG_NORMAL, 
		       "Error with malloc of key in %s()!\n",
		       __FUNCTION__);
	  ipc_events_malloc_failed(intdata);
	  FREE(keypayload);
	  return;
	}

      debug_printf(DEBUG_KEY, "PTK : ");
      debug_hex_printf(DEBUG_KEY, (uint8_t *)intdata->statemachine->PTK, 32);
      debug_printf(DEBUG_KEY, "\n");
      
      if (aes_unwrap((uint8_t *) &intdata->statemachine->PTK[16], 
		     (keylen-8)/8, keypayload, key) != 0)
	{
	  debug_printf(DEBUG_NORMAL, "Failed AES unwrap. (Data will be"
		       " invalid!)\n");
	  if (intdata->statemachine->PTK == NULL) debug_printf(DEBUG_NORMAL, "Unwrap failed because PTK is NULL!\n");
		ipc_events_error(intdata, IPC_EVENT_ERROR_FAILED_AES_UNWRAP, intdata->desc);
		cardif_disassociate(intdata, DISASSOC_CIPHER_REJECT); 
	}
      
      FREE(keypayload);
      keypayload = key;
      key = NULL;
      break;
      
    default:
      debug_printf(DEBUG_NORMAL, "Unknown version %d!\n", version);
      break;
    }
  
  debug_printf(DEBUG_KEY, "Decypted data (%d) : \n", keylen);
  debug_hex_dump(DEBUG_KEY, keypayload, keylen);
  
  FREE(keypayload);
  FREE(key);
}

/**
 * Generate the pre-Temporal key. (PTK) Using the authenticator, and 
 * supplicant nonces.  (Anonce, and Snonce.)  The PTK is used for keying
 * when we are ready.
 **/
char *eapol_key_type2_gen_ptk(context *intdata, char *Anonce)
{
  char prfdata[76];  // 6*2 (MAC addrs) + 32*2 (nonces)
  char *retval = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((Anonce != NULL), "Anonce != NULL", FALSE))
    return NULL;

  memset((char *)&prfdata, 0x00, 76);

  debug_printf(DEBUG_INT, "Checking MAC data :\n");
  debug_printf(DEBUG_INT, "Source MAC : \n");
  debug_hex_printf(DEBUG_INT, (uint8_t *)intdata->source_mac, 6);
  debug_printf(DEBUG_INT, "Dest MAC :\n");
  debug_hex_printf(DEBUG_INT, (uint8_t *)intdata->dest_mac, 6);
  if (memcmp((char *)&intdata->source_mac, (char *)&intdata->dest_mac, 6) < 0)
    {
      memcpy((char *)&prfdata[0], (char *)&intdata->source_mac, 6);
      memcpy((char *)&prfdata[6], (char *)&intdata->dest_mac, 6);
    } 
  else if (memcmp((char *)&intdata->source_mac, (char *)&intdata->dest_mac,
		  6) > 0)
    {
      memcpy((char *)&prfdata[0], (char *)&intdata->dest_mac, 6);
      memcpy((char *)&prfdata[6], (char *)&intdata->source_mac, 6);
    } 
  else 
    {
      debug_printf(DEBUG_NORMAL, "Source and Destination MAC addresses "
		   "match!  The PTK won't be valid!\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_INVALID_PTK, intdata->desc);
      return NULL;
    }

  debug_printf(DEBUG_INT, "Checking nonces :\n");
  debug_printf(DEBUG_INT, "Anonce : \n");
  debug_hex_printf(DEBUG_INT, (uint8_t *)Anonce, 32);
  debug_printf(DEBUG_INT, "Snonce :\n");
  debug_hex_printf(DEBUG_INT, intdata->statemachine->SNonce, 32);
  if (memcmp(intdata->statemachine->SNonce, Anonce, 32) < 0)
    {
      memcpy((char *)&prfdata[12], intdata->statemachine->SNonce, 32);
      memcpy((char *)&prfdata[44], Anonce, 32);
    } 
  else if (memcmp(intdata->statemachine->SNonce, Anonce, 32) > 0)
    {
      memcpy((char *)&prfdata[12], Anonce, 32);
      memcpy((char *)&prfdata[44], intdata->statemachine->SNonce, 32);
    } 
  else 
    {
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

  if (intdata->statemachine->PMK == NULL) return NULL;

  debug_printf(DEBUG_KEY, "PMK : ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *) intdata->statemachine->PMK, 32);
  wpa_PRF((uint8_t *) intdata->statemachine->PMK, 32, (uint8_t *) "Pairwise key expansion", 22,
	  (uint8_t *)&prfdata, 76, (uint8_t *) retval, 64);

  debug_printf(DEBUG_KEY, "PTK : ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *) retval, 64);

  return retval;
}

/**
 * When a MIC failure occures, we need to send the AP a request for
 * a new key. (Reference 802.11i-D3.0.pdf page 43, line 8)
 **/
void eapol_key_type2_request_new_key(context *intdata, 
				       char unicast)
{
  struct wpa2_key_packet *outkeydata;
  uint16_t value16, keyindex, len;
  char key[16];

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  outkeydata = (struct wpa2_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

  // Clear everything out.
  memset(&intdata->sendframe[OFFSET_TO_EAPOL+4], 0x00,
	 sizeof(struct wpa2_key_packet));

  outkeydata->key_descriptor = WPA2_KEY_TYPE;

  value16 = (WPA2_REQUEST_FLAG | WPA2_ERROR_FLAG);

  if (unicast == 1)
    {
      // Set the key flags to indicate this is a pairwise key, with an
      // index of 0.
      keyindex = (WPA2_PAIRWISE_KEY | wpa2_pairwise_key_ver);
    } else {
      // Set the key flags to indicate this is a group key. We don't know the
      // index, so for now we will use 1.
      keyindex = ((1 << 4) | wpa2_group_key_ver);
    }

  value16 = (value16 | keyindex);

  memcpy(outkeydata->key_information, &value16, 2);

  // Build the response.
  len = sizeof(struct wpa2_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe); 
  
  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "No valid PTK available!  We will not "
		   "be able to request a new key!\n");
      return;
    }

  memcpy(key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);

  cardif_sendframe(intdata);
  intdata->statemachine->eapolEap = FALSE;
}


/**
 * Process a GTK KDE, and set the keys as needed.
 **/
char eapol_key_type2_do_gtk_kde(context *intdata, uint8_t *key, 
				uint16_t kdelen, uint8_t keylen, 
				uint8_t *keyrsc, char version)
{
  char keyindex = 0, txkey = 0;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((key != NULL), "key != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((keyrsc != NULL), "keyrsc != NULL", FALSE))
    return XEMALLOC;

  debug_printf(DEBUG_KEY, "KDE (%d) : \n", kdelen);
  debug_hex_dump(DEBUG_KEY, key, kdelen);
  
  keyindex = WPA2_KEY_INDEX_MASK & key[0];
  
//  if (WPA2_TX_KEY_MASK & key[0]) txkey = 1;
  
  kdelen -= 2;
  key += 2;

  // At this point, the only thing left should be the key.
  keylen = kdelen;

  debug_printf(DEBUG_KEY, "Setting GTK of length %d with index of %d.\n", 
	       kdelen, keyindex);

  debug_printf(DEBUG_KEY, "Key is : ");
  debug_hex_printf(DEBUG_KEY, key, keylen);
  
  switch (version)
    {
    case 1:
      wpa_common_set_key(intdata, NULL, keyindex, txkey, (char *)key, keylen);
      break;

    case 2:
      wpa_common_set_key(intdata, NULL, keyindex, txkey, (char *)key, keylen);
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown encryption/MAC type %d.\n", version);
	  ipc_events_error(intdata, IPC_EVENT_ERROR_UNKNOWN_KEY_REQUEST, intdata->desc);
      break;
    }

  debug_printf(DEBUG_NORMAL, "Interface '%s' set new group IEEE 802.11i/WPA2 key.\n", intdata->desc);

  return XENONE;
}

/**
 * Process an STAKey KDE and set keys as needed.
 **/
char eapol_key_type2_do_stakey_kde(context *intdata, 
				   uint8_t *key, uint16_t keylen, 
				   uint8_t *keyrsc, char version)
{
  debug_printf(DEBUG_NORMAL, "STAkeys are not supported at this time! "
	       "(Ignoring)\n");
  return XENONE;
}

/**
 * Process a MAC address KDE.
 **/
char eapol_key_type2_do_mac_kde(context *intdata, uint8_t *key,
				uint16_t keylen, char version)
{
  debug_printf(DEBUG_NORMAL, "MAC KDEs are not supported at this time! "
	       "(Ignoring)\n");
  return XENONE;
}

/**
 * Process a PMKID KDE.
 **/
char eapol_key_type2_do_pmkid_kde(context *ctx,
				  uint8_t *key, uint16_t kdelen, char version)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((key != NULL), "key != NULL", FALSE))
    return XEMALLOC;

  debug_printf(DEBUG_KEY, "KDE (%d) : \n", kdelen);
  debug_hex_dump(DEBUG_KEY, key, kdelen);

  if (pmksa_populate_keydata(ctx, key) == 0)
  {
	  debug_printf(DEBUG_NORMAL, "Interface '%s' used a cached PMK to connect.\n", ctx->desc);
	  statemachine_change_state(ctx, AUTHENTICATED);
  }
  else
  {
	  // If we are on a PSK network, then a cache miss should be a non-issue.
	  if ((ctx->conn->association.psk == NULL) && (ctx->conn->association.psk_hex == NULL) &&
		  (ctx->conn->association.temp_psk == NULL))
	  {
		  debug_printf(DEBUG_NORMAL, "Interface '%s' had a cache miss.  You will have to do a full authentication.\n", ctx->desc);

		  debug_printf(DEBUG_INT, "PMKID : ");
		  debug_hex_printf(DEBUG_INT, key, 16);

		  pmksa_dump_cache(ctx);

		  // Kick out an EAPoL start.
		  txStart(ctx);

		  return XECACHEMISS;
	  }
  }

  return XENONE;
}

/**
 * Given the IE from the decrypted data, verify that it matches what
 * the AP originally told us.  If not, we should fail, and send a deauth.
 **/
int eapol_key_type2_cmp_ie(context *intdata, uint8_t *iedata,
			   int len)
{
  uint8_t *apie, ielen;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((iedata != NULL), "iedata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((intdata->conn != NULL), "intdata->conn != NULL", FALSE))
	  return XEMALLOC;

  if (intdata->conn->flags & CONFIG_NET_IS_HIDDEN)
  {
	  debug_printf(DEBUG_NORMAL, "Interface '%s' connected to a hidden SSID.  We don't know the IE that was used, so we won't check.  (Man-in-the-middle checks have been weakened.)\n", intdata->desc);
	  return 0;
  }

  if (iedata[0] != WPA2_EID)
    {
      debug_printf(DEBUG_NORMAL, "Data presented doesn't appear to be a valid"
		   " WPA2/802.11i IE!\n");
      return -1;
    }

  debug_printf(DEBUG_KEY, "Got an IE of        : \n");
  debug_hex_dump(DEBUG_KEY, (uint8_t *) iedata, len);

  // Be sure *NOT* to free apie, as it is a reference pointer only!!!
  config_ssid_get_rsn_ie(intdata->intTypeData, &apie, &ielen);

  debug_printf(DEBUG_KEY, "AP sent us an IE of (%d) : \n", ielen);
  debug_hex_dump(DEBUG_KEY, (uint8_t *) apie, ielen);

  if (len != ielen)
    {
      debug_printf(DEBUG_NORMAL, "The length of the IE from the AP and IE in"
		   " key messages were different!  IEs are invalid!\n");
      return -1;
    }

  if (memcmp(apie, iedata, len) != 0)
    {
      debug_printf(DEBUG_NORMAL, "The IE from the AP and the IE in the key "
		   "messages don't match!\n");
      return -1;
    }

  return XENONE;
}

/**
 * \brief Process key data provided in the key frame.
 *
 * Given a string of bytes, go through it, and parse the information looking
 * for different Key Data Encapsulations (KDEs).  Depending on the KDE that
 * we find, we will pass the data on for further processing.
 *
 * @param[in] intdata   The context for the interface that we are working with.
 * @param[in] keydata   The keydata field from the WPA2 key frame.  (This is the undefined length field at the end of the frame.)
 * @param[in] len		The number of bytes in the keydata
 * @param[in] keylen	The length of the keys that we are using.  (May be 0 if we are processing a frame that isn't expected to have a GTK KDE.)
 * @param[in] keyrsc    The RSC field provided in the key frame.
 * @param[in] version	The version field from the key frame.
 * @param[in] cmpies    A TRUE/FALSE value that indicates if we should compare the IE data in the keydata field against the IEs provided by the AP.
 *                      This should be set to FALSE when dealing with the first frame of the handshake.
 *
 * \retval XENONE on success
 **/
char eapol_key_type2_process_keydata(context *intdata, 
				     uint8_t *keydata, uint16_t len, 
				     uint8_t keylen, uint8_t *keyrsc, 
				     char version, char cmpies)
{
  uint8_t kdeval[3] = {0x00, 0x0f, 0xac};
  int i = 0, done = 0;
  uint8_t *p, kdelen;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((keydata != NULL), "keydata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((keyrsc != NULL), "keyrsc != NULL", FALSE))
    return XEMALLOC;

  while ((i < len) && (!done))
    {
      if ((keydata[i] == 0x30) && (cmpies == TRUE))
	{
	  // We are testing the IE to see if it matches what the AP gave us.
	  if (eapol_key_type2_cmp_ie(intdata, &keydata[i], (keydata[i+1]+2))
	      != XENONE)
	    {
	      debug_printf(DEBUG_NORMAL, "IE presented by the AP doesn't "
			   "match the IE in the key message!  Assuming "
			   "an active attack is in progress!\n");
		  ipc_events_error(intdata, IPC_EVENT_ERROR_IES_DONT_MATCH, intdata->desc);
	      cardif_disassociate(intdata, DISASSOC_INVALID_IE);
	      return -1;
	    }
	}

      if (keydata[i] == WPA2_EXTENDED_KEY_DATA)
	{
	  kdelen = keydata[i+1];
	  if (kdelen == 0)
	    {
	      debug_printf(DEBUG_KEY, "Remaining KDE data is padding.\n");
	      return XENONE;
	    }

	  if (memcmp(&keydata[i+2], kdeval, 3) == 0)
	    {
	      // This isn't a key type that we know how to deal with,
	      // ignore it.
	      p = (uint8_t *)&keydata[i+6];

	      switch (keydata[i+5])
		{
		case 0:
		  debug_printf(DEBUG_KEY, "KDE : Reserved\n");
		  break;
		  
		case WPA2_EXTENDED_GTK_KEY:
		  debug_printf(DEBUG_KEY, "KDE : GTK KDE\n");
		  if (eapol_key_type2_do_gtk_kde(intdata, p, kdelen-4, keylen, 
						 keyrsc, version) != XENONE)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't set the GTK! "
				   "Aborting the connection!\n");
		      return -1;
		    }
		  break;
		  
		case WPA2_EXTENDED_STA_KEY:
		  debug_printf(DEBUG_KEY, "KDE : STAKey KDE\n");
		  if (eapol_key_type2_do_stakey_kde(intdata, p, kdelen-4, 
						    keyrsc, version) != XENONE)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't set STAKey!\n");
		      return -1;
		    }
		  break;
		  
		case WPA2_EXTENDED_MAC_ADDRESS:
		  debug_printf(DEBUG_KEY, "KDE : MAC address KDE\n");
		  if (eapol_key_type2_do_mac_kde(intdata, p, kdelen-4, 
						 version) != XENONE)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't processing MAC "
				   "address KDE!\n");
		      return -1;
		    }
		  break;
		  
		case WPA2_EXTENDED_PMKID:
		  debug_printf(DEBUG_KEY, "KDE : PMKID KDE\n");
		  if (eapol_key_type2_do_pmkid_kde(intdata, p, kdelen-4, 
						   version) != XENONE)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't process PMKID!\n");
		      return -1;
		    }
		  break;
		  
		default:
		  debug_printf(DEBUG_NORMAL, "Unknown KDE found!\n");
		  break;
		}
	    }
	  else 
	    {
	      debug_printf(DEBUG_NORMAL, "KDE contained an OUI that we don't"
			   " understand!\n");
	    }
	}
      i += (keydata[i+1] + 2);
    }
  i++;

  return XENONE;
}

/**
 * When we have completed the PTK piece, and the pairwise key has been
 * applied to the interface, we need to get the group key.  The authenticator
 * will send us a group key that is encrypted.  We should decrypt it, apply
 * it to our interface, and send the authenticator a message to let it know
 * that we have a group key.
 **/
void eapol_key_type2_do_gtk(context *intdata)
{
  struct wpa2_key_packet *inkeydata, *outkeydata;
  uint16_t value16, keyflags, version, len;
  unsigned char *keydata = NULL;
  char key[48], rc4_ek[48];
  char zeros[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((intdata->intType == ETH_802_11_INT), "intdata->intType == ETH_802_11_INT", FALSE))
	  return;

  if (!xsup_assert((intdata->intTypeData != NULL), "intdata->intTypeData != NULL", FALSE))
	  return;

  wctx = intdata->intTypeData;

  inkeydata = (struct wpa2_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];
  outkeydata = (struct wpa2_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

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
	 sizeof(struct wpa2_key_packet));

  outkeydata->key_descriptor = WPA2_KEY_TYPE;

  memcpy(&value16, inkeydata->key_information, 2);
  value16 = ntohs(value16);

  keyflags = 0;
  keyflags = (value16 & WPA2_KEYTYPE_MASK);
  version = keyflags;
  wpa2_group_key_ver = version;

  // Verify that our flags are correct.  (We don't check for the install flag,
  // for now.  Since the WPA spec doesn't explicitly require that the install
  // flag be set.)
  if (!((value16 & WPA2_KEY_ACK_FLAG) &&
	(value16 & WPA2_KEY_MIC_FLAG) && (value16 & WPA2_SECURE_FLAG)))
    {
      debug_printf(DEBUG_NORMAL, "Invalid flags in GTK message 1!\n");
      return;
    }

  value16 = ntohs(inkeydata->key_material_len);
  
  keydata = (unsigned char *)Malloc(value16+8);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for key data!\n");
	  ipc_events_malloc_failed(intdata);
      return;
    }

  memcpy(keydata, inkeydata->keydata, value16);

  debug_printf(DEBUG_KEY, "Setting GTK! (Version : %d  Length : %d)\n", 
	       version, value16);

  if (!intdata->statemachine->PTK)
    {
      debug_printf(DEBUG_NORMAL, "No valid PTK available!  We won't be able"
		   " to continue.\n");
      FREE(keydata);
      return;
    }

  switch (version)
    {
    case 1:
      // Decrypt the GTK.
      memset(rc4_ek, 0x00, 32);
      memcpy(rc4_ek, inkeydata->key_iv, 16);
      memcpy(&rc4_ek[16], &intdata->statemachine->PTK[16], 16);
      rc4_skip((uint8_t *) rc4_ek, 32, 256, keydata, value16);

      debug_printf(DEBUG_KEY, "Decrypted data : (%d)\n", value16);
      debug_hex_dump(DEBUG_KEY, keydata, value16);

      if (eapol_key_type2_process_keydata(intdata, keydata, value16, 
					  ntohs(inkeydata->key_length),
					  inkeydata->key_rsc, version, TRUE) 
	  != XENONE)
	{
	  FREE(keydata);
	  return;
	}
      break;

    case 2:
      // First, decrypt the GTK
      memset(key, 0x00, 32);
      if (aes_unwrap((uint8_t *) &intdata->statemachine->PTK[16], 
		     (value16-8)/8, keydata, (uint8_t *) key) != 0)
      {
		debug_printf(DEBUG_NORMAL, "Failed AES unwrap.\n");
		if (intdata->statemachine->PTK == NULL) debug_printf(DEBUG_NORMAL, "Unwrap failed because PTK is NULL!\n");
		ipc_events_error(intdata, IPC_EVENT_ERROR_FAILED_AES_UNWRAP, intdata->desc);
		cardif_disassociate(intdata, DISASSOC_CIPHER_REJECT); 
      }

      debug_printf(DEBUG_KEY, "Result : ");
      debug_hex_printf(DEBUG_KEY, (uint8_t *)key, value16);

      if (eapol_key_type2_process_keydata(intdata, (uint8_t *)key, value16, 
					  ntohs(inkeydata->key_length),
					  inkeydata->key_rsc, version, TRUE)
	  != XENONE)
	{
	  FREE(keydata);
	  debug_printf(DEBUG_NORMAL, "Unable to process key data!\n");
	  cardif_disassociate(intdata, 0);  // Fix this to be a valid reason.
	  return;
	}
      break;
    }

  debug_printf(DEBUG_NORMAL, "Set new IEEE 802.11i/WPA2 group key.\n");

  // Build the response.
  len = sizeof(struct wpa2_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  value16 = (version | WPA2_KEY_MIC_FLAG | WPA2_SECURE_FLAG);
  value16 = htons(value16);
  memcpy(&outkeydata->key_information, &value16, 2);

  outkeydata->key_length = inkeydata->key_length;
  memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter, 8);

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe); 
  
  memcpy(key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);

  // Dump what we built.
  eapol_key_type2_dump(intdata, (char *) intdata->sendframe);

  if (intdata->conn->association.auth_type == AUTH_PSK)
    {
      // If we are using PSK, and we made it here, then we are in 
      // FORCED AUTHENTICATED state.
	  debug_printf(DEBUG_NORMAL, "Setting to S_FORCE_AUTH state!\n");
	  statemachine_change_state(intdata, S_FORCE_AUTH);
      cardif_drop_unencrypted(intdata, FALSE);
    } else {
      // Drop unencrypted frames.
      cardif_drop_unencrypted(intdata, TRUE);
    }

  FREE(keydata);
}

/**
 * Handle the first packet in the four-way handshake.
 **/
void eapol_key_type2_do_type1(context *intdata)
{
  struct wpa2_key_packet *inkeydata, *outkeydata;
  uint16_t keyflags, len, value16;
  int i, version;
  uint8_t ielen;
  char key[16];
  char wpa_ie[256];
  char zeros[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (intdata->intType != ETH_802_11_INT)
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to process a key message on non-802.11 interface '%s'.\n", intdata->desc);
	  return;
  }

  if (intdata->intTypeData == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Interface '%s' claims to be 802.11, but it doesn't have a wireless context!?\n", intdata->desc);
	  return;
  }

  wctx = intdata->intTypeData;

  inkeydata = (struct wpa2_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];
  outkeydata = (struct wpa2_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

  if ((memcmp(inkeydata->key_replay_counter, wctx->replay_counter, 8) <= 0) && 
      (memcmp(inkeydata->key_replay_counter, zeros, 8) != 0))
    {
      debug_printf(DEBUG_NORMAL, "Invalid replay counter!  Discarding!\n");
      intdata->recv_size = 0;
      return;
    }

  // Clear everything out.
  memset(&intdata->sendframe[OFFSET_TO_EAPOL+4], 0x00,
	 sizeof(struct wpa2_key_packet));

  // XXX Need to do this better.  Tie it in with Nonce code from SIM/AKA.
  for (i=0;i<32;i++)
    {
      outkeydata->key_nonce[i] = rand();
    }

  FREE(intdata->statemachine->SNonce);

  intdata->statemachine->SNonce = (uint8_t *)Malloc(32);
  if (intdata->statemachine->SNonce == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for SNonce in "
		   "%s at %d!\n", __FUNCTION__, __LINE__);
	  ipc_events_malloc_failed(intdata);
      return;
    }
  memcpy(intdata->statemachine->SNonce, (char *)&outkeydata->key_nonce[0],
	 32);

  value16 = ntohs(inkeydata->key_material_len);

  version = ntohs((uint16_t)(*inkeydata->key_information)) | WPA2_KEYTYPE_MASK;

  // Check the IE field to see if we have any KDEs to parse.
  // We can discard the result field because the only thing we can possibly expect is a PMKID KDE, and
  // if it isn't there, then it is okay.
  if (eapol_key_type2_process_keydata(intdata, inkeydata->keydata, value16, 
					  ntohs(inkeydata->key_length), inkeydata->key_rsc, version, FALSE) != XENONE)
  {
	  return;
  }

  // Calculate the PTK.
  FREE(intdata->statemachine->PTK);

  intdata->statemachine->PTK = (uint8_t *)eapol_key_type2_gen_ptk(intdata,
						       (char *)&inkeydata->key_nonce);

  if (intdata->statemachine->PTK == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to generate the PTK for interface '%s'!\n", intdata->desc);
	  return;
  }

  outkeydata->key_descriptor = WPA2_KEY_TYPE;

  memcpy(&value16, inkeydata->key_information, 2);
  value16 = ntohs(value16);

  keyflags = 0;
  keyflags = (value16 & WPA2_KEYTYPE_MASK);
  version = keyflags;
  wpa2_pairwise_key_ver = version;
  keyflags |= (WPA2_PAIRWISE_KEY | WPA2_KEY_MIC_FLAG);
  keyflags = htons(keyflags);

  memcpy(&outkeydata->key_information, &keyflags, 2);
  
  len = sizeof(struct wpa2_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  outkeydata->key_length = inkeydata->key_length;

  memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter, 8);

  if (cardif_get_wpa2_ie(intdata, wpa_ie, &ielen) < 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't locate WPA2 information element!\n");
	  intdata->send_size = 0;
	  return;
  }

  memcpy(&intdata->sendframe[OFFSET_TO_EAPOL+4+sizeof(struct wpa2_key_packet)], 
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
  eapol_key_type2_dump(intdata, (char *) intdata->sendframe);
}

/**
 * Handle the third packet in the 4 way handshake.  We should be able to
 * generate the pairwise key at this point.
 **/
void eapol_key_type2_do_type3(context *intdata)
{
  struct wpa2_key_packet *inkeydata, *outkeydata;
  uint8_t *keydata = NULL;
  uint8_t *aesval = NULL;
  uint16_t keyflags, len, value16, keylen = 0;
  int version = 0, encdata = 0;
  char key[32], rc4_ek[32];
  uint8_t framecpy[1530];
  int framesize;
  char zeros[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  wireless_ctx *wctx = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  xsup_assert((intdata->eap_state != NULL), "intdata->eap_state != NULL", TRUE);

  if (intdata->intType != ETH_802_11_INT) 
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to process a key frame on non-802.11 interface '%s'.\n", intdata->desc);
	  return;
  }

  if (intdata->intTypeData == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Interface '%s' claims to be wireless, but has no wireless context!?\n", intdata->desc);
	  return;
  }

  wctx = intdata->intTypeData;

  memset(key, 0x00, 32);

  // Clear everything out.
  if (intdata->sendframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Buffer for sending a frame is NULL!\n");
    }
     
  memset(intdata->sendframe, 0x00, 1520);

  inkeydata = (struct wpa2_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];
  outkeydata = (struct wpa2_key_packet *)&intdata->sendframe[OFFSET_TO_EAPOL+4];

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
  memcpy(wctx->replay_counter, inkeydata->key_replay_counter, 8);

  memset(&intdata->sendframe[OFFSET_TO_EAPOL], 0x00,
	sizeof(struct wpa2_key_packet)+280);

  outkeydata->key_descriptor = WPA2_KEY_TYPE;

  memcpy(&value16, inkeydata->key_information, 2);
  value16 = ntohs(value16);
  
  keyflags = 0;
  keyflags = (value16 & WPA2_KEYTYPE_MASK);
  version = keyflags;  

  keyflags = 0;
  keyflags = (value16 & WPA2_KEYTYPE_MASK);
  keyflags |= (WPA2_PAIRWISE_KEY | WPA2_KEY_MIC_FLAG);

  // If the authenticator sets the secure flag, we need to do the same.
  if (value16 & WPA2_SECURE_FLAG) keyflags |= WPA2_SECURE_FLAG;
  if (value16 & WPA2_ENCRYPTED_DATA) encdata = 1;


  keyflags = htons(keyflags);

  memcpy(&outkeydata->key_information, &keyflags, 2);
  
  len = sizeof(struct wpa2_key_packet);
  intdata->send_size = len+OFFSET_TO_EAPOL+4;

  outkeydata->key_length = inkeydata->key_length;

  memcpy(&outkeydata->key_replay_counter, &inkeydata->key_replay_counter, 8);
  memcpy(&outkeydata->key_nonce, intdata->statemachine->SNonce, 32);

  memcpy(outkeydata->key_nonce, intdata->statemachine->SNonce,
	 32);

  eapol_build_header(intdata, EAPOL_KEY, (intdata->send_size-OFFSET_TO_EAPOL-4), 
		     (char *) intdata->sendframe); 

  memcpy(key, intdata->statemachine->PTK, 16);
  mic_wpa_populate((char *) intdata->sendframe, intdata->send_size+4, key, 16);  

  // Dump what we built.
  eapol_key_type2_dump(intdata, (char *) intdata->sendframe);

  // Get TK1
  value16 = ntohs(inkeydata->key_length);
  memcpy(key, (char *)&intdata->statemachine->PTK[32], value16);
  
  debug_printf(DEBUG_KEY, "TK1 : ");
  debug_hex_printf(DEBUG_KEY, (uint8_t *) key, value16);
  
  // We need to send the result frame now, but that will result in the
  // "sendframe" being zeroed out.  So, we need to make a copy.
  framesize = intdata->recv_size;
  memcpy(&framecpy, intdata->recvframe, framesize);
  inkeydata = (struct wpa2_key_packet *)&framecpy[OFFSET_TO_EAPOL+4];

  cardif_sendframe(intdata);
  intdata->statemachine->eapolEap = FALSE;
  intdata->send_size = 0;

  keylen = ntohs(inkeydata->key_material_len);

  eapol_key_type2_dump(intdata, (char *) &framecpy);

  if ((encdata) && (keylen > 0))
    {
      keydata = (uint8_t *)Malloc(keylen);
      if (keydata == NULL)
        {
          debug_printf(DEBUG_NORMAL,
	    "Error with malloc of keydata in eapol_key_type2_do_type3()\n");
		  ipc_events_malloc_failed(intdata);
	  return;
	}

      memcpy(keydata, inkeydata->keydata, keylen);
      
      switch (version)
	{
	case 1:
		if (intdata->statemachine->PTK == NULL)
		{
			debug_printf(DEBUG_NORMAL, "The PTK is NULL.  We will be unable to generate keys!\n");
			cardif_disassociate(intdata, 0);
			return;
		}

	  memset(rc4_ek, 0x00, 32);
	  memcpy(rc4_ek, inkeydata->key_iv, 16);
	  memcpy(&rc4_ek[16], &intdata->statemachine->PTK[16], 16);
	  rc4_skip((uint8_t *) rc4_ek, 32, 256, keydata, keylen);
	  break;
	  
	case 2:
	  aesval = (uint8_t *)Malloc(keylen);
	  if (aesval == NULL)
	    {
	      debug_printf(DEBUG_NORMAL,
			   "Error with malloc of aesval in %s()!\n",
			   __FUNCTION__);
	      FREE(keydata);
	      return;
	    }

	  if (aes_unwrap((uint8_t *) &intdata->statemachine->PTK[16], 
			 ((keylen)/8)-1, keydata, aesval) != 0)
	    {
	      debug_printf(DEBUG_NORMAL, "Failed AES unwrap!\n");
		  if (intdata->statemachine->PTK == NULL) debug_printf(DEBUG_NORMAL, "Unwrap failed because there is no PTK set!\n");
		  ipc_events_error(intdata, IPC_EVENT_ERROR_FAILED_AES_UNWRAP, intdata->desc);
	      FREE(keydata);
		  cardif_disassociate(intdata, DISASSOC_CIPHER_REJECT);  
	      return;
	    } else {
	      FREE(keydata);
	      keydata = aesval;
	      aesval = NULL;
	    }
	  break;
	  
	default:
	  debug_printf(DEBUG_NORMAL, "Unknown version ID! (Version = %d)\n",
		       version);
	  ipc_events_error(intdata, IPC_EVENT_ERROR_UNKNOWN_KEY_REQUEST, intdata->desc);
	  FREE(keydata);
	  cardif_disassociate(intdata, DISASSOC_BAD_RSN_VERSION);  
	  return;
	  break;
	}

      debug_printf(DEBUG_KEY, "Keydata (%d) : \n", keylen);
      debug_hex_dump(DEBUG_KEY, keydata, keylen);

      if (eapol_key_type2_process_keydata(intdata, keydata, keylen,
					  ntohs(inkeydata->key_length), 
					  inkeydata->key_rsc, version, TRUE) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Error processing key data!\n");
	  FREE(keydata);
	  cardif_disassociate(intdata, DISASSOC_BAD_RSN_VERSION);  
	  return;
	}

      FREE(keydata);
    }

  if (intdata->conn->association.auth_type == AUTH_PSK)
    {
     // If we are using PSK, and we made it here, then we are in 
      // FORCED AUTHENTICATED state.
	  statemachine_change_state(intdata, S_FORCE_AUTH);
      cardif_drop_unencrypted(intdata, FALSE);
    } else {
      // Drop unencrypted frames.
      cardif_drop_unencrypted(intdata, TRUE);
    }
  
  debug_printf(DEBUG_KEY, "Setting PTK of length %d with index 0.\n", value16);
  
  switch (version) 
    {
    case 1:
      wpa_common_set_key(intdata, intdata->dest_mac, 0, TRUE,
			 key, value16);
      break;

    case 2:
      wpa_common_set_key(intdata, intdata->dest_mac, 0, TRUE,
			 key, value16);
      break;
    }
  debug_printf(DEBUG_NORMAL, "Interface '%s' set new pairwise IEEE 802.11i/WPA2 key.\n", intdata->desc);

#ifdef WINDOWS
	// We need to let the event core know that we are done doing the PSK handshake.  This allows it to
	// go through the event loop one more time to verify that the AP didn't drop us.  If it did drop us,
	// it is a pretty sure indication that our PSK is invalid.  If it didn't, then we should be good.
	// Note that sometimes APs will drop us a few seconds after the association, even if the PSK is
	// valid.  This is *NOT* an indication that the key is wrong!
  	UNSET_FLAG(((wireless_ctx *)intdata->intTypeData)->flags, WIRELESS_SM_PSK_DONE);
#endif

	ipc_events_ui(intdata, IPC_EVENT_PSK_SUCCESS, intdata->intName);
}

/**
 * Given a key packet, look at the flags and determine which piece of the
 * four-way handshake to pass it on to.
 **/
void eapol_key_type2_determine_key(context *intdata)
{
  struct wpa2_key_packet *keydata;
  int keyflags;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  keydata = (struct wpa2_key_packet *)&intdata->recvframe[OFFSET_TO_EAPOL+4];  
  memcpy(&keyflags, keydata->key_information, 2);

  keyflags = ntohs(keyflags);

  if (keyflags & WPA2_KEY_MIC_FLAG)
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
  if ((keyflags & WPA2_PAIRWISE_KEY) && (keyflags & WPA2_KEY_ACK_FLAG) &&
      (keyflags & WPA2_KEY_MIC_FLAG) && (keyflags & WPA2_INSTALL_FLAG))
    {
      debug_printf(DEBUG_KEY, "Key Packet #3 (response) :\n");
      eapol_key_type2_do_type3(intdata);
    } 
  else if ((keyflags & WPA2_PAIRWISE_KEY) && (keyflags & WPA2_KEY_ACK_FLAG))
    {
      debug_printf(DEBUG_KEY, "Key Packet #1 (response) :\n");
      eapol_key_type2_do_type1(intdata);
    } 
  else if ((keyflags & WPA2_KEY_MIC_FLAG) && (keyflags & WPA2_PAIRWISE_KEY))
    {
      debug_printf(DEBUG_NORMAL, "Got Key Packet #2!  (This shouldn't happen!"
		   ")\n");
      return;
    } 
  else if ((keyflags & WPA2_SECURE_FLAG) && 
	   (keyflags & WPA2_KEY_MIC_FLAG) && (keyflags & WPA2_PAIRWISE_KEY))
    {
      debug_printf(DEBUG_NORMAL, "Got Key Packet #4!  (This shouldn't happen"
		   "!)\n");
      return;
    } else if (!(keyflags & WPA2_PAIRWISE_KEY))
       {
	  // We have a group key packet.
	  eapol_key_type2_do_gtk(intdata);
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
 * Process a WPA frame that we get from the authenticator.
 **/
void eapol_key_type2_process(context *intdata)
{
  uint8_t *inframe;
  int insize;
  char tpmk[256];
  wireless_ctx *wctx;
  char *pskptr = NULL;

  if (!xsup_assert((intdata != NULL), "intdata != NULL", FALSE))
    return;

  if (!xsup_assert((intdata->statemachine != NULL), 
		   "intdata->statemachine != NULL", FALSE))
    return;

  if (!xsup_assert((intdata->conn != NULL), "intdata->conn != NULL", FALSE)) return;

  inframe = intdata->recvframe;
  insize = intdata->recv_size;

  debug_printf(DEBUG_KEY, "Processing WPA2 key message!\n");

  eapol_key_type2_dump(intdata, (char *) inframe);

  if (intdata->conn->association.psk != NULL) pskptr = intdata->conn->association.psk;
  // The one below ALWAYS needs to come last, so that a PSK entered from the login component of a UI takes
  // precident over one that was saved.
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
		      return;
		    }

		  memset(wctx->cur_essid, 0x00, 99);

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
		      return;
		    }
		  
		  memcpy(intdata->statemachine->PMK, (char *)&tpmk, 32);
		}
	  } else if (intdata->conn->association.psk_hex != NULL)
	  {
	      // We have a hex key, we need to convert it from ASCII to real
	      // hex.
			if ((intdata->conn->association.psk_hex == NULL) ||
				(strlen(intdata->conn->association.psk_hex) != 64))
		{
		  debug_printf(DEBUG_NORMAL, "Invalid HEX key defined for "
			       "WPA2-PSK!\n");
		  ipc_events_error(intdata, IPC_EVENT_ERROR_PMK_UNAVAILABLE, intdata->desc);
		  return;
		}
			process_hex(intdata->conn->association.psk_hex, 
				strlen(intdata->conn->association.psk_hex), (char *)&tpmk);
	      intdata->statemachine->PMK = (uint8_t *)Malloc(32);
	      if (intdata->statemachine->PMK == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for "
			       "intdata->statemachine->PMK in %s:%d!\n",
			       __FUNCTION__, __LINE__);
		  return;
		}
	    }
	  else // Don't have a key.
	  {
		  debug_printf(DEBUG_NORMAL, "There is no WPA2-PSK key defined!\n");
		  return;   // Don't do anything else.
	  }

	  if (intdata->statemachine->PMK == NULL)
	  {
	  debug_printf(DEBUG_NORMAL, "There is no PMK available!  WPA2 cannot"
		       " continue!\n");
	  ipc_events_error(intdata, IPC_EVENT_ERROR_PMK_UNAVAILABLE, intdata->desc);
	  return;
	  }
	}

  eapol_key_type2_determine_key(intdata);

  if (intdata->send_size > 0)
    {
      cardif_sendframe(intdata);
      intdata->statemachine->eapolEap = FALSE;
    }
}
