/**
 * EAPOL Function implementations for supplicant
 * 
 * \file eapaka.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error message signaling.
 * \todo Add support for temporary username/password pairs.
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/AKA support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/


#ifdef EAP_SIM_ENABLE     // Only build this if it has been enabled.

#include <inttypes.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "winscard.h"
#include "profile.h"
#include "xsupconfig.h"
#include "xsup_common.h"
#include "eap_sm.h"
#include "eapaka.h"
#include "../sim/eapsim.h"
#include "../sim/sm_handler.h"
#include "../sim/fips.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "aka.h"
#include "ipc_callout.h"
#include "xsup_ipc.h"
#include "frame_structs.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/*************************************************************************
 *
 *  Ask the SIM card what our IMSI is so that it can be used for our username
 *  during the authentication.
 *
 *************************************************************************/
int eapaka_get_username()
{
  char *imsi;  
  char realm[25], card_mode=0;
  char *readers, *username;
  struct config_eap_aka *userdata;
  struct config_network *network_data;
  SCARDCONTEXT ctx;
  SCARDHANDLE hdl;

  network_data = config_get_network_config();

  if (!xsup_assert((network_data != NULL), "network_data != NULL", FALSE))
    return XEBADCONFIG;

  userdata = (struct config_eap_aka *)network_data->methods->method_data;

  // Initalize our smartcard context, and get ready to authenticate.
  if (sm_handler_init_ctx(&ctx) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize smart card context!\n");
      return XESIMGENERR;
    }

  readers = sm_handler_get_readers(&ctx);
  if (readers == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't list available readers!\n");
      return XESIMGENERR;
    }

  // Connect to the smart card.
  if (sm_handler_card_connect(&ctx, &hdl, readers) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
      return XESIMGENERR;
    }

  // Wait for up to 10 seconds for the smartcard to become ready.
  if (sm_handler_wait_card_ready(&hdl, 10) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready after 10 seconds!\n");
      return XESIMGENERR;
    }

  imsi = sm_handler_3g_imsi(&hdl, card_mode, userdata->password);
  if (imsi == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error starting smart card, and getting IMSI!\n");
      return XESIMGENERR;
    }

  debug_printf(DEBUG_AUTHTYPES, "SIM IMSI (AKA) : %s\n",imsi);

  FREE(network_data->identity);
  
  network_data->identity = (char *)Malloc(50);  // 50 should be plenty!
  if (network_data->identity == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for identity!\n");
      return XEMALLOC;
    }

  username = network_data->identity;
  userdata->username = username;
  memset(username, 0x00, 50);

  username[0] = '1';  // An IMSI should always start with a 1.
  if (Strncpy(&username[1], 50, imsi, 18) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to overflow buffer in %s() at %d!\n",
		  __FUNCTION__, __LINE__);
	  return XEMALLOC;
  }

  if (userdata->auto_realm == TRUE)
    {
      memset(&realm, 0x00, 25);
      sprintf((char *)&realm, "@mnc%c%c%c.mcc%c%c%c.owlan.org",
	      username[4], username[5], username[6], username[1], username[2],
	      username[3]);

      debug_printf(DEBUG_AUTHTYPES, "Realm Portion : %s\n",realm);
      if (Strcat(username, 50, realm) != 0)
	{
	  fprintf(stderr, "Refusing to overwrite the string!\n");
	  return XEMALLOC;
	}
    }

  // Close the smartcard, so that we know what state we are in.
  sm_handler_close_sc(&hdl, &ctx);

  FREE(imsi);
  FREE(readers);

  debug_printf(DEBUG_AUTHTYPES, "Username is now : %s\n", username);

  return XENONE;
}

/*************************************************************************
 *
 *  Allocate temporary memory, and determine if the card reader is attached.
 *
 *************************************************************************/
int eapaka_setup(eap_type_data *eapdata)
{
  struct aka_eaptypedata *mydata;
  struct config_eap_aka *userdata;
  char *imsi;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-AKA) Initalized\n");

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return XEMALLOC;

  if (eapdata->eap_data != NULL)
    {
      eapaka_deinit(eapdata);
    }

  eapdata->eap_data = (char *)Malloc(sizeof(struct aka_eaptypedata));
  if (eapdata->eap_data == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for EAP-AKA "
		   "specific data structure!\n");
      return XEMALLOC;
    }

  mydata = (struct aka_eaptypedata *)eapdata->eap_data;
  userdata = (struct config_eap_aka *)eapdata->eap_conf_data;

  mydata->numrands = 0;
  mydata->nonce_mt = NULL;
  mydata->sync_fail = FALSE;
  FREE(mydata->keyingMaterial);

  eapdata->eap_data = (void *)mydata;

#ifndef RADIATOR_TEST
  // Initalize our smartcard context, and get ready to authenticate.
  if (sm_handler_init_ctx(&mydata->scntx) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize smart card context!\n");
      return XESIMGENERR;
    }

  mydata->readers = sm_handler_get_readers(&mydata->scntx);
  if (mydata->readers == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't get any available readers!\n");
      return XESIMGENERR;
    }

  // Connect to the smart card.
  if (sm_handler_card_connect(&mydata->scntx, &mydata->shdl, mydata->readers) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
      return XESIMGENERR;
    }

  // Wait for up to 20 seconds for the smartcard to become ready.
  if (sm_handler_wait_card_ready(&mydata->shdl, 20) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready after 20 seconds!\n");
      return XESIMGENERR;
    }

  imsi = sm_handler_3g_imsi(&mydata->shdl, mydata->card_mode, userdata->password);
  if (imsi == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error starting smart card, and getting IMSI!\n");
      return XESIMGENERR;
    }
#endif

  if (userdata->username == NULL)
    {
      userdata->username = imsi;
    } else {
#ifndef RADIATOR_TEST
      FREE(imsi);
#endif
    }

  eap_type_common_init_eap_data(eapdata);

  return XENONE;
}

/************************************************************************
 *
 *  Determine if we are ready to do EAP-AKA.
 *
 ************************************************************************/
void eapaka_check(eap_type_data *eapdata)
{
  struct config_eap_aka *akaconf;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  akaconf = eapdata->eap_data;

  if (akaconf->password == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Don't have a valid password for EAP-AKA!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (eapaka_setup(eapdata) != XENONE)
    {
      eap_type_common_fail(eapdata);
      return;
    }
}

/************************************************************************
 *
 * Process an EAP-AKA challenge message.
 *
 *  The value passed in to eappayload should be the first byte following
 *  the challenge/response identifier.
 *
 ************************************************************************/
void eapaka_do_challenge(eap_type_data *eapdata, uint8_t *eappayload, 
			 uint16_t size)
{
  uint16_t packet_offset = 0;
  int retval = XENONE;
  struct aka_eaptypedata *aka;
  struct config_eap_aka *akaconf;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eappayload != NULL), "eappayload != NULL", FALSE))
    return;

  if (!xsup_assert((size < 1500), "size < 1500", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", 
		   FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), 
		   "eapdata->eap_conf_data != NULL", FALSE))
    return;

  aka = (struct aka_eaptypedata *)eapdata->eap_data;
  akaconf = (struct config_eap_aka *)eapdata->eap_conf_data;

  while (packet_offset < size)
    {
      switch (eappayload[packet_offset])
	{
	case AT_RAND:
      	  retval = aka_do_at_rand(aka, eappayload, &packet_offset);
	  if (retval != XENONE) return;
	  break;

	case AT_AUTN:
       	  retval = aka_do_at_autn(aka, eappayload, &packet_offset);
	  if (retval != XENONE) return;
	  break;

	case AT_IV:
	  debug_printf(DEBUG_AUTHTYPES, "Got an IV (Not supported)\n");
    	  aka_skip_not_implemented(eappayload, &packet_offset);
	  break;

	case AT_MAC:
	  retval = aka_do_at_mac(eapdata, aka, eappayload, size,
				 &packet_offset, akaconf->username);
	  if (retval == XEAKASYNCFAIL)
	    {
	      debug_printf(DEBUG_AUTHTYPES, "Sync failure..  Doing sync "
			   "failure.\n");
	      aka->sync_fail = TRUE;
	      if (retval != XENONE) return;
	    } else if (retval != XENONE) return;
	  break;
	}
    }

}

/************************************************************************
 *
 * Process an AKA request.
 *
 ************************************************************************/
void eapaka_process(eap_type_data *eapdata)
{
  uint8_t *eappayload = NULL, chal_type;
  struct config_eap_aka *akaconf;
  struct aka_eaptypedata *akadata;
  
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;
  
  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE)) return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), 
		   "eapdata->eap_conf_data != NULL", FALSE))
    return;

  akaconf = eapdata->eap_conf_data;
  akadata = eapdata->eap_data;

  eappayload = &eapdata->eapReqData[sizeof(struct eap_header)];

  switch (eappayload[0])
    {
    case AKA_IDENTITY:
      debug_printf(DEBUG_AUTHTYPES, "Got AKA_IDENTITY!\n");
      debug_printf(DEBUG_AUTHTYPES, "Not implemented!\n");
      chal_type = AKA_IDENTITY;
      break;

    case AKA_AUTHENTICATION_REJECT:
      debug_printf(DEBUG_AUTHTYPES, "Got an AKA_AUTHENTICATION_REJECT!\n");
      debug_printf(DEBUG_AUTHTYPES, "Not implemented!\n");
      chal_type = AKA_AUTHENTICATION_REJECT;
      break;

    case AKA_SYNC_FAILURE:
      debug_printf(DEBUG_AUTHTYPES, "Got an AKA_SYNC_FAILURE!\n");
      debug_printf(DEBUG_AUTHTYPES, "Not implemented!  (And, we should *NEVER*"
		   " get this!\n");
      chal_type = AKA_SYNC_FAILURE;
      break;

    case AKA_NOTIFICATION:
      debug_printf(DEBUG_AUTHTYPES, "Got an AKA_NOTIFICATION!\n");
      debug_printf(DEBUG_AUTHTYPES, "Not implemented!\n");
      chal_type = AKA_NOTIFICATION;
      break;
  
    case AKA_REAUTHENTICATION:
      debug_printf(DEBUG_AUTHTYPES, "Got an AKA_REAUTHENTICATION!\n");
      debug_printf(DEBUG_AUTHTYPES, "Not implemented!\n");
      chal_type = AKA_REAUTHENTICATION;
      break;

    case AKA_CLIENT_ERROR:
      debug_printf(DEBUG_AUTHTYPES, "Got an AKA_CLIENT_ERROR!\n");
      debug_printf(DEBUG_AUTHTYPES, "Not implemented!\n");
      chal_type = AKA_CLIENT_ERROR;
      break;

    case AKA_CHALLENGE:
      debug_printf(DEBUG_AUTHTYPES, "Got AKA_CHALLENGE!\n");
      eapaka_do_challenge(eapdata, (uint8_t *)&eappayload[1]);
      chal_type = AKA_CHALLENGE;
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown SubType value! (%d)\n",
                   eappayload[0]);
      eapdata->ignore = TRUE;
      eapdata->decision = EAP_FAIL;
      return;
      break;
    }

  eapdata->ignore = FALSE;
  eapdata->decision = COND_SUCC;
  eapdata->methodState = MAY_CONT;
}

/************************************************************************
 *
 * Build an AKA response.
 *
 ************************************************************************/
uint8_t *eapaka_buildResp(eap_type_data *eapdata)
{
  uint16_t reslen = 0, reallen = 0;
  struct config_eap_aka *akaconf = NULL;
  struct aka_eaptypedata *akadata = NULL;
  struct typelength *typelen = NULL;
  struct typelengthres *typelenres = NULL;
  uint8_t reqId, mac_calc[16];
  struct eap_header *eaphdr;
  uint8_t *payload = NULL, *framecpy = NULL, *data = NULL;
  uint16_t offset, i = 0, retsize;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		  FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    return NULL;

  akaconf = eapdata->eap_conf_data;
  akadata = eapdata->eap_data;

  if (akadata->chal_type == AKA_CHALLENGE)
    {
      if (akadata->sync_fail == TRUE)
	{
	  // Handle a sync failure response.
	  return aka_do_sync_fail(akadata, eap_type_common_get_eap_reqId(eapdata->eapReqData));
	}

      reqId = eap_type_common_get_eap_reqId(eapdata->eapReqData);

      data = Malloc(1024);  // Should be enough to hold our response.
      if (data ==  NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
		       "response data in %s()!\n", __FUNCTION__);
	  return NULL;
	}

      eaphdr = data;

      eaphdr->eap_code = EAP_RESPONSE_PKT;
      eaphdr->eap_identifier = reqId;
      eaphdr->eap_type = EAP_TYPE_AKA;

      payload = &data[sizeof(struct eap_header)];

      memset(payload, 0x00, 10);

      offset = 0;
      typelen = (struct typelength *)payload;
      typelen->type = AKA_CHALLENGE;

      reslen = akadata->reslen;
      if ((reslen % 4) != 0)
	{
	  reallen = reslen + (reslen % 4);
	}
      else
	{
	  reallen = reslen;
	}
      
      offset += 3;
      typelenres = (struct typelengthres *)&payload[offset];
      typelenres->type = AT_RES;
      typelenres->length = (reallen/4)+1;
      typelenres->reserved = htons(reslen);
      
      offset += 4;

      memcpy(&payload[offset], akadata->res, reslen);

      offset += reslen;

      if (reallen > reslen)
	{
	  for (i=0;i<(reallen-reslen);i++)
	    {
	      payload[offset] = 0x00;
	      offset++;
	    }
	}
    
      typelenres = (struct typelenres *)&payload[offset];
      typelenres->type = AT_MAC;
      typelenres->length = 5;
      typelenres->reserved = 0x0000;
      offset += 4;

      retsize = offset+16+sizeof(struct eap_header);

      framecpy = Malloc(retsize);
      if (framecpy == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store the "
		       "packet to hash!\n");
	  eapdata->ignore = TRUE;
	  eapdata->decision = EAP_FAIL;
	  return NULL;
	}

      eaphdr->eap_length = htons(retsize);

      memcpy(framecpy, data, retsize);
      debug_printf(DEBUG_AUTHTYPES, "Preframe : \n");
      debug_hex_dump(DEBUG_AUTHTYPES, framecpy, retsize);

      // Zero out the mac.
      memset((uint8_t *)&framecpy[offset+sizeof(struct eap_header)], 0x00, 16);
      debug_printf(DEBUG_AUTHTYPES, "Frame to hash :\n");
      debug_hex_dump(DEBUG_AUTHTYPES, framecpy, retsize);

      HMAC(EVP_sha1(), (uint8_t *)&akadata->K_aut[0], 16, framecpy, retsize,
	   mac_calc, &i);

      FREE(framecpy);
 
      debug_printf(DEBUG_AUTHTYPES, "MAC = ");
      debug_hex_printf(DEBUG_AUTHTYPES, mac_calc, 16);

      memcpy(&payload[offset], mac_calc, 16);
    }
  else
    {
      eapdata->ignore = TRUE;
      eapdata->decision = EAP_FAIL;
      return NULL;
    }

  return data;
}

/************************************************************************
 *
 * Determine if there is keying material available.
 *
 ************************************************************************/
uint8_t eapaka_isKeyAvailable(eap_type_data *eapdata)
{
  struct aka_eaptypedata *akadata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return FALSE;

  akadata = (struct aka_eaptypedata *)eapdata->eap_data;

  if (akadata->keyingMaterial != NULL) return TRUE;

  return FALSE;
}

/************************************************************************
 *
 * Return the keying material.
 *
 ************************************************************************/
uint8_t *eapaka_getKey(eap_type_data *eapdata)
{
  struct aka_eaptypedata *akadata;
  uint8_t *keydata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return FALSE;

  akadata = (struct aka_eaptypedata *)eapdata->eap_data;

  keydata = Malloc(64);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to return key "
		   "data!\n");
      return NULL;
    }

  memcpy(keydata, akadata->keyingMaterial, 64);

  return keydata;
}

/************************************************************************
 *
 * Clean up any resources we used.
 *
 ************************************************************************/
void eapaka_deinit(eap_type_data *eapdata)
{
  struct aka_eaptypedata *mydata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-AKA) Cleaning up!\n");
  mydata = (struct aka_eaptypedata *)eapdata->eap_data;

#ifndef RADIATOR_TEST
  sm_handler_close_sc(&mydata->shdl, &mydata->scntx);
#endif

  FREE(mydata);
}

#endif
