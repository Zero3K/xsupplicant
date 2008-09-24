/**
 * EAP-SIM implementation for Xsupplicant
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapsim.c
 *
 * \author chris@open1x.org
 *
 * \todo Put IPC error events in this file!
 * \todo Add UI provided username/password here.
 * \todo Add support for PIN reprompting.
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/


#ifdef EAP_SIM_ENABLE     // Only build this if it has been enabled.

#ifndef WINDOWS
#include <inttypes.h>
#include <unistd.h>
#else
#include "../../stdintwin.h"
#endif

#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>

#include "xsupconfig.h"
#include "../../context.h"
#include "../../xsup_common.h"
#include "winscard.h"
#include "../../eap_sm.h"
#include "eapsim.h"
#include "sm_handler.h"
#include "sim.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../eap_type_common.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

// On Windows, do_sha1() is also defined in win_cert_handler.c.  Since win_cert_handler.c is
// always included in the Windows builds, and EAP-SIM may not be, we don't build this version
// on Windows.
#ifndef WINDOWS
char *do_sha1(char *tohash, int size)
{
  EVP_MD_CTX ctx;
  char *hash_ret;
  int evp_ret_len;

  if (!xsup_assert((tohash != NULL), "tohash != NULL", FALSE))
    return NULL;

  if (!xsup_assert((size > 0), "size > 0", FALSE))
    return NULL;

  hash_ret = (char *)Malloc(21);  // We should get 20 bytes returned.
  if (hash_ret == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for 'hash_ret' in "
		   "%s().\n", __FUNCTION__);
      return NULL;
    }
 
  EVP_DigestInit(&ctx, EVP_sha1());
  EVP_DigestUpdate(&ctx, tohash, size);
  EVP_DigestFinal(&ctx, hash_ret, (int *)&evp_ret_len);

  if (evp_ret_len != 20)
    {
      debug_printf(DEBUG_NORMAL, "Invalid result from OpenSSL SHA calls! "
		   "(%s:%d)\n", __FUNCTION__, __LINE__);
      return NULL;
    }

  return hash_ret;
}
#endif

int eapsim_get_username(context *ctx)
{
  char *imsi = NULL;  
  char realm[25], card_mode=0;
  char *readers = NULL, *username = NULL;    // username is a reference pointer.  IT SHOULD NEVER BE FREED!
  char *password = NULL;                     // password is a reference pointer.  IT SHOULD NEVER BE FREED!
  struct config_eap_sim *userdata = NULL;
  SCARDCONTEXT sctx;
  SCARDHANDLE hdl;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEBADCONFIG;

  if (!xsup_assert((ctx->prof != NULL), "ctx->prof != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((ctx->prof->method != NULL), "ctx->prof->method != NULL", FALSE))
	  return XEBADCONFIG;

  if (!xsup_assert((ctx->prof->method->method_data != NULL),
	  "ctx->prof->method->method_data != NULL", FALSE))  return XEBADCONFIG;

  userdata = (struct config_eap_sim *)ctx->prof->method->method_data;

  // Initalize our smartcard context, and get ready to authenticate.
  if (sm_handler_init_ctx(&sctx) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize smart card context!\n");
      return XESIMGENERR;
    }

  readers = sm_handler_get_readers(&sctx);
  if (readers == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find any valid card readers!\n");
      return XESIMGENERR;
    }

  // Connect to the smart card.
  if (sm_handler_card_connect(&sctx, &hdl, readers) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
      return XESIMGENERR;
    }

  // Wait for up to 10 seconds for the smartcard to become ready.
  // XXX This is going to need to change.  It will cause problems!
  if (sm_handler_wait_card_ready(&hdl, 10) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready after 10 seconds!\n");
      return XESIMGENERR;
    }

  if (ctx->prof->temp_password != NULL)
  {
	  password = ctx->prof->temp_password;
  }
  else
  {
	  password = userdata->password;

	  if (password == NULL)
	  {
		  debug_printf(DEBUG_NORMAL, "No temporary or stored password is available for EAP-SIM on interface '%s'!\n", ctx->desc);
		  return XEGENERROR;
	  }
  }

  imsi = sm_handler_2g_imsi(&hdl, card_mode, password);
  if (imsi == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error starting smart card, and getting "
		   "IMSI!\n");
      return XESIMGENERR;
    }

  debug_printf(DEBUG_AUTHTYPES, "SIM IMSI : %s\n",imsi);

  FREE(ctx->prof->temp_username);

  ctx->prof->temp_username = (char *)Malloc(256);  
  if (ctx->prof->temp_username == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for identity information!  (%s:%d)\n", __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

  // 'username' is a referential pointer.  It shouldn't be freed!
  username = ctx->prof->temp_username;

  username[0] = '1';  // An IMSI should always start with a 1.
  if (Strncpy(&username[1], 50, imsi, 18) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to overflow a buffer in %s() at %d!\n",
		  __FUNCTION__, __LINE__);
	  return XEMALLOC;
  }

  if (userdata->auto_realm == TRUE)
    {
      memset(&realm, 0x00, 25);
      _snprintf((char *)&realm, 25, "@mnc%c%c%c.mcc%c%c%c.owlan.org",
	      username[4], username[5], username[6], username[1], username[2],
	      username[3]);

      debug_printf(DEBUG_AUTHTYPES, "Realm Portion : %s\n",realm);
      if (Strcat(username, 50, realm) != 0)
		{
			fprintf(stderr, "Refusing to overflow string!\n");
			return XEMALLOC;
		}
    }

  // Close the smartcard, so that we know what state we are in.
  sm_handler_close_sc(&hdl, &sctx);

  FREE(imsi);
  FREE(readers);

  debug_printf(DEBUG_AUTHTYPES, "Username is now : %s\n", username);

  return XENONE;
}

/***********************************************************************
 *
 * Check to see that we are properly configured to do an EAP-SIM
 * authentication.
 *
 ***********************************************************************/
void eapsim_check(eap_type_data *eapdata)
{
  struct config_eap_sim *simconf;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  simconf = (struct config_eap_sim *)eapdata->eap_conf_data;

  if (simconf->password == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No PIN available for EAP-SIM!\n");
      eap_type_common_fail(eapdata);
      return;
    }
}

/***********************************************************************
 *
 * Init EAP-SIM method.
 *
 ***********************************************************************/
uint8_t eapsim_init(eap_type_data *eapdata)
{
  struct eaptypedata *simdata = NULL;
  struct config_eap_sim *userdata = NULL;
  char *imsi;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (eapdata->eap_data == NULL)
    {
      eapdata->eap_data = Malloc(sizeof(struct eaptypedata));
      if (eapdata->eap_data == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
		       "data for EAP-SIM!\n");
	  return FALSE;
	}
    }

  simdata = eapdata->eap_data;

  FREE(simdata->keyingMaterial);

  if (sm_handler_init_ctx(&simdata->scntx) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize smart card context!\n");
      return FALSE;
    }

  simdata->readers = sm_handler_get_readers(&simdata->scntx);
  if (simdata->readers == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find any smart card readers "
		   "attached to the system!\n");
      return FALSE;
    }

  if (sm_handler_card_connect(&simdata->scntx, &simdata->shdl, 
			      simdata->readers) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
      return FALSE;
    }

  // Wait 20 seconds for the smartcard to become ready.
  if (sm_handler_wait_card_ready(&simdata->shdl, 20) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready after 20 "
		   "seconds!\n");
      return FALSE;
    }

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    return FALSE;

  userdata = eapdata->eap_conf_data;

  if (userdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid EAP-SIM configuration!\n");
      return FALSE;
    }

  if (userdata->password == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No PIN available.\n");
      return FALSE;
    }

  imsi = sm_handler_2g_imsi(&simdata->shdl, simdata->card_mode,
			    userdata->password);

  if (userdata->username == NULL)
    {
      userdata->username = imsi;
    }
  else
    {
      FREE(imsi);
    }

  eap_type_common_init_eap_data(eapdata);

  return TRUE;
}

/***********************************************************************
 *
 * Process an EAP-SIM start packet.
 *
 ***********************************************************************/
void eapsim_do_start(eap_type_data *eapdata)
{
  struct eaptypedata *simdata;
  int retval, outptr = 0;
  uint16_t offset = 0, size = 0, value16 = 0;
  struct eap_header *eaphdr;
  struct config_eap_sim *simconf;
  char *username;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  simdata = (struct eaptypedata *)eapdata->eap_data;
  simconf = (struct config_eap_sim *)eapdata->eap_conf_data;

  if (simdata->response_data != NULL)
    {
      debug_printf(DEBUG_NORMAL, "SIM response data was not properly "
                   "deallocated!  Please check the code!\n");
      FREE(simdata->response_data);
    }

  // Allocate some memory for the request.
  simdata->response_data = Malloc(1500);
  if (simdata->response_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store response "
		   "data!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (simconf->username == NULL)
    {
      username = eapdata->ident;
    }
  else
    {
      username = simconf->username;
    }

  retval = sim_build_start(simdata, simdata->response_data, &outptr);
  if (retval != XENONE)
    {
      FREE(simdata->response_data);
      eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "SIM small dump (%d): \n", outptr);
  debug_hex_dump(DEBUG_AUTHTYPES, simdata->response_data, outptr);
  simdata->response_size = outptr;

  offset = sizeof(struct eap_header)+3;

  eaphdr = (struct eap_header *)eapdata->eapReqData;

  size = ntohs(eaphdr->eap_length) - sizeof(struct eap_header);

  while (offset < size)
    {
      switch (eapdata->eapReqData[offset])
	{
	case AT_MAC:
	  debug_printf(DEBUG_NORMAL, "You cannot have an AT_MAC in a Start "
		       "packet!\n");
	  eap_type_common_fail(eapdata);
	  return;

	case AT_ANY_ID_REQ:
	case AT_FULLAUTH_ID_REQ:
	case AT_PERMANENT_ID_REQ:
	  retval = sim_build_fullauth(username, eapdata->eapReqData, &offset,
				      simdata->response_data,
				      &simdata->response_size);
	  if (retval != XENONE)
	    {
	      eap_type_common_fail(eapdata);
	      FREE(simdata->response_data);
	      return;
	    }
	  break;

	case AT_VERSION_LIST:
	  retval = sim_at_version_list(username, simdata, eapdata->eapReqData,
				       &offset, simdata->response_data,
				       &simdata->response_size);
	  if (retval != XENONE)
	    {
	      eap_type_common_fail(eapdata);
	      FREE(simdata->response_data);
	      return;
	    }
	  break;

	default:
	  debug_printf(DEBUG_NORMAL, "Unknown SIM type! (%02X)\n",
		       eapdata->eapReqData[offset]);
	  break;
	}
    }

  value16 = htons(simdata->response_size);
  memcpy(&simdata->response_data[1], &value16, 2);  
}

/***********************************************************************
 *
 * Process an EAP-SIM challenge message.
 *
 ***********************************************************************/
void eapsim_do_challenge(eap_type_data *eapdata)
{
  struct eaptypedata *simdata = NULL;
  int retval = 0;   
  uint16_t offset = 0, size = 0, value16 = 0;
  struct eap_header *eaphdr = NULL;
  struct config_eap_sim *simconf = NULL;
  char *username = NULL;
  uint8_t nsres[16], mac_calc[16], K_int[16];
  struct typelength *typelen = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  simdata = (struct eaptypedata *)eapdata->eap_data;
  simconf = (struct config_eap_sim *)eapdata->eap_conf_data;

  if (simdata->response_data != NULL)
    {
      debug_printf(DEBUG_NORMAL, "SIM response data was not properly "
		   "deallocated!  Please check the code!\n");
      FREE(simdata->response_data);
    }

  // Allocate some memory for the request.
  simdata->response_data = Malloc(1500);
  if (simdata->response_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store response "
                   "data!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (simconf->username == NULL)
    {
      username = eapdata->ident;
    }
  else
    {
      username = simconf->username;
    }

  offset = sizeof(struct eap_header)+3;

  eaphdr = (struct eap_header *)eapdata->eapReqData;

  size = ntohs(eaphdr->eap_length) - sizeof(struct eap_header);

  typelen = (struct typelength *)simdata->response_data;
  typelen->type = SIM_CHALLENGE;
  typelen->length = 3;

  simdata->response_size = sizeof(struct typelength)+1;

  while (offset < size)
    {
      switch (eapdata->eapReqData[offset])
	{
	case AT_RAND:
	  retval = sim_do_at_rand(simdata, username, (uint8_t *)&nsres, 
				  eapdata->eapReqData, &offset,
				  simdata->response_data, 
				  &simdata->response_size, (uint8_t *)&K_int);
	  if (retval != XENONE)
	    {
	      eap_type_common_fail(eapdata);
	      FREE(simdata->response_data);
	      return;
	    }

	case AT_IV:
	  debug_printf(DEBUG_AUTHTYPES, "Got an IV (Not supported)\n");
	  sim_skip_not_implemented(eapdata->eapReqData, &offset);
	  break;

	case AT_ENCR_DATA:
	  debug_printf(DEBUG_AUTHTYPES, "Got an AT_ENCR_DATA (Not supported)"
		       "\n");
	  sim_skip_not_implemented(eapdata->eapReqData, &offset);
	  break;

	case AT_MAC:
	  retval = sim_do_at_mac(eapdata, simdata, 
				 &eapdata->eapReqData[sizeof(struct eap_header)],
				 size, &offset,
				 simdata->response_data, 
				 &simdata->response_size, (uint8_t *)&K_int);
	  if (retval != XENONE)
	    {
	      eap_type_common_fail(eapdata);
	      FREE(simdata->response_data);
	      return;
	    }
	  break;
	}
    }

  if (simdata->workingversion == 1)
    {
      debug_printf(DEBUG_AUTHTYPES, "nsres = ");
      debug_hex_printf(DEBUG_AUTHTYPES, nsres, 12);
      
	  memset(&simdata->response_data[1], 0x00, 2);
      retval = sim_do_v1_response(eapdata, simdata->response_data,
				  &simdata->response_size, (uint8_t *)&nsres,
				  (uint8_t *)&K_int);
      if (retval != XENONE)
	{
	  eap_type_common_fail(eapdata);
	  FREE(simdata->response_data);
	  return;
	}
    }

  value16 = htons(simdata->response_size);
  memcpy(&simdata->response_data[1], &value16, 2);

  eapdata->methodState = DONE;
  eapdata->decision = COND_SUCC;
  eapdata->ignore = FALSE;
}

/***********************************************************************
 *
 * Process an EAP-SIM request message.
 *
 ***********************************************************************/
void eapsim_process(eap_type_data *eapdata)
{
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  if (eapdata->methodState == INIT)
    {
      if (eapsim_init(eapdata) == FALSE)
	{
	  eap_type_common_fail(eapdata);
	  return;
	}
    }

  switch (eapdata->eapReqData[sizeof(struct eap_header)])
    {
    case SIM_START:
      eapsim_do_start(eapdata);
      break;

    case SIM_CHALLENGE:
      eapsim_do_challenge(eapdata);
      break;

    case SIM_NOTIFICATION:
      debug_printf(DEBUG_NORMAL, "Got SIM_NOTIFICATION! (Unsupported)\n");
      break;

    case SIM_REAUTHENTICATION:
      debug_printf(DEBUG_NORMAL, "Got SIM_REAUTHENTICATION! (Unsupported)\n");
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown Sub-Type value! (%d)\n",
		   eapdata->eapReqData[sizeof(struct eap_header)]);
      break;
    }
}

/***********************************************************************
 *
 * Build an EAP-SIM response message.
 *
 ***********************************************************************/
uint8_t *eapsim_buildResp(eap_type_data *eapdata)
{
  struct eaptypedata *simdata = NULL;
  uint8_t *resp_pkt = NULL;
  struct eap_header *eaphdr = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return NULL;
    }

  simdata = (struct eaptypedata *)eapdata->eap_data;

  if (!xsup_assert((simdata->response_data != NULL), "simdata->response_data != NULL", FALSE)) return NULL;

  resp_pkt = Malloc(sizeof(struct eap_header) + simdata->response_size+10);
  if (resp_pkt == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for response "
		   "packet!\n");
      FREE(simdata->response_data);
      return NULL;
    }

  eaphdr = (struct eap_header *)resp_pkt;
  
  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
  eaphdr->eap_length = htons((sizeof(struct eap_header) + simdata->response_size));
  eaphdr->eap_type = EAP_TYPE_SIM;

  memcpy(&resp_pkt[sizeof(struct eap_header)], simdata->response_data,
	 simdata->response_size);

  FREE(simdata->response_data);
  
  return resp_pkt;
}

/***********************************************************************
 *
 * Determine if keying material is available.
 *
 ***********************************************************************/
uint8_t eapsim_isKeyAvailable(eap_type_data *eapdata)
{
  struct eaptypedata *simdata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (eapdata->eap_data == NULL) return FALSE;

  simdata = (struct eaptypedata *)eapdata->eap_data;

  if (simdata->keyingMaterial != NULL) return TRUE;

  return FALSE;
}

/***********************************************************************
 *
 * Return the keying material.
 *
 ***********************************************************************/
uint8_t *eapsim_getKey(eap_type_data *eapdata)
{
  struct eaptypedata *simdata;
  uint8_t *keydata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return FALSE;

  simdata = (struct eaptypedata *)eapdata->eap_data;

  keydata = Malloc(64);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store key "
		   "data!\n");
      return NULL;
    }

  memcpy(keydata, simdata->keyingMaterial, 64);

  return simdata->keyingMaterial;
}

/***********************************************************************
 *
 * Clean up after ourselves.
 *
 ***********************************************************************/
void eapsim_deinit(eap_type_data *eapdata)
{
  FREE(eapdata->eap_data);

  debug_printf(DEBUG_AUTHTYPES, "(EAP-SIM) Deinit.\n");
}

#endif
