/**
 * EAPOL Function implementations for supplicant
 * 
 * \file eapaka.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/AKA support was funded by Internet
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

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

#include "winscard.h"
#include "xsupconfig.h"
#include "../../context.h"
#include "../../xsup_common.h"
#include "../../eap_sm.h"
#include "eapaka.h"
#include "../sim/eapsim.h"
#include "../sim/sm_handler.h"
#include "../sim/fips.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "aka.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../frame_structs.h"
#include "../../ipc_events_index.h"
#include "../../event_core.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/**
 *  \brief Ask the SIM card what our IMSI is so that it can be used for our username
 *			during the authentication.
 *
 *	@param[in] ctx   The context for the interface that wants to know the AKA IMSI.
 *
 * \retval XENONE on success, anything else is an error.
 **/
int eapaka_get_username(context *ctx)
{
  char *imsi = NULL;  
  char realm[25], card_mode=0;
  char *readers = NULL, *username = NULL;    // 'username' is a reference pointer.  IT SHOULD NEVER BE FREED!
  char *password = NULL;                     // This is only a reference pointer.  IT SHOULD NEVER BE FREED!
  struct config_eap_aka *userdata = NULL;
  SCARDCONTEXT sctx;
  SCARDHANDLE hdl;
  int retval = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEBADCONFIG;

  if (!xsup_assert((ctx->prof != NULL), "ctx->prof != NULL", FALSE)) return XEBADCONFIG;

  if (!xsup_assert((ctx->prof->method != NULL), "ctx->prof->method != NULL", FALSE)) return XEBADCONFIG;

  if (!xsup_assert((ctx->prof->method->method_data != NULL), "ctx->prof->method->method_data != NULL", FALSE)) return XEBADCONFIG;

  userdata = (struct config_eap_aka *)ctx->prof->method->method_data;

  // Initalize our smartcard context, and get ready to authenticate.
  if (sm_handler_init_ctx(&sctx) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize smart card context!\n");
      return XESIMGENERR;
    }

  // Connect to the smart card.
  if (sm_handler_card_connect(&sctx, &hdl, userdata->reader) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
      return XESIMGENERR;
    }

  // Wait for the smartcard to become ready.
  if (sm_handler_wait_card_ready(&hdl, 1) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }

  // Get our password.  It may be in temp_password, or in the configuration.
  if (ctx->prof->temp_password != NULL)
  {
	  password = ctx->prof->temp_password;
  }
  else
  {
	  password = userdata->password;
  }

  retval = sm_handler_3g_imsi(&hdl, card_mode, password, &imsi);
  switch (retval)
  {
  case SM_HANDLER_ERROR_BAD_PIN_MORE_ATTEMPTS:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_BAD_PIN_MORE_ATTEMPTS, NULL);
	  context_disconnect(ctx);
      return FALSE;
	  break;

  case SM_HANDLER_ERROR_BAD_PIN_CARD_BLOCKED:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_BAD_PIN_CARD_BLOCKED, NULL);
	  context_disconnect(ctx);
      return FALSE;
	  break;

  case SM_HANDLER_ERROR_3G_NOT_SUPPORTED:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_3G_NOT_SUPPORTED, NULL);
	  context_disconnect(ctx);
      return FALSE;
	  break;

  case SM_HANDLER_ERROR_NONE:
	  // Do nothing.
	  break;

  default:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_UNKNOWN_SIM_ERROR, NULL);
	  context_disconnect(ctx);
	  return FALSE;
	  break;
  }

  debug_printf(DEBUG_AUTHTYPES, "SIM IMSI (AKA) : %s\n",imsi);

  FREE(ctx->prof->temp_username);
  
  ctx->prof->temp_username = (char *)Malloc(50);  // 50 should be plenty!
  if (ctx->prof->temp_username == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for SIM identity!\n");
      return XEMALLOC;
    }

  // 'username' is a referential pointer!  It should never be freed!
  username = ctx->prof->temp_username;

  username[0] = '0';  // An AKA IMSI should always start with a 0.
  if (Strncpy(&username[1], 50, imsi, 18) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to overflow buffer in %s() at %d!\n",
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
			fprintf(stderr, "Refusing to overflow the string!\n");
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

/**
 * \brief Determine in a PIN is needed.
 *
 * @param[in] ctx   The context for the interface that we want to see if a PIN is required on.
 * @param[in] userdata   The EAP-AKA configuration that will (or already may be) bound to the context.
 *
 * \retval TRUE if a PIN is required
 * \retval FALSE if a PIN is NOT required
 * \retval XE* if an error occurred.
 **/
int eapaka_is_pin_needed(context *ctx, struct config_eap_aka *userdata)
{
  char card_mode=0;
  char *readers = NULL;
  SCARDCONTEXT sctx;
  SCARDHANDLE hdl;
  int retval = 0;

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEBADCONFIG;

  if (!xsup_assert((userdata != NULL), "userdata != NULL", FALSE)) return XEBADCONFIG;

  // Initalize our smartcard context, and get ready to authenticate.
  if (sm_handler_init_ctx(&sctx) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize smart card context!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }

  // Connect to the smart card.
  if (sm_handler_card_connect(&sctx, &hdl, userdata->reader) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }

  if (sm_handler_wait_card_ready(&hdl, 1) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready after 10 seconds!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }


  retval = sm_handler_3g_pin_needed(&hdl, 0);
  if (retval == -1) 
  {
	  retval = FALSE;
  }
  else
  {
	  retval = TRUE;
  }

  // Close the smartcard, so that we know what state we are in.
  sm_handler_close_sc(&hdl, &sctx);

  FREE(readers);

  return retval;
}


/**
 *  \brief Allocate temporary memory, and determine if the card reader is attached.
 *
 **/
int eapaka_setup(eap_type_data *eapdata)
{
  struct aka_eaptypedata *mydata = NULL;
  struct config_eap_aka *userdata = NULL;
  char *imsi = NULL;
  context *ctx = NULL;
  int retval = 0;
  char *password = NULL;
  char *username = NULL;
  char realm[25];

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


  ctx = event_core_get_active_ctx();

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
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }

  // Connect to the smart card.
  if (sm_handler_card_connect(&mydata->scntx, &mydata->shdl, userdata->reader) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error connecting to smart card reader!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }

  if (sm_handler_wait_card_ready(&mydata->shdl, 1) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Smart Card wasn't ready!\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_CARD_NOT_READY, NULL);
      return XESIMGENERR;
    }

  if (ctx->prof->temp_password != NULL)
  {
	  password = ctx->prof->temp_password;
  }
  else
  {
	  password = userdata->password;
  }

  retval = sm_handler_3g_imsi(&mydata->shdl, mydata->card_mode, password, &imsi);
  switch (retval)
  {
  case SM_HANDLER_ERROR_BAD_PIN_MORE_ATTEMPTS:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_BAD_PIN_MORE_ATTEMPTS, NULL);
	  context_disconnect(ctx);
      return FALSE;
	  break;

  case SM_HANDLER_ERROR_BAD_PIN_CARD_BLOCKED:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_BAD_PIN_CARD_BLOCKED, NULL);
	  context_disconnect(ctx);
      return FALSE;
	  break;

  case SM_HANDLER_ERROR_3G_NOT_SUPPORTED:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_3G_NOT_SUPPORTED, NULL);
	  context_disconnect(ctx);
      return FALSE;
	  break;

  case SM_HANDLER_ERROR_NONE:
	  // Do nothing.
	  break;

  default:
	  if (ctx->prof->temp_password != NULL) FREE(ctx->prof->temp_password);  // So we don't attempt to reuse bad credentials.
	  ipc_events_error(ctx, IPC_EVENT_ERROR_UNKNOWN_SIM_ERROR, NULL);
	  context_disconnect(ctx);
	  return FALSE;
	  break;
  }
#endif

  eapdata->credsSent = TRUE;

  if (userdata->username == NULL)
    {
		userdata->username = Malloc(50);
		if (userdata->username == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store IMSI!\n");
			eap_type_common_fail(eapdata);
			return FALSE;
		}

		username = userdata->username;
		username[0] = '0';   // AKA uses 0 to identify it as opposed to EAP-SIM.
		Strncpy(&username[1], 49, imsi, strlen(imsi)+1);
		FREE(imsi);

		if (userdata->auto_realm == TRUE)
		{
			memset(&realm, 0x00, 25);
			_snprintf((char *)&realm, 25, "@mnc%c%c%c.mcc%c%c%c.owlan.org",
				username[4], username[5], username[6], username[1], username[2],
				username[3]);

			debug_printf(DEBUG_AUTHTYPES, "Realm Portion : %s\n",realm);
			if (Strcat(username, 50, realm) != 0)
			{
				fprintf(stderr, "Refusing to overflow the string!\n");
				return XEMALLOC;
			}
		}
    } else {
#ifndef RADIATOR_TEST
      FREE(imsi);
#endif
    }

  eap_type_common_init_eap_data(eapdata);

  return XENONE;
}

/**
 * \brief Determine if we are ready to do EAP-AKA.
 *
 **/
void eapaka_check(eap_type_data *eapdata)
{
  struct config_eap_aka *akaconf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  ctx = event_core_get_active_ctx();
  akaconf = eapdata->eap_conf_data;

  // A PIN may not be needed, so see if we have one, if we don't then see if it is needed.
  if ((akaconf->password == NULL) && (ctx->prof->temp_password == NULL))
  {
	  if (eapaka_is_pin_needed(ctx, akaconf) == TRUE)
	  {
		  debug_printf(DEBUG_NORMAL, "No PIN available for EAP-AKA.\n");
		  ipc_events_error(ctx, IPC_EVENT_ERROR_NO_PIN, NULL);
		  eap_type_common_fail(eapdata);
		  context_disconnect(ctx);
		  return;
	  }
  }

  if (eapdata->methodState == INIT)
  {
	  if (eapaka_setup(eapdata) != XENONE)
	    {
	      eap_type_common_fail(eapdata);
	      return;
	    }
  }
}

/**
 * \brief Process an EAP-AKA identity message.
 *
 *  The value passed in to eappayload should be the first byte following
 *  the challenge/response identifier.
 *
 **/
void eapaka_do_identity(eap_type_data *eapdata, uint8_t *eappayload, 
			 uint16_t size)
{
  uint16_t packet_offset = 0;
  int retval = XENONE;
  struct aka_eaptypedata *aka = NULL;
  struct config_eap_aka *akaconf = NULL;

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

  debug_printf(DEBUG_AUTHTYPES, "Packet dump :\n");
  debug_hex_dump(DEBUG_AUTHTYPES, eappayload, size);

  while (packet_offset < size)
    {
      switch (eappayload[packet_offset])
		{
		  case AT_ANY_ID_REQ:
		  case AT_IDENTITY:
		  case AT_FULLAUTH_ID_REQ:
		  case AT_PERMANENT_ID_REQ:
			debug_printf(DEBUG_AUTHTYPES, "ID request %d.\n", eappayload[packet_offset]);
			retval = aka_do_at_identity(aka, eappayload, &packet_offset);
			if (retval != XENONE) return;
			break;

		  default:
			  debug_printf(DEBUG_NORMAL, "Unknown message in AKA identity request!\n");
			  eap_type_common_fail(eapdata);
			  return;
		}
    }
}

/**
 * \brief Process an AKA Notification message.
 *
 **/
void eapaka_do_notification(eap_type_data *eapdata, uint8_t *eappayload, 
			 uint16_t size)
{
  uint16_t packet_offset = 0;
  int retval = XENONE;
  struct aka_eaptypedata *aka = NULL;
  struct config_eap_aka *akaconf = NULL;
  struct typelengthres *tlr = NULL;
  context *ctx = NULL;
  char error_str[10];

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

  debug_printf(DEBUG_AUTHTYPES, "Inner dump : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, eappayload, size);

  packet_offset += 3;  // To get past the 2 reserved bytes and outer type.
  tlr = (struct typelengthres *)&eappayload[packet_offset];

  memset(&error_str, 0x00, sizeof(error_str));
  sprintf(&error_str, "%d", ntohs(tlr->reserved));

  switch (ntohs(tlr->reserved))
  {
  case GENERAL_FAILURE_POST_AUTH:
	  debug_printf(DEBUG_NORMAL, "[EAP-AKA] General failure after authentication.\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_NOTIFICATION, error_str);
	  eap_type_common_fail(eapdata);
	  break;

  case GENERAL_FAILURE_PRE_AUTH: 
	  debug_printf(DEBUG_NORMAL, "[EAP-AKA] General failure.\n");
	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_NOTIFICATION, error_str);
	  eap_type_common_fail(eapdata);
	  break;

  case USER_AUTHENTICATED:
	  debug_printf(DEBUG_NORMAL, "[EAP-AKA] Success.  User has been successfully authenticated.\n");
	  return;
	  break;

  case USER_DENIED:
	  debug_printf(DEBUG_NORMAL, "[EAP-AKA] User has been temporarily denied access to the requested service.\n");
  	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_NOTIFICATION, error_str);
	  eap_type_common_fail(eapdata);
	  break;
	  
  case USER_NO_SUBSCRIPTION:
	  debug_printf(DEBUG_NORMAL, "[EAP-AKA] User has not subscribed to the requested service.\n");
  	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_NOTIFICATION, error_str);
	  eap_type_common_fail(eapdata);
	  break;
	  
  default:
	  debug_printf(DEBUG_NORMAL, "Unknown AKA notification value (%d).  Assuming failure.\n", ntohs(tlr->reserved));
  	  ipc_events_error(ctx, IPC_EVENT_ERROR_SIM_NOTIFICATION, error_str);
	  eap_type_common_fail(eapdata);
	  break;
  }

	ctx = event_core_get_active_ctx();
	context_disconnect(ctx);
}

/**
 * \brief Process an EAP-AKA challenge message.
 *
 *  The value passed in to eappayload should be the first byte following
 *  the challenge/response identifier.
 *
 **/
void eapaka_do_challenge(eap_type_data *eapdata, uint8_t *eappayload, 
			 uint16_t size)
{
  uint16_t packet_offset = 0;
  int retval = XENONE;
  struct aka_eaptypedata *aka = NULL;
  struct config_eap_aka *akaconf = NULL;
  context *ctx = NULL;

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

  debug_printf(DEBUG_AUTHTYPES, "Inner dump : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, eappayload, size);

  packet_offset += 3;  // To get past the 2 reserved bytes and outer type.

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

	case AT_ENCR_DATA:
		debug_printf(DEBUG_AUTHTYPES, "Got an AT_ENCR_DATA (Not supported)\n");
		aka_skip_not_implemented(eappayload, &packet_offset);
		break;

	case AT_CHECKCODE:
		debug_printf(DEBUG_AUTHTYPES, "Got an AT_CHECKCODE (Not supported)\n");
		aka_skip_not_implemented(eappayload, &packet_offset);
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
	    } else if (retval == XESIMBADMAC)
		{
			debug_printf(DEBUG_NORMAL, "MAC check failure in EAP-AKA.\n");
			eap_type_common_fail(eapdata);

			ctx = event_core_get_active_ctx();
			context_disconnect(ctx);
			return;
		} else if (retval != XENONE) return;
	  break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown AKA inner type %d!  Skipping.\n", eappayload[packet_offset]);
		aka_skip_not_implemented(eappayload, &packet_offset);
		break;
	}
    }

}

/**
 * \brief Process an AKA request.
 *
 **/
void eapaka_process(eap_type_data *eapdata)
{
  uint8_t *eappayload = NULL, chal_type = 0;
  struct config_eap_aka *akaconf = NULL;
  struct aka_eaptypedata *akadata = NULL;
  uint16_t size = 0;
  
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
  size = eap_type_common_get_eap_length(eapdata->eapReqData);

  // Subtract the header.
  size -= sizeof(struct eap_header);

  switch (eappayload[0])
    {
    case AKA_IDENTITY:
      debug_printf(DEBUG_AUTHTYPES, "Got AKA_IDENTITY!\n");
      eapaka_do_identity(eapdata, (uint8_t *)&eappayload[3], (size-5));  // -5 since we already consumed [0] through [3].
      chal_type = AKA_IDENTITY;
	  akadata->chal_type = AKA_IDENTITY;
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
      eapaka_do_notification(eapdata, (uint8_t *)&eappayload[3], (size-5));  // -5 since we already consumed [0] through [3].
      chal_type = AKA_NOTIFICATION;
	  akadata->chal_type = AKA_NOTIFICATION;
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
      eapaka_do_challenge(eapdata, (uint8_t *)&eappayload[0], size); 
	  akadata->chal_type = AKA_CHALLENGE;
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

/**
 * \brief Build an AKA response.
 *
 **/
uint8_t *eapaka_buildResp(eap_type_data *eapdata)
{
  uint16_t reslen = 0, reallen = 0;
  struct config_eap_aka *akaconf = NULL;
  struct aka_eaptypedata *akadata = NULL;
  struct typelength *typelen = NULL;
  struct typelengthres *typelenres = NULL;
  uint8_t reqId = 0, mac_calc[20];
  struct eap_header *eaphdr = NULL;
  uint8_t *payload = NULL, *framecpy = NULL, *data = NULL;
  uint16_t offset = 0, i = 0, retsize = 0;

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

  if (akadata->chal_type == AKA_IDENTITY)
  {
	  framecpy = aka_resp_identity(akadata, eap_type_common_get_eap_reqid(eapdata->eapReqData), eapdata->ident);
	  eapdata->ignore = FALSE;
	  eapdata->methodState = CONT;
	  return framecpy;
  }
  else if (akadata->chal_type == AKA_CHALLENGE)
    {
      if (akadata->sync_fail == TRUE)
		{
			// Make sure we don't do this again. ;)
			akadata->sync_fail = FALSE;

		  // Handle a sync failure response.
		  return aka_do_sync_fail(akadata, eap_type_common_get_eap_reqid(eapdata->eapReqData));
		}

      reqId = eap_type_common_get_eap_reqid(eapdata->eapReqData);

      data = Malloc(1024);  // Should be enough to hold our response.
      if (data ==  NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
		       "response data in %s()!\n", __FUNCTION__);
		  return NULL;
		}

      eaphdr = (struct eap_header *)data;

      eaphdr->eap_code = EAP_RESPONSE_PKT;
      eaphdr->eap_identifier = reqId;
      eaphdr->eap_type = EAP_TYPE_AKA;

      payload = &data[sizeof(struct eap_header)];

      offset = 0;
      typelenres = (struct typelengthres *)payload;
      typelenres->type = AKA_CHALLENGE;

      reslen = akadata->reslen;
      if ((reslen % 4) != 0)
		{
		  reallen = reslen + (reslen % 4);
		}
	    else
		{
		  reallen = reslen;
		}
      
      offset += sizeof(struct typelengthres)-1;

      typelenres = (struct typelengthres *)&payload[offset];
      typelenres->type = AT_RES;
      typelenres->length = (reallen/4)+1;
      typelenres->reserved = htons(reslen*8);		// Size in bits.
      
      offset += sizeof(struct typelengthres);

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
    
      typelenres = (struct typelengthres *)&payload[offset];
      typelenres->type = AT_MAC;
      typelenres->length = 5;
      typelenres->reserved = 0x0000;
      offset += sizeof(struct typelengthres);

      retsize = offset+16+sizeof(struct eap_header);

      framecpy = Malloc(retsize+1);
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

      HMAC(EVP_sha1(), akadata->K_aut, 16, framecpy, retsize,
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

/**
 * \brief Determine if there is keying material available.
 *
 **/
uint8_t eapaka_isKeyAvailable(eap_type_data *eapdata)
{
  struct aka_eaptypedata *akadata = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return FALSE;

  akadata = (struct aka_eaptypedata *)eapdata->eap_data;

  if (akadata->keyingMaterial != NULL) return TRUE;

  return FALSE;
}

/**
 * \brief Return the keying material.
 *
 **/
uint8_t *eapaka_getKey(eap_type_data *eapdata)
{
  struct aka_eaptypedata *akadata = NULL;
  uint8_t *keydata = NULL;

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

/**
 * \brief Clean up any resources we used.
 *
 **/
void eapaka_deinit(eap_type_data *eapdata)
{
  struct aka_eaptypedata *mydata = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-AKA) Cleaning up!\n");
  mydata = (struct aka_eaptypedata *)eapdata->eap_data;

#ifndef RADIATOR_TEST
  sm_handler_close_sc(&mydata->shdl, &mydata->scntx);
#endif

  FREE(mydata);
  eapdata->eap_data = NULL;
}

#endif
