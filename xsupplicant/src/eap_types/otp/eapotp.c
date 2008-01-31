/**
 * EAP One Time Password (OTP/GTC) implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapotp.c
 *
 * \author chris@open1x.org
 *
 **/

#include <openssl/ssl.h>
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#else
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../eap_sm.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "eapotp.h"
#include "../../xsup_common.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

static uint8_t new_response = FALSE;

/*****************************************************
 *
 * Setup to handle OTP EAP requests
 *
 *****************************************************/
int eapotp_init(eap_type_data *eapdata)
{
  // Do anything special that might be needed for this EAP type to work.
  debug_printf(DEBUG_AUTHTYPES, "Initalized EAP-OTP!\n");

  eap_type_common_init_eap_data(eapdata);

  return XENONE;
}

/*****************************************************
 *
 * Check to see if we are prepared to do an OTP authentication.
 *
 *****************************************************/
void eapotp_check(eap_type_data *eapdata)
{
  // For GTC and OTP, there really isn't anything to check.
}

/*****************************************************
 *
 * Respond to an OTP request.
 *
 *****************************************************/
uint8_t *eapotp_buildResp(eap_type_data *eapdata)
{
  struct eap_header *eaphdr;
  struct config_pwd_only *otpconf;
  uint8_t *retdata;
  uint16_t datasize, respofs = 0;
  uint8_t reqId;
  uint8_t eapType;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL), "eapReqData != NULL", 
		   FALSE))
    return NULL;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP/GTC) Building response.\n");

  otpconf = (struct config_pwd_only *)eapdata->eap_conf_data;

  if (!xsup_assert((otpconf != NULL), "otpconf != NULL", FALSE))
    return NULL;

  if (new_response == TRUE)
    {
      datasize = sizeof(struct eap_header) + strlen(RESPONSE_TEXT) + 
	+strlen(eapdata->ident) + strlen(otpconf->password) + 1;
    }
  else
    {
      datasize = sizeof(struct eap_header) + strlen(otpconf->password) + 1;
    }

  retdata = Malloc(datasize);
  if (retdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store result "
		   "data.\n");
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  eaphdr = (struct eap_header *)eapdata->eapReqData;
  reqId = eaphdr->eap_identifier;
  eapType = eaphdr->eap_type;

  eaphdr = (struct eap_header *)retdata;
  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = reqId;

#ifdef WINDOWS
  eaphdr->eap_length = htons(datasize-1);  // The windows strcpy_s puts a null at the end of the string, but we don't want to send that.
#else
  eaphdr->eap_length = htons(datasize);
#endif
  eaphdr->eap_type = eapType;

  respofs = sizeof(struct eap_header);

  if (new_response == TRUE)
    {
      if (xsup_common_strcpy((char *)&retdata[respofs], (datasize - respofs), RESPONSE_TEXT) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Attempt to overflow a buffer in %s() at %d!\n",
				__FUNCTION__, __LINE__);
		  return NULL;
	  }

      respofs += strlen(RESPONSE_TEXT);
      if (xsup_common_strcpy((char *)&retdata[respofs], (datasize - respofs), eapdata->ident) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Attempt to overflow a buffer in %s() at %d!\n",
			  __FUNCTION__, __LINE__);
		  return NULL;
	  }

      respofs += strlen(eapdata->ident);
      retdata[respofs] = 0x00;
      respofs++;
    }

  // Then, copy the response.
  if (xsup_common_strcpy((char *)&retdata[respofs], (datasize - respofs), otpconf->password) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to overflow a buffer in %s() at %d!\n",
		  __FUNCTION__, __LINE__);
	  return NULL;
  }

  return retdata;
}

/*****************************************************
 *
 * Process OTP EAP Requests
 *
 ******************************************************/
void eapotp_process(eap_type_data *eapdata)
{
  char *otp_chal;
  struct config_pwd_only *userdata;
  uint16_t eaplen;
  struct eap_header *header;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP/GTC) Processing.\n");
  
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eapReqData != NULL), 
		   "eapdata->eapReqData != NULL", FALSE))
    return;

  eapdata->decision = MAY_CONT;
       
  userdata = eapdata->eap_conf_data;

  if (!xsup_assert((userdata != NULL), "userdata != NULL", FALSE))
    return;

  header = (struct eap_header *)eapdata->eapReqData;

  eaplen = ntohs(header->eap_length);

  // Allocating 'eaplen' will result in a buffer that is a bit bigger than
  // we really need, but we will be deallocating it shortly. ;)
  otp_chal = (char *)Malloc(eaplen+1);
  if (otp_chal == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for OTP/GTC "
		   "challenge!\n");
	  ipc_events_malloc_failed(NULL);
      return;
    }
  
  memcpy(otp_chal, &eapdata->eapReqData[sizeof(struct eap_header)], 
	 eaplen - sizeof(struct eap_header));
  debug_printf(DEBUG_AUTHTYPES, "(GTC/OTP) Challenge : %s\n",otp_chal);

  if (strncmp(CHALLENGE_TEXT, otp_chal, strlen(CHALLENGE_TEXT)) == 0)
    {
      debug_printf(DEBUG_AUTHTYPES, "Will use new response method!\n");
      new_response = TRUE;
    }
  
  if (userdata->password == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No password available for EAP-GTC/OTP! (Trying to request one.)\n");
	  if (ipc_events_request_eap_upwd("EAP-GTC", otp_chal) != IPC_SUCCESS)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't request password from UI!  Failing.\n");
		  eap_type_common_fail(eapdata);
	      FREE(otp_chal);
	  }
	  else
	  {
		  eapdata->ignore = TRUE;       // Don't do anything just yet.
		  eapdata->methodState = CONT;
		  eapdata->decision = COND_SUCC;  // We may be able to succeed.
	  }
      return;
    }
  
  // Otherwise, we are basically done.
  FREE(otp_chal);

  eapdata->methodState = DONE;
  eapdata->decision = COND_SUCC;
}

/*******************************************************
 *
 * Return any keying material that we may have.
 *
 *******************************************************/
uint8_t eapotp_isKeyAvailable(eap_type_data *eapdata)
{
  return FALSE;   // No keys to return (ever)
}

/*******************************************************
 *
 * Stub for key returning function.
 *
 *******************************************************/
uint8_t *eapotp_getKey(eap_type_data *eapdata)
{
  debug_printf(DEBUG_NORMAL, "There is an error in your build of Xsupplicant!"
	       "\n");
  ipc_events_error(NULL, IPC_EVENT_ERROR_INVALID_KEY_REQUEST, NULL);
  return NULL;
}

/*******************************************************
 *
 * Clean up after ourselves.  This will get called when we get a packet that
 * needs to be processed requests a different EAP type.  It will also be 
 * called on termination of the program.
 *
 *******************************************************/
void eapotp_deinit(eap_type_data *eapdata)
{
  // Clean up after ourselves.
  debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP) Cleaning up.\n");
}

