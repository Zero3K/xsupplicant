/**
 * The driver function for a Linux application layer EAPOL 
 * implementation
 *
 * \file eapmd5.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <string.h>
#include <stdlib.h>

#include "md5.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"   
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "../../eap_sm.h"
#include "eapmd5.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

#ifndef WINDOWS
#include <strings.h>
#include "src/event_core.h"
#else
#include <winsock2.h>
#include "src/event_core_win.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define MD5_LENGTH    0x10

/*****************************************************
 *
 * Setup to handle MD5 EAP requests
 *
 * This function is called each time we recieve a packet of the EAP type MD5.
 * At a minimum, it should check to make sure it's stub in the structure 
 * exists, and if not, set up any variables it may need.  Since MD5 doesn't
 * have any state that needs to survive successive calls, we don't need to 
 * do anything here.
 *
 *****************************************************/
int eapmd5_setup(eap_type_data *eapdata)
{
  // Do anything special that might be needed for this EAP type to work.
  debug_printf(DEBUG_AUTHTYPES, "Initalized EAP-MD5!\n");

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return XEMALLOC;

  eap_type_common_init_eap_data(eapdata);

  return XENONE;
}

/************************************************************************
 *
 *  Verify the packet is really for MD5.
 *
 ************************************************************************/
void eapmd5_check(eap_type_data *eapdata)
{
  struct eap_header *myeap = NULL;
  struct config_pwd_only *md5conf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eapReqData != NULL), 
		   "eapdata->eapReqData != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }
  
  myeap = (struct eap_header *)eapdata->eapReqData;

  if (myeap == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid packet was passed in to %s!\n",
		   __FUNCTION__);
      eap_type_common_fail(eapdata);
      return;
    }

  if (myeap->eap_code != EAP_REQUEST_PKT)
    {
      debug_printf(DEBUG_NORMAL, "EAP isn't a request packet!?\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (myeap->eap_identifier == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP identifier!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (ntohs(myeap->eap_length) < (17 + sizeof(struct eap_header)))
    {
      debug_printf(DEBUG_NORMAL, "Not enough data for valid EAP method.\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (eapdata->eapReqData[sizeof(struct eap_header)] != MD5_LENGTH)
    {
      debug_printf(DEBUG_NORMAL, "MD5 challenge is greater than 16 bytes!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  md5conf = (struct config_pwd_only *)eapdata->eap_conf_data;

  if (md5conf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid configuration for "
		   "EAP-MD5!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (md5conf->password == NULL)
    {
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
	      debug_printf(DEBUG_NORMAL, "No password available for EAP-MD5!\n");
	      eap_type_common_fail(eapdata);
	      return;
		}

		if (ctx->prof->temp_password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-MD5!\n");
			eap_type_common_fail(eapdata);
			return;
		}
    }
}

/***********************************************************************
 *
 * Process the packet, and pull out the pieces needed to build a 
 * response.
 *
 ***********************************************************************/
void eapmd5_process(eap_type_data *eapdata)
{
  struct eap_header *eaphdr;
  struct config_pwd_only *md5conf;
  uint8_t *challenge;
  uint8_t eapid;
  uint8_t *tohash;
  int tohashlen;
  uint8_t md5_result[16];
  struct MD5Context md5ctx;
  char *password = NULL;
  context *ctx = NULL;
  uint8_t challen = 0;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-MD5) Processing.\n");

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  eapdata->ignore = TRUE;   // Start by assuming we will ignore what came
                            // in.

  challen = eapdata->eapReqData[sizeof(struct eap_header)];
  challenge = Malloc(challen+1);  
  if (challenge == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store EAP MD5"
                   " challenge.\n");
	  ipc_events_malloc_failed(NULL);
      return;
    }

  memcpy(challenge,
	 (uint8_t *)&eapdata->eapReqData[sizeof(struct eap_header)], 
	 challen+1);

  eaphdr = (struct eap_header *)eapdata->eapReqData;

  eapid = eaphdr->eap_identifier;

  md5conf = (struct config_pwd_only *)eapdata->eap_conf_data;

  if (!xsup_assert((md5conf != NULL), "md5conf != NULL", FALSE))
    {
      FREE(challenge);
      return;
    }

	ctx = event_core_get_active_ctx();
	if (ctx == NULL)
	{
      debug_printf(DEBUG_NORMAL, "No password available for EAP-MD5!\n");
      eap_type_common_fail(eapdata);
	  FREE(challenge);
      return;
	}

	if (ctx->prof->temp_password == NULL)
    {
		if (md5conf->password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-MD5!\n");
			eap_type_common_fail(eapdata);
			FREE(challenge);
			return;
		}

		password = _strdup(md5conf->password);
    }
  else
  {
	  password = _strdup(ctx->prof->temp_password);
  }

  tohashlen = (1+challen+strlen(password));
  tohash = (uint8_t *)Malloc(tohashlen);
  if (tohash == NULL)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-MD5) Couldn't allocate memory for "
		   "building hash source!\n");
	  ipc_events_malloc_failed(NULL);
  	  eap_type_common_fail(eapdata);

      FREE(challenge);
	  FREE(password);
      return;
    }

  // Build the information we need to hash. Start with the EAP identifier.
  tohash[0] = eapid;

  // Then, we need the password.
  memcpy(&tohash[1], password, strlen(password));

  // Then the random value sent to us.
  memcpy(&tohash[1+strlen(password)], &challenge[1], challen);

  // Now, run it through the hash routine.
  MD5Init(&md5ctx);
  MD5Update(&md5ctx, tohash, tohashlen);
  MD5Final(&md5_result[0], &md5ctx);

  // We are done with tohash, so free it.
  FREE(tohash);
  FREE(eapdata->eap_data);

  eapdata->eap_data = Malloc(MD5_LENGTH);
  if (eapdata->eap_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store EAP MD5"
                   " challenge.\n");
	  ipc_events_malloc_failed(NULL);
      FREE(challenge);
	  FREE(password);
	  eap_type_common_fail(eapdata);
      return;
    }

  memcpy(eapdata->eap_data, md5_result, MD5_LENGTH);

  eapdata->methodState = DONE;
  eapdata->decision = COND_SUCC;
  eapdata->ignore = FALSE;
  eapdata->credsSent = TRUE;

  FREE(challenge);
  FREE(password);
}

/********************************************************************
 *
 *  Build the response to send back to the authenticator.
 *
 ********************************************************************/
uint8_t *eapmd5_buildResp(eap_type_data *eapdata)
{
  struct eap_header *eaphdr = NULL;
  struct config_pwd_only *md5conf = NULL;
  uint8_t *retdata;
  uint8_t datasize;
  uint8_t reqId;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) 
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL), "eapReqData != NULL", FALSE))
    return NULL;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-MD5) Building Response.\n");

  md5conf = (struct config_pwd_only *)eapdata->eap_conf_data;

  if (!xsup_assert((md5conf != NULL), "md5conf != NULL", FALSE))
    return NULL;

  if (eapdata->eap_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid response data found!\n");
      return NULL;
    }

  if (eapdata->ident == NULL)
    {
      debug_printf(DEBUG_NORMAL, "EAP identity field is NULL!\n");
      debug_printf(DEBUG_NORMAL, "Do you have an Identity defined in your "
		   "configuration file?  (Or, an Inner_ID if this is being "
		   "used as a phase 2 method.)\n");
      eap_type_common_fail(eapdata);
      return NULL;
    }
      
  datasize = (sizeof(struct eap_header)+sizeof(struct md5_values)+
	      strlen(eapdata->ident));

  retdata = Malloc(datasize);
  if (retdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store result "
		   "packet!\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return NULL;
    }

  eaphdr = (struct eap_header *)eapdata->eapReqData;
  reqId = eaphdr->eap_identifier;

  eaphdr = (struct eap_header *)retdata;
  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = reqId;
  eaphdr->eap_length = htons(datasize);
  eaphdr->eap_type = EAP_TYPE_MD5;
  
  // First comes the length.
  retdata[sizeof(struct eap_header)] = MD5_LENGTH;
  memcpy(&retdata[sizeof(struct eap_header)+1], eapdata->eap_data, MD5_LENGTH);
  memcpy(&retdata[sizeof(struct eap_header)+1+MD5_LENGTH],
	 eapdata->ident, strlen(eapdata->ident));

  FREE(eapdata->eap_data);

  eapdata->ignore = FALSE;

  return retdata;
}

/********************************************************************
 *
 *  MD5 doesn't create keying material, so always return FALSE.
 *
 ********************************************************************/
uint8_t eapmd5_isKeyAvailable(eap_type_data *eapdata)
{
  return FALSE;
}

/********************************************************************
 *
 *  No keying material to return.  But, this function should never get
 *  called.  So, if it does, then display an error message.
 *
 ********************************************************************/
uint8_t *eapmd5_getKey(eap_type_data *eapdata)
{
  debug_printf(DEBUG_NORMAL, "A request to get a key from EAP-MD5 was "
	       "generated.  There is something wrong with the EAP "
	       "state machine.\n");
  ipc_events_error(NULL, IPC_EVENT_ERROR_INVALID_KEY_REQUEST, "EAP-MD5");

  return NULL;
}


/*****************************************************************
 *
 * Clean up any memory that we have used.
 *
 *****************************************************************/
void eapmd5_deinit(eap_type_data *eapdata)
{
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  FREE(eapdata->eap_data);
}
