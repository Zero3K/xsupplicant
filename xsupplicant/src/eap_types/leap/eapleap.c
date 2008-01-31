/**
 * LEAP implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapleap.c
 *
 * \author Marios Karagiannopoulos (marios@master.math.upatras.gr)
 *
 * Modified to support dynamic keying by Chris Hessing, with help from
 * Gilbert Goodwill.
 **/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef WINDOWS
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "src/xsup_err.h"
#include "src/frame_structs.h"
#include "src/eap_sm.h"
#include "eapleap.h"
#include "leapmd4.h"
#include "src/eap_types/mschapv2/mschapv2.h"
#include "src/ipc_callout.h"
#include "src/xsup_ipc.h"
#include "src/eap_types/eap_type_common.h"
#include "src/ipc_events.h"
#include "src/ipc_events_index.h"

#ifdef WINDOWS
#include "src/event_core_win.h"
#else
#include "src/event_core.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define LEAP_LENGTH    0x08

/**
 *  Convert a regular ASCII password in to a Unicode password, and generate
 *  an MD4 hash of it.
 **/
static void ntPwdHash(unsigned char *MD4Hash, char *password) 
{
    char unicodePass[513];
    char passLen;
    int i;

    if (!xsup_assert((MD4Hash != NULL), "MD4Hash != NULL", FALSE))
      return;

    if (!xsup_assert((password != NULL), "password != NULL", FALSE))
      return;

    /* Microsoft passwords are unicode.  Convert plain text password
       to unicode by inserting a zero every other byte */
    passLen = strlen(password);
    for (i = 0; i < passLen; i++) {
        unicodePass[2 * i] = password[i];
        unicodePass[2 * i + 1] = 0;
    }
    /* Encrypt plain text password to a 16-byte MD4 hash */
    md4_calc(MD4Hash, (uint8_t *) unicodePass, passLen * 2);
}

void leap_mschap(char * password, char * response, uint8_t *apc) 
{
    unsigned char MD4Hash[16], MD4HashHash[16];

    if (!xsup_assert((password != NULL), "password != NULL", FALSE))
      return;

    if (!xsup_assert((response != NULL), "response != NULL", FALSE))
      return;

    ntPwdHash(MD4Hash, password);
    md4_calc(MD4HashHash, MD4Hash, 16);
    ChallengeResponse((char *)apc, (char *) MD4HashHash, response);
}


/**
 * Setup to handle LEAP EAP requests
 *
 * This function is called when we receive the first packet of a LEAP 
 * authentication request.  At a minimum, it should check to make sure it's
 * stub in the structure exists, and if not, set up any varliables it may need.
 *
 **/
int eapleap_init(eap_type_data *eapdata)
{
  struct leap_data *mydata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return XEMALLOC;

  mydata = (struct leap_data *)Malloc(sizeof(struct leap_data));
  if (mydata == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Cannot allocate memory in %s()!\n",
		   __FUNCTION__);
	  ipc_events_malloc_failed(NULL);
      return XEMALLOC;
    }

  FREE(mydata->keyingMaterial);

  mydata->eapsuccess = FALSE;

  if (eapdata->eap_data != NULL)
    {
      eapleap_deinit(eapdata);
    }

  eap_type_common_init_eap_data(eapdata);

  eapdata->eap_data = mydata;
 
  return XENONE;
}

/**
 *  Check to make sure we have everything we need to do a LEAP authentication.
 **/
void eapleap_check(eap_type_data *eapdata)
{
  struct config_pwd_only *leapconf = NULL;
  struct leap_data *leapdata = NULL;
  context *ctx = NULL;
  
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "(LEAP) Checking..\n");

  if (eapdata->methodState == INIT)
    {
      if (eapleap_init(eapdata) != XENONE)
        {
          eap_type_common_fail(eapdata);
          return;
        }
    }

  leapconf = (struct config_pwd_only *)eapdata->eap_conf_data;

  leapdata = (struct leap_data *)eapdata->eap_data;

  FREE(leapdata->password);

	ctx = event_core_get_active_ctx();
	if (ctx == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No password available for LEAP!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	if (ctx->prof->temp_password == NULL)
    {
		if (leapconf->password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for LEAP!\n");
			eap_type_common_fail(eapdata);
			return;
		}
		else
		{
			leapdata->password = _strdup(leapconf->password);
		}
    }
  else
  {
	  leapdata->password = _strdup(ctx->prof->temp_password);
  }

}

/**
 * Process an EAP Request Packet that contains LEAP.
 **/
void eapleap_request_pkt(eap_type_data *eapdata)
{
  struct leap_data *leapdata = NULL;
  struct config_pwd_only *leapconf;
  uint8_t chall_response[24];
  
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

  leapconf = (struct config_pwd_only *)eapdata->eap_conf_data;

  leapdata = (struct leap_data *)eapdata->eap_data;

  leapdata->eapsuccess = FALSE;

  leapdata->leapchallenges = (struct leap_challenges *)Malloc(sizeof(struct leap_challenges));
  if (leapdata->leapchallenges == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store LEAP "
		   "challenge data.\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return;
    }

  leapdata->leaprequest = (struct leap_requests *)Malloc(sizeof(struct leap_requests));
  if (leapdata->leaprequest == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store LEAP "
		   "request data!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  // store Peer challenge
  memcpy(leapdata->leaprequest, 
	 &eapdata->eapReqData[sizeof(struct eap_header)],
	 sizeof(struct leap_requests));

  memcpy(leapdata->leapchallenges->pc, leapdata->leaprequest->randval, 8);

  if (leapdata->leaprequest->count != LEAP_LENGTH)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-LEAP) Incorrect length for LEAP "
		   "random value!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  memset(chall_response, 0x00, 24);

  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Incoming Peer Challenge Random "
	       "Value (Length = %d) : ", leapdata->leaprequest->count);
  debug_hex_printf(DEBUG_AUTHTYPES, leapdata->leaprequest->randval,
		   leapdata->leaprequest->count);

  if (!xsup_assert((leapdata->password != NULL), "leapdata->password != NULL",
		   FALSE))
    {
      debug_printf(DEBUG_NORMAL, "LEAP doesn't have a valid password!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  NtChallengeResponse((char *)leapdata->leapchallenges->pc, leapdata->password,
		      (char *)&chall_response, 0);

  // Store peer response.
  memcpy(leapdata->leapchallenges->pr, chall_response, 24);

  if (eapdata->ident == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid username available!\n");
      debug_printf(DEBUG_NORMAL, "Did you remember to specify an Identity "
		   "setting in the configuration file?\n");
      eap_type_common_fail(eapdata);
      return;
    }

  leapdata->result_size = 24+3+strlen(eapdata->ident)+1;
  leapdata->result = Malloc(leapdata->result_size);
  if (leapdata->result == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store LEAP "
		   "response!\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return;
    }

  // Construct the LEAP response sub fields packet
  // let's start with the version number (LEAP subfield)

  // byte 0: Version
  // byte 1: Unused - Reserved
  // byte 2: Count
  // byte 3..26: MS-CHAP Challenge Response
  // byte 27..m: username
  leapdata->result[0] = 0x01;
  leapdata->result[1] = 0x00; // Reserved - Unused
  leapdata->result[2] = 24;   // Count

  // Include MSCHAP Challenge response in the built packet.
  memcpy(&leapdata->result[3], chall_response, 24);

  // Include username in the built packet
  memcpy(&leapdata->result[24+3], eapdata->ident, strlen(eapdata->ident)+1);

  leapdata->eaptype = EAP_RESPONSE_PKT;

  eapdata->ignore = FALSE;
  eapdata->methodState = MAY_CONT;
}

/**
 * Process an EAP Response Packet that contains LEAP.
 **/
void eapleap_response_pkt(eap_type_data *eapdata)
{
  struct leap_data *leapdata = NULL;
  struct leap_responses *leapresponse = NULL;
  uint8_t *challenge_response_got;
  uint8_t challenge_response_expected[24];
  struct config_pwd_only *leapconf;
  uint8_t MD4Hash[16], MD4HashHash[16], MasterKey[16];

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
  
  leapconf = (struct config_pwd_only *)eapdata->eap_conf_data;

  leapdata = (struct leap_data *)eapdata->eap_data;

  leapresponse = (struct leap_responses *)&eapdata->eapReqData[sizeof(struct eap_header)];
  
  challenge_response_got = Malloc(leapresponse->count+1);
  if (challenge_response_got == NULL)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-LEAP) challenge_response_got is NULL"
		   " after malloc!\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return;
    }

  memcpy(challenge_response_got, &leapresponse->randval, leapresponse->count);

  // store AP response.
  memcpy(leapdata->leapchallenges->apr, leapresponse->randval, 24);

  // Let's contstruct the expected one.
  memset(challenge_response_expected, 0x00, 24);

  // Calculate the 24 bytes MS-CHAP Challenge Response
  leap_mschap(leapdata->password, (char *)&challenge_response_expected,
	      leapdata->leapchallenges->apc);
  
  if (memcmp(challenge_response_got, challenge_response_expected, 24) == 0)
    {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) AP Challenge Response got is "
		   "valid!\n");
      leapdata->eapsuccess = TRUE;
    }
  else
    {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) AP Challenge Response got is "
		   "NOT valid!\n");
    }

  FREE(challenge_response_got);

  // We were successful, so generate keying material.
  ntPwdHash(MD4Hash, leapdata->password);
  md4_calc(MD4HashHash, MD4Hash, 16);
  debug_printf(DEBUG_AUTHTYPES, "leap_session_key : ");
  debug_hex_printf(DEBUG_AUTHTYPES, MD4HashHash, 16);

  GetMasterLEAPKey((char *)&MD4HashHash, (char *)leapdata->leapchallenges->apc,
		   (char *)leapdata->leapchallenges->apr, 
		   (char *)leapdata->leapchallenges->pc, 
		   (char *)leapdata->leapchallenges->pr,
		   (char *)&MasterKey);

  debug_printf(DEBUG_AUTHTYPES, "Master LEAP Key : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)&MasterKey, 16);

  // Finally, populate our keying material.
  FREE(leapdata->keyingMaterial);
  
  leapdata->keyingMaterial = Malloc(64);
  if (leapdata->keyingMaterial == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store keying "
		   "material!\n");
	  ipc_events_malloc_failed(NULL);
      return;
    }

  memcpy(&leapdata->keyingMaterial[32], &MasterKey, 16);
  memcpy(leapdata->keyingMaterial, &MasterKey, 16);

  leapdata->eaptype = EAP_REQUEST_PKT;
  eapdata->methodState = DONE;
  eapdata->ignore = FALSE;
  eapdata->decision = UNCOND_SUCC;
  eapdata->altAccept = TRUE;
}

/**
 * Process an EAP Success Packet during a LEAP conversation.
 **/
void eapleap_success_pkt(eap_type_data *eapdata)
{
  struct leap_data *leapdata = NULL;
  uint8_t chall_response[17];
  struct config_pwd_only *leapconf;

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

  leapconf = (struct config_pwd_only *)eapdata->eap_conf_data;

  if (eapdata->ident == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid username available!\n");
      debug_printf(DEBUG_NORMAL, "Did you remember to specify an Identity in "
		   "the configuration file?\n");
      eap_type_common_fail(eapdata);
      return;
    }

  leapdata = (struct leap_data *)eapdata->eap_data;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Got EAP-SUCCESS\n");
  memset(&chall_response, 0x00, 8);
  NtChallengeResponse((char *)leapdata->leaprequest->randval, 
		      leapdata->password,
		      (char *)&chall_response, 0);

  GenerateNTResponse((char *)leapdata->leapchallenges->pr, 
		     (char *)leapdata->leapchallenges->pc,
		     eapdata->ident, leapdata->password, 
		     (char *)&chall_response, 0);

  // store AP challenge
  memcpy(&leapdata->leapchallenges->apc, chall_response, 8);
  
  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) GenerateNTResponse Calculated "
	       ": ");
  debug_hex_printf(DEBUG_AUTHTYPES, chall_response, 8);
  
  leapdata->result_size = 8+3+strlen(eapdata->ident)+1;
  leapdata->result = Malloc(leapdata->result_size);
  if (leapdata->result == NULL)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-LEAP) Couldn't allocate memory to store"
		   " success response!\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return;
    }

  // Construct the LEAP request sub fields packet
  // let's start with the version number (LEAP subfield)

  // byte 0: Version
  // byte 1: Unused - Reserved
  // byte 2: Count
  // byte 3..10: MS-CHAP Nt Challenge Response
  // byte 11..m: username

  leapdata->result[0] = 0x01;
  leapdata->result[1] = 0x00;  // Reserved - Unused
  leapdata->result[2] = 8;     // Count

  // Include MSCHAP Challenge response in the built packet
  memcpy(&leapdata->result[3], chall_response, 8);
  
  // include username in the built packet.
  memcpy(&leapdata->result[8+3], eapdata->ident, strlen(eapdata->ident)+1);

  // Store the new random value to leapdata for further validation of the
  // AP response!
  memcpy(&leapdata->leaprequest->randval[0], chall_response, 8);

  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Request packet for mutual "
	       "authentication built!\n");

  leapdata->eaptype = EAP_REQUEST_PKT;

  eapdata->ignore = FALSE;
  eapdata->methodState = MAY_CONT;
}

/**
 *  Process a LEAP request.
 **/
void eapleap_process(eap_type_data *eapdata)
{
  struct eap_header *eaphdr;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(LEAP) Processing.\n");

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  // Since LEAP is a weird protocol, we will get EAP requests, responses,
  // and successes.  So, we need to check for each type, and process them
  // as needed.
  eaphdr = (struct eap_header *)eapdata->eapReqData;

  switch (eaphdr->eap_code)
    {
    case EAP_REQUEST_PKT:
      eapleap_request_pkt(eapdata);
      break;

    case EAP_SUCCESS_PKT:
      eapleap_success_pkt(eapdata);
      break;

    case EAP_RESPONSE_PKT:
      eapleap_response_pkt(eapdata);
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown EAP packet type!  (%02X)\n",
		   eaphdr->eap_code);
      break;
    }
}

/**
 *  Build a LEAP response.
 **/
uint8_t *eapleap_buildResp(eap_type_data *eapdata)
{
  uint8_t *response;
  struct leap_data *leapdata;
  struct eap_header *eaphdr;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return NULL;
    }

  leapdata = (struct leap_data *)eapdata->eap_data;

  if (leapdata->result == NULL)
    {
      if (eapdata->decision != UNCOND_SUCC)
	{
	  debug_printf(DEBUG_NORMAL, "LEAP had nothing to send, but didn't "
		       "seem to signal the state machine correctly?\n");
	  eap_type_common_fail(eapdata);
	}
      eapdata->ignore = TRUE;
      return NULL;
    }

  // Otherwise, we need to build an EAP header, and send things on.
  response = Malloc(leapdata->result_size + sizeof(struct eap_header));
  if (response == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to build response "
		   "packet!\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return NULL;
    }

  eaphdr = (struct eap_header *)response;

  switch (leapdata->eaptype)
    {
    case EAP_SUCCESS_PKT:
      // Build a success packet to send to the AP.
      eaphdr->eap_code = leapdata->eaptype;
      eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
      eaphdr->eap_length = htons(sizeof(struct eap_header));
      eaphdr->eap_type = EAP_SUCCESS_PKT;
      break;

    case EAP_REQUEST_PKT:
    case EAP_RESPONSE_PKT:
      // Build a normal EAP packet to send to the AP.
      eaphdr->eap_code = leapdata->eaptype;
      eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
      eaphdr->eap_length = htons(leapdata->result_size + sizeof(struct eap_header));
      eaphdr->eap_type = EAP_TYPE_LEAP;

      memcpy(&response[sizeof(struct eap_header)], leapdata->result,
	     leapdata->result_size);
      break;
    }

  FREE(leapdata->result);

  return response;
}

/**
 *  Determine if key data is available.  
 **/
uint8_t eapleap_isKeyAvailable(eap_type_data *eapdata)
{
  struct leap_data *leapdata;
  
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL),
		   "eapdata->eap_data != NULL", FALSE))
    return FALSE;

  leapdata = (struct leap_data *)eapdata->eap_data;

  if (leapdata->keyingMaterial == NULL) return FALSE;

  return TRUE;
}

/**
 *  Return key data.
 **/
uint8_t *eapleap_getKey(eap_type_data *eapdata)
{
  struct leap_data *leapdata;
  uint8_t *keydata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL),
                   "eapdata->eap_data != NULL", FALSE))
    return FALSE;

  leapdata = (struct leap_data *)eapdata->eap_data;

  keydata = Malloc(64);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to return key "
		   "data!\n");
      return NULL;
    }

  memcpy(keydata, leapdata->keyingMaterial, 64);

  return keydata;
}

/**
 *  Return the length of the keying material.
 **/
uint8_t eapleap_getKey_len(eap_type_data *eapdata)
{
  return 16;
}

/**
 *  Clean up following our authentication.
 **/
void eapleap_deinit(eap_type_data *eapdata)
{
  struct leap_data *leapdata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return;

  leapdata = (struct leap_data *)eapdata->eap_data;

  FREE(leapdata->keyingMaterial);
  FREE(leapdata->leaprequest);
  FREE(leapdata->leapchallenges);
  FREE(leapdata->password);
  FREE(leapdata);

  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Cleaning up.\n");
}
