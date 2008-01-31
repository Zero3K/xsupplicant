/**
 * EAP-MSCHAPv2 Function implementations
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapmschapv2.c
 *
 * \author chris@open1x.org
 *
 **/

#include <openssl/rand.h>
#include <string.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "../../eap_sm.h"
#include "eapmschapv2.h"
#include "mschapv2.h"
#include "../../ipc_callout.h"
#include "../../xsup_ipc.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

#ifndef WINDOWS
#include <netinet/in.h>
#include "src/event_core.h"
#else
#include "src/event_core_win.h"
#endif 




#ifdef USE_EFENCE
#include <efence.h>
#endif

static uint8_t *peer_challenge = NULL;
static uint8_t *authenticator_challenge = NULL;
static uint8_t eap_fast_mode = 0;

/******************************************************************
 *
 *  *** NOTE *** This function must be called *BEFORE* the init 
 *  phase of the EAP method.  Calling it later will do nothing.
 *
 *  Set the peer_challenge, and authenticator_challenge variables
 *  above so that we can know that we are in the goofy EAP-FAST mode
 *  of MS-CHAPv2 and act accordingly.
 *
 ******************************************************************/
// XXX Store this someplace that isn't a global variable!!!
uint8_t eapmschapv2_set_challenges(uint8_t *pc, uint8_t *ac)
{
  FREE(peer_challenge);
  FREE(authenticator_challenge);

  if ((ac == NULL) && (pc == NULL)) 
    {
      debug_printf(DEBUG_AUTHTYPES, "Cleared MS-CHAPv2 provisioning mode.\n");
      return TRUE;
    }

  peer_challenge = Malloc(16);
  if (peer_challenge == NULL) 
  {
	  ipc_events_malloc_failed(NULL);
	  return FALSE;
  }

  memcpy(peer_challenge, pc, 16);

  debug_printf(DEBUG_AUTHTYPES, "Peer Challenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, peer_challenge, 16);

  authenticator_challenge = Malloc(16);
  if (authenticator_challenge == NULL)
    {
      FREE(peer_challenge);
	  ipc_events_malloc_failed(NULL);
      return FALSE;
    }

  memcpy(authenticator_challenge, ac, 16);
  
  debug_printf(DEBUG_AUTHTYPES, "Authenticator Challenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, authenticator_challenge, 16);

  return TRUE;
}

/******************************************************************
 *
 *  Configured EAP-MS-CHAPv2 to run in the weird EAP-FAST modes.
 *
 ******************************************************************/
void eapmschapv2_set_eap_fast_mode(eap_type_data *ctx, uint8_t enable)
{
  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "Setting EAP-FAST mode for MS-CHAPv2!\n");
  eap_fast_mode = enable;
}

/******************************************************************
 *
 * Execute the INIT functions for this EAP method.
 *
 ******************************************************************/
int eapmschapv2_init(eap_type_data *eapdata)
{
  struct mschapv2_vars *mscv2data = NULL;
  struct config_eap_mschapv2 *eapconf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return XEMALLOC;

  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  if (eapconf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid configuration for "
		   "EAP-MSCHAPv2.\n");
      eap_type_common_fail(eapdata);
      return XEGENERROR;
    }

  // It is possible that this is a reauthentication, and something is
  // already on our EAP data hook.  So, clear it out.
  eapmschapv2_deinit(eapdata);

  eapdata->eap_data = (uint8_t *)Malloc(sizeof(struct mschapv2_vars));
  if (eapdata->eap_data == NULL) 
  {
	  ipc_events_malloc_failed(NULL);
	  return XEMALLOC;
  }

  mscv2data = (struct mschapv2_vars *)eapdata->eap_data;

  if ((peer_challenge != NULL) && (authenticator_challenge != NULL))
    {
      eap_fast_mode = TRUE;
      mscv2data->AuthenticatorChallenge = authenticator_challenge;
      mscv2data->PeerChallenge = peer_challenge;
    }

	ctx = event_core_get_active_ctx();
	if (ctx == NULL)
	{
      debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2!\n");
      eap_type_common_fail(eapdata);
      return XEGENERROR;
	}

	if (ctx->prof->temp_password == NULL)
    {
		if (eapconf->password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2!\n");
			eap_type_common_fail(eapdata);
			return XEGENERROR;
		}
		else
		{
			mscv2data->password = _strdup(eapconf->password);
		}
    }
  else
  {
	  mscv2data->password = _strdup(ctx->prof->temp_password);
  }

  eap_type_common_init_eap_data(eapdata);

  return XENONE;
}

/******************************************************************
 *
 * Verify that this packet is really an EAP-MSCHAPv2 packet.
 *
 ******************************************************************/
void eapmschapv2_check(eap_type_data *eapdata)
{
  struct eap_header *myeap = NULL;
  struct mschapv2_challenge *mv2 = NULL;
  struct config_eap_mschapv2 *eapconf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

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
      debug_printf(DEBUG_NORMAL, "EAP isn't a request packet!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (ntohs(myeap->eap_length) < (2 + sizeof(struct eap_header)))
    {
      debug_printf(DEBUG_NORMAL, "Not enough data for valid EAP method.\n");
      eap_type_common_fail(eapdata);
      return;
    }

  mv2 = (struct mschapv2_challenge *)&eapdata->eapReqData[sizeof(struct eap_header)];
  
  if ((mv2->OpCode < MS_CHAPV2_CHALLENGE) || (mv2->OpCode > MS_CHAPV2_FAILURE))
    {
      debug_printf(DEBUG_NORMAL, "Unsupported EAP-MSCHAPv2 OpCode!  (Code : "
		   "%d)\n", mv2->OpCode);
      eap_type_common_fail(eapdata);
      return;
    }

  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  if (eapconf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid configuration for "
		   "EAP-MSCHAPv2.\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (eapconf->password == NULL)
    {
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
	      debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2!\n");
	      eap_type_common_fail(eapdata);
	      return;
		}

		if (ctx->prof->temp_password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2!\n");
			eap_type_common_fail(eapdata);
			return;
		}
    }
}

/**
 * \brief Strip the domain off the username (if present).
 *
 * \note  The caller is expected to free the value returned in "shortname".
 *
 * @param[in] longname   The username that MAY contain a DOMAIN\ format.
 * @param[out] shortname   The username without the DOMAIN\ format.
 **/
void eapmschapv2_strip_backslash(char *longname, char **shortname)
{	
	char *substr = NULL;

	if (longname == NULL) 
	{
		(*shortname) = NULL;
		return;
	}

	substr = strstr(longname, "\\");
	if (substr == NULL)
	{
		(*shortname) = _strdup(longname);
		return;
	}

	// Otherwise, return 1 character beyond the one we found.
	(*shortname) = _strdup(substr+1);   // Ick!  Pointer math. ;)
}

/******************************************************************
 *
 *  Process an MSCHAPv2 challenge message.  It should return one of the
 *  eapMethod state values.
 *
 ******************************************************************/
uint8_t eapmschapv2_challenge(eap_type_data *eapdata)
{
  struct mschapv2_challenge *challenge = NULL;
  struct mschapv2_vars *myvars = NULL;
  struct config_eap_mschapv2 *eapconf = NULL;
  char *username = NULL;
  char *ident = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
		   "eapdata->eapReqData != NULL", FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), 
		   "eapdata->eap_conf_data != NULL", FALSE))
    return EAP_FAIL;

  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;

  challenge = (struct mschapv2_challenge *)&eapdata->eapReqData[sizeof(struct eap_header)];

  debug_printf(DEBUG_AUTHTYPES, "(EAP-MS-CHAPv2) ID : %02X\n",
	       challenge->MS_CHAPv2_ID);

  // Store a copy for the response.
  myvars->MS_CHAPv2_ID = challenge->MS_CHAPv2_ID;

  // This value should *ALWAYS* be 0x10.
  if (challenge->Value_Size != 0x10)
    {
      if (eapconf->ias_quirk == 1)
	{
	  debug_printf(DEBUG_NORMAL, "(EAP-MS-CHAPv2) Invalid Value-Size! "
		       "(%d), forced to 0x10 (ias_quirk = yes)\n", 
		       challenge->Value_Size);
	  challenge->Value_Size = 0x10;
	}
      else 
	{
	  debug_printf(DEBUG_NORMAL, "(EAP-MS-CHAPv2) Invalid Value-Size! (%d)"
		       "\n", challenge->Value_Size);
	  debug_printf(DEBUG_NORMAL, "(EAP-MS-CHAPv2) Should you enable "
		       "ias_quirk?\n");
	  return EAP_FAIL;
	}
    }


  if (eap_fast_mode != TRUE)
    {
      FREE(myvars->AuthenticatorChallenge);
      
      myvars->AuthenticatorChallenge = (uint8_t *)Malloc(16);
      if (myvars->AuthenticatorChallenge == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for the "
		       "Authenticator Challenge!\n");
	  ipc_events_malloc_failed(NULL);

	  return EAP_FAIL;
	}

      memcpy(myvars->AuthenticatorChallenge, &challenge->Challenge, 16);
    }

  debug_printf(DEBUG_AUTHTYPES, "Authenticator Challenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) myvars->AuthenticatorChallenge,
		   16);

  if (eap_fast_mode != TRUE)
    {
      FREE(myvars->PeerChallenge);
      
      // Ignore the RADIUS host, we probably don't care.
      myvars->PeerChallenge = (uint8_t *)Malloc(16);
      if (myvars->PeerChallenge == NULL) 
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for the "
		       "Peer Challenge!\n");

	  ipc_events_malloc_failed(NULL);

	  return EAP_FAIL;
	}
      
      RAND_bytes((uint8_t *) myvars->PeerChallenge, 16);
    }

  debug_printf(DEBUG_AUTHTYPES, "Generated PeerChallenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) myvars->PeerChallenge,16);

  myvars->NtResponse = (uint8_t *)Malloc(24);
  if (myvars->NtResponse == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for the "
		   "NtResponse!\n");
	  ipc_events_malloc_failed(NULL);

      return EAP_FAIL;
    }

  eapmschapv2_strip_backslash(eapdata->ident, &username);

  if (eapconf->nthash)
    {
      GenerateNTResponse((char *)myvars->AuthenticatorChallenge,
			 (char *)myvars->PeerChallenge, username, 
			 eapconf->nthash, (char *)myvars->NtResponse, 1);
    } else {
    GenerateNTResponse((char *)myvars->AuthenticatorChallenge,
		       (char *)myvars->PeerChallenge, username,
		       myvars->password, (char *)myvars->NtResponse, 0);
    }

  debug_printf(DEBUG_AUTHTYPES, "myvars->NtResponse = ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) myvars->NtResponse, 24);

  // Everything is good, so continue.
  return MAY_CONT;
}

/******************************************************************
 *
 *  Process a success message.  It should return one of the eapMethod state
 *  values.
 *
 ******************************************************************/
uint8_t eapmschapv2_success(eap_type_data *eapdata)
{
  struct mschapv2_success_request *success;
  int respOk = 0;
  struct config_eap_mschapv2 *eapconf;
  struct mschapv2_vars *myvars;
  uint8_t NtHash[16], NtHashHash[16], MasterKey[16];
  uint8_t mppeSend[16], mppeRecv[16];
  uint16_t eaplen=0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return EAP_FAIL;

  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;

  success = (struct mschapv2_success_request *)&eapdata->eapReqData[sizeof(struct eap_header)];  

  eaplen = eap_type_common_get_eap_length(eapdata->eapReqData);

  // Add a NULL to the end, in case we didn't get one.
  eapdata->eapReqData[eaplen+1] = 0x00;

  if (eapconf->nthash)
    {
      CheckAuthenticatorResponse(eapconf->nthash,
				 (char *)myvars->NtResponse, 
				 (char *)myvars->PeerChallenge,
				 (char *)myvars->AuthenticatorChallenge,
				 eapdata->ident, 
				 (char *)&success->MsgField[2], &respOk, 1);
    } else {
      CheckAuthenticatorResponse(myvars->password,
				 (char *)myvars->NtResponse, 
				 (char *)myvars->PeerChallenge,
				 (char *)myvars->AuthenticatorChallenge,
				 eapdata->ident, 
				 (char *)&success->MsgField[2], &respOk, 0);
    }

  if (respOk != 1)
    {
      debug_printf(DEBUG_NORMAL, "Authenticator response invalid!\n");
      return EAP_FAIL;
    }

  // Otherwise, generate our keying material.
  // We were successful, so generate keying material.
  if (!eapconf->nthash)
    {
      NtPasswordHash(myvars->password, (char *)&NtHash);
    }
  else
    {
      process_hex(myvars->password, strlen(myvars->password), 
		  (char *)NtHash);
    }

  HashNtPasswordHash((char *)&NtHash, (char *)&NtHashHash);
  GetMasterKey((char *)&NtHashHash, (char *)myvars->NtResponse, 
	       (char *)&MasterKey);

  // Now, get the send key.
  GetAsymetricStartKey((char *)&MasterKey, (char *)&mppeSend, 16, TRUE, FALSE);

  // And the recv key.
  GetAsymetricStartKey((char *)&MasterKey, (char *)&mppeRecv, 16, FALSE, 
		       FALSE);

  // Finally, populate our myvars->keyingMaterial.
  FREE(myvars->keyingMaterial);

  myvars->keyingMaterial = (uint8_t *)Malloc(64);  // 32 bytes each.
  if (myvars->keyingMaterial == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store keying"
		   " material!\n");
	  ipc_events_malloc_failed(NULL);

      return EAP_FAIL;
    }

  memcpy(&myvars->keyingMaterial[32], &mppeRecv, 16);

  memcpy(myvars->keyingMaterial, &mppeSend, 16);

  eapdata->decision = COND_SUCC;
  eapdata->eapKeyAvailable = TRUE;
  eapdata->altAccept = TRUE;

  return MAY_CONT;
}

/******************************************************************
 *
 *  Parse an MS-CHAPv2 error string in to the numeric failure value, 
 *  and the text error value.
 *
 ******************************************************************/
uint8_t eapmschapv2_parse_error_string(char *err_string, uint16_t *errcode, 
				       char **errtext)
{
  /*
   The Message field format is:

     "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>"

  */
  uint16_t offset = 0;
  char *strdata = NULL;

  if ((err_string[0] != 'E') || (err_string[1] != '='))
    {
      debug_printf(DEBUG_NORMAL, "Message string contains invalid starting "
		   "characters.  It should start with 'E=', but actually "
		   "started with '%c%c'.\n", err_string[0], err_string[1]);
      return XEGENERROR;
    }

  strdata = err_string + 2;  // Start beyond the E= portion.

  while ((offset < strlen(err_string)) && (strdata[offset] != ' '))
    {
      offset++;
    }

  if (strdata[offset] == ' ')
    {
      strdata[offset] = 0x00;  // Set a NULL so that atoi can handle it.
      *errcode = atoi(strdata);
      
      debug_printf(DEBUG_AUTHTYPES, "Numeric error code is %d\n", *errcode);
    }

  offset++;

  if ((strdata[offset] != 'R') || (strdata[offset+1] != '='))
    {
      debug_printf(DEBUG_NORMAL, "Message contains invalid characters for "
		   "second element.  It should be 'R=', but actually was "
		   "'%c%c'.\n", strdata[offset], strdata[offset+1]);
      return XEGENERROR;
    }

  offset+=4;  // This should get us to the C= section.

  if ((strdata[offset] != 'C') || (strdata[offset+1] != '='))
    {
      debug_printf(DEBUG_NORMAL, "Message contains invalid characters for "
		   "third element.  It should be 'C=', but actually was "
		   "'%c%c'.\n", strdata[offset], strdata[offset+1]);
      return XEGENERROR;
    }

  offset+=35;  // This should get us to the V= section.

  if ((strdata[offset] != 'V') || (strdata[offset+1] != '='))
    {
      debug_printf(DEBUG_NORMAL, "Message contains invalid characters for "
		   "fourth element.  It should be 'V=', but actually was "
		   "'%c%c'.\n", strdata[offset], strdata[offset+1]);
      return XEGENERROR;
    }

  offset+=2;

  strdata += offset;
  offset = 0;

  while ((offset < strlen(strdata)) && (strdata[offset] != ' '))
    {
      offset++;
    }

  if (strdata[offset] != ' ')
    {
      debug_printf(DEBUG_AUTHTYPES, "Message didn't appear to be valid following"
		   " the password change section.  (Section 'V=')\n");

      // Some authentication servers don't send a properly formatted failure
      // response.  They may omit the text version of the error code.
      return XENONE;
    }

  // Otherwise, set this to a null character.
  strdata[offset] = 0x00;

  if (atoi(strdata) != MSCHAPV2_PASSWORD_CHANGE_VER)
    {
      debug_printf(DEBUG_NORMAL, "The server requested a password change "
		   "protocol version that we don't understand.  Expected "
		   "version %d.  Got version %d.\n", 
		   MSCHAPV2_PASSWORD_CHANGE_VER, atoi(strdata));
      // This error isn't fatal!
    }

  // Finally!  We get to the text version of the failure.
  offset++;
  strdata += offset;
  offset = 0;

  if ((strdata[offset] != 'M') || (strdata[offset+1] != '='))
    {
      debug_printf(DEBUG_NORMAL, "This message didn't appear to have a valid"
		   " text version of the error!  Expected 'M=', found "
		   "'%c%c'.\n", strdata[offset], strdata[offset+1]);
      return XEGENERROR;
    }

  // Otherwise, update our pointer to point to the text of the error.
  strdata += 2;
  *errtext = strdata;

  return XENONE;
}

/******************************************************************
 *
 *  Process a failure message.
 *
 ******************************************************************/
uint8_t eapmschapv2_failure(eap_type_data *eapdata)
{
  struct mschapv2_fail_request *fail = NULL;
  char *err_string = NULL, *err_text = NULL;
  uint16_t errlen = 0, errcode = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return EAP_FAIL;

  // In case we fail parsing the error code, we still end up with the
  // proper end result.
  eapdata->altReject = TRUE;

  fail = (struct mschapv2_fail_request *)&eapdata->eapReqData[sizeof(struct eap_header)];

  if (fail->OpCode != MS_CHAPV2_FAILURE)
    {
      debug_printf(DEBUG_NORMAL, "The OpCode in the MS-CHAPv2 packet doesn't "
		   "indicate that we got an error.  But, we ended up in the "
		   "error state anyway?\n");
      return EAP_FAIL;
    }
  
  errlen = ntohs(fail->MS_Length);

  err_string = Malloc(errlen+1);
  if (err_string == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory needed to parse "
		   "the error string!\n");
	  ipc_events_malloc_failed(NULL);
      return EAP_FAIL;
    }

  memcpy(err_string, fail->MsgField, errlen);

  debug_printf(DEBUG_AUTHTYPES, "Error string is : %s\n", err_string);

  if (eapmschapv2_parse_error_string(err_string, &errcode, &err_text) != XENONE)
    {
      return EAP_FAIL;
    }

  switch (errcode)
    {
    case MSCHAPV2_RESTRICTED_LOGON_HOURS:
      debug_printf(DEBUG_NORMAL, "Your account is restricted to the hours "
		   "you may log in.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_RESTRICTED_HOURS, NULL);
      break;

    case MSCHAPV2_ACCT_DISABLED:
      debug_printf(DEBUG_NORMAL, "Your account has been disabled.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_ACCT_DISABLED, NULL);
      break;

    case MSCHAPV2_PASSWD_EXPIRED:
      debug_printf(DEBUG_NORMAL, "Your password has expired.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_PASSWD_EXPIRED, NULL);
      break;

    case MSCHAPV2_NO_DIALIN_PERMISSION:
      debug_printf(DEBUG_NORMAL, "Your account does not have permission to "
		   "use this network.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_NO_PERMS, NULL);
      break;

    case MSCHAPV2_AUTHENTICATION_FAILURE:
      debug_printf(DEBUG_NORMAL, "General authentication failure.\n");
	  // Don't send an error event here, because it won't be useful to the user.
	  // Instead, they should look at the log file to determine what went wrong.
      break;

    case MSCHAPV2_CHANGING_PASSWORD:
      debug_printf(DEBUG_NORMAL, "There was an error changing your password."
		   "\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_CHANGING_PASSWD, NULL);
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown error type %d returned.  Please "
		   "see text description of the error (on the next line) "
		   "for more information.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_TEXT, err_text);
      break;
    }

  debug_printf(DEBUG_NORMAL, "Server provided text description of the error : "
	       "%s\n", err_text);

  return EAP_FAIL;
}

/******************************************************************
 *
 * Process an EAP-MSCHAPv2 packet, and develop the data needed for
 * the response.
 *
 ******************************************************************/
void eapmschapv2_process(eap_type_data *eapdata)
{
  struct config_eap_mschapv2 *eapconf = NULL;
  struct mschapv2_challenge *challenge = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), 
		   "eapdata->eap_conf_data != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eapReqData != NULL),
		   "eapdata->eapReqData != NULL", FALSE))
    return;

  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  if (eapdata->methodState == INIT)
    {
      if (eapmschapv2_init(eapdata) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Failed to properly initialize "
		       "EAP-MSCHAPv2!\n");
	  eapdata->methodState = EAP_FAIL;
	  return;
	}
    }

  challenge = (struct mschapv2_challenge *)&eapdata->eapReqData[sizeof(struct eap_header)];

  switch (challenge->OpCode)
    {
    case MS_CHAPV2_CHALLENGE:
      eapdata->methodState = eapmschapv2_challenge(eapdata);
      break;

    case MS_CHAPV2_RESPONSE:
      debug_printf(DEBUG_NORMAL, "Got an MS-CHAPv2 response packet!  Your "
		   "RADIUS server is probably broken.\n");
      break;

    case MS_CHAPV2_SUCCESS:
      eapdata->methodState = eapmschapv2_success(eapdata);
      break;

    case MS_CHAPV2_FAILURE:
      eapdata->methodState = eapmschapv2_failure(eapdata);
      break;

    case MS_CHAPV2_CHANGE_PWD:
      debug_printf(DEBUG_NORMAL, "Password changing is not supported!\n");
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown OpCode %d!\n", challenge->OpCode);
      break;
    }
}

/*******************************************************************
 *
 *  Build a challenge response message.
 *
 *******************************************************************/
uint8_t *eapmschapv2_challenge_resp(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars;
  struct config_eap_mschapv2 *eapconf;
  struct mschapv2_response *response;
  uint8_t *resp = NULL;
  uint16_t respsize;
  uint8_t eapid = 0;
  struct eap_header *eap_header;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return NULL;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;
  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  // 54 bytes is the length of the response, including MS-CHAPv2 header.
  respsize = 54+strlen(eapdata->ident)+sizeof(struct eap_header);
  resp = Malloc(respsize);
  if (resp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return frame "
		   "in %s!\n", __FUNCTION__);
      return NULL;
    }

  // Get the EAP ID from the packet sent in.
  eap_header = (struct eap_header *)eapdata->eapReqData;

  eapid = eap_header->eap_identifier;

  // Build the EAP header for the response.
  eap_header = (struct eap_header *)resp;

  eap_header->eap_code = EAP_RESPONSE_PKT;
  eap_header->eap_identifier = eapid;
  eap_header->eap_length = htons(respsize);
  eap_header->eap_type = EAP_TYPE_MSCHAPV2;

  // Now, build the MS-CHAPv2 part of the response.
  response = (struct mschapv2_response *)&resp[sizeof(struct eap_header)];
  response->OpCode = MS_CHAPV2_RESPONSE;
  response->MS_CHAPv2_ID = myvars->MS_CHAPv2_ID;
  response->MS_Length = htons(54+strlen(eapdata->ident));
  response->Value_Size = 49;
  if (eap_fast_mode == TRUE)
    {
      memset((uint8_t *)&response->Peer_Challenge, 0x00, 16);
    }
  else
    {
      memcpy((uint8_t *)&response->Peer_Challenge, myvars->PeerChallenge, 16);
    }
  memset((uint8_t *)&response->Reserved, 0x00, 8);
  memcpy((uint8_t *)&response->NT_Response, myvars->NtResponse, 24);
  
  debug_printf(DEBUG_AUTHTYPES, "response->NT_Response = ");
  debug_hex_printf(DEBUG_AUTHTYPES, response->NT_Response, 24);

  response->Flags = 0;
  memcpy(&resp[sizeof(struct eap_header)+54], eapdata->ident, 
	 strlen(eapdata->ident));

  return resp;
}

/******************************************************************
 *
 *  Build a success response message.
 *
 ******************************************************************/
uint8_t *eapmschapv2_success_resp(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars;
  struct config_eap_mschapv2 *eapconf;
  uint8_t *resp = NULL;
  uint16_t respsize = 0;
  struct eap_header *eap_header;
  uint8_t eapid = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return NULL;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;
  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  // 54 bytes is the length of the response, including MS-CHAPv2 header.
  respsize = sizeof(struct eap_header) + 1;
  resp = Malloc(respsize);
  if (resp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return frame "
                   "in %s!\n", __FUNCTION__);
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  // Get the EAP ID from the packet sent in.
  eap_header = (struct eap_header *)eapdata->eapReqData;

  eapid = eap_header->eap_identifier;

  // Build the EAP header for the response.
  eap_header = (struct eap_header *)resp;

  eap_header->eap_code = EAP_RESPONSE_PKT;
  eap_header->eap_identifier = eapid;
  eap_header->eap_length = htons(respsize);
  eap_header->eap_type = EAP_TYPE_MSCHAPV2;

  resp[sizeof(struct eap_header)] = MS_CHAPV2_SUCCESS;

  return resp;
}

/**********************************************************************
 *
 *  Return a response to a failure message.
 *
 **********************************************************************/
uint8_t *eapmschapv2_failure_resp(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars;
  struct config_eap_mschapv2 *eapconf;
  uint8_t *resp = NULL;
  uint16_t respsize = 0;
  struct eap_header *eap_header;
  uint8_t eapid = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return NULL;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;
  eapconf = (struct config_eap_mschapv2 *)eapdata->eap_conf_data;

  // 54 bytes is the length of the response, including MS-CHAPv2 header.
  respsize = sizeof(struct eap_header) + 1;
  resp = Malloc(respsize);
  if (resp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return frame "
                   "in %s!\n", __FUNCTION__);
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  // Get the EAP ID from the packet sent in.
  eap_header = (struct eap_header *)eapdata->eapReqData;

  eapid = eap_header->eap_identifier;

  // Build the EAP header for the response.
  eap_header = (struct eap_header *)resp;

  eap_header->eap_code = EAP_RESPONSE_PKT;
  eap_header->eap_identifier = eapid;
  eap_header->eap_length = htons(respsize);
  eap_header->eap_type = EAP_TYPE_MSCHAPV2;

  resp[sizeof(struct eap_header)] = MS_CHAPV2_FAILURE;

  return resp;
}

/******************************************************************
 *
 * Build a response packet for EAP-MSCHAPv2.
 *
 ******************************************************************/
uint8_t *eapmschapv2_buildResp(eap_type_data *eapdata)
{
  struct mschapv2_challenge *challenge;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return NULL;

  challenge = (struct mschapv2_challenge *)&eapdata->eapReqData[sizeof(struct eap_header)];

  switch (challenge->OpCode)
    {
    case MS_CHAPV2_CHALLENGE:
      return eapmschapv2_challenge_resp(eapdata);
      break;

    case MS_CHAPV2_RESPONSE:
      debug_printf(DEBUG_NORMAL, "Not sending a response for a response!\n");
      return NULL;
      break;

    case MS_CHAPV2_SUCCESS:
      return eapmschapv2_success_resp(eapdata);
      break;

    case MS_CHAPV2_FAILURE:
      return eapmschapv2_failure_resp(eapdata);
      break;

    case MS_CHAPV2_CHANGE_PWD:
      debug_printf(DEBUG_NORMAL, "Got a request to change the user's password"
		   " but this is unsupported!\n");
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown Op Code, can't build response!\n");
      return NULL;
    }

  return NULL;
}

/******************************************************************
 *
 * Determine if a key is available.
 *
 ******************************************************************/
uint8_t eapmschapv2_isKeyAvailable(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL),
                   "eapdata->eap_data != NULL", FALSE))
    return FALSE;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;

  if (myvars->keyingMaterial == NULL)
    return FALSE;

  return TRUE;
}

/******************************************************************
 *
 * Return the key material that we have developed during the EAP 
 * authentication.
 *
 ******************************************************************/
uint8_t *eapmschapv2_getKey(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars;
  uint8_t *keydata;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL),
                   "eapdata->eap_data != NULL", FALSE))
    return FALSE;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;

  // XXX Fix this up.  (Low priority, since MS-CHAPv2 keying doesn't
  // provide anything useful except for with EAP-FAST.
  /*
  if (myvars->eap_fast_mode == TRUE) printf("Weird EAP-FAST mode enabled!\n");

  if (((peer_challenge != NULL) && (authenticator_challenge != NULL)) ||
  (myvars->eap_fast_mode == TRUE))*/
    {
      // If we get here, then EAP-FAST is using us as an inner method.  So,
      // mangle the key data in the way that it wants, and return it.
      debug_printf(DEBUG_AUTHTYPES, "Returning EAP-FAST style keying material.\n");
      memcpy(&myvars->keyingMaterial[16], &myvars->keyingMaterial[0], 16);
      memcpy(&myvars->keyingMaterial[0], &myvars->keyingMaterial[32], 16);
    }

  keydata = Malloc(64);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for key data!\n");
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  memcpy(keydata, myvars->keyingMaterial, 64);

  return keydata;
}

/**********************************************************************
 *
 * Clean up anything that might be left in memory.
 *
 **********************************************************************/
void eapmschapv2_deinit(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;

  if (eapdata->eap_data != NULL)
    {
      FREE(myvars->AuthenticatorChallenge);
      FREE(myvars->PeerChallenge);
      FREE(myvars->NtResponse);
      FREE(myvars->keyingMaterial);
	  FREE(myvars->password);
      FREE(eapdata->eap_data);
    }
}
