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
#include "../../platform/cardif.h"
#include "../../logon_creds.h"

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

void eapmschapv2_p2_pwd_callback(void *ctxptr, struct eap_sm_vars *p2sm, uint8_t **packet, uint16_t *pktsize)
{
	context *ctx = NULL;
	struct eap_mschapv2_stored_frame *myFrame = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE)) return;

	debug_printf(DEBUG_AUTHTYPES, "%s()\n", __FUNCTION__);

	ctx = ctxptr;

	// Clear the callback.
	ctx->p2_pwd_callback = NULL;

	myFrame = ctx->pwd_callback_data;

	if (!xsup_assert((myFrame != NULL), "myFrame != NULL", FALSE)) return;

	(*packet) = myFrame->eappkt;
	(*pktsize) = myFrame->eaplen;

	myFrame->eappkt = NULL;  // This is okay, because we passed the pointer out.

	// Back up our EAP ID so that we don't discard when we reprocess this frame.
	p2sm->lastId-=3;
	p2sm->ignore = FALSE;
}

/**
 * \brief This callback will be called when a password is set.  We need to reset the context to process the frame, kick it off,
 *        and clear the callback.  (Not necessarily in that order. ;)
 *
 * @param[in] ctxptr   A void pointer to the context that we are processing for.
 **/
void eapmschapv2_pwd_callback(void *ctxptr)
{
	context *ctx = NULL;
	struct eap_mschapv2_stored_frame *myFrame = NULL;
	void *temp = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE)) return;

	ctx = ctxptr;

	event_core_set_active_ctx(ctx);

	// Clear the callback.
	ctx->pwd_callback = NULL;

	myFrame = ctx->pwd_callback_data;

	if (!xsup_assert((myFrame != NULL), "myFrame != NULL", FALSE)) return;

	temp = ctx->recvframe;

	ctx->recvframe = myFrame->frame;
	ctx->recv_size = myFrame->length;

	myFrame->frame = NULL;   // This is okay, because we passed the pointer to ctx->recvframe.

	// Back up our EAP ID so that we don't discard when we reprocess this frame.
	ctx->eap_state->lastId--;
	ctx->statemachine->eapolEap = TRUE;
	ctx->eap_state->ignore = FALSE;   // Don't ignore anymore.

	SET_FLAG(ctx->flags, INT_REPROCESS);

	eapol_execute(ctx);   // Kick it off.

	FREE(ctx->recvframe);
	ctx->recvframe = temp;
}

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

/**
 * \brief Configure EAP-MS-CHAPv2 to run in EAP-FAST anon provisioning mode.
 *
 * @param[in] eapdata   An eap_type_data structure that holds information about this authentication.
 * @apram[in] enable   A TRUE/FALSE value that indicates if we should be in anon provisioning mode.
 *
 **/
void eapmschapv2_set_eap_fast_anon_mode(eap_type_data *eapdata, uint8_t enable)
{
  struct mschapv2_vars *mscv2data = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
	  return;

  mscv2data = (struct mschapv2_vars *)eapdata->eap_data;

  debug_printf(DEBUG_AUTHTYPES, "Setting EAP-FAST mode for MS-CHAPv2!\n");
  mscv2data->eap_fast_mode = enable;
}

/**
 * \brief Check to see if a password is available for this configuration.
 *
 * @param[in] ctx   A context to look in.
 * @param[in] eapconf   A copy of the EAP-MSCHAPv2 configuration entry.
 *
 * \retval TRUE if a password is availble
 * \retval FALSE if a password is not available.
 **/
int eapmschapv2_is_password_avail(context *ctx, struct config_eap_mschapv2 *eapconf)
{
	if ((eapconf != NULL) && (eapconf->password != NULL)) return TRUE;
	if ((ctx != NULL) && (ctx->prof != NULL) && (ctx->prof->temp_password != NULL)) return TRUE;
	if ((eapconf != NULL) && (TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_USE_LOGON_CREDS)) && 
		(logon_creds_password_available() == TRUE)) return TRUE;

	return FALSE;
}

/**
 * \brief Execute the INIT functions for this EAP method.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 * \retval XENONE on success.
 **/
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
      debug_printf(DEBUG_NORMAL, "No context was available, so no password is available for EAP-MSCHAPv2!\n");
      eap_type_common_fail(eapdata);
      return XEGENERROR;
	}

	if (!TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH))
	{
		if (ctx->prof->temp_password != NULL)
		{
			mscv2data->password = _strdup(ctx->prof->temp_password);
		}
		else if ((TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_USE_LOGON_CREDS)) && (logon_creds_password_available() == TRUE))
		{
			mscv2data->password = _strdup(logon_creds_get_password());
		}
		else if (eapconf->password != NULL)
		{
			mscv2data->password = _strdup(eapconf->password);
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2!\n");
			eap_type_common_fail(eapdata);
			return XEGENERROR;
		}
	}

	if ((TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_USE_LOGON_CREDS)) && (logon_creds_username_available() == TRUE))
	{
		eapdata->ident = _strdup(logon_creds_get_username());
	}
	else if (eapdata->ident == NULL)
	{
		// The RADIUS server build in to my Cisco 1200 doesn't do an identity exchange as part of
		// phase 2.  (When doing provisioning.) Since we need to know the identity, we will have to dig it out of the context.
		// (ICK!)
		if ((ctx == NULL) || (ctx->prof == NULL))
		{
			debug_printf(DEBUG_NORMAL, "No profile was bound to your inner EAP method!?  This shouldn't happen!\n");
			eap_type_common_fail(eapdata);
			return -1;
		}

		if (ctx->prof->temp_username != NULL)
		{
			eapdata->ident = _strdup(ctx->prof->temp_username);
		}
		else if (ctx->prof->identity != NULL)
		{
			eapdata->ident = _strdup(ctx->prof->identity);
		}
		else
		{
			// ACK!  We don't know a username to send!?
			debug_printf(DEBUG_NORMAL, "Unable to determine a valid username to send to the server.  Aborting the authentication.\n");
			eap_type_common_fail(eapdata);
			return -1;
		}
	}

  eap_type_common_init_eap_data(eapdata);

  return XENONE;
}

/**
 * \brief Verify that this packet is really an EAP-MSCHAPv2 packet.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an EAP-MSCHAPv2.
 *
 **/
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

  // If we are running in EAP-FAST provisioning mode, it is okay if we don't have a password, we
  // will prompt for one.
  ctx = event_core_get_active_ctx();
  if ((eapmschapv2_is_password_avail(ctx, eapconf) == FALSE) &&
	  (!TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH)))
    {
      debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2!\n");
      eap_type_common_fail(eapdata);
      return;
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

/**
 * \brief Process an MSCHAPv2 challenge message.  It should return one of the
 *			eapMethod state values.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *  \retval uint8_t  one of EAP_FAIL or MAY_CONT.
 **/
uint8_t eapmschapv2_challenge(eap_type_data *eapdata)
{
  struct mschapv2_challenge *challenge = NULL;
  struct mschapv2_vars *myvars = NULL;
  struct config_eap_mschapv2 *eapconf = NULL;
  char *username = NULL;
  char *ident = NULL;

#ifdef WINDOWS
  uint16_t length;
#endif

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
      if (TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_IAS_QUIRK))
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
			 eapconf->nthash, (char *)myvars->NtResponse, USING_NTPWD_PWD);
    } 
  else if (TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH))
  {
#ifdef WINDOWS
	  if (win_impersonate_get_machine_password(&myvars->password, &length) != XENONE)
	  {
		  debug_printf(DEBUG_NORMAL, "Unable to get machine password!\n");
		  eap_type_common_fail(eapdata);
		  return EAP_FAIL;
	  }
#endif // WINDOWS

	  // Doing a machine auth.
      GenerateNTResponse((char *)myvars->AuthenticatorChallenge,
			 (char *)myvars->PeerChallenge, username, 
			 myvars->password, (char *)myvars->NtResponse, USING_MAUTH_PWD);
  }
  else
  {
    GenerateNTResponse((char *)myvars->AuthenticatorChallenge,
		       (char *)myvars->PeerChallenge, username,
		       myvars->password, (char *)myvars->NtResponse, USING_ASCII_PWD);
    }

  debug_printf(DEBUG_AUTHTYPES, "myvars->NtResponse = ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) myvars->NtResponse, 24);

  // Our credentials have been used, so signal it.
  eapdata->credsSent = TRUE;

  // Everything is good, so continue.
  return MAY_CONT;
}

/**
 * \brief Process a success message.  It should return one of the eapMethod state
 *			values.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *  \retval uint8_t  one of EAP_FAIL or MAY_CONT.
 **/
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
				 (char *)&success->MsgField[2], &respOk, USING_NTPWD_PWD);
    } 
  else if (TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH))
  {
	  CheckAuthenticatorResponse(myvars->password,
				 (char *)myvars->NtResponse, 
				 (char *)myvars->PeerChallenge,
				 (char *)myvars->AuthenticatorChallenge,
				 eapdata->ident, 
				 (char *)&success->MsgField[2], &respOk, USING_MAUTH_PWD);
  }
  else {
      CheckAuthenticatorResponse(myvars->password,
				 (char *)myvars->NtResponse, 
				 (char *)myvars->PeerChallenge,
				 (char *)myvars->AuthenticatorChallenge,
				 eapdata->ident, 
				 (char *)&success->MsgField[2], &respOk, USING_ASCII_PWD);
    }

  if (respOk != 1)
    {
      debug_printf(DEBUG_NORMAL, "Authenticator response invalid!\n");
      return EAP_FAIL;
    }

  // Otherwise, generate our keying material.
  // We were successful, so generate keying material.
  if ((!eapconf->nthash) && (!TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH)))
    {
      NtPasswordHash(myvars->password, (char *)&NtHash, TRUE);
    }
  else if (TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH))
  {
	  NtPasswordHash(myvars->password, (char *)&NtHash, FALSE);
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

/**
 * \brief Parse an MS-CHAPv2 error string in to the numeric failure value, 
 *			and the text error value.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *  \retval uint8_t  one of EAP_FAIL or MAY_CONT.
 **/
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

/**
 * \brief Process a failure message.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *  \retval uint8_t  one of EAP_FAIL or MAY_CONT.
 **/
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
	  context_disconnect(event_core_get_active_ctx());
      break;

    case MSCHAPV2_ACCT_DISABLED:
      debug_printf(DEBUG_NORMAL, "Your account has been disabled.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_ACCT_DISABLED, NULL);
	  context_disconnect(event_core_get_active_ctx());
      break;

    case MSCHAPV2_PASSWD_EXPIRED:
      debug_printf(DEBUG_NORMAL, "Your password has expired.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_PASSWD_EXPIRED, NULL);
	  context_disconnect(event_core_get_active_ctx());
      break;

    case MSCHAPV2_NO_DIALIN_PERMISSION:
      debug_printf(DEBUG_NORMAL, "Your account does not have permission to "
		   "use this network.\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_NO_PERMS, NULL);
	  context_disconnect(event_core_get_active_ctx());
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
  	  context_disconnect(event_core_get_active_ctx());
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown error type %d returned.  Please "
		   "see text description of the error (on the next line) "
		   "for more information.\n", errcode);
	  debug_printf(DEBUG_NORMAL, "Error is : %s\n", err_text);
      break;
    }

  if (err_text != NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Server provided text description of the error : "
		       "%s\n", err_text);
  }

  return EAP_FAIL;
}

/**
 * \brief Clean up the memory on the EAP-MSCHAPv2 data hook.
 *
 * @param[in] cbdata   The callback data stored in the context that we need to free.
 **/
void eapmschapv2_cleanup_p2_datahook(void *cbdata)
{
  struct eap_mschapv2_stored_frame *myFrame = NULL;

  // Because of the nature of GTC/OTP, it is possible that cleanup will get called on a NULL pointer.
  // If that happens, silently move on.
  if (cbdata == NULL) return;

  myFrame = cbdata;

  if (myFrame != NULL)
  {
	  FREE(myFrame->frame);
  }
}

/**
 * \brief Process an EAP-MSCHAPv2 packet, and develop the data needed for
 *			the response.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 **/
void eapmschapv2_process(eap_type_data *eapdata)
{
  struct config_eap_mschapv2 *eapconf = NULL;
  struct mschapv2_challenge *challenge = NULL;
  context *ctx = NULL;
  struct eap_mschapv2_stored_frame *myFrame = NULL;

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

	  ctx = event_core_get_active_ctx();

	  if (ctx == NULL)
	  {
		  // This shouldn't be possible, but....
		  debug_printf(DEBUG_NORMAL, "NULL context in %s()!\n", __FUNCTION__);
		  eap_type_common_fail(eapdata);
		  return;
	  }

	  if ((eapmschapv2_is_password_avail(ctx, eapconf) == FALSE) && 
		  (!TEST_FLAG(eapconf->flags, FLAGS_EAP_MSCHAPV2_MACHINE_AUTH)))
	  {
	      debug_printf(DEBUG_NORMAL, "No password available for EAP-MSCHAPv2! (Trying to request one.)\n");
		  if (ipc_events_request_eap_upwd("EAP-MSCHAPv2", "Please enter your password.") != IPC_SUCCESS)
		  {
			  debug_printf(DEBUG_NORMAL, "Couldn't request password from UI!  Failing.\n");
			  eap_type_common_fail(eapdata);
			  return;
		  }
		  else
		  {
			  eapdata->ignore = TRUE;       // Don't do anything just yet.
			  eapdata->methodState = CONT;
			  eapdata->decision = COND_SUCC;  // We may be able to succeed.

			  if ((ctx != NULL) && (ctx->pwd_callback_data != NULL)) 
			  {
				  eapmschapv2_cleanup_p2_datahook(ctx->pwd_callback_data);
				  FREE(ctx->pwd_callback_data);
			  }

			  ctx->pwd_callback_data = Malloc(sizeof(struct eap_mschapv2_stored_frame));
			  if (ctx->pwd_callback_data != NULL)
			  {
				  myFrame = ctx->pwd_callback_data;
				  myFrame->frame = Malloc(FRAMESIZE);
	 			  if (myFrame->frame == NULL)
					{
						FREE(ctx->pwd_callback_data);
					}
					else
					{
						memcpy(myFrame->frame, ctx->recvframe, ctx->recv_size);
						myFrame->length = ctx->recv_size;

						myFrame->eaplen = eap_type_common_get_eap_length(eapdata->eapReqData);
						myFrame->eappkt = Malloc(myFrame->eaplen);
						if (myFrame->eappkt != NULL)
						{
							memcpy(myFrame->eappkt, eapdata->eapReqData, myFrame->eaplen);
						}

						ctx->pwd_callback = eapmschapv2_pwd_callback;
						ctx->p2_pwd_callback = eapmschapv2_p2_pwd_callback;

						// Since we return ignore, our EAP ID won't get updated.  But we need it to, so we
						// update it manually here.  (That way we discard retransmissions.)
						ctx->eap_state->lastId = ctx->eap_state->reqId;
					}

				  return;
			}
	  }
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

/**
 * \brief Build a challenge response message.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 *  \retval ptr   to an EAP-MSCHAPv2 packet to send to the server.
 **/
uint8_t *eapmschapv2_challenge_resp(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars = NULL;
  struct config_eap_mschapv2 *eapconf = NULL;
  struct mschapv2_response *response = NULL;
  uint8_t *resp = NULL;
  uint16_t respsize = 0;
  uint8_t eapid = 0;
  struct eap_header *eap_header = NULL;
  char *username = NULL;
  char *temp = NULL;

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

  if (eapdata->ident == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "No identity available to EAP-MSCHAPv2!  Authentication will fail.\n");
	  eap_type_common_fail(eapdata);
	  return NULL;
  }

  eapmschapv2_strip_backslash(eapdata->ident, &username);

  // 54 bytes is the length of the response, including MS-CHAPv2 header.
  respsize = 54+strlen(username)+sizeof(struct eap_header);
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
  response->MS_Length = htons(54+strlen(username));
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


/*  memcpy(&resp[sizeof(struct eap_header)+54], eapdata->ident, 
	 strlen(eapdata->ident));
	 */
  memcpy(&resp[sizeof(struct eap_header)+54], username, strlen(username));

  return resp;
}

/**
 * \brief Build a success response message.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 *  \retval ptr   to a success reponse to send to the server.
 **/
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

/**
 * \brief Return a response to a failure message.
 *
 * @param[in] eapdata   An eap_type_data   A pointer to a structure that contains the information needed to 
 *											complete an OTP or GTC auth.
 *
 *  \retval ptr   a pointer to a failure packet to send to the server.
 **/
uint8_t *eapmschapv2_failure_resp(eap_type_data *eapdata)
{
  struct mschapv2_vars *myvars = NULL;
  struct config_eap_mschapv2 *eapconf = NULL;
  uint8_t *resp = NULL;
  uint16_t respsize = 0;
  struct eap_header *eap_header = NULL;
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
  struct mschapv2_vars *myvars = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (eapdata->eap_data == NULL) return FALSE;

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
  struct mschapv2_vars *myvars = NULL;
  uint8_t *keydata = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL),
                   "eapdata->eap_data != NULL", FALSE))
    return FALSE;

  myvars = (struct mschapv2_vars *)eapdata->eap_data;

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
  struct mschapv2_vars *myvars = NULL;

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

/**
 * \brief Return a username if we need to override it for some reason (such as a
 *			desire to use logon credentials.
 *
 * \note Any non-NULL value returned here will override any configuration file setting
 *			or user provided entry (if any).  This call should be USED WITH CARE!
 *
 * \retval NULL if no username is to be returned, ptr to the new username otherwise.
 **/
char *eapmschapv2_get_username(void *config)
{
	struct config_eap_mschapv2 *mscv2 = NULL;

	if (config == NULL) return NULL;

	mscv2 = (struct config_eap_mschapv2 *)config;

	if (TEST_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_USE_LOGON_CREDS))
	{
		if (logon_creds_username_available() == TRUE) return logon_creds_get_username();
	}

	return NULL;
}

