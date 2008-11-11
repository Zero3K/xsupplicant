/**
 * EAPTTLS Phase 2 MS-CHAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file mschap.c
 *
 * \author chris@open1x.org
 *
 **/
#include <string.h>
#include <stdlib.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "src/eap_sm.h"
#include "src/ipc_callout.h"
#include "src/xsup_ipc.h"
#include "src/xsup_debug.h"
#include "phase2_common.h"
#include "src/eap_types/mschapv2/mschapv2.h"
#include "mschap.h"
#include "src/eap_types/eap_type_common.h"

#ifdef WINDOWS
#include <windows.h>
#include "src/event_core_win.h"
#else
#include "src/event_core.h"
#endif

/******************************************************************
 *
 *  Determine that we have the proper data needed to complete the
 * authentication.
 *
 ******************************************************************/
void mschap_check(eap_type_data *eapdata)
{
  struct config_eap_ttls *outerdata = NULL;
  struct config_pwd_only *phase2data = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-MS-CHAP) Checking...\n");

  outerdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

  phase2data = (struct config_pwd_only *)outerdata->phase2_data;

  if ((phase2data == NULL) || (phase2data->password == NULL))
    {
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
	      debug_printf(DEBUG_NORMAL, "No password available for TTLS-MSCHAP!\n");
	      eap_type_common_fail(eapdata);
	      return;
		}

		if (ctx->prof->temp_password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for TTLS-MSCHAP!\n");
			eap_type_common_fail(eapdata);
			return;
		}
    }
}

/************************************************************************
 *
 * Process an MS-CHAP request message.  (Which there shouldn't ever be
 * any.)
 *
 ************************************************************************/
void mschap_process(eap_type_data *eapdata, uint8_t *in, uint16_t insize)
{
  // There is nothing to process for MS-CHAP.
  if (in != NULL)
    {
      debug_printf(DEBUG_NORMAL, "Got additional data following the "
                   "completion of the TTLS-MSCHAP handshake.  Your "
		   "authentication will fail.\n");
      eap_type_common_fail(eapdata);

      debug_printf(DEBUG_AUTHTYPES, "Invalid data received (%d) :\n", insize);
      debug_hex_dump(DEBUG_AUTHTYPES, in, insize);
    }
}

/************************************************************************
 *
 * Build an MS-CHAP response message.
 *
 ************************************************************************/
void mschap_buildResp(eap_type_data *eapdata, uint8_t *out, uint16_t *outsize)
{
  struct config_eap_ttls *outerdata = NULL;
  struct config_pwd_only *phase2data = NULL;
  char *username = NULL;
  uint16_t avp_out_size = 0, avp_offset = 0;
  uint8_t session_id = 0;
  uint8_t *challenge = NULL, mschap_challenge[8];
  uint8_t mschap_answer[50], mschap_result[24];
  context *ctx = NULL;
  char *password = NULL;

  *outsize = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-MS-CHAP) Building response.\n");

  outerdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

  phase2data = (struct config_pwd_only *)outerdata->phase2_data;

  ctx = event_core_get_active_ctx();

  if ((ctx != NULL) && (ctx->prof != NULL) && (ctx->prof->temp_username != NULL))
  {
	  username = ctx->prof->temp_username;
  }
  else if (outerdata->inner_id == NULL)
    {
      username = eapdata->ident;
    }
  else
    {
      username = outerdata->inner_id;
    }

  avp_offset = 0;

  build_avp(USER_NAME_AVP, 0, MANDITORY_FLAG, (uint8_t *) username,
            strlen(username), (uint8_t *) out, &avp_out_size);

  avp_offset += avp_out_size;

  // Get the implicit challenge.
  challenge = (uint8_t *) implicit_challenge(eapdata);
  if (challenge == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid implicit challenge in %s()!\n",
		   __FUNCTION__);
      return;
    }

  memcpy(&mschap_challenge, challenge, 8);
  session_id = challenge[8];

  // Send the MS-CHAP challenge AVP.
  build_avp(MS_CHAP_CHALLENGE, MS_VENDOR_ATTR, (MANDITORY_FLAG | VENDOR_FLAG),
	    (uint8_t *) &mschap_challenge, 8, (uint8_t *) &out[avp_offset], 
	    &avp_out_size);

  avp_offset += avp_out_size;

  memset(mschap_answer, 0x00, 50);

  if (ctx == NULL)
	{
      debug_printf(DEBUG_NORMAL, "No password available for TTLS-MSCHAP!\n");
      eap_type_common_fail(eapdata);
      return;
	}

  if (ctx->prof->temp_password == NULL)
    {
		if ((phase2data == NULL) || (phase2data->password == NULL))
		{
			debug_printf(DEBUG_NORMAL, "No password available for TTLS-MSCHAP!\n");
			eap_type_common_fail(eapdata);
			return;
		}

		password = _strdup(phase2data->password);
    }
  else
  {
	  password = _strdup(ctx->prof->temp_password);
  }

  NtChallengeResponse((char *)&mschap_challenge, password, 
		      (char *)&mschap_result, 0);

  FREE(password);

  mschap_answer[0] = session_id;
  mschap_answer[1] = 1;  // Use NT style passwords.
  memcpy(&mschap_answer[26], mschap_result, 24);

  build_avp(MS_CHAP_RESPONSE, MS_VENDOR_ATTR, (MANDITORY_FLAG | VENDOR_FLAG),
	    mschap_answer, 50, &out[avp_offset], &avp_out_size);

  *outsize = avp_offset + avp_out_size;

  debug_printf(DEBUG_AUTHTYPES, "Returning from %s() :\n", __FUNCTION__);
  debug_hex_dump(DEBUG_AUTHTYPES, out, *outsize);

#ifdef HAVE_OSC_TNC
  ttls_tnc_start(out, (size_t*)outsize);
#endif

  eapdata->ignore = FALSE;
  eapdata->methodState = MAY_CONT;
  eapdata->decision = COND_SUCC;
  eapdata->credsSent = TRUE;
}

/************************************************************************
 *
 * Do any cleanup that we need to do.
 *
 ************************************************************************/
void mschap_deinit(eap_type_data *eapdata)
{
  // Nothing to do here.
}
