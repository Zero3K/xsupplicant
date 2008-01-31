/**
 * EAPTTLS Phase 2 CHAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file chap.c
 *
 * \author chris@open1x.org
 *
 * $Id: chap.c,v 1.5 2008/01/26 03:19:43 chessing Exp $
 * $Date: 2008/01/26 03:19:43 $
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
#include "src/eap_types/md5/md5.h"
#include "osc_ttls_tnc.h"
#include "chap.h"
#include "src/eap_types/eap_type_common.h"
#include "src/ipc_events.h"
#include "src/ipc_events_index.h"

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
void chap_check(eap_type_data *eapdata)
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

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-CHAP) Checking...\n");

  outerdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

  phase2data = (struct config_pwd_only *)outerdata->phase2_data;

  if ((phase2data == NULL) || (phase2data->password == NULL))
    {
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
	      debug_printf(DEBUG_NORMAL, "No password available for TTLS-CHAP!\n");
	      eap_type_common_fail(eapdata);
	      return;
		}

		if (ctx->prof->temp_password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for TTLS-CHAP!\n");
			eap_type_common_fail(eapdata);
			return;
		}
    }
}

/*************************************************************************
 *
 * Process a CHAP request message.  (There shouldn't be any.)
 *
 *************************************************************************/
void chap_process(eap_type_data *eapdata, uint8_t *in, uint16_t insize)
{
  // There is nothing to process for CHAP.
  if (in != NULL)
    {
      debug_printf(DEBUG_NORMAL, "Got additional data following the "
                   "completion of the TTLS-CHAP handshake.  Your "
		   "authentication will fail.\n");
      eap_type_common_fail(eapdata);

      debug_printf(DEBUG_AUTHTYPES, "Invalid data received (%d) :\n", insize);
      debug_hex_dump(DEBUG_AUTHTYPES, in, insize);
    }
}

/*************************************************************************
 *
 * Build a CHAP response message.
 *
 *************************************************************************/
void chap_buildResp(eap_type_data *eapdata, uint8_t *out, uint16_t *outsize)
{
  struct config_eap_ttls *outerdata = NULL;
  struct config_pwd_only *phase2data = NULL;
  char *username = NULL, *user_passwd = NULL;
  uint16_t avp_out_size = 0, avp_offset = 0, tohashlen = 0;
  uint8_t session_id = 0;
  uint8_t *challenge = NULL, chap_challenge[18], *tohash = NULL;
  uint8_t chap_hash[17], md5_result[16];
  struct MD5Context md5ctx;
  context *ctx = NULL;

  *outsize = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-CHAP) Building response.\n");

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

  memcpy(&chap_challenge, challenge, 16);
  session_id = challenge[16];
  FREE(challenge);

  if ((phase2data == NULL) || (phase2data->password == NULL))
  {
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
	user_passwd = _strdup(ctx->prof->temp_password);
  }
  else
  {
	user_passwd = phase2data->password;
  }

  tohash = (uint8_t *)Malloc(1+16+strlen(user_passwd));
  if (tohash == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of \"tohash\" in %s().\n",
		   __FUNCTION__);
	  ipc_events_malloc_failed(NULL);
      return;
    }

  tohash[0] = session_id;
  memcpy(&tohash[1], user_passwd, strlen(user_passwd));
  memcpy(&tohash[1+strlen(user_passwd)], &chap_challenge, 16);
  tohashlen = 1+strlen(user_passwd)+16;

  memset(&md5ctx, 0x00, sizeof(md5ctx));

  MD5Init(&md5ctx);
  MD5Update(&md5ctx, tohash, tohashlen);
  MD5Final(&md5_result[0], &md5ctx);

  debug_printf(DEBUG_AUTHTYPES, "MD5 Result : ");
  debug_hex_printf(DEBUG_AUTHTYPES, md5_result, 16);

  chap_hash[0] = session_id;
  memcpy(&chap_hash[1], md5_result, 16);

  build_avp(CHAP_PASSWORD_AVP, 0, MANDITORY_FLAG, chap_hash, 17,
	    (uint8_t *)&out[avp_offset], &avp_out_size);

  avp_offset += avp_out_size;

  build_avp(CHAP_CHALLENGE_AVP, 0, MANDITORY_FLAG, (uint8_t *)&chap_challenge,
	    16, (uint8_t *)&out[avp_offset], &avp_out_size);

  FREE(tohash);

  *outsize = avp_offset + avp_out_size;

  debug_printf(DEBUG_AUTHTYPES, "Returning from %s() :\n", __FUNCTION__);
  debug_hex_dump(DEBUG_AUTHTYPES, out, *outsize);

#ifdef HAVE_OSC_TNC
  ttls_tnc_start(out, (size_t*)outsize);
#endif

  eapdata->ignore = FALSE;
  eapdata->methodState = MAY_CONT;
  eapdata->decision = COND_SUCC;
}

/************************************************************************
 *
 * Do any cleanup that we need to do.
 *
 ************************************************************************/
void chap_deinit(eap_type_data *eapdata)
{
  // Nothing to do here.
}
