/**
 * EAPTTLS Phase 2 PAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file pap.c
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
#include "pap.h"
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
void pap_check(eap_type_data *eapdata)
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

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-PAP) Checking...\n");

  outerdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

  phase2data = outerdata->phase2_data;

  if ((phase2data == NULL) || (phase2data->password == NULL))
    {
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
	      debug_printf(DEBUG_NORMAL, "No password available for TTLS-PAP!\n");
	      eap_type_common_fail(eapdata);
	      return;
		}

		if (ctx->prof->temp_password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for TTLS-PAP!\n");
			eap_type_common_fail(eapdata);
			return;
		}
    }
}

/***********************************************************************
 *
 *  Process a PAP request message.  (There should never be any.)
 *
 ***********************************************************************/
void pap_process(eap_type_data *eapdata, uint8_t *in, uint16_t insize)
{
  // There is nothing to process for PAP.
  if (in != NULL)
    {
      debug_printf(DEBUG_NORMAL, "Got additional data following the "
		   "completion of the TTLS-PAP handshake.  Your authentication"
		   " will fail.\n");
      eap_type_common_fail(eapdata);

      debug_printf(DEBUG_AUTHTYPES, "Invalid data received (%d) :\n", insize);
      debug_hex_dump(DEBUG_AUTHTYPES, in, insize);
    }
}

/***********************************************************************
 *
 * Build a PAP response message.
 *
 ***********************************************************************/
void pap_buildResp(eap_type_data *eapdata, uint8_t *out, uint16_t *outsize)
{
  struct config_eap_ttls *outerdata = NULL;
  struct config_pwd_only *phase2data = NULL;
  char *username = NULL;
  uint16_t avp_out_size = 0, avp_offset = 0;
  uint8_t passwd_size = 0;
  uint8_t *tempbuf = NULL;
  char *password = NULL;
  context *ctx = NULL;

  *outsize = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
                   "eapdata->eap_conf_data != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-PAP) Building response.\n");

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

  // We have the username AVP loaded, so it's time to build the password AVP.
  passwd_size = (strlen(password) +
                 (16-(strlen(password) % 16)));

  tempbuf = (uint8_t *)Malloc(passwd_size);
  if (tempbuf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of tempbuf in %s().\n",
		   __FUNCTION__);
	  ipc_events_malloc_failed(NULL);
      return;
    }

  memcpy(tempbuf, password, strlen(password));

  build_avp(USER_PASSWORD_AVP, 0, MANDITORY_FLAG, (uint8_t *) tempbuf,
            passwd_size, (uint8_t *) &out[avp_offset], &avp_out_size);
  *outsize = avp_offset + avp_out_size;

  FREE(password);
  FREE(tempbuf);

  debug_printf(DEBUG_AUTHTYPES, "Returning from %s() :\n", __FUNCTION__);

#ifdef UNSAFE_DUMPS
  debug_hex_dump(DEBUG_AUTHTYPES, out, *outsize);
#endif

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
void pap_deinit(eap_type_data *eapdata)
{
  // Nothing to do here.
}
