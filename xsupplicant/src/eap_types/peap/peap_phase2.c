/**
 * PEAP phase 2 implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file peap_phase2.c
 *
 * \author chris@open1x.org
 *
 **/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "src/eap_sm.h"
#include "peap_phase2.h"
#include "eappeap.h"
#include "../tls/eaptls.h"
#include "../tls/tls_funcs.h"
#include "src/xsup_err.h"
#include "src/xsup_debug.h"
#include "../mschapv2/eapmschapv2.h"
#include "../otp/eapotp.h"
#include "src/frame_structs.h"
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

#define VALID_EAP_TYPE  EAP_TYPE_MSCHAP

static uint8_t eap_ident = 0;

/*******************************************************************
 *
 *  Set the PEAP version that we will be using.
 *
 *******************************************************************/
uint8_t set_peap_version(struct phase2_data *p2d, uint8_t new_version)
{
  if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
    return XEMALLOC;

  if (new_version > HIGHEST_PEAP_SUPPORTED) 
    {
      p2d->peap_version = HIGHEST_PEAP_SUPPORTED;
      return HIGHEST_PEAP_SUPPORTED;
    }

  /* Only change versions if we are changing to a higher one.  This will   *
   * keep us from backing off to a lower version mid-communication, should *
   * the RADIUS server get confused.                                       */
  if (p2d->peap_version < new_version)
    {
      debug_printf(DEBUG_AUTHTYPES, "PEAP Version changed to %d\n",
		   new_version);

      p2d->peap_version = new_version;
    }
  return p2d->peap_version;
}

/**************************************************************************
 *
 * Get PEAP version #.
 *
 **************************************************************************/
uint8_t get_peap_version(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct phase2_data *p2d;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((eapdata->eap_data != NULL),
		   "eapdata->eap_data != NULL", FALSE))
    return 0;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  p2d = mytls_vars->phase2data;

  if (p2d == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't determine the PEAP version we "
		   "are using!\n");
      return 0;
    }

  return p2d->peap_version;
}

/**************************************************************************
 *
 * Remove the PEAP padding that is used to make a v0 packet a v1 packet.
 *
 **************************************************************************/
void peap_unpad_frame(uint8_t *in, uint16_t in_size, uint8_t *out, 
		      uint16_t *out_size)
{
  if (!xsup_assert((in != NULL), "in != NULL", FALSE))
    return;

  if (!xsup_assert((out != NULL), "out != NULL", FALSE))
    return;

  if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
    return;

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Packet too large in peap_unpad_frame()!\n");
      return;
    }

  if ((in_size - 4) <= 0)
  {
	  debug_printf(DEBUG_NORMAL, "Your RADIUS server is on crack!  It sent an empty inner packet!\n");
	  return;
  }

  *out_size = in_size - 4;

  memcpy(out, &in[4], (in_size - 4));
}

/*************************************************************************
 *
 * Pad out the packet so that a v0 packet is a v1 packet that can be
 * processed by the EAP state machine.
 *
 * A v0 packet is basically missing the first 4 bytes of an EAP message. So,
 * we need to recreate those.  The identifier can't be gleaned from any
 * data we know, so it is stored in a static variable called eap_ident.
 * eap_ident should be incremented each time, before it is used in order
 * to keep the EAP state machine from discarding the packet.
 *
 *************************************************************************/
void peap_pad_frame(uint8_t *in, uint16_t in_size, uint8_t *out, 
		    uint16_t *out_size)
{
  struct eap_header *eaphdr;

  if (!xsup_assert((in != NULL), "in != NULL", FALSE))
    return;

  if (!xsup_assert((out != NULL), "out != NULL", FALSE))
    return;

  if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
    return;

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "In packet size to large!  Ignoring!\n");
      return;
    }

  *out_size = in_size + 4;

  eaphdr = (struct eap_header *)out;

  eaphdr->eap_code = EAP_REQUEST_PKT;

  if (eap_ident == 0xff) eap_ident = 0;

  eap_ident ++;

  eaphdr->eap_identifier = eap_ident;
  eaphdr->eap_length = htons(in_size+4);

  memcpy(&out[4], in, in_size);
}


/***********************************************************************
 *
 * Process a PEAP v1 packet.
 *
 ***********************************************************************/
int do_peap_version1(struct phase2_data *p2d, uint8_t *in, uint16_t in_size, 
		      uint8_t *out, uint16_t *out_size)
{
  uint8_t *padded_frame = NULL;
  uint8_t eapvalue, eapid;
  int retval = XENONE;

  if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((out != NULL), "out != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
    return XEMALLOC;

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Invalid frame passed in to do_peap_version1()!\n");
      return XEINVALIDEAP;
    }

  debug_printf(DEBUG_AUTHTYPES, "Unpadded packet (%d) :\n", in_size);
  debug_hex_dump(DEBUG_AUTHTYPES, in, in_size);
  
  *out_size = 0;

  eapvalue = in[4];
  eapid = in[5]; /* Inner EAP id. */

  debug_printf(DEBUG_AUTHTYPES, "Inner packet : \n");
  if (in_size < 1522)
    {
      debug_hex_dump(DEBUG_AUTHTYPES, in, in_size);
      p2d->sm->eapReq = TRUE;
      p2d->sm->eapReqData = in;
    } else {
      debug_printf(DEBUG_AUTHTYPES, "INVALID PACKET SIZE!\n");
    }

  switch (eapvalue)
    {
      case PEAP_EAP_EXTENSION: /* EAP Extension */
      debug_printf(DEBUG_AUTHTYPES, "Got an EAP extension frame!\n");
      out[0] = EAP_RESPONSE_PKT;
      memcpy(&out[1], &in[1], in_size-1);
      p2d->sm->decision = COND_SUCC;
      *out_size = in_size;
      return XEINNERDONE;
      break;

    default:
      debug_printf(DEBUG_AUTHTYPES, "Running inner state machine...\n");
      eap_sm_run(p2d->sm);
      break;
    }
  
  FREE(padded_frame);

  if (p2d->sm->eapRespData != NULL)
  {
	debug_printf(DEBUG_AUTHTYPES, "Inner EAP returned : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, p2d->sm->eapRespData, eap_type_common_get_eap_length(p2d->sm->eapRespData));
  }
  else
  {
	  debug_printf(DEBUG_AUTHTYPES, "No data returned from inner EAP method.\n");
	  if (p2d->sm->eapSuccess == TRUE) 
	    {
	      debug_printf(DEBUG_AUTHTYPES, "Inner auth completed.\n");
	      retval = XEINNERDONE;
	    }
  }

  if (p2d->sm->eapRespData != NULL)
    {
      *out_size = eap_type_common_get_eap_length(p2d->sm->eapRespData);
      memcpy(out, p2d->sm->eapRespData, *out_size);
      FREE(p2d->sm->eapRespData);
    }

  return retval;
}

/**********************************************************************
 *
 * Process a PEAP v0 packet.  To do this, we want to rebuild the EAP
 * header so that it looks like a PEAP v1 packet.  Once we are done
 * processing the packet as a PEAP v1 packet, we need to remove the
 * padding, so that we send back a v0 packet.
 *
 **********************************************************************/
int do_peap_version0(struct phase2_data *p2d, uint8_t *in, uint16_t in_size, 
		     uint8_t *out, uint16_t *out_size)
{
  uint8_t *padded_frame = NULL, *new_frame = NULL, eframe = 0;
  uint16_t padded_size = 0, new_frame_size = 0;
  int retval = XENONE;

  if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((in != NULL), "in != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((out != NULL), "out != NULL", FALSE))
    return XEMALLOC;

  *out_size = 0;

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Input frame is too big! Ignoring!\n");
      *out_size = 0;
      retval = XEMALLOC;
      goto out;
    }

  padded_size = in_size;

  padded_frame = (uint8_t *)Malloc(in_size+19);  // It is 19 bytes to pad out.
  if (padded_frame == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Unable to allocate memory for padded_frame "
		   "in %s()!\n", __FUNCTION__);
	  ipc_events_malloc_failed(NULL);
      retval = XEMALLOC;
      goto out;
    }

  if ((in[4] == 0x21) && (in[5] == 0x80))
    {
      eframe = 1;
      memcpy(padded_frame, in, in_size);
    }

  if (eframe != 1) 
    {
      peap_pad_frame(in, in_size, (uint8_t *) padded_frame, &padded_size);
    }

  new_frame = (uint8_t *)Malloc(1522);
  if (new_frame == NULL)
    {
      debug_printf(DEBUG_NORMAL, "ACK!  We can't allocate memory!\n");
	  ipc_events_malloc_failed(NULL);
      retval = XEMALLOC;
      goto out;
    }
 
  retval = do_peap_version1(p2d, padded_frame, padded_size, 
			    (uint8_t *) new_frame, &new_frame_size);

  if (eframe != 1) 
    {
      peap_unpad_frame((uint8_t *) new_frame, new_frame_size, out, out_size);
    } else {
      memcpy(out, new_frame, new_frame_size);
      *out_size = new_frame_size;
    }
    
  out:
  FREE(new_frame);
  FREE(padded_frame);

  return retval;
}


/************************************************************************
 *
 * Check to make sure we have enough data to do a phase 2 authentication.
 *
 ************************************************************************/
void peap_phase2_check(eap_type_data *eapdata)
{
  struct config_eap_peap *peapconf = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

  if (peapconf->phase2 == NULL)
    {
      eap_type_common_fail(eapdata);
      return;
    }
}

/************************************************************************
 *
 * Init our phase 2 data.
 *
 ************************************************************************/
uint8_t peap_phase2_init(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct phase2_data *p2d = NULL;
  struct config_eap_peap *peapconf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL),
		   "eapdata->eap_data != NULL", FALSE))
    return FALSE;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (mytls_vars->phase2data == NULL)
    {
      // Allocate memory for phase 2 data.
      mytls_vars->phase2data = Malloc(sizeof(struct phase2_data));
      if (mytls_vars->phase2data == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for phase 2"
		       " data!\n");
	  ipc_events_malloc_failed(NULL);
	  return FALSE;
	}
    }

  peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

  if (!xsup_assert((peapconf != NULL), "peapconf != NULL", FALSE))
    return FALSE;

  p2d = mytls_vars->phase2data;

  if (p2d->sm != NULL)
    {
		// Clear out the old state machine, so we don't end up with any weirdness.
		eap_sm_deinit(&p2d->sm);
    }

  if (eap_sm_init(&p2d->sm) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't init inner EAP state machine."
		       "\n");
	  return FALSE;
	}

  p2d->sm->phase = 2;
  p2d->sm->curMethods = peapconf->phase2;
  p2d->sm->portEnabled = TRUE;
  p2d->sm->idleWhile = config_get_idleWhile();
  
  ctx = event_core_get_active_ctx();

  if ((ctx != NULL) && (ctx->prof != NULL) && (ctx->prof->temp_username != NULL))
  {
	  p2d->sm->ident = ctx->prof->temp_username;
  }
  else if (peapconf->identity != NULL)
  {
	p2d->sm->ident = peapconf->identity;
  }
  else
  {
	  p2d->sm->ident = NULL;
  }

  eap_sm_run(p2d->sm);

  return TRUE;
}

/************************************************************************
 *
 * Process a phase 2 packet.
 *
 ************************************************************************/
void peap_phase2_process(eap_type_data *eapdata, uint8_t *indata, 
			 uint16_t insize)
{
  struct tls_vars *mytls_vars;
  struct phase2_data *p2d;
  struct config_eap_peap *peapconf;
  int res = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), "eapdata->eap_conf_data != NULL",
		FALSE))
		return;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (indata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid data passed in to PEAP phase 2!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  peapconf = (struct config_eap_peap *)eapdata->eap_conf_data;

  if ((peapconf->identity != NULL) && (eapdata->ident != peapconf->identity))
	  eapdata->ident = peapconf->identity;

  p2d = mytls_vars->phase2data;

  if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
    {
		eap_type_common_fail(eapdata);
      return;
    }

  p2d->result_data = Malloc(1520);
  if (p2d->result_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store resulting"
		   " packet.\n");
	  ipc_events_malloc_failed(NULL);
	  eap_type_common_fail(eapdata);
      return;
    }

  switch (p2d->peap_version)
    {
    case 0:
      debug_printf(DEBUG_AUTHTYPES, "Doing PEAP v0!\n");
      res = do_peap_version0(p2d, indata, insize, p2d->result_data,
			     &p2d->result_size);
      if ((res != XENONE) && (res != XEINNERDONE))
	{
	  debug_printf(DEBUG_NORMAL, "Inner PEAP v0 method failed.\n");
	  eap_type_common_fail(eapdata);
	}
      
      if (res == XEINNERDONE)
	{
	  debug_printf(DEBUG_AUTHTYPES, "Inner authentication complete!\n");
      	  eapdata->methodState = p2d->sm->methodState;
       	  eapdata->decision = p2d->sm->decision;
	  eapdata->ignore = p2d->sm->ignore;
       	  eapdata->altAccept = p2d->sm->eapSuccess;
	  eapdata->altReject = p2d->sm->eapFail;
	}	  
      break;

    case 1:
      debug_printf(DEBUG_AUTHTYPES, "Doing PEAP v1!\n");
      res = do_peap_version1(p2d, indata, insize, p2d->result_data,
			     &p2d->result_size);

      if ((res != XENONE) && (res != XEINNERDONE))
	{
	  debug_printf(DEBUG_NORMAL, "Inner PEAP v1 method failed.\n");
	  eap_type_common_fail(eapdata);
	}
      
      if (res == XEINNERDONE)
        {
          debug_printf(DEBUG_AUTHTYPES, "Inner authentication complete!\n");
          eapdata->methodState = p2d->sm->methodState;
          eapdata->decision = p2d->sm->decision;
          eapdata->ignore = p2d->sm->ignore;
	  //          eapdata->altAccept = p2d->sm->eapSuccess;
          eapdata->altReject = p2d->sm->eapFail;
        }
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown PEAP version %d!\n", 
		   p2d->peap_version);
	  ipc_events_error(NULL, IPC_EVENT_ERROR_UNKNOWN_PEAP_VERSION, NULL);
      eap_type_common_fail(eapdata);
      break;
    }
}

/************************************************************************
 *
 * Create a phase 2 response.
 *
 ************************************************************************/
void peap_phase2_buildResp(eap_type_data *eapdata, uint8_t *outdata,
			   uint16_t *outsize)
{
  struct tls_vars *mytls_vars;
  struct phase2_data *p2d;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    {
      *outsize = 0;
      return;
    }

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    {
      *outsize = 0;
      return;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  p2d = mytls_vars->phase2data;

  if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
    {
		eap_type_common_fail(eapdata);
      *outsize = 0;
      return;
    }

  if (p2d->result_data == NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "Nothing to return. ACKing.\n");
      *outsize = 0;
      return;
    }

  *outsize = p2d->result_size;
  memcpy(outdata, p2d->result_data, p2d->result_size);
  
  FREE(p2d->result_data);

  // We need to update the state to return to the phase 1 state machine.
  eapdata->ignore = p2d->sm->ignore;
}

/************************************************************************
 *
 * Clean up anything we have done.
 *
 ************************************************************************/
void peap_phase2_deinit(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars;
  struct phase2_data *p2d;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  p2d = mytls_vars->phase2data;

  if ((p2d != NULL) && (p2d->sm != NULL))
    {
      eap_sm_deinit(&p2d->sm);
    }

  FREE(mytls_vars->phase2data);
}
