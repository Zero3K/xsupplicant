/**
 * EAPTTLS Phase 2 EAP Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ttls_eap.c
 *
 * \author chris@open1x.org
 *
 * $Id: ttls_eap.c,v 1.3 2007/10/17 07:00:55 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:55 $
 **/
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef WINDOWS
#include <Winsock2.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../xsup_err.h"
#include "../../eap_sm.h"
#include "../../ipc_callout.h"
#include "../../frame_structs.h"
#include "../../xsup_ipc.h"
#include "../../xsup_debug.h"
#include "../../xsup_common.h"
#include "phase2_common.h"
#include "osc_ttls_tnc.h"
#include "../../eap_types/tls/eaptls.h"
#include "../../eap_types/tls/tls_funcs.h"
#include "ttls_eap.h"
#include "../../eap_types/eap_type_common.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

/**
 *  \brief Enter INIT state and get everything ready to run EAP.
 *
 * @param[in] eapdata   A pointer to the eap_type_data structure that 
 *                      contains all of the information we need to init
 *                      EAP inside of TTLS.
 * @param[in] fake_id   Should we generate a fake Request-ID request
 *                      in order to allow EAP to start with a 
 *                      response ID message.  (Needed for the first
 *                      EAP authentication in the tunnel.)
 **/
void ttls_eap_init(eap_type_data *eapdata, uint8_t fake_id)
{
  struct tls_vars *mytls_vars = NULL;
  eap_sm *sm = NULL;
  struct config_eap_ttls *ttlsdata = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), 
		   "eapdata->eap_data != NULL", FALSE))
    {
      eapdata->decision = EAP_FAIL;
      eapdata->ignore = TRUE;
      return;
    }

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eapdata->decision = EAP_FAIL;
      eapdata->ignore = TRUE;
      return;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (eap_sm_init(&sm) != XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Error initing phase 2 EAP state machine!\n");
      eapdata->decision = EAP_FAIL;
      eapdata->ignore = TRUE;
      return;
    }

  sm->phase = 2;

  // Make sure we go in to init state, and not disabled.
  sm->portEnabled = TRUE;
  sm->idleWhile = config_get_idleWhile();
  sm->eapRestart = TRUE;

  // Run the EAP state machine once to get everything inited.
  eap_sm_run(sm);

  if (fake_id == TRUE)
  {
	// Then, create a fake request ID.
	sm->eapReqData = build_request_id(1);

	// And a pseudo-fake set of configuration data.
	ttlsdata = (struct config_eap_ttls *)eapdata->eap_conf_data;
	if (ttlsdata == NULL)
	{
      debug_printf(DEBUG_NORMAL, "There is no valid configuration data for "
		   "TTLS-EAP!\n");
      return;
    }

	if (ttlsdata->inner_id != NULL)
		sm->ident = ttlsdata->inner_id;

	if (ttlsdata->phase2_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid phase 2 data for "
		   "TTLS-EAP!\n");
	  eap_type_common_fail(eapdata);
      return;
    }

	sm->curMethods = ttlsdata->phase2_data;
  }

  // Save the state machine pointer.
  mytls_vars->phase2data = sm;
}

/******************************************************************
 *
 *  Determine that we have the proper data needed to complete the
 * authentication.
 *
 ******************************************************************/
void ttls_eap_check(eap_type_data *eapdata)
{
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), 
		   "eapdata->eap_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }
}

/**
 *  Dig through the diameter data that will be returned from the RADIUS
 *  server, and locate the EAP data that we need to pass to the handler.
 *
 *  Although Diameter allows for larger EAP fragement sizes, it is likely
 *  that some RADIUS implementations will send Diameter fragments of 253
 *  bytes.  So, we need to actually rebuild the EAP packet, and return
 *  a pointer to it.  The caller needs to realize that this is newly 
 *  allocated memory, and needs to be sure to free it when it has finished
 *  using it!
 **/
uint8_t *ttls_eap_get_eap(uint8_t *indata, uint16_t insize)
{
  uint32_t *value, attr, value32, newdatasize = 0;
  uint16_t ofs;
  uint8_t *newdata = NULL;

  ofs = 0;
  attr = 0;
  value32 = 0;
  value = NULL;

  debug_printf(DEBUG_AUTHTYPES, "Diameter Data (%d) : \n", insize);
  debug_hex_dump(DEBUG_AUTHTYPES, indata, insize);

  do
    {
      value = (uint32_t *)&indata[ofs];
      attr = ntohl((*value));
      
      // Get the length field.
      value = (uint32_t *)&indata[ofs + sizeof(uint32_t)];
      value32 = ntohl((*value));

      // Mask out extra flags.
      value32 = value32 & 0x00ffffff;

      debug_printf(DEBUG_AUTHTYPES, "Attribute %x found with length of %d.\n",
		   attr, value32);
      
      if (attr == EAP_DIAMETER_TYPE)
	{
	  if (newdata == NULL)
	    {
	      newdata = Malloc(value32 - (sizeof(uint32_t) * 2));
	      if (newdata == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate buffer to "
			       "reassemble EAP data!\n");
		  ipc_events_malloc_failed(NULL);
		  return NULL;
		}
	    }
	  else
	    {
	      newdata = realloc(newdata, newdatasize + (value32 - (sizeof(uint32_t) * 2)));
	      if (errno == ENOMEM)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't grow buffer to store "
			       "additional TTLS-EAP data from the "
			       "authenticator.\n");
		  ipc_events_malloc_failed(NULL);
		  return NULL;
		}
	    }

	  memcpy(&newdata[newdatasize], &indata[ofs + (sizeof(uint32_t) * 2)], 
		 (value32 - (sizeof(uint32_t) * 2)));
	  newdatasize += (value32 - (sizeof(uint32_t) * 2));
	}
      
      ofs += value32;
      if ((ofs % 4) != 0) 
	{
	  ofs += (4 - (ofs % 4));
	  printf("Padding %d byte(s).\n", (4 - (ofs % 4)));
	}
    }
  while ((ofs < insize) && (value32 != 0));

  debug_printf(DEBUG_AUTHTYPES, "Reassembled EAP (%d) : \n", newdatasize);
  debug_hex_dump(DEBUG_AUTHTYPES, newdata, newdatasize);
  return newdata;
}

/***********************************************************************
 *
 *  Process an EAP request message. 
 *
 ***********************************************************************/
void ttls_eap_process(eap_type_data *eapdata, uint8_t *in, uint16_t insize)
{
  struct tls_vars *mytls_vars = NULL;
  eap_sm *sm = NULL;
  struct config_eap_ttls *ttlsdata = NULL;

  xsup_assert((eapdata != NULL), "eapdata != NULL", TRUE);

  if ((in == NULL) || (eapdata->methodState == INIT))
    {
      // We need to init our state and build a fake ID request.
      ttls_eap_init(eapdata, TRUE);
    }
  else
    {
      if (!xsup_assert((eapdata->eap_data != NULL), 
		       "eapdata->eap_data != NULL", FALSE))
	{
		eap_type_common_fail(eapdata);
	  return;
	}

      mytls_vars = (struct tls_vars *)eapdata->eap_data;

	  if (mytls_vars->phase2data == NULL)
	  {
			ttlsdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

			if (ttlsdata->phase2_type != TTLS_PHASE2_EAP)
			{
				debug_printf(DEBUG_AUTHTYPES, "It appears we are starting EAP after doing a "
						"non-EAP phase 2 method.  We will init things.\n");
				ttls_eap_init(eapdata, FALSE);
			}
	  }

      if (!xsup_assert((mytls_vars->phase2data != NULL),
		       "mytls_vars->phase2data != NULL", FALSE))
	{
		eap_type_common_fail(eapdata);
	  return;
	}

      sm = mytls_vars->phase2data;

	  debug_printf(DEBUG_AUTHTYPES, "EAP innner data (%d) :\n", insize);
	  debug_hex_dump(DEBUG_AUTHTYPES, in, insize);

      // Locate the EAP portion of the packet
      sm->eapReqData = ttls_eap_get_eap(in, insize);

      if (sm->eapReqData == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "There didn't appear to be any EAP data "
		       "in the diameter packet!\n");
	  eap_type_common_fail(eapdata);
	  return;
	}
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  sm = mytls_vars->phase2data;

  if (sm == NULL) return;

  sm->eapReq = TRUE;
  debug_printf(DEBUG_AUTHTYPES, "[PHASE2] Running phase 2 state machine!\n");
  eap_sm_run(mytls_vars->phase2data);
  debug_printf(DEBUG_AUTHTYPES, "[PHASE2] Completed phase 2 state machine!\n");
}

/***********************************************************************
 *
 * Build an EAP response message.
 *
 ***********************************************************************/
void ttls_eap_buildResp(eap_type_data *eapdata, uint8_t *out, 
			uint16_t *outsize)
{
  struct eap_header *eaphdr = NULL;
  struct tls_vars *mytls_vars = NULL;
  eap_sm *sm = NULL;
  uint16_t eapsize = 0;
  uint64_t avp_offset = 0;
  uint16_t avp_out_size = 0;

  *outsize = 0;

  xsup_assert((eapdata != NULL), "eapdata != NULL", TRUE);

  if (!xsup_assert((eapdata->eap_data != NULL), 
		   "eapdata->eap_data != NULL", FALSE))
    {
		eap_type_common_fail(eapdata);
      return;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (!xsup_assert((mytls_vars->phase2data != NULL), 
		   "mytls_vars->phase2data != NULL", FALSE))
    {
		eap_type_common_fail(eapdata);
      return;
    }

  sm = (eap_sm *)mytls_vars->phase2data;

  if (!xsup_assert((sm != NULL), "sm != NULL", FALSE))
    {
		eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "(TTLS-EAP) Building response.\n");

  if (!xsup_assert((sm->eapRespData != NULL), "sm->eapRespData != NULL", 
		   FALSE))
    {
		eap_type_common_fail(eapdata);
      return;
    }

  eaphdr = (struct eap_header *)sm->eapRespData;

  eapsize = ntohs(eaphdr->eap_length);

  if (eapsize > 1520)
    {
      debug_printf(DEBUG_NORMAL, "EAP response data was larger than a valid "
		   "packet size!  (Size was %d)\n", eapsize);
      eap_type_common_fail(eapdata);
      return;
    }

  if (eapsize <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Inner EAP didn't return any data.\n");
      eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "sm->eapRespData (%d)  : \n", eapsize);
  debug_hex_dump(DEBUG_AUTHTYPES, sm->eapRespData, eapsize);

  build_avp(EAP_MESSAGE, 0, MANDITORY_FLAG, sm->eapRespData,
            eapsize, (uint8_t *) &out[avp_offset], &avp_out_size);
  *outsize = avp_offset + avp_out_size;

  debug_printf(DEBUG_AUTHTYPES, "Returning from %s() :\n", __FUNCTION__);
  debug_hex_dump(DEBUG_AUTHTYPES, out, *outsize);

  eapdata->ignore = sm->ignore;
  //eapdata->methodState = sm->methodState;
  eapdata->decision = sm->decision;

  if (eapdata->methodState == DONE)
    {
      debug_printf(DEBUG_AUTHTYPES, "Force state machine back in to INIT"
		   " in case we want to do a another EAP auth.\n");
      eap_sm_force_init(sm);
      eapdata->methodState = MAY_CONT;
      sm->methodState = INIT;
    }
}

/************************************************************************
 *
 * Do any cleanup that we need to do.
 *
 ************************************************************************/
void ttls_eap_deinit(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars;
  
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (mytls_vars->phase2data != NULL)
    {
      eap_sm_deinit((eap_sm **)&mytls_vars->phase2data);

      FREE(mytls_vars->phase2data);
    }
}
