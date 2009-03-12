/**
 * EAPTTLS Phase 2 Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ttlsphase2.c
 *
 * \author chris@open1x.org
 *
 **/

#ifndef WINDOWS
#include <inttypes.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../eap_sm.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../mschapv2/mschapv2.h"
#include "phase2_common.h"
#include "pap.h"
#include "chap.h"
#include "mschap.h"
#include "p2mschapv2.h"
#include "ttls_eap.h"
#include "ttlsphase2.h"
#include "../../eap_types/tls/eaptls.h"
#include "../../eap_types/tls/tls_funcs.h"
#include "../../eap_types/eap_type_common.h"

#ifdef HAVE_OSC_TNC
#include <libtnctncc.h>
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

struct phase2_handler {
	char *phase2name;
	void (*check) (eap_type_data *);
	void (*process) (eap_type_data *, uint8_t *, uint16_t);
	void (*buildResp) (eap_type_data *, uint8_t *, uint16_t *);
	void (*deinit) (eap_type_data *);
	ttls_phase2_type phase2type;
};

struct phase2_handler phase2types[] = {
	{"PAP", pap_check, pap_process, pap_buildResp, pap_deinit,
	 TTLS_PHASE2_PAP},
	{"CHAP", chap_check, chap_process, chap_buildResp, chap_deinit,
	 TTLS_PHASE2_CHAP},
	{"MS-CHAP", mschap_check, mschap_process, mschap_buildResp,
	 mschap_deinit,
	 TTLS_PHASE2_MSCHAP},
	{"MS-CHAPv2", mschapv2_check, mschapv2_process, mschapv2_buildResp,
	 mschapv2_deinit, TTLS_PHASE2_MSCHAPV2},
	{"EAP", ttls_eap_check, ttls_eap_process, ttls_eap_buildResp,
	 ttls_eap_deinit, TTLS_PHASE2_EAP},

	{NULL, NULL, NULL, NULL, NULL, -1}
};

/************************************************************************
 *
 *  Search through our list of known phase 2 methods, and find the index
 *  for the configured one.
 *
 ************************************************************************/
signed char ttls_phase2_get_idx(eap_type_data * eapdata)
{
	struct config_eap_ttls *userdata = NULL;
	uint8_t i = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return -1;

	if (!xsup_assert((eapdata->eap_conf_data != NULL),
			 "eapdata->eap_conf_data != NULL", FALSE))
		return -1;

	userdata = (struct config_eap_ttls *)eapdata->eap_conf_data;

	// We need to see what phase 2 method we should use.
	while ((phase2types[i].phase2type != -1) &&
	       (userdata->phase2_type != phase2types[i].phase2type)) {
		i++;
	}

	return i;
}

/*************************************************************************
 *
 *  Based on what is configured for our phase 2 type, check to see that it
 *  is ready to be used.
 *
 *************************************************************************/
void ttls_phase2_check(eap_type_data * eapdata)
{
	signed char idx = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	idx = ttls_phase2_get_idx(eapdata);

	if (phase2types[idx].check == NULL)
		return;

	phase2types[idx].check(eapdata);
}

/*************************************************************************
 *
 *  Process any incoming data that we may have.
 *
 *************************************************************************/
void ttls_phase2_process(eap_type_data * eapdata, uint8_t * indata,
			 uint16_t insize)
{
	signed char idx = 0;
	uint8_t *eapdiameter = NULL;
	struct tls_vars *mytls_vars = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) {
		eapdata->ignore = TRUE;
		return;
	}

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

#if HAVE_OSC_TNC
	if (ttls_tnc_do_process(eapdata, indata, insize) == TRUE) {
		// We consumed indata.
		return;
	}
#endif

	if (indata != NULL) {
		eapdiameter = ttls_eap_get_eap(indata, insize);

		if (eapdiameter == NULL) {
			idx = ttls_phase2_get_idx(eapdata);
		} else {
			idx = 0;
			while ((phase2types[idx].phase2type != -1) &&
			       (TTLS_PHASE2_EAP != phase2types[idx].phase2type))
			{
				idx++;
			}
		}
	} else {
		idx = ttls_phase2_get_idx(eapdata);
	}

	if (idx != mytls_vars->last_eap_type) {
		phase2types[mytls_vars->last_eap_type].deinit(eapdata);

		if (phase2types[idx].check != NULL) {
			phase2types[idx].check(eapdata);
		}
	}

	mytls_vars->last_eap_type = idx;

	if (phase2types[idx].process == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No processing function call available!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	phase2types[idx].process(eapdata, indata, insize);
}

/*************************************************************************
 *
 * Build a phase 2 response packet.
 *
 *************************************************************************/
void ttls_phase2_buildResp(eap_type_data * eapdata, uint8_t * res,
			   uint16_t * res_size)
{
	struct tls_vars *mytls_vars;
	signed char idx = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) {
		*res_size = 0;
		return;
	}

	if (!xsup_assert
	    ((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) {
		eap_type_common_fail(eapdata);
		return;
	}

	mytls_vars = (struct tls_vars *)eapdata->eap_data;

#if HAVE_OSC_TNC
	*res_size = 0;

	ttls_tnc_buildResp(eapdata, res, res_size);

	if ((*res_size) > 0) {
		// We got TNC data.  So, return.
		return;
	}
#endif

	//  idx = ttls_phase2_get_idx(eapdata);
	idx = mytls_vars->last_eap_type;

	if (phase2types[idx].buildResp == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No function defined to build a result "
			     "packet!\n");
		*res_size = 0;
		return;
	}

	phase2types[idx].buildResp(eapdata, res, res_size);
}

/**************************************************************************
 *
 *  Call a phase 2 deinit.
 *
 **************************************************************************/
void ttls_phase2_deinit(eap_type_data * eapdata)
{
	signed char idx = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;

	idx = ttls_phase2_get_idx(eapdata);

	if (phase2types[idx].deinit == NULL)
		return;

	phase2types[idx].deinit(eapdata);
}
