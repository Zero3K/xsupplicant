/**
 * EAPTTLS Phase 2 Common Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file phase2_common.c
 *
 * \author chris@open1x.org
 *
 * $Id: phase2_common.c,v 1.4 2007/10/20 09:19:27 galimorerpg Exp $
 * $Date: 2007/10/20 09:19:27 $
 **/
#include <string.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "src/eap_sm.h"
#include "src/frame_structs.h"
#include "src/eap_types/tls/eaptls.h"
#include "src/eap_types/tls/tls_funcs.h"
#include "phase2_common.h"
#include "src/ipc_events.h"
#include "src/ipc_events_index.h"

#ifdef WINDOWS
#include <Winsock2.h>
#include "src/event_core_win.h"
#else
#include <stdint.h>
#include "src/event_core.h"
#endif

/**************************************************************************
 *
 * Create a properly formatted RADIUS attribute value pair.
 *
 **************************************************************************/
void build_avp(uint32_t avp_value, uint32_t avp_vendor, uint64_t avp_flags,
	       uint8_t * in_value, uint64_t in_value_len, uint8_t * out_value,
	       uint16_t * out_size)
{
	int avp_padded;
	uint32_t avp_vendor_stuff;
	uint32_t avp_code;
	uint32_t bitmask_avp_len;

	if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
		return;

	*out_size = 0;

	if (!xsup_assert((in_value != NULL), "in_value != NULL", FALSE))
		return;

	if (!xsup_assert((out_value != NULL), "out_value != NULL", FALSE))
		return;

	avp_code = htonl(avp_value);
	avp_vendor_stuff = htonl(avp_vendor);

	if (avp_vendor != 0) {
		in_value_len = in_value_len + 4;
	}

	if ((in_value_len % 4) != 0) {
		avp_padded = (in_value_len + (4 - (in_value_len % 4)));
	} else {
		avp_padded = in_value_len;
	}
	bitmask_avp_len = htonl((avp_flags << 24) + in_value_len + 8);

	memset(out_value, 0x00, avp_padded + 12);
	memcpy(&out_value[0], &avp_code, 4);
	memcpy(&out_value[4], &bitmask_avp_len, 4);
	if (avp_vendor != 0) {
		memcpy(&out_value[8], &avp_vendor_stuff, 4);
		memcpy(&out_value[12], in_value, in_value_len);
		*out_size = avp_padded + 8;
	} else {
		memcpy(&out_value[8], in_value, in_value_len);
		*out_size = avp_padded + 8;
	}
}

/************************************************************************
 *
 * From section 10.1 of the TTLS draft, generates data used as challenge
 * material for PAP/CHAP/MSCHAP/MSCHAPv2.
 *
 ************************************************************************/
uint8_t *implicit_challenge(eap_type_data * eapdata)
{
	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return NULL;

	return tls_funcs_gen_keyblock(eapdata->eap_data, TLS_FUNCS_CLIENT_FIRST,
				      TTLS_CHALLENGE, TTLS_CHALLENGE_SIZE);
}

/*******************************************************************
 *
 *  Build a fake request identity message that can be used in phase 2.
 *
 *******************************************************************/
uint8_t *build_request_id(uint8_t reqId)
{
	struct eap_header *eaphdr;
	uint8_t *buffer = NULL;

	buffer = Malloc(sizeof(struct eap_header));
	if (buffer == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store request "
			     "identity packet!\n");
		ipc_events_malloc_failed(NULL);
		return NULL;
	}

	eaphdr = (struct eap_header *)buffer;

	eaphdr->eap_code = EAP_REQUEST_PKT;
	eaphdr->eap_identifier = reqId;
	eaphdr->eap_length = ntohs(sizeof(struct eap_header));
	eaphdr->eap_type = EAP_TYPE_IDENTITY;

	return buffer;
}
