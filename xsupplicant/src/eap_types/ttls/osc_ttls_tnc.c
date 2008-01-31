/**
 * EAPTTLS OSC Proprietary TNC Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file osc_ttls_tnc.c
 *
 * \author mikem@open.com.au
 *
 * $Id: osc_ttls_tnc.c,v 1.2 2007/09/24 02:12:30 galimorerpg Exp $
 * $Date: 2007/09/24 02:12:30 $
 **/

#ifdef HAVE_OSC_TNC

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "eap_sm.h"
#include "eap_types/ttls/phase2_common.h"
#include "xsup_debug.h"
#include "eap_types/eap_type_common.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

#include "eap_types/ttls/osc_ttls_tnc.h"
#include <libtnctncc.h>

#ifdef USE_EFENCE
#include <efence.h>
#endif

// global variables to hold destination buffer and lengths
// for sending messages. Since there is only ever one network
// connection being created in a single instance of xsupplicant, we do  not use
// the TNC connection ID to find out what connection we are talking about.
static uint8_t *dest_buf;
static size_t  *dest_size;
static uint8_t *resbuf;
static size_t ressize;

void ttls_tnc_start(uint8_t *out_value, size_t *out_size)
{
  // When the handshake starts, the IMC may try to send message(s) to the IMV
  // by calling TNC_TNCC_SendBatch
  // Remember the destination output buffer for when TNC_TNCC_SendBatch
  // is called
  dest_buf = out_value;
  dest_size = out_size;

  if (libtnc_tncc_BeginSession(0) != TNC_RESULT_SUCCESS)
    {
      debug_printf(DEBUG_NORMAL, "libtnc_tncc_BeginSession failed\n");
      return;
    }
  debug_printf(DEBUG_NORMAL, "Started IMC handshake\n");
}

/**
 * Process incoming decrypted inner message, looking for TNC IMC messages
 * and pass each one to the IMCs
 */
void ttls_tnc_process(uint8_t *in_value, size_t in_size, uint8_t *out_value,
                      size_t *out_size)
{
  int i = 0;

  while (i < in_size - 8) // AVP must be at least 8 octets
    {
      int      avpcode = ntohl(*(uint32_t*)(in_value + i));
      int      avplength = ntohl(*(uint32_t*)(in_value + i + 4));
      int      avpflags = (avplength >> 24) & 0xff;
      uint8_t *avpdata;
      int      avpdatalength;

      // Make sure we cant be fooled by silly sizes
      avplength &= 0xffffff;
      if (i + avplength > in_size)
	break;
      if (avpflags & 0x80)
        {
	  // Vendor ID is present
	  int avpvendor = ntohl(*(uint32_t*)(in_value + i + 8));
	  avpdata = in_value + i + 12;
	  avpdatalength = avplength - 12;
	  if (   avpvendor == OSC_VENDOR_ATTR
		 && avpcode == OSC_INTEGRITY_MESSAGE)
            {
	      // Its an OSC-Integrity-Message, which contains a TNCCS-Batch
	      // and has to be given to the IMC. This call may result in a 
	      // call to TNC_TNCC_SendBatch
	      // to send another batch of messages to the IMV at the server
	      dest_buf = out_value;
	      dest_size = out_size;
	      debug_printf(DEBUG_NORMAL, "Received an OSC-Integrity-Message\n"
			   );
	    }
        }
      else
        {
	  avpdata = in_value + i + 8;
	  avpdatalength = avplength - 8;
        }
      i += avplength;
      // Pad up to multiple of 4:
      if (i % 4)
	i += 4 - (i % 4);
    }
}

// Does the extra processing needed by Xsupplicant. (And calls the 
// process function above.)  Returns 1 if we created any data.
uint8_t ttls_tnc_do_process(eap_type_data *eapdata, uint8_t *indata, 
			 uint16_t insize)
{
  uint8_t result = 0;

  if (indata == NULL) return 0;

  resbuf = Malloc(1500);
  if (resbuf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store TNC data!"
		   "\n");
	  ipc_events_malloc_failed(NULL);
      eap_type_common_fail(eapdata);
      return 0;
    }

  ttls_tnc_process(indata, insize, resbuf, &ressize);

  if (ressize > 0)
    {
      // We have a valid result.
      result = 1;

      debug_printf(DEBUG_AUTHTYPES, "OSC TNC Response data : \n");
      debug_hex_dump(DEBUG_AUTHTYPES, resbuf, ressize);
    }
  else
    {
      FREE(resbuf);
    }

  return result;
}

void ttls_tnc_buildResp(eap_type_data *eapdata, uint8_t *result,
			uint16_t *result_size)
{
  if (ressize <= 0)
    {
      (*result_size) = 0;
      return;
    }

  // Otherwise, copy the data over to the result buffer, and move on.
  (*result_size) = ressize;

  memcpy(result, resbuf, ressize);

  FREE(resbuf);

  ressize = 0;
}

/**      
 * Called by TNCC when a finished batch is ready to send
 */
TNC_Result TNC_TNCC_SendBatch(
			      /*in*/ TNC_ConnectionID connectionID,
			      /*in*/ const char* messageBuffer,
			      /*in*/ size_t messageLength)
{
  int avp_out_size;

  // Append an OSC-Integrity-Message to the current output buffer
  build_avp(OSC_INTEGRITY_MESSAGE, OSC_VENDOR_ATTR, VENDOR_FLAG,
	    (uint8_t *)messageBuffer, messageLength,
	    dest_buf + *dest_size, &avp_out_size);
  *dest_size += avp_out_size;
  return TNC_RESULT_SUCCESS;
}

#endif
