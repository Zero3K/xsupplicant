/**
 * Support for Trusted Network Connect EAP method
 *
 * \file eaptnc.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * \todo Add error events to this file!
 *
 **/

#ifdef HAVE_TNC
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#else
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../../stdintwin.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <libtnctncc.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "libxsupconfig/xsupconfig.h"   
#include "../../context.h"
#include "../../eap_sm.h"
#include "../../xsup_common.h"
#include "eaptnc.h"
#include "../eap_type_common.h"

#ifndef WINDOWS
#include "../../event_core.h"
#else
#include "../../event_core_win.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifndef WINDOWS
#warning Use config data, and get rid of the #define below.
#endif

// XXX Make this configurable.
#define TNC_MAX_FRAG  900

uint32_t totalretsize = 0;

struct tnc_data *tncdatahook = NULL;    // Used to provide binding on our *SendBatch call.

static int connectionID = 0;            // Start with a connection ID of 0.

/**
 * \brief Validate the TNC flags byte to be sure that it is using a version we support, and doesn't
 *        have any of the reserved bits set.
 *
 * @param[in] flagsver   The byte that we want to verify has the proper settings for TNC.
 *
 * \retval XENONE on success
 * \retval XEINVALIDFLAGSVER on failure.
 **/
int eaptnc_check_flags_ver(uint8_t flagsver)
{
  int retval = XENONE;

  // We don't want to terminate when we find an error.  Instead, we want
  // to kick back error message for each part of the check that fails.
  if ((flagsver & TNC_VERSION_MASK) > TNC_MAX_VERSION_SUPPORTED)
    {
      debug_printf(DEBUG_NORMAL, "Invalid version number %d!  We currently "
		   "only support up to version %d.\n", 
		   (flagsver & TNC_VERSION_MASK), TNC_MAX_VERSION_SUPPORTED);
      retval = XEINVALIDFLAGSVER;
    }

  if ((flagsver & TNC_RESERVED_FLAGS) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid flags set for EAP-TNC!  Something "
		   "was set to 1 in bit positions 4 and/or 5.\n");
      retval = XEINVALIDFLAGSVER;
    }

  return retval;
}

/**
 *  \brief Start a TNC conversation with the server.
 *
 * @param[in] eapdata   A pointer to the EAP data that we may need to complete a TNC authentication.
 *
 * \retval XENONE on success
 * \retval !XENONE on failure
 **/
int eaptnc_do_start(eap_type_data *eapdata)
{
	context *ctx = NULL;

  // A start message should contain a single byte that contains the start
  // flag, and a version flag.  So, we should make sure that there isn't
  // anything extra before we continue.

  if (eap_type_common_get_eap_length(eapdata->eapReqData) > 
      (sizeof(struct eap_header)+1))
    {
      debug_printf(DEBUG_NORMAL, "The start message from the authenticator "
		   "contained data beyond the start flag.  This is not "
		   "allowed!\n");
      return XEGENERROR;
    }
 
  if (eapdata->eap_data != NULL)
  {
	  debug_printf(DEBUG_NORMAL, "EAP data hook is unavailable!  (Did the previous EAP method "
			"free it?\n");
	  return XEGENERROR;
  }

  // Otherwise, create our structure.
  eapdata->eap_data = Malloc(sizeof(struct tnc_data));
  if (eapdata->eap_data == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store TNC stucture!!\n");
	  return XEMALLOC;
  }

  tncdatahook = (struct tnc_data *)eapdata->eap_data;

  ctx = event_core_get_active_ctx();
  if (ctx == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to start a TNC session with an invalid context!?\n");
	  return XEGENERROR;
  }

  // Remember the TNC connection ID, so that we can operate on the right context if the IMC
  // asks us to do something.
  if (ctx->tnc_connID == -1) {
	  ctx->tnc_connID = connectionID;

	  connectionID++;
  }

  if (libtnc_tncc_BeginSession(ctx->tnc_connID) != TNC_RESULT_SUCCESS)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-TNC) Failed to start TNC session!\n");
      return XETNCLIBFAILURE;
    }

  debug_printf(DEBUG_NORMAL, "(EAP-TNC) Started IMC Handshake.\n");
  return XENONE;
}

/**
 * \brief Process a bulk TNC data request.  (Basically, anything that isn't a TNC start message.)
 *
 * @param[in] eapdata   A pointer to EAP data that may be needed to complete a TNC session.
 *
 * \retval XENONE on success
 * \retval !XENONE on failure
 **/
int eaptnc_do_bulk_data(eap_type_data *eapdata)
{
  int retval = XENONE;
  int err = 0;
  uint8_t *dataptr = NULL;
  uint16_t datalen = 0;
  uint32_t value32 = 0;
  uint32_t expected = 0;
  uint8_t *tosend = NULL;
  struct tnc_data *tnc = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return XEGENERROR;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE))
	return XEGENERROR;

  if (!xsup_assert((eapdata->eapReqData != NULL), 
		   "eapdata->eapReqData != NULL", FALSE))
    return XEGENERROR;

  ctx = event_core_get_active_ctx();
  if (ctx == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Attempted to start a TNC bulk data transfer with an invalid context!?\n");
	  return XEGENERROR;
  }

  tnc = (struct tnc_data *)eapdata->eap_data;

  datalen = eap_type_common_get_eap_length(eapdata->eapReqData);
  datalen -= sizeof(struct eap_header);

  dataptr = &eapdata->eapReqData[sizeof(struct eap_header)];

  if (eap_type_common_get_eap_length(eapdata->eapReqData) <= (sizeof(struct eap_header)+1))
    {
		if (((dataptr[0] & TNC_MASK_OUT_VER) == 0x00) && (tnc->tncoutqueue == NULL))
		{
			debug_printf(DEBUG_NORMAL, "The server ACKed our ACK?\n");
			eap_type_common_fail(eapdata);
			return XEGENERROR;
		}
    }

  if (dataptr[0] & TNC_LENGTH_FLAG)
    {
      dataptr++;
      datalen--;
      
      memcpy(&value32, dataptr, sizeof(uint32_t));
      value32 = ntohl(value32);
      
      debug_printf(DEBUG_AUTHTYPES, "Expecting %d byte(s) of data from "
		   "TNC authenticator.\n", value32);

	  tnc->expected_in = value32;
      
      dataptr += 4;
      datalen -= 4;
    }
  else
    {
      // Skip the flags byte.
      dataptr++;
      datalen--;
    }

  // Starting at the current position of dataptr, and going to dataptr+datalen
  // is the next block of data we need.
  if (tnc->tncinqueue == NULL)
    {
		if (queue_create(&tnc->tncinqueue) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't create TNC queue!\n");
			return XEMALLOC;
		}
    }

  if (datalen > 0)
  {
	err = queue_enqueue(&tnc->tncinqueue, dataptr, datalen);
	if (err != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't enqueue new incoming TNC data! (Error : %d)\n", err);
	  return XEMALLOC;
	}
  }
  else
  {
	  debug_printf(DEBUG_AUTHTYPES, "TNC appears to be an ACK.\n");
  }

  dataptr = &eapdata->eapReqData[sizeof(struct eap_header)];

  if (!(dataptr[0] & TNC_MORE_FLAG))
    {
      // There is nothing more that will be sent to us (in this block).
      // Check that we have enough data.  If we don't have exactly the right
      // amount, display a message, and continue.
		err = queue_get_size(&tnc->tncinqueue, &value32);
		if (err != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't determine queue depth! (Error : %d)\n", err);
			return XEGENERROR;
		}

		if (value32 < tnc->expected_in)
		{
		  debug_printf(DEBUG_NORMAL, "There is less data in the TNC buffer "
			       "than we expected.  It is likely that TNC will "
				   "fail.  (Expected : %d   Got : %d)\n", tnc->expected_in, value32);
		}

		// Remember what we expected.
		expected = value32;

		if (queue_dequeue(&tnc->tncinqueue, &tosend, &value32) != 0)
		{
			debug_printf(DEBUG_AUTHTYPES, "Couldn't dequeue any data for TNC!\n");
			return XEGENERROR;
		}

		if (expected != value32)  // Uhh...  This shouldn't be possible!
		{
			debug_printf(DEBUG_NORMAL, "Failed to dequeue as much data as the queue claimed it had! (Expected %d, got %d)\n", expected, value32);
			FREE(tosend);
			return XEGENERROR;
		}

      // We have an XML block to send.
      if (libtnc_tncc_ReceiveBatch(ctx->tnc_connID, tosend, value32) != TNC_RESULT_SUCCESS)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't send TNC batch to libtnc!\n");
	  if (queue_destroy(&tnc->tncinqueue) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't destroy used queue!\n");
	  }

	  FREE(tosend);
	  return XEGENERROR;
	}

	  FREE(tosend);

	  if (queue_queue_done(&tnc->tncinqueue) == 1)
	  {
		  queue_destroy(&tnc->tncinqueue);
		  tnc->expected_in = 0;
	  }
      
   }

  return retval;
}

/**
 * \brief Process a version 1 TNC request.
 *
 *  Right now, there is only 1 version of TNC.  But, since a version is included it is reasonable that
 *  there may be other versions developed.  If there are, we should be able to integrate them easily.
 *
 * @param[in] eapdata   A pointer to EAP data that may be needed to complete a TNC session.
 * @param[in] eapreq   A pointer to a buffer containing the EAP request message.
 * @param[in] size   The size of the EAP request message.
 *
 * \retval XENONE on success
 * \retval !XENONE on failure
 **/
uint16_t eaptnc_process_version_1(eap_type_data *eapdata, uint8_t *eapreq,
				  uint16_t size)
{
  int retval = XENONE;

  if (eapreq[0] & TNC_START_FLAG)
    {
      // Process a start message.
      debug_printf(DEBUG_AUTHTYPES, "(EAP-TNC) Process Start\n");
      retval = eaptnc_do_start(eapdata);
    }
  else
    {
      // Process a bulk data frame.
      debug_printf(DEBUG_AUTHTYPES, "(EAP-TNC) Process bulk data\n");
      retval = eaptnc_do_bulk_data(eapdata);
    }

  return retval;
}

/**
 * \brief Verify that we have everything we need to run TNC.
 *
 * @param[in] eapdata   A pointer to EAP data that may be needed to complete a TNC session.
 **/
void eaptnc_check(eap_type_data *eapdata)
{
	if (eapdata->eap_data != NULL)
		tncdatahook = (struct tnc_data *)eapdata->eap_data;
}

/**
 * \brief Process a TNC request.
 *
 * @param[in] eapdata   A pointer to EAP data that may be needed to complete this TNC session.
 **/
void eaptnc_process(eap_type_data *eapdata)
{
  uint16_t retval = 0, eapsize = 0;
  struct eap_header *eaphdr;
  uint8_t *tnc_data;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eapReqData != NULL), 
		   "eapdata->eapReqData != NULL", FALSE))
    {
      eapdata->ignore = TRUE;
      eapdata->decision = EAP_FAIL;
      return;
    }

  // If we get here, then we can assume the credentials used were valid.
  // So, we want to sent credsSent to FALSE so that if the user is failed
  // because of bad posture, they aren't prompted for their password again.
  eapdata->credsSent = FALSE;

  eaphdr = (struct eap_header *)eapdata->eapReqData;

  eapsize = ntohs(eaphdr->eap_length) - sizeof(struct eap_header);

  tnc_data = &eapdata->eapReqData[sizeof(struct eap_header)];

  // The code, identifier, length, and type should be stripped at this point.
  // So start by validating the Flags/Ver byte, and process from there.
  retval = eaptnc_check_flags_ver(tnc_data[0]);
  if (retval != XENONE) return;

  // This is overkill for now, but since there is a version, we implement
  // this now, so we can expand it later.
  switch ((tnc_data[0] & TNC_VERSION_MASK))
    {
    case 1:
      // Process a version 1 request.
      retval = eaptnc_process_version_1(eapdata, tnc_data, eapsize);
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown TNC version in request! (Version %d)\n",
		  (tnc_data[0] & TNC_VERSION_MASK));

	  eap_type_common_fail(eapdata);
      break;
    }
}

/**
 *  \brief Build a TNC response.
 *
 * @param[in] eapdata   A pointer to EAP data that may be needed to complete a TNC session.
 *
 * \retval ptr to the resulting EAP packet that is to be sent to the authenticator.
 * \retval NULL on failure
 **/
uint8_t *eaptnc_buildResp(eap_type_data *eapdata)
{
  uint8_t *resdata = NULL, *resdataptr = NULL, *retdata = NULL, *dataptr = NULL, *dequeue_data = NULL;
  struct eap_header *eaphdr = NULL;
  uint32_t value32 = 0, cpysize = 0, extra = 0, totalsize = 0, queuesize = 0, res_size = 0, retlen = 0;
  uint16_t value16 = 0;
  struct tnc_data *tnc = NULL;
  uint8_t *tosend = NULL;
  int maxsize = TNC_MAX_FRAG;
  int more = 0;
  int athead = 0;

  if (eapdata == NULL) return NULL;

  if (eapdata->eap_data == NULL) return NULL;

  tnc = (struct tnc_data *)eapdata->eap_data;

  // XXX Need to set a way to specify a fragment size.
  resdata = Malloc(1010);
  if (resdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store TNC "
		   "result fragment.\n");
      return NULL;
    }

  resdataptr = resdata;

  // Build an EAP header.
  eaphdr = (struct eap_header *)resdata;
  
  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
  eaphdr->eap_type = EAP_TYPE_TNC;

  resdataptr += sizeof(struct eap_header);

  // Otherwise, return some data from the buffer.
  if (tnc->tncoutqueue == NULL)
    {
      // Send an ACK.
      debug_printf(DEBUG_AUTHTYPES, "(EAP-TNC) ACKing.\n");
      eaphdr->eap_length = htons(sizeof(struct eap_header)+1);
      resdataptr[0] = 0x00 | TNC_MAX_VERSION_SUPPORTED;    // TNC-ACK.
      return resdata;
    }

  FREE(resdata);  // This memory was only needed if we sent an ACK.

  if (queue_get_size(&tnc->tncoutqueue, &queuesize) < 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Error getting queue depth!\n");
		  return NULL;
	  }

  athead = queue_at_head(&tnc->tncoutqueue);

  if (queuesize == 0)
    {
      debug_printf(DEBUG_AUTHTYPES, "No data left to send.\n");
      return NULL;
    }

	  res_size = maxsize - 6;  // Leave room in case we need to slap a length header on.

	  more = queue_dequeue(&tnc->tncoutqueue, &dequeue_data, &res_size);

  	  if (more < 0) 
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't get more fragments to send to authenticator.\n");
		  return NULL;  
	  }

	  // If we are at the head of the list, we need to send a length.
	  if (athead == TRUE) 
	  {
		retdata = Malloc(res_size + 5 + sizeof(struct eap_header));
		if (retdata == NULL) 
		{
			FREE(dequeue_data);
			return NULL;
		}

		dataptr = (uint8_t *)&retdata[5];
		retdata[0] = TNC_LENGTH_FLAG;  // Length is included in this message.
		cpysize = res_size;
		retlen = htonl(queuesize);
		memcpy(&retdata[1], &retlen, sizeof(uint32_t));
		res_size+=5;
	  }
	  else
	  {
		  retdata = Malloc(res_size+1+sizeof(struct eap_header));
		  if (retdata == NULL) 
		  {
			  FREE(dequeue_data);
			  return NULL;
		  }

		  cpysize = res_size;
		  dataptr = (uint8_t *)&retdata[1];
		  res_size++;
	  }

	  // If more == TRUE then we have more fragments, and need to include that indication
	  if (more == TRUE) 
	  {
		  retdata[0] |= TNC_MORE_FLAG;
	  }

	  memcpy(dataptr, dequeue_data, cpysize);

	  FREE(dequeue_data);

	  if (queue_queue_done(&tnc->tncoutqueue) != 0)
	  {
		  debug_printf(DEBUG_TLS_CORE, "Finished with queue... Freeing.\n");
		  if (queue_destroy(&tnc->tncoutqueue) != 0)
		  {
			  debug_printf(DEBUG_NORMAL, "Couldn't destroy queue data!  (We will probably leak memory.)\n");
		  }
	  }

  retdata[0] |= TNC_MAX_VERSION_SUPPORTED;

  resdata = malloc(res_size + sizeof(struct eap_header));
  if (resdata == NULL) return NULL;

  eaphdr = (struct eap_header *)resdata;
  
  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
  eaphdr->eap_type = EAP_TYPE_TNC;

  resdataptr = resdata;
  resdataptr += sizeof(struct eap_header);

  value16 = res_size+sizeof(struct eap_header);
  eaphdr->eap_length = htons(value16);

  memcpy(&resdata[sizeof(struct eap_header)], retdata, res_size);

  FREE(retdata);

  debug_printf(DEBUG_AUTHTYPES, "TNC returns (%d) : \n", res_size+sizeof(struct eap_header));
  debug_hex_dump(DEBUG_AUTHTYPES, resdata, res_size + sizeof(struct eap_header));

  eapdata->methodState = MAY_CONT;
  eapdata->decision = COND_SUCC;
  eapdata->ignore = FALSE;
  
  return resdata;
}

/**
 * \brief Check to see if keys are available.  (For EAP-TNC there NEVER will be!)
 *
 *  There will never be keying material available from the current 
 *  incarnation of this standard!
 *
 * @param[in] eapdata   The EAP data that may be needed to complete a TNC session.
 *
 * \retval FALSE since TNC should *NEVER* be used as a phase 1 method, and should *NEVER* have keying material.
 **/
uint8_t eaptnc_isKeyAvailable(eap_type_data *eapdata)
{
  return FALSE;
}

/**
 * \brief Return any EAP specific keying material.  (None will be returned because TNC doesn't generate
 *        any, and it isn't a valid phase 1 method.)
 *
 * @param[in] eapdata   A pointer to EAP specific data that may be used to complete a TNC session.
 * 
 * \retval NULL since keying material will *NEVER* be generated!
 **/
uint8_t *eaptnc_getKey(eap_type_data *eapdata)
{
  debug_printf(DEBUG_NORMAL, "EAP-TNC was asked to provide keying material! "
	       "If you ever see this message, then there is something badly "
	       "broken in the code!  Please report it along with a full "
	       "debug output!\n");
  return NULL;
}

/**
 *  \brief Clean up any memory that was used by EAP TNC.
 *
 * @param[in] eapdata   A pointer to a buffer that we would have used to store EAP specific data.  This
 *                      buffer is what we need to clean up.
 **/
void eaptnc_deinit(eap_type_data *eapdata)
{
	struct tnc_data *tnc = NULL;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-TNC) Deinit.\n");

	if (eapdata == NULL) return;

	if (eapdata->eap_data == NULL) return;

	tnc = (struct tnc_data *)eapdata->eap_data;

	if (tnc->tncinqueue != NULL)
	{
		if (queue_destroy(&tnc->tncinqueue) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't clean up incoming queue!\n");
		}
	}

	if (tnc->tncoutqueue != NULL)
	{
		if (queue_destroy(&tnc->tncoutqueue) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't clean up outgoing queue!\n");
		}
	}

	tnc->expected_in = 0;

	FREE(eapdata->eap_data);
	tnc = NULL;

	tncdatahook = NULL;
}

/**
 * \brief Callback used by TNCC when it has a finished batch that is ready to 
 *        be sent.
 *
 * @param[in] connectionID   The connectionID used by the IMC to keep track of the connection.
 * @param[in] messageBuffer   The message that should be sent to the server.
 * @param[in] messageLength   The length of the buffer pointed to by messageBuffer.
 *
 * \retval TNC_RESULT_FATAL on error
 * \retval TNC_RESULT_SUCCESS on success
 *
 **/
TNC_Result TNC_TNCC_SendBatch(
			      /*in*/ TNC_ConnectionID connectionID,
			      /*in*/ const char* messageBuffer,
			      /*in*/ size_t messageLength)
{
	if (tncdatahook == NULL)
	{
		debug_printf(DEBUG_NORMAL, "TNC data hook not available.\n");
		return TNC_RESULT_FATAL;
	}

	if (tncdatahook->tncoutqueue == NULL)
	{
		if (queue_create(&tncdatahook->tncoutqueue) != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't create outbound queue!\n");
			return TNC_RESULT_FATAL;
		}
	}

	if (queue_enqueue(&tncdatahook->tncoutqueue, (uint8_t *)messageBuffer, messageLength) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't enqueue data in outbound queue.\n");
		return TNC_RESULT_FATAL;
	}

	return TNC_RESULT_SUCCESS;
}

#endif /* HAVE_TNC */
