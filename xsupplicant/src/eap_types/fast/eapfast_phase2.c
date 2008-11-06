/**
 * EAP-FAST provisioning function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapfast_phase2.c
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error message signaling.
 **/

#include <openssl/ssl.h>

#ifdef OPENSSL_HELLO_EXTENSION_SUPPORTED

#ifdef WINDOWS
#include <Winsock2.h>
#endif

#include <openssl/hmac.h>

#include "../../xsup_err.h"
#include "../../xsup_debug.h"
#include "../../xsup_common.h"
#include "xsupconfig.h"
#include "../../eap_sm.h"
#include "../tls/eaptls.h"
#include "../eap_type_common.h"
#include "../tls/tls_funcs.h"
#include "../mschapv2/eapmschapv2.h"
#include "../../context.h"
#include "eapfast.h"
#include "eapfast_phase2.h"
#include "eapfast_xml.h"

#ifdef WINDOWS
#include "../../event_core_win.h"
#else
#include "../../event_core.h"
#endif

static uint8_t result_tlv_needed = FALSE, result_tlv_included = FALSE;

// Forward decls for things that need it.
uint8_t *eapfast_phase2_gen_error_tlv(uint32_t, uint16_t);

/**
 *  \brief Init phase 2 for EAP-FAST.
 *
 * @param[in] eapdata   A pointer to a structure that contains the information we need to complete phase 2 of the 
 *						EAP-FAST authentication.
 **/
void eapfast_phase2_init(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  struct config_eap_fast *fastconf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL),
		   "eapdata->eap_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "(EAP-FAST) Phase 2 init.\n");

  fastconf = (struct config_eap_fast *)eapdata->eap_conf_data;
  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (mytls_vars->phase2data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Phase 2 data is not initialized!  Your "
		   "authentication will fail!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  phase2 = mytls_vars->phase2data;

  if (phase2->sm == NULL)
    {
      if (eap_sm_init(&phase2->sm) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't init inner EAP state machine."
		       "\n");
	  return;
	}
	  phase2->sm->phase = 2;
    }
  else
    {
      phase2->sm->eapRestart = TRUE;
      phase2->sm->eapReq = FALSE;
    }

  FREE(phase2->simckj);

  phase2->sm->portEnabled = TRUE;
  phase2->sm->idleWhile = config_get_idleWhile();
  phase2->sm->curMethods = fastconf->phase2;
  phase2->sm->methodState = INIT;

  if (fastconf->innerid != NULL)
    {
      phase2->sm->ident = fastconf->innerid;
    }

  ctx = event_core_get_active_ctx();
  if ((ctx != NULL) && (ctx->prof != NULL) && (ctx->prof->temp_username != NULL))
  {
	  phase2->sm->ident = ctx->prof->temp_username;
  }

  eap_sm_run(phase2->sm);
}

/***************************************************************
 *
 *  Clean up our phase 2 after using EAP-FAST.
 *
 ***************************************************************/
void eapfast_phase2_deinit(eap_type_data *eapdata)
{
  struct eapfast_phase2 *phase2 = NULL;
  struct tls_vars *mytls_vars = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-FAST) Phase 2 deinit.\n");

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (mytls_vars->phase2data == NULL)
  {
	  // Nothing to free here, bail out.
	  return;
  }

  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  eap_sm_deinit(&phase2->sm);

  FREE(phase2->result_data);
  FREE(phase2->pkeys);

  if (phase2->pacs != NULL)
    {
      FREE(phase2->pacs->pac_opaque);
      FREE(phase2->pacs->pacinfo.aid);
      FREE(phase2->pacs->pacinfo.iid);
      FREE(phase2->pacs->pacinfo.aid_info);
	  FREE(phase2->pacs);
    }

  FREE(phase2->simckj);
}

/***************************************************************
 *
 *  Check that everything is in place to allow the authentication to 
 *  continue!
 *
 ***************************************************************/
void eapfast_phase2_check(eap_type_data *eapdata)
{
  // Nothing much to check here.
}

/***************************************************************
 *
 *  Build a TLV NAK.
 *
 ***************************************************************/
uint16_t eapfast_phase2_tlv_nak(eap_type_data *eapdata, uint8_t *indata, 
				uint32_t vendor_id, uint16_t tlvtype)
{
  struct nak_tlvs *nak = NULL;
  struct eapfast_tlv *tlv = NULL, *srctlv = NULL;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  debug_printf(DEBUG_AUTHTYPES, "Building PAC NAK for Vendor ID %d, TLV type "
	       "%d!\n", vendor_id, tlvtype);

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  srctlv = (struct eapfast_tlv *)indata;

  tlv = (struct eapfast_tlv *)&phase2->result_data[phase2->result_size];

  tlv->type = htons(FAST_NAK_TLV | MANDATORY_TLV);
  tlv->length = htons(6);     // Will always be 6, for now.

  nak = (struct nak_tlvs *)tlv->data;

  nak->vendorid = htonl(vendor_id);
  nak->naktype = htons(tlvtype);

  return srctlv->length+4;
}

/***************************************************************
 *
 *  Handle a vendor specific NAK.  (Since we don't handle vendor 
 *  specific TLVs for now.)
 *
 ***************************************************************/
uint16_t eapfast_phase2_vendor_tlv_nak(eap_type_data *eapdata, uint8_t *indata)
{
  struct vendor_tlv_type *tlv = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  tlv = (struct vendor_tlv_type *)indata;

  return eapfast_phase2_tlv_nak(eapdata, indata, ntohl(tlv->vendor_id), 
				FAST_VENDOR_SPECIFIC_TLV);
}

/***************************************************************
 *
 *  Display the PAC type.
 *
 ***************************************************************/
void eapfast_phase2_PAC_id_to_str(int debuglevel, uint8_t pacid)
{
  switch (pacid)
    {
    case FAST_RESULT_TLV:
      debug_printf_nl(debuglevel, "FAST_RESULT_TLV");
      break;

    case FAST_NAK_TLV:
      debug_printf_nl(debuglevel, "FAST_NAK_TLV");
      break;

    case FAST_ERROR_TLV:
      debug_printf_nl(debuglevel, "FAST_ERROR_TLV");
      break;

    case FAST_VENDOR_SPECIFIC_TLV:
      debug_printf_nl(debuglevel, "FAST_VENDOR_SPECIFIC_TLV");
      break;

    case FAST_EAP_PAYLOAD_TLV:
      debug_printf_nl(debuglevel, "FAST_EAP_PAYLOAD_TLV");
      break;

    case FAST_INTERMEDIATE_RESULT_TLV:
      debug_printf_nl(debuglevel, "FAST_INTERMEDIATE_RESULT_TLV");
      break;

    case FAST_PAC_TLV:
      debug_printf_nl(debuglevel, "FAST_PAC_TLV");
      break;

    case FAST_CRYPTO_BINDING_TLV:
      debug_printf_nl(debuglevel, "FAST_CRYPTO_BINDING_TLV");
      break;

    case FAST_SERVER_TRUSTED_ROOT_TLV:
      debug_printf_nl(debuglevel, "FAST_SERVER_TRUSTED_ROOT_TLV");
      break;

    case FAST_REQUEST_ACTION_TLV:
      debug_printf_nl(debuglevel, "FAST_REQUEST_ACTION_TLV");
      break;

    case FAST_PKCS7_TLV:
      debug_printf_nl(debuglevel, "FAST_PKCS7_TLV");
      break;

    default:
      debug_printf_nl(debuglevel, "UNKNOWN! (%d)", pacid);
      break;
    }
}

/*******************************************************************
 *
 *  Process a PAC-Key TLV.
 *
 *******************************************************************/
uint16_t eapfast_phase2_process_pac_key(uint8_t *indata, uint8_t *pac_key)
{
  struct eapfast_tlv *fasttlv = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((pac_key != NULL), "pac_key != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  if (ntohs(fasttlv->length) != 32)
    {
      debug_printf(DEBUG_NORMAL, "Invalid PAC-Key length of %d!\n",
		   ntohs(fasttlv->length));
      return 0;
    }

  memcpy(pac_key, &indata[4], 32);

  return 36;        // Should always be the length of the PAC-Info TLV.
}

/*******************************************************************
 *
 *  Process a PAC-Opaque TLV.
 *
 *******************************************************************/
uint16_t eapfast_phase2_process_pac_opaque(uint8_t *indata, 
					   uint8_t **pac_opaque, uint16_t *len)
{
  struct eapfast_tlv *fasttlv = NULL;
  uint8_t *opaque = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((pac_opaque != NULL), "pac_opaque != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  debug_printf(DEBUG_AUTHTYPES, "PAC-Opaque is %d byte(s) long.\n",
	       ntohs(fasttlv->length));
  *len = ntohs(fasttlv->length) + 4;

  opaque = Malloc(ntohs(fasttlv->length)+4);
  if (opaque == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store temporary"
		   " PAC-Opaque value!\n");
      return 0;
    }

  memcpy(opaque, indata, ntohs(fasttlv->length)+4);

  (*pac_opaque) = opaque;

  return (ntohs(fasttlv->length)+4);
}

/**
 * \brief Process a PAC-Info, PAC-Type TLV.
 *
 * @param[in] indata   The payload of a packet, starting with the PAC-Info, PAC-Type TLV.
 * @param[out] pac_type   The value in the PAC-Type TLV.
 *
 * \retval uint16_t  The number of bytes consumed.
 **/
uint16_t eapfast_phase2_process_pac_type(uint8_t *indata, uint16_t *pac_type)
{
  struct pac_info_pac_type *pacinfo = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((pac_type != NULL), "pac_type != NULL", FALSE))
    return 0;

  pacinfo = (struct pac_info_pac_type *)indata;

  if (ntohs(pacinfo->length) != 2)
    {
      debug_printf(DEBUG_NORMAL, "Invalid PAC-Type length!  Expected 2, got "
		   "%d!\n", ntohs(pacinfo->length));
      return 0;
    }

  (*pac_type) = ntohs(pacinfo->pac_type);

  return ntohs(pacinfo->length)+4;
}

/*******************************************************************
 *
 *  Process a PAC Info AID TLV.
 *
 *******************************************************************/
uint16_t eapfast_phase2_process_aid(uint8_t *indata, uint8_t **aid, 
				    uint16_t *len)
{
  struct eapfast_tlv *fasttlv = NULL;
  uint8_t *myaid = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((aid != NULL), "aid != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  debug_printf(DEBUG_AUTHTYPES, "AID is %d byte(s) long.\n",
	       ntohs(fasttlv->length));

  *len = ntohs(fasttlv->length);

  myaid = Malloc(ntohs(fasttlv->length));
  if (myaid == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store the "
		   "AID provided in the PAC-Info TLV.\n");
      return 0;
    }

  memcpy(myaid, indata+4, ntohs(fasttlv->length));

  (*aid) = myaid;

  return ntohs(fasttlv->length)+4;
}

/********************************************************************
 *
 *  Process a PAC-Info Information ID TLV.
 *
 ********************************************************************/
uint16_t eapfast_phase2_process_iid(uint8_t *indata, uint8_t **iid, 
				    uint16_t *len)
{
  struct eapfast_tlv *fasttlv = NULL;
  uint8_t *tempiid = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((iid != NULL), "iid != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  debug_printf(DEBUG_AUTHTYPES, "IID length is %d byte(s).\n", 
	       ntohs(fasttlv->length));

  *len = ntohs(fasttlv->length);

  tempiid = Malloc(ntohs(fasttlv->length));
  if (tempiid == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store IID "
		   "information!\n");
      return 0;
    }
  
  memcpy(tempiid, indata+4, ntohs(fasttlv->length));

  (*iid) = tempiid;

  return (ntohs(fasttlv->length)+4);
}

/*******************************************************************
 *
 *  Process a PAC-Info AID Info TLV.
 *
 *******************************************************************/
uint16_t eapfast_phase2_process_pac_aidinfo(uint8_t *indata, 
					    uint8_t **aid_info,
					    uint16_t *len)
{
  struct eapfast_tlv *fasttlv = NULL;
  uint8_t *tempaidi = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((aid_info != NULL), "aid_info != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  debug_printf(DEBUG_AUTHTYPES, "AID Info is %d byte(s).\n",
	       ntohs(fasttlv->length));

  *len = ntohs(fasttlv->length);

  tempaidi = Malloc(ntohs(fasttlv->length));
  if (tempaidi == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store AID "
		   "info.\n");
      return 0;
    }

  memcpy(tempaidi, indata+4, ntohs(fasttlv->length));

  (*aid_info) = tempaidi;
  
  return (ntohs(fasttlv->length)+4);
}

/*******************************************************************
 *
 *  Process a PAC-Info Credential Lifetime message.
 *
 *******************************************************************/
uint16_t eapfast_phase2_process_cred_lifetime(uint8_t *indata, uint8_t *cred)
{
  struct eapfast_tlv *fasttlv = NULL;
  
  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((cred != NULL), "cred != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  if (ntohs(fasttlv->length) != 4)
    {
      debug_printf(DEBUG_NORMAL, "Invalid Credential length!  Expected a "
		   "length of 4, got a length of %d.\n", fasttlv->length);
      return fasttlv->length+4;
    }

  memcpy(cred, fasttlv->data, 4);

  return ntohs(fasttlv->length)+4;
}


/*******************************************************************
 *
 *  Process a PAC Info TLV and all of it's children.
 *
 *******************************************************************/
uint16_t eapfast_phase2_process_pac_info(uint8_t *indata, 
					 struct pac_info *pacinfo)
{
  struct eapfast_tlv *fasttlv = NULL;
  uint16_t consumed = 0, result = 0, size = 0;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  if (!xsup_assert((pacinfo != NULL), "pacinfo != NULL", FALSE))
    return 0;

  fasttlv = (struct eapfast_tlv *)indata;

  size = ntohs(fasttlv->length);

  debug_printf(DEBUG_AUTHTYPES, "Processing %d byte(s) of data.\n", size);

  indata+=4;

  while (consumed < size)
    {
      fasttlv = (struct eapfast_tlv *)&indata[consumed];

      debug_printf(DEBUG_AUTHTYPES, "Data (%d) : \n", (size - consumed));
      debug_hex_dump(DEBUG_AUTHTYPES, &indata[consumed], (size - consumed));

      switch ((ntohs(fasttlv->type) & MANDATORY_TLV_MASK_OUT))
        {
        case FAST_CRED_LIFETIME:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Info  CRED_LIFETIME TLV\n");
	  result = eapfast_phase2_process_cred_lifetime(&indata[consumed],
							(uint8_t *)&pacinfo->cred_lifetime);
          break;

        case FAST_AUTHORITY_ID:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Info  AUTHORITY_ID TLV.\n");
	  result = eapfast_phase2_process_aid(&indata[consumed],
					      &pacinfo->aid, 
					      &pacinfo->aid_len);
          break;

        case FAST_INFO_ID:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Info  INFO_ID TLV.\n");
	  result = eapfast_phase2_process_iid(&indata[consumed],
					      &pacinfo->iid,
					      &pacinfo->iid_len);
          break;

        case FAST_AUTH_ID_INFO:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Info  AUTH_ID_INFO TLV.\n");
	  result = eapfast_phase2_process_pac_aidinfo(&indata[consumed],
						      &pacinfo->aid_info,
						      &pacinfo->aid_info_len);
          break;

	case FAST_PAC_TYPE:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Info  PAC_TYPE TLV.\n");
	  result = eapfast_phase2_process_pac_type(&indata[consumed], 
						   &pacinfo->pac_type);
          break;

	default:
	  debug_printf(DEBUG_NORMAL, "Unknown/unexpected PAC-Info sub-value "
		       "of %d found!\n", ntohs(fasttlv->type));
	  return 0;
	}

      consumed += result;
    }

  return (consumed + 4);
}

/*******************************************************************
 *
 *  Write the PAC to a file for later use.
 *
 *******************************************************************/
int eapfast_phase2_store_pac(eap_type_data *eapdata, struct pac_values *pacs)
{
  xmlDocPtr doc = NULL;
  struct config_eap_fast *fastconf = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return -1;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    return -1;

  fastconf = (struct config_eap_fast *)eapdata->eap_conf_data;

  eapfast_xml_init();

  doc = eapfast_xml_open_pac(fastconf->pac_location);
  if (doc == NULL)
    {
      // We need to create a new PAC file.
      doc = eapfast_xml_create_pac_struct();
    }

  if (eapfast_xml_add_pac(doc, pacs) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error adding PAC data to PAC data structure "
		   "in memory!\n");
      return -1;
    }

  if (eapfast_xml_save(fastconf->pac_location, doc) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't save PAC file to location '%s'.\n");
      debug_printf(DEBUG_NORMAL, "You will be forced to provision again.\n");
      return -1;
    }

  return 0;
}

/*******************************************************************
 *
 *  Send a PAC Acknowledgement.
 *
 *******************************************************************/
void eapfast_phase2_build_pac_ack(eap_type_data *eapdata)
{
  // The ACK structure is the same as the TLV result.  So we will just
  // use that here.
  struct eapfast_tlv_result *ack = NULL;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  struct eapfast_tlv *tlv = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  debug_printf(DEBUG_AUTHTYPES, "Building PAC ACK!\n");
  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  tlv = (struct eapfast_tlv *)&phase2->result_data[phase2->result_size];
  tlv->type = htons(FAST_PAC_TLV | MANDATORY_TLV);
  tlv->length = htons(sizeof(struct eapfast_tlv_result));

  phase2->result_size += sizeof(struct eapfast_tlv);

  ack = (struct eapfast_tlv_result *)&phase2->result_data[phase2->result_size];

  ack->type = htons(FAST_PAC_ACK);
  ack->length = htons(2);
  ack->status = htons(1);   // Success.

  // And we are done.
  eapdata->methodState = DONE;

  phase2->result_size += sizeof(struct eapfast_tlv_result);
}

/*******************************************************************
 *
 *  Process a PAC TLV.
 *
 *******************************************************************/
uint16_t eapfast_phase2_pac_process(eap_type_data *eapdata, uint8_t *indata, 
				    uint16_t insize)
{
  struct eapfast_tlv *fastlv = NULL;
  uint16_t consumed = 0, result = 0, size = 0;
  struct pac_values pacs;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint8_t *temp = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return 0;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  memset(&pacs, 0x00, sizeof(pacs));

  // We need to loop through all of the TLVs that we have in this EAP message,
  // and process each one.

  fastlv = (struct eapfast_tlv *)indata;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  size = ntohs(fastlv->length);

  debug_printf(DEBUG_AUTHTYPES, "Processing %d byte(s) of data.\n", size);
  
  indata+=4;

  while (consumed < size)
    {
      fastlv = (struct eapfast_tlv *)&indata[consumed];

      debug_printf(DEBUG_AUTHTYPES, "Remaining (%d) : \n", insize - consumed);
      debug_hex_dump(DEBUG_AUTHTYPES, &indata[consumed], (insize - consumed));

      switch ((ntohs(fastlv->type) & MANDATORY_TLV_MASK_OUT))
	{
	case FAST_PAC_KEY:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Key TLV.\n");
	  result = eapfast_phase2_process_pac_key(&indata[consumed], 
						  (uint8_t *)&pacs.pac_key);
	  break;
	  
	case FAST_PAC_OPAQUE:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Opaque TLV.\n");
	  result = eapfast_phase2_process_pac_opaque(&indata[consumed], 
						     &pacs.pac_opaque,
						     &pacs.pac_opaque_len);
	  break;
	  
	case FAST_PAC_INFO:
	  debug_printf(DEBUG_AUTHTYPES, "Got a PAC-Info TLV.\n");
	  result = eapfast_phase2_process_pac_info(&indata[consumed], 
						   &pacs.pacinfo);
	  break;
	  
	default:
	  debug_printf(DEBUG_NORMAL, "Unknown/unexpected PAC TLV request %d."
		       "\n", fastlv->type);
	  result = 0;
	  break;
	}

      if (result == 0) 
	{
	  debug_printf(DEBUG_NORMAL, "An error occurred processing PAC "
		       "information.  You will need to attempt to provision "
		       "again.\n");
	  return 0;
	}

      consumed += result;
    }

  if (eapfast_phase2_store_pac(eapdata, &pacs) == 0)
    {
      eapfast_phase2_build_pac_ack(eapdata);
    }
  else
    {
      // Return an error.
      temp = eapfast_phase2_gen_error_tlv(FAST_TUNNEL_COMPROMISE_ERROR,
					  (ntohs(fastlv->type) & MANDATORY_TLV));

      memcpy(&phase2->result_data[phase2->result_size], temp,
	     sizeof(struct eapfast_tlv_error));

      FREE(temp);
      phase2->result_size += sizeof(struct eapfast_tlv_error);
    }

  return (consumed + 4);
}

/**************************************************************
 *
 *  Generate the values needed to crypto bind the tunnel, and to
 *  populate EAP-MSCHAPv2 if we are going to use anonymous provisioning.
 *
 **************************************************************/
void eapfast_phase2_provision_gen_crypt(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint8_t *keyblock = NULL, *temp = NULL;
  int offset_to_prov_keys = 0;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
                   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;
  
  offset_to_prov_keys = tls_funcs_get_keyblock_len(mytls_vars);

  keyblock = tls_funcs_gen_keyblock(mytls_vars, TLS_FUNCS_SERVER_FIRST,
				    FAST_PROVISIONING_SESSION_KEY,
				    FAST_PROVISIONING_SESSION_KEY_LEN);

  if (keyblock == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to generate cryptobinding keys!  Your authentication will fail.\n");
	  eap_type_common_fail(eapdata);
	  return;
  }

  temp = &keyblock[offset_to_prov_keys];

  phase2->pkeys = Malloc(sizeof (struct provisioning_keys));
  if (phase2->pkeys == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Failed to allocate memory to store keys "
		   "needed to complete provisioning.\n");
      FREE(keyblock);
      return;
    }

  memcpy(phase2->pkeys, temp, sizeof(struct provisioning_keys));

  FREE(keyblock);
}

/**************************************************************
 *
 *  Process a phase 2 EAP message.
 *
 **************************************************************/
uint16_t eapfast_phase2_eap_process(eap_type_data *eapdata, uint8_t *indata, 
				    uint16_t insize)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint16_t eapsize = 0;
  uint8_t doneinit = 0;
  struct eapfast_tlv *fasttlv = NULL;
  struct config_eap_fast *fastconfig = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  fasttlv = (struct eapfast_tlv *)indata;

  debug_printf(DEBUG_AUTHTYPES, "Processing phase 2 EAP.\n");
  debug_printf(DEBUG_AUTHTYPES, "EAP portion (%d) : \n", insize - 4);
  debug_hex_dump(DEBUG_AUTHTYPES, indata + 4, ntohs(fasttlv->length));

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;
  fastconfig = (struct config_eap_fast *)eapdata->eap_conf_data;

  phase2->sm->eapReqData = &indata[4];
  phase2->sm->eapReq = TRUE;

  if (phase2->sm->methodState == INIT)
    {
      doneinit = TRUE;

      // Need to generate some crypto data.
      eapfast_phase2_provision_gen_crypt(eapdata);

	  if ((phase2->provisioning == TRUE) && (phase2->anon_provisioning == TRUE) &&
	  (fastconfig->phase2->method_num == EAP_TYPE_MSCHAPV2))
	{
	  debug_printf(DEBUG_AUTHTYPES, "Setting up EAP-MS-CHAPv2.\n");
	  debug_printf(DEBUG_AUTHTYPES, "Peer Challenge : ");
	  debug_hex_printf(DEBUG_AUTHTYPES, phase2->pkeys->MSCHAPv2_ClientChallenge, 16);
	  debug_printf(DEBUG_AUTHTYPES, "Authenticator Challenge : ");
	  debug_hex_printf(DEBUG_AUTHTYPES, phase2->pkeys->MSCHAPv2_ServerChallenge, 16);

	  // Tweak MS-CHAPv2 to work properly for provisioning.
	  if (eapmschapv2_set_challenges(phase2->pkeys->MSCHAPv2_ClientChallenge,
					 phase2->pkeys->MSCHAPv2_ServerChallenge) != TRUE)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't configure challenge values"
			   " needed for MS-CHAPv2.\n");
	      eap_type_common_fail(eapdata);
	      return 0;
	    }
	}

      if (phase2->provisioning == FALSE) 
	{
	  debug_printf(DEBUG_AUTHTYPES, "Clearing EAP-FAST provisioning mode "
		       "from MS-CHAPv2.\n");
	  if (eapmschapv2_set_challenges(NULL, NULL) != TRUE)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't clear MS-CHAPv2 challenges"
			   "! If you are using MS-CHAPv2 as an inner "
			   "authentication method, it will probably fail!\n");
	    }
	}
    }

  eap_sm_run(phase2->sm);

  eapdata->ignore = phase2->sm->ignore;
  
  if ((phase2->sm->eapRespData != NULL) && (phase2->result_data != NULL))
    {
      // Build up the response data.
      eapsize = eap_type_common_get_eap_length(phase2->sm->eapRespData);

      memcpy(&phase2->result_data[phase2->result_size + 4], 
	     phase2->sm->eapRespData, eapsize);
      fasttlv = (struct eapfast_tlv *)&phase2->result_data[phase2->result_size];

      fasttlv->type = htons(FAST_EAP_PAYLOAD_TLV | MANDATORY_TLV);
      fasttlv->length = htons(eapsize);
      phase2->result_size += eapsize + 4;  // 4 for 2 16 bit numbers that make
                                           // up the EAP-FAST TLV headers.
    }
  else
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  fasttlv = (struct eapfast_tlv *)indata;

  return ntohs(fasttlv->length) + 4;
}

/***************************************************************
 *
 *  Generate an error TLV.
 *
 ***************************************************************/
uint8_t *eapfast_phase2_gen_error_tlv(uint32_t reason, uint16_t mandatory)
{
  uint8_t *result = NULL;
  struct eapfast_tlv_error *error = NULL;

  if (result_tlv_included == FALSE) result_tlv_needed = TRUE;

  result = Malloc(sizeof(struct eapfast_tlv_error));
  if (result == NULL) return NULL;

  error = (struct eapfast_tlv_error *)result;

  error->type = htons(FAST_ERROR_TLV | mandatory);
  error->length = htons(sizeof(struct eapfast_tlv_error)-4);
  error->error_code = htonl(reason);

  return result;
}

/********************************************************************
 *
 *  Build a REQUEST_ACTION TLV response.
 *
 ********************************************************************/
uint8_t *eapfast_phase2_gen_request_action_tlv(uint16_t reason)
{
  uint8_t *result = NULL;
  struct eapfast_tlv_request_action *action = NULL;

  result = Malloc(sizeof(struct eapfast_tlv_request_action));
  if (result == NULL) return NULL;

  action = (struct eapfast_tlv_request_action *)result;

  action->type = htons(FAST_REQUEST_ACTION_TLV | MANDATORY_TLV);
  action->length = htons(sizeof(struct eapfast_tlv_request_action) - 4);
  action->action = htons(reason);

  return result;
}

/***************************************************************
 *
 *  Generate our own result TLV
 *
 ***************************************************************/
uint8_t *eapfast_phase2_get_result_tlv(uint16_t status)
{
  uint8_t *result = NULL;
  struct eapfast_tlv_result *resulttlv = NULL;

  result = Malloc(sizeof(struct eapfast_tlv_result));
  if (result == NULL) return NULL;

  resulttlv = (struct eapfast_tlv_result *)result;

  resulttlv->type = htons(FAST_RESULT_TLV | MANDATORY_TLV);
  resulttlv->length = htons(2);
  resulttlv->status = htons(status);

  return result;
}

/***************************************************************
 *
 *  Process a phase 2 result TLV message.
 *
 ***************************************************************/
uint16_t eapfast_phase2_process_result_tlv(eap_type_data *eapdata, 
					   uint8_t *indata, uint16_t insize)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  struct eapfast_tlv_result *fasttlv = NULL;
  uint8_t *temp = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  fasttlv = (struct eapfast_tlv_result *)indata;

  if (ntohs(fasttlv->length) != 2)
    {
      debug_printf(DEBUG_NORMAL, "Got an invalid TLV_RESULT message!\n");
      temp = eapfast_phase2_gen_error_tlv(FAST_UNEXPECTED_TLVS_EXCHANGED,
					  (ntohs(fasttlv->type) & MANDATORY_TLV));

      memcpy(&phase2->result_data[phase2->result_size], temp, 
	     sizeof(struct eapfast_tlv_error));

      FREE(temp);
      phase2->result_size += sizeof(struct eapfast_tlv_error);
      return ntohs(fasttlv->length);
    }

  if ((ntohs(fasttlv->status) < 1) || (ntohs(fasttlv->status) > 2))
    {
      debug_printf(DEBUG_NORMAL, "Got an invalid result value in TLV_RESULT "
		   "message!  (Value was %d)\n", ntohs(fasttlv->status));
      temp = eapfast_phase2_gen_error_tlv(FAST_UNEXPECTED_TLVS_EXCHANGED,
					  (ntohs(fasttlv->type) & MANDATORY_TLV));

      memcpy(&phase2->result_data[phase2->result_size], temp,
             sizeof(struct eapfast_tlv_error));

      FREE(temp);
      phase2->result_size += sizeof(struct eapfast_tlv_error);
      return ntohs(fasttlv->length);
    }

  switch (ntohs(fasttlv->status))
    {
    case FAST_RESULT_SUCCESS:
      debug_printf(DEBUG_NORMAL, "Inner result is a success!\n");
      eapdata->methodState = CONT;
      eapdata->decision = COND_SUCC;
      break;

    case FAST_RESULT_FAILURE:
      debug_printf(DEBUG_NORMAL, "Inner result is a FAILURE!\n");
      eapdata->methodState = DONE;
      eapdata->decision = EAP_FAIL;
      break;
    }

  // Create our own result TLV to be sent back.
  temp = eapfast_phase2_get_result_tlv(ntohs(fasttlv->status));

  memcpy(&phase2->result_data[phase2->result_size], temp,
	 sizeof(struct eapfast_tlv_result));

  phase2->result_size += sizeof(struct eapfast_tlv_result);

  return sizeof(struct eapfast_tlv_result);
}

/***************************************************************
 *
 *  Generate our own intermediate result TLV
 *
 ***************************************************************/
uint8_t *eapfast_phase2_get_intermediate_result_tlv(uint16_t status)
{
  uint8_t *result = NULL;
  struct eapfast_tlv_result *resulttlv = NULL;

  result = Malloc(sizeof(struct eapfast_tlv_result));
  if (result == NULL) return NULL;

  resulttlv = (struct eapfast_tlv_result *)result;

  resulttlv->type = htons(FAST_INTERMEDIATE_RESULT_TLV | MANDATORY_TLV);
  resulttlv->length = htons(2);
  resulttlv->status = htons(status);

  return result;
}

/***************************************************************
 *
 *  Our crypto binding failed.  So, wipe out the data that we were
 *  building, and replace it with a result failure, and an error of
 *  binding failed.
 *
 ***************************************************************/
void eapfast_phase2_binding_failed(eap_type_data *eapdata)
{
  uint8_t *temp = NULL;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  struct eapfast_tlv *tlv = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  // Clean out the existing data.
  FREE(phase2->result_data);
  phase2->result_size = 0;

  // Now allocate some new memory, and fill it.
  phase2->result_data = Malloc(1500);
  if (phase2->result_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store failure "
		   "data!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  temp = eapfast_phase2_get_result_tlv(FAST_RESULT_FAILURE);
  tlv = (struct eapfast_tlv *)temp;

  memcpy(phase2->result_data, temp, ntohs(tlv->length)+4);
  phase2->result_size = ntohs(tlv->length)+4;

  FREE(temp);

  temp = eapfast_phase2_gen_error_tlv(FAST_TUNNEL_COMPROMISE_ERROR, 
				      MANDATORY_TLV);
  tlv = (struct eapfast_tlv *)temp;

  memcpy(&phase2->result_data[phase2->result_size], temp, 
	 ntohs(tlv->length)+4);

  phase2->result_size += ntohs(tlv->length)+4;

  debug_printf(DEBUG_AUTHTYPES, "Error result (%d) :\n", phase2->result_size);
  debug_hex_dump(DEBUG_AUTHTYPES, phase2->result_data, phase2->result_size);
}

/***************************************************************
 *
 *  Process an Intermedia result TLV.
 *
 ***************************************************************/
int eapfast_phase2_intermediate_result_process(eap_type_data *eapdata,
					       uint8_t *indata,
					       uint16_t insize)
{
  struct eapfast_tlv_result *fasttlv = NULL;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint8_t *temp = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  if (!xsup_assert((insize >= 6), "insize >= 6", FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  fasttlv = (struct eapfast_tlv_result *)indata;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  if ((ntohs(fasttlv->status) < 1) || (ntohs(fasttlv->status) > 2))
    {
      debug_printf(DEBUG_NORMAL, "Got an invalid result value in TLV_RESULT "
                   "message!  (Value was %d)\n", ntohs(fasttlv->status));
      temp = eapfast_phase2_gen_error_tlv(FAST_UNEXPECTED_TLVS_EXCHANGED,
                                          (ntohs(fasttlv->type) & MANDATORY_TLV));

      memcpy(&phase2->result_data[phase2->result_size], temp,
             sizeof(struct eapfast_tlv_error));

      FREE(temp);
      phase2->result_size += sizeof(struct eapfast_tlv_error);
      return ntohs(fasttlv->length);
    }

  switch (ntohs(fasttlv->status))
    {
    case FAST_RESULT_SUCCESS:
      debug_printf(DEBUG_NORMAL, "Intermediate result is a success!\n");
      break;

    case FAST_RESULT_FAILURE:
      debug_printf(DEBUG_NORMAL, "Intermediate result is a FAILURE!\n");
      break;
    }

  // Create our own result TLV to be sent back.
  temp = eapfast_phase2_get_intermediate_result_tlv(ntohs(fasttlv->status));

  memcpy(&phase2->result_data[phase2->result_size], temp,
         sizeof(struct eapfast_tlv_result));

  phase2->result_size += sizeof(struct eapfast_tlv_result);

  return sizeof(struct eapfast_tlv_result);
}

/****************************************************************
 *
 *  The T-PRF as specified in section 5.5 of draft-cam-winget-eap-fast-03.txt.
 *
 *  NOTE :  The value of result_size is the target we are shooting for.
 *  If it isn't a multiple of 20, then we will round up to the next value
 *  of 20, and return everything.  This shouldn't be a problem, since the
 *  caller will still get the data they need, and when the data is freed
 *  the extra memory will be freed as well.
 *
 ****************************************************************/
uint8_t *eapfast_phase2_t_prf(uint8_t *key, uint16_t keylen, char *label,
			      uint8_t *seed, uint16_t seedlen, 
			      uint16_t result_size)
{
  uint8_t *s = NULL, *result = NULL, *feed = NULL;
  uint16_t length = 0, i = 0, sizeofs = 0, sizeoffeed = 0;
  uint8_t mac[20];
  unsigned int mdlen = 0;

  if (!xsup_assert((key != NULL), "key != NULL", FALSE))
    return NULL;

  if (!xsup_assert((label != NULL), "label != NULL", FALSE))
    return NULL;

  if ((result_size % 20) == 0)
    {
      length = result_size;
    }
  else
    {
      length = (20 - (result_size % 20)) + result_size;
    }

  result = Malloc(length);
  if (result == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to create the "
		   "T-PRF values!\n");
      return NULL;
    }

  s = Malloc(strlen(label) + 1 + seedlen);  
  if (s == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to create 'S' in "
		   "the T-PRF!\n");
      FREE(result);
      return NULL;
    }

  // Create the "S".
  strcpy(s, label);
  s[strlen(label)] = 0x00;

  if (seed != NULL)
    {
      memcpy(&s[strlen(label)+1], seed, seedlen);
    }

  sizeofs = strlen(label) + 1 + seedlen;

  // Now, hash the number of times needed to generate the right amount of
  // material.
  for (i = 0;i < (length/20);i++)
    {
      if (i == 0)
	{
	  feed = Malloc(sizeofs+4);
	  if (feed == NULL)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't allocate temporary space "
			   "to store 'to hash' data!\n");
	      FREE(result);
	      FREE(s);
	      return NULL;
	    }

	  memcpy(feed, s, sizeofs);
	  sizeoffeed = sizeofs;

	  feed[sizeoffeed] = (result_size >> 8);
	  feed[sizeoffeed+1] = (result_size & 0xff);
	  sizeoffeed+=2;
	  feed[sizeoffeed] = 0x01;
	  sizeoffeed++;
	}
      else
	{
	  feed = Malloc(sizeofs+20+3);
	  if (feed == NULL)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't allocate temporary space "
			   "to store 'to hash' data!\n");
	      FREE(result);
	      FREE(s);
	      return NULL;
	    }

	  memcpy(feed, &result[(i-1)*20], 20);
	  memcpy(&feed[20], s, sizeofs);
	  sizeoffeed = 20 + sizeofs;
	  feed[sizeoffeed] = (result_size >> 8);
	  feed[sizeoffeed+1] = (result_size & 0xff);
	  sizeoffeed += 2;
	  feed[sizeoffeed] = (i+1);
	  sizeoffeed++;
	}

      HMAC(EVP_sha1(), key, keylen, feed, sizeoffeed, (unsigned char *)&mac, 
	   &mdlen);
      memcpy(&result[i*20], mac, 20);

      FREE(feed);
      sizeoffeed = 0;
    }

	FREE(s);

  return result;
}

/*****************************************************************
 *
 *  Return the current S-IMCK[j].
 *
 *****************************************************************/
uint8_t *eapfast_phase2_get_simckj(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  return phase2->simckj;
}

/****************************************************************
 *
 *  Generate the CMK[j] needed to check the compound MAC.
 *
 ****************************************************************/
uint8_t *eapfast_phase2_gen_cmkj(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint8_t *keyblock = NULL;
  uint8_t *key = NULL;						// The keyblock modified to fit in EAP-FAST mode.
  uint8_t *cmkj = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  debug_printf(DEBUG_AUTHTYPES, "Key data :\n");
  debug_hex_dump(DEBUG_AUTHTYPES, phase2->sm->eapKeyData, 64);

  key = Malloc(32);
  if (key == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to allocate memory to create EAP-FAST formatted keyblock!\n");
	  eap_type_common_fail(eapdata);
	  return NULL;
  }

  // If we get here, then EAP-FAST is using us as an inner method.  So,
  // mangle the key data in the way that it wants, and return it.

  // NOTE : Some inner methods don't return keys.  In this case, we are supposed to use
  // a key of all 0s.  Since we memset() the keydata to 0s when we allocate it, we need
  // to just skip this next part if there is no data.
  if (phase2->sm->eapKeyData != NULL)
  {
	  memcpy(&key[16], &phase2->sm->eapKeyData[0], 16);
	  memcpy(&key[0], &phase2->sm->eapKeyData[32], 16);
  }

  debug_printf(DEBUG_AUTHTYPES, "Key data : ");
  debug_hex_printf(DEBUG_AUTHTYPES, key, 32);
 
  if (phase2->simckj == NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "Generating a new S-IMCK[0].\n");
      phase2->simckj = Malloc(40);
      if (phase2->simckj == NULL) 
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
		       "S-IMCK[0]!\n");
	  return NULL;
	}

      memcpy(phase2->simckj, phase2->pkeys->session_key_seed, 40);

	  debug_printf(DEBUG_AUTHTYPES, "S-IMCK[0] : ");
	  debug_hex_printf(DEBUG_AUTHTYPES, phase2->simckj, 40);
    }

  keyblock = eapfast_phase2_t_prf(phase2->simckj, 40,
				  FAST_IMCK_LABEL, key, 32, 60);

  cmkj = Malloc(20);
  if (cmkj == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store CMK[j]!\n");
      return NULL;
    }

  // Store the new S-IMCK[j]
  memcpy(phase2->simckj, keyblock, 40);

  debug_printf(DEBUG_AUTHTYPES, "S-IMCK[j] : ");
  debug_hex_printf(DEBUG_AUTHTYPES, phase2->simckj, 40);

  memcpy(cmkj, keyblock+40, 20);

  debug_printf(DEBUG_AUTHTYPES, "CMK[j] : ");
  debug_hex_printf(DEBUG_AUTHTYPES, cmkj, 20);

  return cmkj;
}

/****************************************************************
 *
 *  Process a crypto binding TLV, and verify that it is valid.  If it
 *  isn't valid, then wipe out the result packet that we have been 
 *  building, and replace it with a Result-Failure TLV, and an Error TLV
 *  that indicates the problem was with the crypto-binding.
 *
 ****************************************************************/
int eapfast_phase2_check_crypto_binding(eap_type_data *eapdata, 
					uint8_t *indata, uint16_t insize)
{
  struct eapfast_crypto_binding_tlv *binding = NULL, *maccheck = NULL;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint8_t *temp = NULL;
  uint8_t mac[20], nonce[32];
  int len = 0;
  uint8_t *cmkj = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  if (!xsup_assert((insize >= sizeof(struct eapfast_crypto_binding_tlv)), 
		   "insize is invalid", FALSE))
    {
      eap_type_common_fail(eapdata);
      return 0;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  binding = (struct eapfast_crypto_binding_tlv *)indata;
  
  if ((ntohs(binding->length)+4) != sizeof(struct eapfast_crypto_binding_tlv))
    {
      debug_printf(DEBUG_NORMAL, "Crypto-Binding packet is a runt!\n");
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }

  binding = (struct eapfast_crypto_binding_tlv *)indata;

  if (binding->version != FAST_CRYPTO_BIND_VERSION)
    {
      debug_printf(DEBUG_NORMAL, "Crypto-Binding version is invalid!  "
		   "(Expected %d, got %d.)\n", FAST_CRYPTO_BIND_VERSION,
		   binding->version);
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }

  debug_printf(DEBUG_AUTHTYPES, "Crypto-Binding version is %d.\n",
	       binding->version);

  if (binding->eap_version != eapfast_get_ver(eapdata))
    {
      debug_printf(DEBUG_NORMAL, "Crypto-Binding EAP version is invalid!  "
		   "(Expected %d, got %d.)\n", eapfast_get_ver(eapdata),
		   binding->eap_version);
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }

  debug_printf(DEBUG_AUTHTYPES, "EAP Version is %d\n", binding->eap_version);

  if (binding->subtype != FAST_BINDING_REQUEST)
    {
      debug_printf(DEBUG_NORMAL, "Crypto-Binding subtype is invalid!  "
		   "(Expected %d, got %d.)\n", FAST_BINDING_REQUEST,
		   binding->subtype);
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }

  /*
  if (phase2->sm->eapKeyAvailable != TRUE)
    {
      debug_printf(DEBUG_NORMAL, "No keying material available from phase 2! "
		   "(Unable to generate the Compound MAC.)\n");
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }
  */

  temp = Malloc(ntohs(binding->length)+4);
  if (temp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store temporary"
		   " Crypto-Binding TLV data.\n");
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }

  if (!xsup_assert((phase2->sm != NULL), "phase2->sm != NULL", FALSE))
    {
      eapfast_phase2_binding_failed(eapdata);
      FREE(temp);
      return 0;
    }

  memcpy(temp, binding, (ntohs(binding->length)+4));
  maccheck = (struct eapfast_crypto_binding_tlv *)temp;

  // Zero out the MAC section.
  memset(maccheck->compound_mac, 0x00, sizeof(maccheck->compound_mac));

  debug_printf(DEBUG_AUTHTYPES, "Phase 2 Keying material (%d) : ",
	       phase2->sm->eapKeyLen);
  debug_hex_printf(DEBUG_AUTHTYPES, phase2->sm->eapKeyData,
		   phase2->sm->eapKeyLen);

  cmkj = eapfast_phase2_gen_cmkj(eapdata);

  HMAC(EVP_sha1(), cmkj, 20, (unsigned char *)maccheck, 
       sizeof(struct eapfast_crypto_binding_tlv), (unsigned char *)&mac, 
       &len);

  debug_printf(DEBUG_AUTHTYPES, "Calculated Compound MAC (%d)\t: ", len);
  debug_hex_printf(DEBUG_AUTHTYPES, mac, len);

  debug_printf(DEBUG_AUTHTYPES, "Expected Compound MAC \t: ");
  debug_hex_printf(DEBUG_AUTHTYPES, binding->compound_mac, 
		   sizeof(binding->compound_mac));

  if (memcmp(mac, binding->compound_mac, sizeof(binding->compound_mac)) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Compound MAC check failed!\n");
      eapfast_phase2_binding_failed(eapdata);
      FREE(temp);
      return 0;
    }

  memcpy(nonce, binding->nonce, 32);

  FREE(temp);

  // The MAC check was a success.  So, now we need to build the response
  // CMAC, and send it along too.
  temp = Malloc(sizeof(struct eapfast_crypto_binding_tlv));
  if (temp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to return the "
		   "crypto binding result.\n");
      eapfast_phase2_binding_failed(eapdata);
      return 0;
    }

  memset(temp, 0x00, sizeof(struct eapfast_crypto_binding_tlv));

  binding = (struct eapfast_crypto_binding_tlv *)temp;
  binding->type = htons(MANDATORY_TLV | FAST_CRYPTO_BINDING_TLV);
  binding->length = htons(sizeof(struct eapfast_crypto_binding_tlv)-4);
  binding->reserved = 0;
  binding->version = FAST_CRYPTO_BIND_VERSION;
  binding->eap_version = FAST_VERSION1;
  binding->subtype = FAST_BINDING_RESPONSE;

  memcpy(binding->nonce, nonce, 32);

  binding->nonce[31]++;

  HMAC(EVP_sha1(), cmkj, 20, temp, sizeof(struct eapfast_crypto_binding_tlv),
       (unsigned char *)&mac, &len);

  memcpy(binding->compound_mac, mac, 20);

  memcpy(&phase2->result_data[phase2->result_size], temp, 
	 sizeof(struct eapfast_crypto_binding_tlv));

  phase2->result_size += sizeof(struct eapfast_crypto_binding_tlv);

  return sizeof(struct eapfast_crypto_binding_tlv);
}

/*********************************************************************
 *
 *  Process an ERROR TLV from the server.    This code should validate 
 *  the error from the server, and display some form of an error message
 *  to the user.
 *
 *********************************************************************/
uint16_t eapfast_phase2_process_error_tlv(uint8_t *indata)
{
  struct eapfast_tlv_error *error = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return 0;

  error = (struct eapfast_tlv_error *)indata;

  if (ntohs(error->length) != 4)
    {
      debug_printf(DEBUG_NORMAL, "The TLV length for the ERROR TLV was "
		   "invalid.  Expected 4, got %d.\n", ntohs(error->length));

      return ntohs(error->length)+4;
    }

  switch (ntohl(error->error_code))
    {
    case FAST_TUNNEL_COMPROMISE_ERROR:
      debug_printf(DEBUG_NORMAL, "[EAP-FAST] Tunnel has been compromised!\n");
      break;

    case FAST_UNEXPECTED_TLVS_EXCHANGED:
      debug_printf(DEBUG_NORMAL, "[EAP-FAST] Unexpected TLVs exchanged!\n");
      break;

    default:
      debug_printf(DEBUG_NORMAL, "[EAP-FAST] Unknown error received.  (Error "
		   "was %d.)\n", ntohl(error->error_code));
      break;
    }

  return ntohs(error->length)+4;
}

/**
 * \brief Create a request to get a PAC.
 *
 * @param[in] eapdata   The EAP-FAST state data.
 **/
void eapfast_phase2_create_PAC_request(eap_type_data *eapdata)
{
	struct eapfast_pac_request_tlv *pac_request = NULL;
	struct eapfast_phase2 *phase2 = NULL;
	struct tls_vars *mytls_vars = NULL;
	uint8_t *data = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
	{
		eap_type_common_fail(eapdata);
		return;
	}

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
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

	debug_printf(DEBUG_NORMAL, "Requesting a new PAC.\n");
	phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

	data = eapfast_phase2_gen_request_action_tlv(FAST_REQUEST_PROCESS_TLV);
	memcpy(&phase2->result_data[phase2->result_size], data, sizeof(struct eapfast_tlv_request_action));
	phase2->result_size += sizeof(struct eapfast_tlv_request_action);

	pac_request = (struct eapfast_pac_request_tlv *)&phase2->result_data[phase2->result_size];
	phase2->result_size += sizeof(struct eapfast_pac_request_tlv);

	pac_request->type = ntohs(FAST_PAC_TLV);
	pac_request->length = ntohs(sizeof(struct eapfast_pac_request_tlv)-4);
	pac_request->pac_type = ntohs(10);
	pac_request->pac_length = ntohs(2);
	pac_request->req_type = ntohs(1);
}
						   
/***************************************************************
 *
 *  Process a phase 2 packet.
 *
 ***************************************************************/
void eapfast_phase2_process(eap_type_data *eapdata, uint8_t *indata, 
			    uint16_t insize)
{
  struct eapfast_tlv *fastlv = NULL;
  uint16_t value16 = 0;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint16_t consumed = 0, result = 0;
  uint8_t request_pac = FALSE;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
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

  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  // Clear out our storage area, so that we can build the new response.
  FREE(phase2->result_data);

  phase2->result_size = 0;
  phase2->result_data = Malloc(1600);  // Should be plenty of space.
  if (phase2->result_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store response "
		   "data.\n");
      eap_type_common_fail(eapdata);
      return;
    }

  // Need to loop through all TLVs included, and make sure we process each one.
  while (consumed < insize)
    {
      fastlv = (struct eapfast_tlv *)&indata[consumed];
      value16 = ntohs(fastlv->type);

      debug_printf(DEBUG_AUTHTYPES, "(Offset %d) PAC id (%d) : ", consumed, 
		   (value16 & MANDATORY_TLV_MASK_OUT));
      eapfast_phase2_PAC_id_to_str(DEBUG_AUTHTYPES,
				   (value16 & MANDATORY_TLV_MASK_OUT));
      debug_printf_nl(DEBUG_AUTHTYPES, "\n");

      switch (value16 & MANDATORY_TLV_MASK_OUT)
	{
	case FAST_RESULT_TLV:
	  result = eapfast_phase2_process_result_tlv(eapdata, 
						     &indata[consumed], 
						     (insize - consumed));

  	  if ((phase2->provisioning == TRUE) && (phase2->anon_provisioning == FALSE))
	  {
		  // We need to explicitly request a PAC.
		  request_pac = TRUE;
	  }
	  break;
	  
	case FAST_NAK_TLV:
	  // It is possible that the supplicant *COULD* get a NAK TLV, but
	  // that should require that we are attempting to use a TLV that
	  // may not be supported by the server.  Since this implementation
	  // doesn't support anything like that, we should never get a
	  // NAK!  If such code is ever added, we need to implement something
	  // here.
	  debug_printf(DEBUG_NORMAL, "Got a TLV NAK.  This shouldn't happen!"
		       "\n");
	  result = 0;
	  break;
	  
	case FAST_ERROR_TLV:
	  debug_printf(DEBUG_NORMAL, "Got an ERROR TLV.\n");
	  result = eapfast_phase2_process_error_tlv(&indata[consumed]);
	  break;
	  
	case FAST_VENDOR_SPECIFIC_TLV:
	  debug_printf(DEBUG_NORMAL, "Vendor specific TLV found, but not "
		       "supported.  NAKing.\n");
	  result = eapfast_phase2_vendor_tlv_nak(eapdata, &indata[consumed]);
	  break;
	  
	case FAST_EAP_PAYLOAD_TLV:
	  result = eapfast_phase2_eap_process(eapdata, &indata[consumed], 
					      (insize - consumed));
	  break;
	  
	case FAST_INTERMEDIATE_RESULT_TLV:
	  result = eapfast_phase2_intermediate_result_process(eapdata, 
							      &indata[consumed],
							      (insize - consumed));
	  break;

	case FAST_PAC_TLV:
	  result = eapfast_phase2_pac_process(eapdata, &indata[consumed], 
					      (insize - consumed));
	  break;
	  
	case FAST_CRYPTO_BINDING_TLV:
	  result = eapfast_phase2_check_crypto_binding(eapdata, 
						       &indata[consumed],
						       (insize - consumed));

	  if (request_pac == TRUE)
	  {
		  eapfast_phase2_create_PAC_request(eapdata);
	  }
	  break;
	  
	case FAST_SERVER_TRUSTED_ROOT_TLV:
	  debug_printf(DEBUG_NORMAL, "Got a 'Server trusted root' TLV, but "
		       "this is not implemented, and should not happen!\n");
	  result = eapfast_phase2_tlv_nak(eapdata, &indata[consumed],
					  0x00000000, 
					  FAST_SERVER_TRUSTED_ROOT_TLV);
	  break;
	  
	case FAST_REQUEST_ACTION_TLV:
	  debug_printf(DEBUG_NORMAL, "The server sent us a request for "
		       "action TLV.  But, we should NEVER get one!  NAKing!\n");
	  result = eapfast_phase2_tlv_nak(eapdata, &indata[consumed],
					  0x00000000, FAST_REQUEST_ACTION_TLV);
	  break;
	  
	case FAST_PKCS7_TLV:
	  debug_printf(DEBUG_NORMAL, "Use of a PKCS#7 certificate is not "
		       "currently supported!\n");
	  result = eapfast_phase2_tlv_nak(eapdata, &indata[consumed],
					  0x00000000, FAST_PKCS7_TLV);
	  break;
	  
	default:
	  debug_printf(DEBUG_NORMAL, "Unknown TLV type %d.\n", 
		       ntohs(fastlv->type));
	  result = eapfast_phase2_tlv_nak(eapdata, &indata[consumed],
					  0x00000000, ntohs(fastlv->type));
	  break;
	}

      if (result == 0)
	{
	  // ACK!  We couldn't process something for some reason.  (The reason
	  // should have been displayed by the called function.)
	  return;
	}

      consumed += result;
    }
}

/**********************************************************************
 *
 *  Build an EAP-FAST response.
 *
 **********************************************************************/
void eapfast_phase2_buildResp(eap_type_data *eapdata, uint8_t *result,
			      uint16_t *result_size)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    {
      *result_size = 0;
      return;
    }

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      *result_size = 0;
      return;
    }

  mytls_vars = (struct tls_vars *)eapdata->eap_data;
  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  if (eapdata->ignore == TRUE)
  {
	  (*result) = NULL;
	  (*result_size) = 0;

	  if (phase2->result_data != NULL)
	  {
		  FREE(phase2->result_data);
		  phase2->result_size = 0;
	  }

	  return;
  }
      
  if (phase2->result_data == NULL)
    {
		debug_printf(DEBUG_AUTHTYPES, "Nothing to return, ACKing.\n");
      *result_size = 0;
      return;
    }

  memcpy(result, phase2->result_data, phase2->result_size);
  *result_size = phase2->result_size;
}

#endif // OPENSSL_HELLO_EXTENSION_SUPPORTED
