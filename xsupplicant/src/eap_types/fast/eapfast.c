/**
 * EAP-FAST Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapfast.c
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error message signaling.
 * \todo Add support for temporary username/password pairs.
 * \todo Add support for password reprompting.
 *
 **/

#ifdef EAP_FAST

#include <string.h>
#include <stdlib.h>

#ifdef WINDOWS
#include <Winsock2.h>
#endif

#include "xsupconfig.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "../../xsup_common.h"
#include "../../eap_sm.h"
#include "eapfast.h"
#include "eapfast_phase2.h"
#include "eapfast_xml.h"
#include "../tls/eaptls.h"
#include "../tls/tls_funcs.h"
#include "../eap_type_common.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/****************************************************************
 *
 * This is called if methodState == INIT.  It should set up all of the
 * memory that we will need to complete the authentication.
 *
 ****************************************************************/
uint8_t eapfast_init(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct config_eap_fast *fastconf = NULL;
  struct eapfast_phase2 *fastphase2 = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  fastconf = (struct config_eap_fast *)eapdata->eap_conf_data;

  if (!xsup_assert((fastconf != NULL), "fastconf != NULL", FALSE))
    return FALSE;
  
  if (eapdata->eap_data == NULL)
    {
      eapdata->eap_data = Malloc(sizeof(struct tls_vars));
      if (eapdata->eap_data == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store FAST "
		       "specific data structures.\n");
	  return FALSE;
	}
    }

  mytls_vars = eapdata->eap_data;

  if (tls_funcs_init(mytls_vars, EAP_TYPE_FAST) != XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize SSL engine!\n");
      return FALSE;
    }
  
  if (tls_funcs_build_new_session(mytls_vars) != XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize SSL context!\n");
      return FALSE;
    }

  mytls_vars->cncheck = FALSE;
  mytls_vars->cnexact = FALSE;
  mytls_vars->resume = RES_NO;

  FREE(mytls_vars->keyblock);

  fastphase2 = (struct eapfast_phase2 *)Malloc(sizeof(struct eapfast_phase2));
  if (fastphase2 == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error allocating memory for EAP-FAST phase"
		   " data!\n");
      return FALSE;
    }

  mytls_vars->phase2data = fastphase2;
  mytls_vars->handshake_done = FALSE;

  eapfast_phase2_init(eapdata);

  eap_type_common_init_eap_data(eapdata);

  eapdata->methodState = MAY_CONT;

  return TRUE;
}

/****************************************************************
 *
 *  Get the version number we have stored away.  If something goes
 *  wrong, we will return 0, which should cause the server to reject
 *  our request.
 *
 ****************************************************************/
uint8_t eapfast_get_ver(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *fastphase2 = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return 0;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return 0;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (!xsup_assert((mytls_vars->phase2data != NULL), 
		   "mytls_vars->phase2data != NULL", FALSE))
    return 0;

  fastphase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  return fastphase2->version;
}

/****************************************************************
 *
 *  Set the value of the version number.  Store it in a structure
 *  for later use.
 *
 ****************************************************************/
void eapfast_set_ver(eap_type_data *eapdata, uint8_t ver)
{
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *fastphase2 = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

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

  fastphase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  if (ver == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid version requested for EAP-FAST! "
		   "Version 0 is not allowed.\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (ver > FAST_MAX_VER)
    {
      debug_printf(DEBUG_AUTHTYPES, "The server requested version %d.  But, "
		   "the highest we support is %d.  Requesting we use %d.\n",
		   ver, FAST_MAX_VER, FAST_MAX_VER);
      fastphase2->version = FAST_MAX_VER;
    }
  else
    {
      fastphase2->version = ver;
    }
}

/****************************************************************
 *
 *  Check to be sure we are ready to handle an EAP-FAST authentication.
 *
 ****************************************************************/
void eapfast_check(eap_type_data *eapdata)
{
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "(EAP-FAST) Checking...\n");
  if (eapdata->methodState == INIT)
    {
      if (eapfast_init(eapdata) != TRUE)
	{
	  debug_printf(DEBUG_NORMAL, "Failed to init EAP-FAST!\n");
	  eap_type_common_fail(eapdata);
	  return;
	}
    }

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }

  eapfast_phase2_check(eapdata);
}

/***************************************************************
 *
 *  Read an AID from the first packet.
 *
 ***************************************************************/
uint8_t eapfast_get_aid(uint8_t *indata, uint8_t **aid, uint16_t *aid_len)
{
  struct eapfast_tlv *fasttlv = NULL;
  uint8_t *tempaid = NULL;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return FALSE;
  
  fasttlv = (struct eapfast_tlv *)indata;

  if (ntohs(fasttlv->type) != FAST_AUTHORITY_ID) 
    {
      debug_printf(DEBUG_AUTHTYPES, "Not an authority ID TLV!\n");
      return FALSE;
    }

  // Otherwise, make a copy for later use.
  (*aid_len) = ntohs(fasttlv->length);

  tempaid = (uint8_t *)Malloc((*aid_len));
  if (tempaid == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store AID.\n");
      return FALSE;
    }

  memcpy(tempaid, fasttlv->data, (*aid_len));

  (*aid) = tempaid;

  return TRUE;
}

/***************************************************************
 *
 *  Given an AID, parse the PAC file and see if we have any valid
 *  authentication data that can be used.  Based on what we find, we
 *  should prep the TLS library to behave correctly.
 *
 ***************************************************************/
uint8_t eapfast_check_pac(eap_type_data *eapdata, uint8_t *aid, 
			  uint16_t aid_len)
{
  struct config_eap_fast *eapfast_config = NULL;
  struct eapfast_phase2 *fastp2 = NULL;
  struct tls_vars *mytls_vars = NULL;
  char *straid = NULL;
  xmlDocPtr doc = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_conf_data != NULL), 
		   "eapdata->eap_conf_data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return FALSE;
    }

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    {
      eap_type_common_fail(eapdata);
      return FALSE;
    }

  eapfast_config = (struct config_eap_fast *)eapdata->eap_conf_data;

  mytls_vars = eapdata->eap_data;

  if (!xsup_assert((mytls_vars->phase2data != NULL), 
		   "mytls_vars->phase2data != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return FALSE;
    }

  fastp2 = mytls_vars->phase2data;

  // Convert AID to a string.
  straid = eap_type_common_convert_hex(aid, aid_len);

  // Search for the AID in the XML file.
  eapfast_xml_init();
  doc = eapfast_xml_open_pac(eapfast_config->pac_location);

  if (doc == NULL) 
    {
      eapfast_xml_deinit(doc);
      return FALSE;
    }

  fastp2->pacs = Malloc(sizeof(struct pac_values));
  if (fastp2->pacs == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store PAC data!\n");
      return FALSE;
    }

  if (eapfast_xml_find_pac_data(doc, straid, fastp2->pacs) != 0)
    {
      eapfast_xml_deinit(doc);
      FREE(fastp2->pacs);
      return FALSE;
    }

  // If it is there, then store it and return TRUE.
  eapfast_xml_deinit(doc);

  return TRUE;
}

/***************************************************************
 *
 *  Given the server random, create the master secret, and pass
 *  it in to the TLS engine.
 *
 ***************************************************************/
int eapfast_calc_master_secret(struct tls_vars *mytls_vars, 
			       uint8_t *server_random)
{
  uint8_t *client_random = NULL, *master_secret = NULL;
  uint8_t randoms[64];
  struct eapfast_phase2 *phase2 = NULL;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return -1;

  if (!xsup_assert((server_random != NULL), "server_random != NULL", FALSE))
    return -1;

  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  client_random = tls_funcs_get_client_random(mytls_vars);

  memcpy(&randoms[0], server_random, 32);
  memcpy(&randoms[32], client_random, 32);

  debug_printf(DEBUG_AUTHTYPES, "Server Random : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, server_random, 32);

  debug_printf(DEBUG_AUTHTYPES, "Client Random : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, client_random, 32);

  debug_printf(DEBUG_AUTHTYPES, "PAC Key : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, phase2->pacs->pac_key, 32);

  debug_printf(DEBUG_AUTHTYPES, "Randoms : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, randoms, 64);

  debug_printf(DEBUG_AUTHTYPES, "Label : %s\n", FAST_PAC_TO_MSLH);

  master_secret = eapfast_phase2_t_prf(phase2->pacs->pac_key, 32,
				       FAST_PAC_TO_MSLH, randoms, 64, 48);

  debug_printf(DEBUG_AUTHTYPES, "Master Secret :\n");
  debug_hex_dump(DEBUG_AUTHTYPES, master_secret, 48);

  if (tls_funcs_set_master_secret(mytls_vars, master_secret, 48) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't set master secret!\n");
      return -1;
    }

  FREE(master_secret);
  FREE(client_random);

  return 0;
}

/***************************************************************
 *
 *  (pre)Process a TLS packet to see if it contains the server random.
 *  If it does, then calculate the MSK, and feed it back in to the
 *  SSL engine.
 *
 ***************************************************************/
void eapfast_parse_tls(struct tls_vars *mytls_vars, uint8_t *packet)
{
  struct eapfast_phase2 *phase2 = NULL;
  struct tls_server_hello *hello = NULL;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return;

  if (!xsup_assert((packet != NULL), "packet != NULL", FALSE))
    return;

  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

  if (packet[sizeof(struct eap_header)] & EAPTLS_LENGTH_INCL)
    {
      hello = (struct tls_server_hello *)&packet[sizeof(struct eap_header)+5];
    }
  else
    {
      hello = (struct tls_server_hello *)&packet[sizeof(struct eap_header)];
    }

  if (hello->content_type != TLS_HANDSHAKE_TYPE)
    {
      debug_printf(DEBUG_AUTHTYPES, "Packet is not a handshake packet, "
		   "ignoring.\n");
      debug_printf(DEBUG_AUTHTYPES, "Expected %d, got %d.\n", 
		   TLS_HANDSHAKE_TYPE, hello->content_type);
      return;
    }

  if (ntohs(hello->rec_version) < ntohs(0x0301))
    {
      debug_printf(DEBUG_NORMAL, "TLS version is not 1.0 or greater!\n");
      return;
    }

  if (hello->handshake_type != TLS_SERVER_HELLO)
    {
      debug_printf(DEBUG_AUTHTYPES, "Packet is not a server hello.  "
		   "Ignoring.\n");
      return;
    }

  if (ntohs(hello->shake_version) < ntohs(0x0301))
    {
      debug_printf(DEBUG_NORMAL, "Server Handshake version is not TLS 1.0 "
		   "or greater!\n");
      return;
    }

  if (eapfast_calc_master_secret(mytls_vars, hello->server_random) == 0)
    {
      // We don't need to parse TLS packets anymore.
      phase2->need_ms = FALSE;
    }
}

/***************************************************************
 *
 *  Process an EAP-FAST packet.
 *
 ***************************************************************/
void eapfast_process(eap_type_data *eapdata)
{
  uint8_t *tls_type = NULL, *resbuf = NULL;
  uint8_t fast_version = 0;
  struct tls_vars *mytls_vars = NULL;
  struct eapfast_phase2 *phase2 = NULL;
  uint8_t *aid = NULL;
  uint16_t aid_len = 0, resout = 0;
  int bufsiz = 0;
  struct config_eap_fast *fastconf = NULL;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-FAST) Processing.\n");
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

  fastconf = (struct config_eap_fast *)eapdata->eap_conf_data;
  mytls_vars = eapdata->eap_data;

  tls_type = &eapdata->eapReqData[sizeof(struct eap_header)];
  fast_version = (tls_type[0] & FAST_VERSION_MASK);

  eapfast_set_ver(eapdata, fast_version);

  debug_printf(DEBUG_AUTHTYPES, "Requested EAP-FAST version is %d.\n", 
	       fast_version);

  tls_type[0] = (tls_type[0] & FAST_VERSION_MASK_OUT);

  if ((eapdata->eapReqData[sizeof(struct eap_header)] == EAPTLS_START)
      || (mytls_vars->handshake_done != TRUE))
    {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-FAST) Processing packet.\n");

      if (eapdata->eapReqData[sizeof(struct eap_header)] == EAPTLS_START)
		{
		  if (eapfast_get_aid(&eapdata->eapReqData[sizeof(struct eap_header)+1],
			      &aid, &aid_len) == TRUE)
		    {
		      debug_printf(DEBUG_AUTHTYPES, "Got AID (%d byte(s)) : ", aid_len);
		      debug_hex_printf(DEBUG_AUTHTYPES, aid, aid_len);
	      
		      if (eapfast_check_pac(eapdata, aid, aid_len) == FALSE)
				{
				  debug_printf(DEBUG_AUTHTYPES, "Couldn't locate a PAC file. "
					       "We will provision one.\n");

				  // We don't have a PAC, are we allowed to provision one?
				  if (TEST_FLAG(fastconf->provision_flags, EAP_FAST_PROVISION_ALLOWED))
				  {
					  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;
					  phase2->provisioning = TRUE;

					  if (TEST_FLAG(fastconf->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED))	
					  {
						  // Do authenticated mode.
						  debug_printf(DEBUG_NORMAL, "Doing authenticated provisioning mode.\n");
						  phase2->anon_provisioning = FALSE;
					  }
					  else if (TEST_FLAG(fastconf->provision_flags, EAP_FAST_PROVISION_ANONYMOUS))
					  {
						  // Set our cipher suite to only allow Anon-DH mode, which should force
						  // any authenticator in to anonymous provisioning, or a failure case.
						  debug_printf(DEBUG_NORMAL, "Doing unauthenticated provisioning mode.\n");
						  tls_funcs_set_cipher_list(mytls_vars, "ADH-AES128-SHA");
						  phase2->anon_provisioning = TRUE;
					  }
				  }
				  else
				  {
					  debug_printf(DEBUG_NORMAL, "EAP-FAST provisioning is currently disabled!  We cannot continue!\n");
					  eap_type_common_fail(eapdata);
				  }
			  }
		      else
  			  {
				  phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;
				  phase2->provisioning = FALSE;

				  // We have a PAC, so configure TLS, and move on.
				  if (tls_funcs_set_hello_extension(mytls_vars, 
						    FAST_SESSION_TICKET,
						    phase2->pacs->pac_opaque,
						    phase2->pacs->pac_opaque_len) != 1)
				    {
				      debug_printf(DEBUG_NORMAL, "Error attempting to set the "
						   "session key data for EAP-FAST!\n");
				      eap_type_common_fail(eapdata);
				      return;
				    }
		  
				  // Let us know that we need to "hand parse" the Server 
				  // Hello packet to get the server random.
				  phase2->need_ms = TRUE;
			}
	    }
	  else
	    {
	      eap_type_common_fail(eapdata);
	      return;
	    }
	}

      FREE(aid);

      phase2 = (struct eapfast_phase2 *)mytls_vars->phase2data;

      if (phase2->need_ms == 1)
		{
		  eapfast_parse_tls(mytls_vars, eapdata->eapReqData);
		}

      eapdata->methodState = tls_funcs_process(eapdata->eap_data,
					       eapdata->eapReqData);

      if ((mytls_vars->handshake_done == TRUE) && (phase2->provisioning == TRUE))
		mytls_vars->send_ack = TRUE;
    }
  else
    {
      // Handle phase 2 stuff.
      resout = eap_type_common_get_eap_length(eapdata->eapReqData);

      if (tls_funcs_buffer(eapdata->eap_data, 
			   &eapdata->eapReqData[sizeof(struct eap_header)],
			   resout) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "There was an error buffering data "
		       "fragments.  Discarding fragment.\n");
	  eapdata->ignore = FALSE;
	  return;
	}

      bufsiz = tls_funcs_decrypt_ready(eapdata->eap_data);
      debug_printf(DEBUG_AUTHTYPES, "Decrypt ready returned : %d\n", bufsiz);
      switch (bufsiz)
	{
	case 0:
	  // Nothing to do yet.
	  break;

	case -1:
	  // Got an error.  Discard the frame.
	  eap_type_common_fail(eapdata);
	  break;

	default:
	  resbuf = Malloc(bufsiz);
	  if (resbuf == NULL)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory needed to "
			   "store decrypted data!\n");
	      eap_type_common_fail(eapdata);
	      break;
	    }

	  resout = bufsiz;

	  if (tls_funcs_decrypt(eapdata->eap_data, resbuf, &resout) != XENONE)
	    {
	      debug_printf(DEBUG_NORMAL, "Decryption failed!\n");
	      eap_type_common_fail(eapdata);
	      break;
	    }

	  debug_printf(DEBUG_AUTHTYPES, "Inner dump (%d) :\n", resout);
	  debug_hex_dump(DEBUG_AUTHTYPES, resbuf, resout);
	  eapfast_phase2_process(eapdata, resbuf, resout);

	  FREE(resbuf);
	  break;
	}
    }
}

/***************************************************************
 *
 *  Build a response to an EAP-FAST request.
 *
 ***************************************************************/
uint8_t *eapfast_buildResp(eap_type_data *eapdata)
{
  struct config_eap_fast *eapconf = NULL;
  uint8_t *res = NULL, *fastres = NULL;
  uint16_t res_size = 0, total_size = 0;
  struct eap_header *eaphdr = NULL;
  uint8_t reqId = 0;
  struct tls_vars *mytls_vars = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_conf_data != NULL),
		   "eapdata->eap_conf_data != NULL", FALSE))
    return NULL;

  eapconf = eapdata->eap_conf_data;
  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if ((mytls_vars->handshake_done == TRUE) &&
      (tls_funcs_data_pending(mytls_vars) == 0))
    {
      if ((mytls_vars->handshake_done == TRUE) && (mytls_vars->send_ack == FALSE))
		{
		  // Handle phase 2 stuff.
		  res = Malloc(1520);
		  if (res == NULL) 
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
				   "result.\n");
		      return NULL;
		    }
		  eapfast_phase2_buildResp(eapdata, res, &res_size);
	  
		  tls_funcs_encrypt(eapdata->eap_data, res, res_size);
	  
		  FREE(res);
		}
    }

  if ((eapconf->chunk_size == 0) || (eapconf->chunk_size > MAX_CHUNK))
    eapconf->chunk_size = MAX_CHUNK;

  if (tls_funcs_get_packet(eapdata->eap_data, eapconf->chunk_size, &res,
			   &res_size) != XENONE)
    {
      return NULL;
    }

  if (res == NULL) return NULL;

  mytls_vars->send_ack = FALSE;

  eaphdr = (struct eap_header *)eapdata->eapReqData;
  reqId = eaphdr->eap_identifier;

  fastres = Malloc(res_size + sizeof(struct eap_header));
  if (fastres == NULL) return NULL;

  eaphdr = (struct eap_header *)fastres;

  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = reqId;
  total_size = res_size + sizeof(struct eap_header);
  eaphdr->eap_length = htons(total_size);
  eaphdr->eap_type = EAP_TYPE_FAST;

  memcpy(&fastres[sizeof(struct eap_header)], res, res_size);

  fastres[sizeof(struct eap_header)] |= eapfast_get_ver(eapdata);

  FREE(res);

  return fastres;
}

/***************************************************************
 *
 *  Determine if we have keying material available.
 *
 ***************************************************************/
uint8_t eapfast_isKeyAvailable(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  uint8_t *simckj = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return FALSE;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  if (mytls_vars->handshake_done == FALSE) return FALSE;

  if (mytls_vars->keyblock != NULL) 
    {
      FREE(mytls_vars->keyblock);
    }

  simckj = eapfast_phase2_get_simckj(eapdata);

  if (simckj == NULL) return FALSE;

  mytls_vars->keyblock = eapfast_phase2_t_prf(simckj, 40, FAST_SESSION_KEY,
					      NULL, 0, 64);

  if (mytls_vars->keyblock != NULL) return TRUE;

  return FALSE;
}

/***************************************************************
 *
 *  If there is keying material available, then return a key.
 *
 ***************************************************************/
uint8_t *eapfast_getKey(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;
  uint8_t *retkey = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL",
		   FALSE))
    return NULL;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  retkey = Malloc(64);
  if (retkey == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to return key "
		   "data!\n");
      return NULL;
    }

  memcpy(retkey, mytls_vars->keyblock, 64);

  return retkey;
}

/***************************************************************
 *
 *  Clean up any memory that we have used.
 *
 ***************************************************************/
void eapfast_deinit(eap_type_data *eapdata)
{
  struct tls_vars *mytls_vars = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eap_data != NULL),
		   "eapdata->eap_data != NULL", FALSE))
    return;

  mytls_vars = (struct tls_vars *)eapdata->eap_data;

  eapfast_phase2_deinit(eapdata);
  tls_funcs_deinit(mytls_vars);

  FREE(mytls_vars);
  FREE(eapdata->eap_data);

  debug_printf(DEBUG_DEINIT, "(EAP-FAST) Cleaned up.\n");
}

#endif // EAP_FAST
