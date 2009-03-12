/**
 * PEAP extensions protocols.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * NOTE : This code was developed using documentation from Microsoft.  Please
 *		  see Microsofts Open Specification Promise (available here: http://www.microsoft.com/interop/osp),
 *		  for information on any licenseing restrictions your usage may
 *		  have.
 *
 * \file peap_extensions.c
 *
 * \author chris@open1x.org
 *
 **/  
    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
    
#ifdef WINDOWS
#include <Winsock2.h>
#endif	/*  */
    
#include <openssl/hmac.h>
    
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "src/eap_sm.h"
#include "peap_phase2.h"
#include "eappeap.h"
#include "peap_extensions.h"
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
    
/**
 * \brief PRF+ as defined by the Microsoft PEAP documentation.
 *
 * @param[in] key   The "TempKey" as defined by the Microsoft PEAP documentation
 *					(The first 40 octets of the TK)
 * @param[in] seed   The IPMK Seed.  
 * @param[in] len   The minimum amount of result data we need to provide.
 *
 * \retval NULL on failure
 * \retval uint8_t* containing at least 'len' bytes
 **/ 
    uint8_t * prf_plus(uint8_t * key, uint8_t * seed, uint8_t len) 
{
	uint8_t iterations = 0;
	int i = 0;
	uint8_t * temp_data = NULL;
	uint8_t last_val[20];
	uint8_t * Tn = NULL;
	uint8_t mac[20];
	unsigned int mdlen = 0;
	if (!xsup_assert((key != NULL), "key != NULL", FALSE))
		return NULL;
	if (!xsup_assert((seed != NULL), "seed != NULL", FALSE))
		return NULL;
	if (!xsup_assert((len < 256), "len < 256", FALSE))
		return NULL;	// This should be impossible, but put it here anyway in case we ever change the type of len in the future.
	iterations = (len / 20);
	if ((len % 20) != 0)
		iterations++;	// We need a fractional amount of data, so round up.
	Tn = Malloc(iterations * 20);
	if (Tn == NULL)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to allocate memory to hash cryptobinding data!\n");
		return NULL;
		}
	temp_data = Malloc(PEAP_CRYPTOBINDING_IPMK_SEED_LEN + 3);
	if (temp_data == NULL)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to allocate memory to hash cryptobinding data!\n");
		return NULL;
		}
	debug_printf(DEBUG_AUTHTYPES, "IPMK Seed : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, seed,
			PEAP_CRYPTOBINDING_IPMK_SEED_LEN);
	memcpy(temp_data, seed, PEAP_CRYPTOBINDING_IPMK_SEED_LEN);
	temp_data[PEAP_CRYPTOBINDING_IPMK_SEED_LEN] = 0x01;
	debug_printf(DEBUG_AUTHTYPES, "T1 :\n");
	debug_hex_dump(DEBUG_AUTHTYPES, temp_data,
			(PEAP_CRYPTOBINDING_IPMK_SEED_LEN + 3));
	
	    // Malloc should have inited everything else to 0x00, so we don't need to set those.
	    HMAC(EVP_sha1(), key, 40, temp_data,
		  (PEAP_CRYPTOBINDING_IPMK_SEED_LEN + 3), (unsigned char *)&mac,
		  &mdlen);
	if (mdlen != 20)
		 {
		debug_printf(DEBUG_NORMAL,
			      "The SHA1 hash function didn't return valid data!\n");
		FREE(temp_data);
		FREE(Tn);
		return NULL;
		}
	debug_printf(DEBUG_AUTHTYPES, "Hash result (%d) : ", mdlen);
	debug_hex_printf(DEBUG_AUTHTYPES, mac, mdlen);
	memcpy(Tn, &mac[0], mdlen);	// Copy the initial data to Tn.
	memcpy(&last_val[0], &mac[0], mdlen);
	FREE(temp_data);
	if (iterations >= 2)
		 {
		for (i = 2; i <= iterations; i++)
			 {
			temp_data =
			    Malloc(20 + PEAP_CRYPTOBINDING_IPMK_SEED_LEN + 3);
			if (temp_data == NULL)
				 {
				debug_printf(DEBUG_NORMAL,
					      "Unable to allocate memory to hash cryptobinding data!\n");
				return NULL;
				}
			memcpy(temp_data, last_val, 20);
			memcpy(&temp_data[20], seed,
				PEAP_CRYPTOBINDING_IPMK_SEED_LEN);
			temp_data[20 + PEAP_CRYPTOBINDING_IPMK_SEED_LEN] = i;
			debug_printf(DEBUG_AUTHTYPES, "T%d :\n", i);
			debug_hex_dump(DEBUG_AUTHTYPES, temp_data,
					(20 + PEAP_CRYPTOBINDING_IPMK_SEED_LEN +
					 3));
			
			    // Malloc should have inited everything else to 0x00, so we don't need to set those.
			    HMAC(EVP_sha1(), key, 40, temp_data,
				  (20 + PEAP_CRYPTOBINDING_IPMK_SEED_LEN + 3),
				  (unsigned char *)&mac, &mdlen);
			if (mdlen != 20)
				 {
				debug_printf(DEBUG_NORMAL,
					      "SHA1 hash didn't return valid data in %s()!\n",
					      __FUNCTION__);
				FREE(temp_data);
				FREE(Tn);
				return NULL;
				}
			FREE(temp_data);
			debug_printf(DEBUG_AUTHTYPES, "Hash result (%d) : ",
				       mdlen);
			debug_hex_printf(DEBUG_AUTHTYPES, mac, mdlen);
			memcpy(&last_val[0], &mac[0], 20);
			memcpy(&Tn[((i - 1) * 20)], &mac[0], 20);
			}
		}
	return Tn;
}


/**
 * \brief Process a Cryptobinding TLV.
 *
 * @param[in] p2d   The phase 2 data structure for this authentication.
 * @param[in] in   A pointer to the offset in the inner packet that contains the result TLV.
 * @param[in] in_size   The total buffer length that 'in' points to.
 * @param[out] out   A pointer to a memory buffer offset where we can safely write our result TLV data to.
 * @param[out] out_size   A pointer to an integer that will be incremented by the size of the TLV we write back.
 **/ 
void peap_extensions_process_cryptobinding_tlv(eap_type_data * eapdata,
					       struct phase2_data *p2d,
					       uint8_t * in, uint16_t in_size,
					       uint8_t * out,
					       uint16_t * out_size) 
{
	peap_tlv_header * tlvdata = NULL;
	peap_tlv_cryptobinding_data * cryptodata = NULL;
	peap_tlv_cryptobinding_data * hashdata = NULL;
	uint16_t * result_val = NULL;
	uint16_t * send_result = NULL;
	uint8_t tohash_data[61];
	uint8_t * tk = NULL;	// Tunnel Key (TK)  -- Reference pointer (DON'T FREE)
	uint8_t isk[64];	// Inner Session Key (ISK)
	uint8_t *ipmk = NULL;	// Intermediate PEAP MAC Key (IPMK)
	struct tls_vars *mytls_vars = NULL;	// Reference pointer (DON'T FREE)
	uint8_t ipmk_seed[PEAP_CRYPTOBINDING_IPMK_SEED_LEN];
	uint8_t * TempKey = NULL;	// Reference pointer (DON'T FREE!)
	uint8_t *cmk = NULL;	// Reference pointer (DON'T FREE!)
	uint8_t mac[20];
	unsigned int mdlen = 0;
	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return;
	if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
		return;
	if (!xsup_assert((in != NULL), "in != NULL", FALSE))
		return;
	if (!xsup_assert((in_size > 0), "in_size > 0", FALSE))
		return;
	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return;
	if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
		return;
	tlvdata = (peap_tlv_header *) in;
	if ((ntohs(tlvdata->tlv_type) & (~PEAP_TLV_TYPE_FLAGS)) !=
	      PEAP_TLV_CRYPTOBINDING)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Error processing PEAP TLV extension!   %s() was called, but the TLV handed in wasn't a result TLV!\n",
			      __FUNCTION__);
		return;
		}
	cryptodata =
	    (peap_tlv_cryptobinding_data *) & in[sizeof(peap_tlv_header)];
	debug_printf(DEBUG_AUTHTYPES, "Reserved : %d\n",
		       cryptodata->reserved);
	debug_printf(DEBUG_AUTHTYPES, "Version  : %d\n", cryptodata->version);
	debug_printf(DEBUG_AUTHTYPES, "Recv Ver.: %d\n",
		      cryptodata->recvVersion);
	debug_printf(DEBUG_AUTHTYPES, "SubType  : %d\n", cryptodata->subType);
	
#ifdef UNSAFE_DUMPS
	    debug_printf(DEBUG_AUTHTYPES, "Nonce    : ");
	debug_hex_printf(DEBUG_AUTHTYPES, cryptodata->nonce, 32);
	debug_printf(DEBUG_AUTHTYPES, "Cmpd MAC : ");
	debug_hex_printf(DEBUG_AUTHTYPES, cryptodata->compoundMac, 20);
	
#endif				// UNSAFE_DUMPS
	    if (cryptodata->subType != 0)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Server sent us something other than a cryptobinding request!?\n");
		return;
		}
	memcpy(&tohash_data[0], in, 60);
	tohash_data[60] = EAP_TYPE_PEAP;
	hashdata =
	    (peap_tlv_cryptobinding_data *) &
	    tohash_data[sizeof(peap_tlv_header)];
	memset(hashdata->compoundMac, 0x00, 20);	// 0 out the MAC.
	debug_printf(DEBUG_AUTHTYPES, "Data to hash : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, tohash_data, 61);
	mytls_vars = (struct tls_vars *)eapdata->eap_data;
	if (mytls_vars == NULL)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to obtain TLS key data needed for PEAP cryptobinding!\n");
		return;
		}
	tk = mytls_vars->keyblock;	// First 60 bytes
	debug_printf(DEBUG_AUTHTYPES, "TK : \n");
	debug_hex_dump(DEBUG_AUTHTYPES, tk, 60);
	memset(&isk[0], 0x00, 64);
	
	    // Generate the Peer ISK using the phase 2 EAP method key data.
	    // Peer ISK = MS-MPPE-Send-Key | MS-MPPE-Recv-Key
	    // Existing EAP methods should already do this.  (Except MS-CHAPv2 in EAP-FAST mode!!)
	    if (p2d->sm->eapKeyAvailable == TRUE)
		 {
		memcpy(&isk[0], p2d->sm->eapKeyData, 64);
		debug_printf(DEBUG_AUTHTYPES, "ISK :\n");
		debug_hex_dump(DEBUG_AUTHTYPES, isk, 64);
		}
	
	    // Otherwise, leave it all 0s.
	    memset(&ipmk_seed[0], 0x00, sizeof(ipmk_seed));
	memcpy(&ipmk_seed[0], PEAP_CRYPTOBINDING_IPMK_SEED_STR,
		 PEAP_CRYPTOBINDING_IPMK_SEED_STR_LEN);
	memcpy(&ipmk_seed[PEAP_CRYPTOBINDING_IPMK_SEED_STR_LEN], &isk[16], 16);
	memcpy(&ipmk_seed[PEAP_CRYPTOBINDING_IPMK_SEED_STR_LEN + 16], isk, 16);
	TempKey = tk;		// First 40 octets.
	ipmk = prf_plus(TempKey, ipmk_seed, 60);
	if (ipmk == NULL)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to generate the IPMK for PEAP Cryptobinding.\n");
		return;
		}
	cmk = ipmk + 40;
	
#ifdef UNSAFE_DUMPS
	    debug_printf(DEBUG_AUTHTYPES, "IPMK : ");
	debug_hex_printf(DEBUG_AUTHTYPES, ipmk, 40);
	debug_printf(DEBUG_AUTHTYPES, "CMK : ");
	debug_hex_printf(DEBUG_AUTHTYPES, cmk, 20);
	
#endif	/*  */
	    HMAC(EVP_sha1(), cmk, 20, &tohash_data[0], 61,
		  (unsigned char *)&mac, &mdlen);
	if (mdlen != 20)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Unable to compute the Compound MAC.  SHA-1 didn't return 20 bytes of data!\n");
		return;
		}
	
#ifdef UNSAFE_DUMPS
	    debug_printf(DEBUG_AUTHTYPES, "Compound MAC : ");
	debug_hex_printf(DEBUG_AUTHTYPES, mac, 20);
	
#endif	/*  */
	    
	    // TODO : Finish implementation of Cryptobinding.
}


/**
 * \brief Process a Result TLV.
 *
 * @param[in] p2d   The phase 2 data structure for this authentication.
 * @param[in] in   A pointer to the offset in the inner packet that contains the result TLV.
 * @param[in] in_size   The total buffer length that 'in' points to.
 * @param[out] out   A pointer to a memory buffer offset where we can safely write our result TLV data to.
 * @param[out] out_size   A pointer to an integer that will be incremented by the size of the TLV we write back.
 **/ 
void peap_extensions_process_result_tlv(struct phase2_data *p2d, uint8_t * in,
					uint16_t in_size, uint8_t * out,
					uint16_t * out_size) 
{
	peap_tlv_header * tlvdata = NULL;
	uint16_t * result_val = NULL;
	uint16_t * send_result = NULL;
	if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
		return;
	if (!xsup_assert((in != NULL), "in != NULL", FALSE))
		return;
	if (!xsup_assert((in_size > 0), "in_size > 0", FALSE))
		return;
	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return;
	if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
		return;
	tlvdata = (peap_tlv_header *) in;
	if ((ntohs(tlvdata->tlv_type) & (~PEAP_TLV_TYPE_FLAGS)) !=
	      PEAP_TLV_RESULT)
		 {
		debug_printf(DEBUG_NORMAL,
			      "Error processing PEAP TLV extension!   %s() was called, but the TLV handed in wasn't a result TLV!\n",
			      __FUNCTION__);
		return;
		}
	result_val = (uint16_t *) (&in[sizeof(peap_tlv_header)]);
	
	    // Set up the common values.
	    tlvdata = (peap_tlv_header *) out;
	tlvdata->tlv_length = htons(2);
	tlvdata->tlv_type = htons(PEAP_TLV_RESULT | PEAP_TLV_MANDATORY_FLAG);
	send_result = (uint16_t *) & out[sizeof(peap_tlv_header)];
	(*out_size) += (sizeof(peap_tlv_header) + sizeof(uint16_t));
	switch (ntohs((*result_val)))
		 {
	default:
	case PEAP_TLV_RESULT_RESERVED:
		debug_printf(DEBUG_NORMAL,
			      "Server sent us a reserved, or unknown result code of %d.\n",
			      result_val);
		
		    // Fall through.
	case PEAP_TLV_RESULT_FAILURE:
		(*send_result) = htons(PEAP_TLV_RESULT_FAILURE);
		break;
	case PEAP_TLV_RESULT_SUCCESS:
		(*send_result) = htons(PEAP_TLV_RESULT_SUCCESS);
		break;
		}
}


/**
 * \brief Process a Result TLV.
 *
 * @param[in] p2d   The phase 2 data structure for this authentication.
 * @param[in] in  A pointer to the inner EAP packet taken from the TLS tunnel.
 * @param[in] in_size   The size of the inner EAP packet from the TLS tunnel.
 * @param[out]  out   A pointer to a buffer that will hold our response.
 * @param[out]  out_size   A pointer to an integer that will contain the size of our response.
 **/ 
int peap_extensions_process(eap_type_data * eapdata, struct phase2_data *p2d,
			    uint8_t * in, uint16_t in_size, uint8_t * out,
			    uint16_t * out_size) 
{
	uint8_t * dataptr = NULL;
	uint16_t dataofs = 0;
	peap_tlv_header * tlvdata = NULL;
	uint16_t * resultsize = NULL;
	uint16_t outdataofs = 0;
	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
		return XEGENERROR;
	if (!xsup_assert((p2d != NULL), "p2d != NULL", FALSE))
		return XEGENERROR;
	if (!xsup_assert((in != NULL), "in != NULL", FALSE))
		return XEGENERROR;
	if (!xsup_assert((in_size > 0), "in_size > 0", FALSE))
		return XEGENERROR;
	if (!xsup_assert((out != NULL), "out != NULL", FALSE))
		return XEGENERROR;
	if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
		return XEGENERROR;
	dataofs = sizeof(struct eap_header);
	outdataofs = sizeof(struct eap_header);
	(*out_size) = 0;
	while (dataofs < in_size)
		 {
		dataptr = &in[dataofs];
		tlvdata = (peap_tlv_header *) dataptr;
		debug_printf(DEBUG_AUTHTYPES, "Masked TLV TYPE : %d\n",
			       (ntohs(tlvdata->tlv_type) &
				(~PEAP_TLV_TYPE_FLAGS)));
		debug_printf(DEBUG_AUTHTYPES, "Length          : %d\n",
			      ntohs(tlvdata->tlv_length));
		if ((ntohs(tlvdata->tlv_type) & PEAP_TLV_MANDATORY_FLAG) ==
		     PEAP_TLV_MANDATORY_FLAG)
			 {
			debug_printf(DEBUG_AUTHTYPES, "TLV is MANDATORY!\n");
			}
		
		    // Switch on the value with the upper flag bits masked out.
		    switch ((ntohs(tlvdata->tlv_type) & (~PEAP_TLV_TYPE_FLAGS)))
			 {
		case PEAP_TLV_RESULT:
			debug_printf(DEBUG_AUTHTYPES,
				      "TLV is a Result TLV.\n");
			peap_extensions_process_result_tlv(p2d, dataptr,
							    (in_size - dataofs),
							    &out[outdataofs],
							    out_size);
			outdataofs = (*out_size) + sizeof(struct eap_header);
			dataofs += sizeof(peap_tlv_header) + ntohs(tlvdata->tlv_length);	// Skip this TLV.
			break;
		case PEAP_TLV_CRYPTOBINDING:
			debug_printf(DEBUG_AUTHTYPES,
				      "TLV is a Cryptobinding TLV.\n");
			peap_extensions_process_cryptobinding_tlv(eapdata, p2d,
								   dataptr,
								   (in_size -
								    dataofs),
								   &out
								   [outdataofs],
								   out_size);
			outdataofs = (*out_size) + sizeof(struct eap_header);
			dataofs += sizeof(peap_tlv_header) + ntohs(tlvdata->tlv_length);	// Skip this TLV.
			break;
		default:
			debug_printf(DEBUG_AUTHTYPES,
				      "TLV is of unknown type %d.\n",
				      (ntohs(tlvdata->tlv_type) &
				       (~PEAP_TLV_TYPE_FLAGS)));
			dataofs +=
			    sizeof(peap_tlv_header) +
			    ntohs(tlvdata->tlv_length);
			break;
			}
		}
	out[0] = EAP_RESPONSE_PKT;
	out[1] = in[1];	// EAP ID
	resultsize = (uint16_t *) & out[2];
	(*out_size) = outdataofs;
	(*resultsize) = htons((*out_size));
	out[4] = PEAP_EAP_EXTENSION;
	p2d->sm->decision = COND_SUCC;
	return XEINNERDONE;
}


