/**
 * EAP-PSK implementation for XSupplicant
 * 
 * \file eappsk.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifdef EXPERIMENTAL

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

#ifndef WINDOWS
#include <unistd.h>
#else
#include <Winsock2.h>
#endif

#include <stdlib.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "xsupconfig.h"
#include "../../xsup_common.h"
#include "../../eap_sm.h"
#include "eappsk.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../ipc_callout.h"
#include "../../frame_structs.h"
#include "../../context.h"
#include "../../event_core.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "psk_crypt.h"

/**
 * \brief Initialize EAP-PSK by allocating memory to store data.
 *
 * @param[in] eapdata   The eap_type_data structure that we can use to store
 *						state data.
 **/
void eappsk_init(eap_type_data *eapdata)
{
	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-PSK) Init.\n");

	if (eapdata->eap_data != NULL) FREE(eapdata->eap_data);

	eapdata->eap_data = Malloc(sizeof(eappsk_data));
	if (eapdata->eap_data == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store EAP-PSK state data.\n");
		eap_type_common_fail(eapdata);
		return;
	}
}

/**
 * \brief Verify that we are in the proper state to perform an EAP-PSK
 *        authentication.
 *
 * @param[in] eapdata   The eap_data structure that we need to hold data.
 **/
void eappsk_check(eap_type_data *eapdata)
{
  struct eap_header *myeap = NULL;
  struct config_pwd_only *pskconf = NULL;
  context *ctx = NULL;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  if (!xsup_assert((eapdata->eapReqData != NULL), 
		   "eapdata->eapReqData != NULL", FALSE))
    {
      eap_type_common_fail(eapdata);
      return;
    }
  
  myeap = (struct eap_header *)eapdata->eapReqData;

  if (myeap == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid packet was passed in to %s!\n",
		   __FUNCTION__);
      eap_type_common_fail(eapdata);
      return;
    }

  if (myeap->eap_code != EAP_REQUEST_PKT)
    {
      debug_printf(DEBUG_NORMAL, "EAP isn't a request packet!?\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (myeap->eap_identifier == 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP identifier!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  pskconf = (struct config_pwd_only *)eapdata->eap_conf_data;

  if (pskconf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There is no valid configuration for "
		   "EAP-PSK!\n");
      eap_type_common_fail(eapdata);
      return;
    }

  if (pskconf->password == NULL)
    {
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
	      debug_printf(DEBUG_NORMAL, "No password available for EAP-PSK!\n");
	      eap_type_common_fail(eapdata);
	      return;
		}

		if (ctx->prof->temp_password == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-PSK!\n");
			eap_type_common_fail(eapdata);
			return;
		}
    }

  if (eapdata->methodState == INIT)
  {
	  eappsk_init(eapdata);
  }
}

/**
 * \brief Derive the keyblock for this EAP method.
 *
 * @param[in] kdk   The key deriving key.
 * @param[in] rand_p   Our random value.
 **/
uint8_t *eappsk_derive_keyblock(uint8_t *kdk, uint8_t *rand_p)
{
	uint8_t *keyblock = NULL;
	AES_KEY key;
	char temp_data[16];
	char key_block[16];
	uint8_t count = 0;

	if (!xsup_assert((kdk != NULL), "kdk != NULL", FALSE)) return NULL;
	if (!xsup_assert((rand_p != NULL), "rand_p != NULL", FALSE)) return NULL;

	// Allocate the memory for our keyblock.
	keyblock = Malloc(16 * 9);
	if (keyblock == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate the memory to generate keyblock!\n");
		return NULL;
	}

	AES_set_encrypt_key(kdk, 16*8, &key);

	AES_ecb_encrypt(rand_p, &temp_data[0], &key, AES_ENCRYPT);

	for (count = 1; count <= 9; count++)
	{
		temp_data[15] ^= count;
		AES_ecb_encrypt(temp_data, key_block, &key, AES_ENCRYPT);

		memcpy(&keyblock[(count-1)*16], &key_block[0], 16);
		temp_data[15] ^= count;       // Undo the previous XOR.
	}

	debug_printf(DEBUG_AUTHTYPES, "Derived keyblock :\n");
	debug_hex_dump(DEBUG_AUTHTYPES, keyblock, (16*9));

	return keyblock;
}

/**
 * \brief Derive the PSK from the password according to Appendix A of RFC 4764.
 *
 * @param[in] password   The ASCII password provided by the user.
 *
 * \retval NULL on error, anything else is the PSK.
 **/
uint8_t *eappsk_get_psk(char *password, char *id_s, char *id_p)
{
	uint8_t p16[16];
	uint8_t *datablock = NULL;
	uint8_t hash[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
		0x76, 0x54, 0x32, 0x10};   // Initial value.
	int needed_length = 0;
	int i = 0;
	AES_KEY key;
	uint8_t temp_data[16];
	int x = 0;
	uint8_t salt[12];

	if (strlen(password) < 16)
	{
		// Pad it to be 16.
		memset(&p16[0], 0x00, 16);
		memcpy(&p16[0], password, strlen(password));
	}
	else
	{
		// Need to compress the password to make it 16 bytes.

		// First, make sure we have a multiple of 16 bytes.
		needed_length = strlen(password) + (16 - (strlen(password) % 16));
		datablock = Malloc(needed_length);
		if (datablock == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to allocate memory needed to store password data block!\n");
			return NULL;
		}

		memcpy(datablock, password, strlen(password));

		for (i = 0; i < (needed_length/16); i++)
		{
			AES_set_encrypt_key(hash, 16*8, &key);

			AES_ecb_encrypt((unsigned char *)&datablock[(i*16)], (unsigned char *)&temp_data, &key, AES_ENCRYPT);

			for (x = 0; x < 16; x++)
			{
				hash[x] ^= temp_data[x];
			}
		}

		memcpy(&p16[0], &hash[0], 16);

		free(datablock);
	}

	debug_printf(DEBUG_AUTHTYPES, "P16 : ");
	debug_hex_printf(DEBUG_AUTHTYPES, p16, 16);

	memset(&salt[0], 0x00, 12);
	if (strlen(id_s) > 12)
	{
		memcpy(&salt[0], id_s, 12);
	}
	else
	{
		memcpy(&salt[0], id_s, strlen(id_s));
	}

	memset(&temp_data[0], 0x00, 12);
	if (strlen(id_p) > 12)
	{
		memcpy(&temp_data[0], id_p, 12);
	}
	else
	{
		memcpy(&temp_data[0], id_p, strlen(id_p));
	}

	for (i = 0; i < 12; i++)
	{
		salt[i] ^= temp_data[i];
	}

	debug_printf(DEBUG_AUTHTYPES, "Salt : ");
	debug_hex_printf(DEBUG_AUTHTYPES, salt, 12);

	datablock = Malloc(16);
	if (datablock == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory needed to store PSK result.\n");
		return NULL;
	}

	if (PKCS5_PBKDF2_HMAC_SHA1(p16, 16, salt, 12, 5000, 16, datablock) != TRUE)
	{
		free(datablock);
		return NULL;
	}

	debug_printf(DEBUG_AUTHTYPES, "Result : ");
	debug_hex_printf(DEBUG_AUTHTYPES, datablock, 16);

	return datablock;
}

/**
 * \brief Derive the PSK from the provided key data.
 *
 * @param[in] eapdata   The eap_data structure that contains the information we
 *						need to process.
 **/
uint8_t eappsk_derive_psks(eap_type_data *eapdata)
{
	eappsk_data *pskdata = NULL;
	struct config_pwd_only *pskcfg = NULL;
	AES_KEY key;
	char iv[AES_BLOCK_SIZE];
	char data[16];
	char tempdata[16];
	int i = 0;
	char *password = NULL;   // This is a reference pointer, DO NOT free it!
	context *ctx = NULL;
	char *psk = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return FALSE;

	pskdata = (eappsk_data *)eapdata->eap_data;

	pskcfg = (struct config_pwd_only *)eapdata->eap_conf_data;

	if (pskcfg->password != NULL)
	{
		password = pskcfg->password;
	}
	else
	{
		ctx = event_core_get_active_ctx();
		if (ctx == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No password available for EAP-PSK!\n");
			return FALSE;
		}

		password = ctx->prof->temp_password;
	}

	// If the password we are given is 16 characters, assume it is a straight PSK.
	if (strlen(password) == 16)
	{
		psk = strdup(password);
	}
	else if (strlen(password) == 32)
	{
		// This is probably a hexidecimal representation of a PSK. ;)
		psk = Malloc(16);
		if (psk == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store PSK information!\n");
			return FALSE;
		}

		process_hex(password, strlen(password), psk);
	}
	else
	{
		psk = eappsk_get_psk(password, pskdata->id_s, eapdata->ident);
		if (psk == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to derive the PSK from the provided password!\n");
			return FALSE;
		}
	}

	AES_set_encrypt_key(psk, 16*8, &key);

	memset(&iv[0], 0x00, AES_BLOCK_SIZE);
	memset(&data[0], 0x00, 16);

	AES_ecb_encrypt(&data[0], &iv[0], &key, AES_ENCRYPT);

	memcpy(&tempdata[0], &iv[0], 16);
	tempdata[AES_BLOCK_SIZE-1] ^= 0x01;

	AES_ecb_encrypt(&tempdata[0], &pskdata->ak[0], &key, AES_ENCRYPT);

	memcpy(&tempdata[0], &iv[0], 16);
	tempdata[AES_BLOCK_SIZE-1] ^= 0x02;

	AES_ecb_encrypt(&tempdata[0], &pskdata->kdk[0], &key, AES_ENCRYPT);

#ifdef UNSAFE_DUMPS
	debug_printf(DEBUG_AUTHTYPES, "AK : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskdata->ak, 16);

	debug_printf(DEBUG_AUTHTYPES, "KDK : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskdata->kdk, 16);
#endif

	FREE(psk);

	return TRUE;
}

/**
 * \brief Process an EAP-PSK packet with the flags set to 0.
 *
 * @param[in] eapdata   The eap_data structure that contains the information we
 *						need to process.
 **/
void eappsk_process_packet0(eap_type_data *eapdata)
{
	eappsk_packet0 *pskpacket = NULL;
	eappsk_data *pskdata = NULL;
	struct eap_header *eaphdr = NULL;
	uint16_t nai_size = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return;

	pskdata = (eappsk_data *)eapdata->eap_data;

	pskpacket = (eappsk_packet0 *)&eapdata->eapReqData[sizeof(struct eap_header)+1];

	debug_printf(DEBUG_AUTHTYPES, "RAND_S : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskpacket->rand_s, 16);

	memcpy(&pskdata->rand_s[0], pskpacket->rand_s, 16);

	eaphdr = (struct eap_header *)eapdata->eapReqData;

	nai_size = ntohs(eaphdr->eap_length) - sizeof(struct eap_header) - 1 - 16;
	pskdata->id_s = Malloc(nai_size+2);
	if (pskdata->id_s == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory needed to store ID_S!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	memcpy(pskdata->id_s, pskpacket->nai_id, nai_size);
	debug_printf(DEBUG_AUTHTYPES, "NAI ID : %s\n", pskdata->id_s);

	if (eappsk_derive_psks(eapdata) == FALSE)
	{
		eap_type_common_fail(eapdata);
		return;
	}

	eapdata->methodState = MAY_CONT;

	pskdata->packetnum = 1;			// Send a response of packet type 1.
}

/**
 * \brief Process an EAP-PSK packet with the flags set to 2.
 *
 * @param[in] eapdata   The eap_data structure that contains the information we
 *						need to process.
 **/
void eappsk_process_packet2(eap_type_data *eapdata)
{
	eappsk_packet2 *pskpacket = NULL;
	eappsk_data *pskdata = NULL;
	struct eap_header *eaphdr = NULL;
	char *mac_s = NULL;
	char *mac_s_data = NULL;
	unsigned char *result;
	unsigned int result_size;
	int pchn_size = 0;
	uint8_t flags = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return;

	pskdata = (eappsk_data *)eapdata->eap_data;

	pskpacket = (eappsk_packet2 *)&eapdata->eapReqData[sizeof(struct eap_header)];

	debug_printf(DEBUG_AUTHTYPES, "RAND_S : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskpacket->rand_s, 16);

	debug_printf(DEBUG_AUTHTYPES, "Stored : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskdata->rand_s, 16);

	if (memcmp(pskpacket->rand_s, pskdata->rand_s, 16) != 0)
	{
		debug_printf(DEBUG_NORMAL, "The server random sent in packet 0 doesn't match the one sent in packet 2!  Authentication failed.\n");
		eap_type_common_fail(eapdata);
		return;
	}

	// MAC_S = CMAC-AES-128(AK, ID_S||RAND_P)
	mac_s_data = Malloc(strlen(pskdata->id_s)+16);
	if (mac_s_data == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store MAC_S value!\n");
		eap_type_common_fail(eapdata);
		return;
	}

	strcpy(mac_s_data, pskdata->id_s);
	memcpy(&mac_s_data[strlen(pskdata->id_s)], pskdata->rand_p, 16);

	mac_s = cmac_aes_128(pskdata->ak, mac_s_data, ((strlen(pskdata->id_s)+16)*8));
	if (mac_s == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to create MAC_S!\n");
		eap_type_common_fail(eapdata);
		FREE(mac_s_data);
		return;
	}

	if (memcmp(mac_s, pskpacket->mac_s, 16) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Server MAC check failed!\n");
		eap_type_common_fail(eapdata);
		FREE(mac_s);
		FREE(mac_s_data);
		return;
	}

	FREE(mac_s);
	FREE(mac_s_data);

	// Derive the keyblock so that we have the data we need.
	pskdata->keydata = eappsk_derive_keyblock(pskdata->kdk, pskdata->rand_p);

	eaphdr = (struct eap_header *)eapdata->eapReqData;

	pchn_size = ntohs(eaphdr->eap_length) - 16 - 16 - 1 - sizeof(struct eap_header);

	debug_printf(DEBUG_AUTHTYPES, "Key : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskdata->keydata, 16);

	debug_printf(DEBUG_AUTHTYPES, "Nonce : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskpacket->pchn_nonce, 4);

	if (eax_decrypt(pskdata->keydata, pskpacket->pchn_nonce, (unsigned char *)eaphdr, &pskpacket->pchn_tag[0],
		&pskpacket->pchn_flags, 1, &result, &result_size) == 0)
	{
		debug_printf(DEBUG_NORMAL, "Failed to decrypt the protected channel.\n");
		eap_type_common_fail(eapdata);
		return;
	}

	memcpy(&pskdata->nonce[0], &pskpacket->pchn_nonce[0], 4);

	debug_printf(DEBUG_AUTHTYPES, "PChannel Flags = %d\n", result[0]);

	flags = result[0] & 0xc0;			// Mask out everything but the upper two bits.

	switch(flags)
	{
	case EAP_PSK_FLAGS_CONT:
		debug_printf(DEBUG_NORMAL, "PSK extended authentication is not currently supported!\n");
		eapdata->methodState = DONE;
		eap_type_common_fail(eapdata);
		return;
		break;

	case EAP_PSK_FLAGS_SUCCESS:
		debug_printf(DEBUG_NORMAL, "Server indicates the PSK handshake was a success.\n");
		break;

	case EAP_PSK_FLAGS_FAILURE:
		debug_printf(DEBUG_NORMAL, "Server indicates the PSK handshake failed.\n");
		eapdata->methodState = DONE;
		eap_type_common_fail(eapdata);
		return;
		break;

	default:
		debug_printf(DEBUG_NORMAL, "This should be impossible!\n");
		eap_type_common_fail(eapdata);
		return;
		break;
	}

	eapdata->methodState = MAY_CONT;
	eapdata->decision = COND_SUCC;

	pskdata->packetnum = 3;			// Send a response of packet type 3.
}

/**
 * \brief Create a packet with the flags set to 1.  (A response to the inbound packet with the
 *			flags set to 0.)
 *
 * @param[in] eapdata   The eap_data structure that contains the information we 
 *						need to process.
 **/
uint8_t *eappsk_create_packet1(eap_type_data *eapdata)
{
	int i = 0;
	eappsk_packet1 *pskpacket1 = NULL;
	eappsk_data *pskdata = NULL;
	struct eap_header *eaphdr = NULL;
	uint16_t size = 0;
	uint8_t *respData = NULL;
	uint8_t *mac_p_data = NULL;
	uint8_t *mac_p = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return NULL;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return NULL;

	pskdata = (eappsk_data *)eapdata->eap_data;

	for (i = 0; i < 16; i++)
	{
		pskdata->rand_p[i] = (char)((float)(rand() % 0xff));
	}

	// flags + rand_s + rand_p + mac_p + strlen(username)
	size = sizeof(struct eap_header) + 1 + 16 + 16 + 16 + strlen(eapdata->ident);
	respData = Malloc(size);
	if (respData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to store EAP-PSK response.\n");
		eap_type_common_fail(eapdata);
		return NULL;
	}
	
	eaphdr = (struct eap_header *)respData;
	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
	eaphdr->eap_type = EAP_TYPE_PSK;
	eaphdr->eap_length = htons(size);

	pskpacket1 = (eappsk_packet1 *)&respData[sizeof(struct eap_header)];
	pskpacket1->flags = 1 << 6;
	memcpy(&pskpacket1->rand_s[0], &pskdata->rand_s[0], 16);
	memcpy(&pskpacket1->rand_p[0], &pskdata->rand_p[0], 16);
	memcpy(&pskpacket1->nai_p[0], &eapdata->ident[0], strlen(eapdata->ident));

	debug_printf(DEBUG_AUTHTYPES, "ID_P : %s\n", eapdata->ident);
	debug_printf(DEBUG_AUTHTYPES, "ID_S : %s\n", pskdata->id_s);
	debug_printf(DEBUG_AUTHTYPES, "RAND_S : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskdata->rand_s, 16);
	debug_printf(DEBUG_AUTHTYPES, "RAND_P : ");
	debug_hex_printf(DEBUG_AUTHTYPES, pskdata->rand_p, 16);

	// MAC_P = CMAC-AES-128(AK, ID_P||ID_S||RAND_S||RAND_P)
	mac_p_data = Malloc(strlen(eapdata->ident)+strlen(pskdata->id_s)+16+16);
	if (mac_p_data == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory needed to store MAC_P creation data!\n");
		return NULL;
	}

	memcpy(mac_p_data, eapdata->ident, strlen(eapdata->ident));
	memcpy(&mac_p_data[strlen(eapdata->ident)], pskdata->id_s, strlen(pskdata->id_s));
	i = strlen(eapdata->ident) + strlen(pskdata->id_s);
	memcpy(&mac_p_data[i], pskdata->rand_s, 16);
	i += 16;
	memcpy(&mac_p_data[i], pskdata->rand_p, 16);
	i += 16;

	debug_printf(DEBUG_AUTHTYPES, "To MAC data (%d) :\n", i);
	debug_hex_dump(DEBUG_AUTHTYPES, mac_p_data, i);

	mac_p = cmac_aes_128(pskdata->ak, mac_p_data, (i*8));

	debug_printf(DEBUG_AUTHTYPES, "MAC_P : ");
	debug_hex_printf(DEBUG_AUTHTYPES, mac_p, 16);

	FREE(mac_p_data);

	memcpy(pskpacket1->mac_p, mac_p, 16);

	FREE(mac_p);

	eapdata->methodState = MAY_CONT;

	return respData;
}

/**
 * \brief Create a packet with the flags set to 3.  (A response to the inbound packet with the
 *			flags set to 2.)
 *
 * @param[in] eapdata   The eap_data structure that contains the information we 
 *						need to process.
 **/
uint8_t *eappsk_create_packet3(eap_type_data *eapdata)
{
	eappsk_packet3 *pskpacket = NULL;
	eappsk_data *pskdata = NULL;
	struct eap_header *eaphdr = NULL;
	uint16_t size = 0;
	unsigned int enc_size = 0;
	uint8_t *respData = NULL;
	uint8_t *encdata = NULL;
	uint8_t toencdata[1];
	uint8_t *tag[16];
	uint32_t *nonce_ptr;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return NULL;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return NULL;

	pskdata = (eappsk_data *)eapdata->eap_data;

	size = sizeof(struct eap_header) + sizeof(eappsk_packet3);
	respData = Malloc(size);
	if (respData == NULL) return NULL;

	eaphdr = (struct eap_header *)respData;
	eaphdr->eap_code = EAP_RESPONSE_PKT;
	eaphdr->eap_identifier = eap_type_common_get_eap_reqid(eapdata->eapReqData);
	eaphdr->eap_type = EAP_TYPE_PSK;
	eaphdr->eap_length = htons(size);

	pskpacket = (eappsk_packet3 *)&respData[sizeof(struct eap_header)];
	pskpacket->flags = 3 << 6;
	
	memcpy(&pskpacket->rand_s[0], &pskdata->rand_s[0], 16);
	toencdata[0] = EAP_PSK_FLAGS_SUCCESS;

	nonce_ptr = (unsigned int *)&pskdata->nonce;
	(*nonce_ptr)++;

	if (eax_encrypt(pskdata->keydata, &pskdata->nonce[0], (unsigned char *)eaphdr, &toencdata[0], 1, &encdata,
		&enc_size, (unsigned char *)&tag[0]) != 1)
	{
		debug_printf(DEBUG_NORMAL, "Unable to encrypt protected channel data.\n");
		eap_type_common_fail(eapdata);
		FREE(respData);
		return NULL;
	}

	pskpacket->pchn_flags = encdata[0];
	memcpy(&pskpacket->pchn_nonce[0], &pskdata->nonce[0], 4);
	memcpy(&pskpacket->pchn_tag[0], &tag[0], 16);

	return respData;
}

void eappsk_process(eap_type_data *eapdata)
{
	uint8_t flags = 0;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-PSK) Processing.\n");

  flags = eapdata->eapReqData[sizeof(struct eap_header)] & 0xc0;  // Mask out all but the high bits.
  flags = flags >> 6;

  switch (flags)
  {
  case 0:
	  eappsk_process_packet0(eapdata);
	  break;

  case 1:
	  debug_printf(DEBUG_NORMAL, "Receipt of packet ID 1 not allowed on supplicants!\n");
	  break;

  case 2:
	  eappsk_process_packet2(eapdata);
	  break;

  case 3:
	  debug_printf(DEBUG_NORMAL, "Receipt of packet ID 3 not allowed on supplicants!\n");
	  break;

  default:
	  debug_printf(DEBUG_NORMAL, "Unknown EAP-PSK packet ID %d!\n", flags);
	  break;
  }
}

uint8_t *eappsk_buildResp(eap_type_data *eapdata)
{
	eappsk_data *pskdata = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return NULL;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return NULL;

	pskdata = (eappsk_data *)eapdata->eap_data;

	debug_printf(DEBUG_AUTHTYPES, "(EAP-PSK) Building Response.\n");

	switch (pskdata->packetnum)
	{
	case 0:
		// Not allowed.
		debug_printf(DEBUG_NORMAL, "Got a request to send a type 0 PSK packet!?  This isn't allowed!\n");
		break;

	case 1:
		return eappsk_create_packet1(eapdata);
		break;

	case 2:
		// Not allowed.
		debug_printf(DEBUG_NORMAL, "Got a request to send a type 2 PSK packet!?  This isn't allowed!\n");
		break;

	case 3:
		return eappsk_create_packet3(eapdata);
		break;

	default:
		// Mass confusion!
		debug_printf(DEBUG_NORMAL, "Got a request for type %d, which isn't defined by the standard!\n", pskdata->packetnum);
		break;
	}

	eap_type_common_fail(eapdata);
	return NULL;
}

uint8_t eappsk_isKeyAvailable(eap_type_data *eapdata)
{
	eappsk_data *pskdata = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return FALSE;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return FALSE;

	pskdata = (eappsk_data *)eapdata->eap_data;

	if (pskdata->keydata != NULL) return TRUE;

	return FALSE;
}

uint8_t *eappsk_getKey(eap_type_data *eapdata)
{
	eappsk_data *pskdata = NULL;
	uint8_t *keydata = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return NULL;

	if (!xsup_assert((eapdata->eap_data != NULL), "eapdata->eap_data != NULL", FALSE)) return NULL;

	pskdata = (eappsk_data *)eapdata->eap_data;

  keydata = Malloc(64);
  if (keydata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to return key "
		   "block!\n");
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  memcpy(keydata, &pskdata->keydata[16], 64);

  debug_printf(DEBUG_AUTHTYPES, "Generated keyblock : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, keydata, 64);

  return keydata;
}

void eappsk_deinit(eap_type_data *eapdata)
{
	eappsk_data *pskdata = NULL;

	if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE)) return;

	pskdata = (eappsk_data *)eapdata->eap_data;

	if (pskdata == NULL) return;

	FREE(pskdata->keydata);
	FREE(pskdata->id_s);

	pskdata = NULL;
	FREE(eapdata->eap_data);
}

#endif   // EXPERIMENTAL