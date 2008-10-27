/**
 *  CMAC implementation as defined by NIST document SP_800-38B.pdf.
 **/

#ifdef EXPERIMENTAL

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>

#ifdef WINDOWS
#include <Winsock2.h>
#endif

#include "../../xsup_debug.h"

//#define TEST_DISPLAY	1

#ifdef TEST_DISPLAY
void dump(char *msg, unsigned char *data, unsigned int length)
{
	unsigned int i = 0;

	printf("%s ", msg);

	for (i = 0; i < length; i++)
	{
		printf("%02X ", data[i]);
	}

	printf("\n");
}
#endif

/**
 * \brief Implementation of the subkey generation as defined by NIST
 *			publication SP_800-38B.pdf.
 *
 * @param[in] key   The key used in CMAC AES-128.
 *
 **/
void cmac_aes_128_subkey(unsigned char *key, unsigned char *k1, unsigned char *k2)
{
	unsigned char ciph0b[16];
	AES_KEY akey;
	unsigned char L[16];
	int i = 0;
	char need_one = 0;
	char last_one = 0;
	char do_xor = 0;

	memset(&ciph0b[0], 0x00, 16);   // Create 128 bits of 0.

	AES_set_encrypt_key(key, 16*8, &akey);

	AES_ecb_encrypt(ciph0b, &L[0], &akey, AES_ENCRYPT);

	if ((L[0] & 0x80) == 0x80) do_xor = 1;  // MSB is 1.

	for (i = 15; i >= 0; i--)
	{
		last_one = need_one;
		if ((L[i] & 0x80) == 0x80)
		{
			need_one = 1;
		}
		else
		{
			need_one = 0;
		}

		k1[i] = L[i] << 1;

		if (last_one == 1) k1[i] |= 0x01;
	}

	if (do_xor == 1) k1[15] = k1[15] ^ 0x87;

	do_xor = 0;

	// Get K2
	if ((k1[0] & 0x80) == 0x80) do_xor = 1;  // MSB is 1.

	for (i = 15; i >= 0; i--)
	{
		last_one = need_one;
		if ((k1[i] & 0x80) == 0x80)
		{
			need_one = 1;
		}
		else
		{
			need_one = 0;
		}

		k2[i] = k1[i] << 1;

		if (last_one == 1) k2[i] |= 0x01;
	}

	if (do_xor == 1) k2[15] = k2[15] ^ 0x87;

}

/**
 * \brief Implementation of the CMAC as defined by NIST publication
 *			publication SP_800-38B.pdf.
 *
 * @param[in] key   The key used in CMAC AES-128.
 * @param[in] indata   The data to be MACed.
 * @param[in] size	The size of indata (in bits).
 *
 **/
unsigned char *cmac_aes_128(unsigned char *key, unsigned char *indata, unsigned int size)
{
	unsigned char k1[16], k2[16], C[16], temp[16];
	unsigned int blocks = 0;
	unsigned int i, x;
	unsigned char *Mblocks = NULL;
	AES_KEY akey;
	unsigned char *retval = NULL;

	cmac_aes_128_subkey(key, &k1[0], &k2[0]);

#ifdef TEST_DISPLAY
	dump("k1 :", k1, 16);
	dump("k2 :", k2, 16);
#endif

	if (size == 0)
	{
		blocks = 1;
	}
	else
	{
		blocks = size/128;

		if ((size % 128) != 0) blocks++;
	}

	Mblocks = malloc(blocks * 16);
	if (Mblocks == NULL) return NULL;

	memset(Mblocks, 0x00, (blocks * 16));

	memcpy(Mblocks, indata, (size / 8));

#ifdef TEST_DISPLAY
	dump("Mblocks:", Mblocks, (blocks * 16));
#endif

	if ((size == 0) || ((size % 128) != 0))
	{
		// This isn't a complete block, so use k2.

		// Find where we need to put the 1.
		if (size == 0)
		{
			x = 0;
		}
		else
		{
			x = (size/8);
		}

		Mblocks[x] = 0x80;

#ifdef TEST_DISPLAY
		dump("Final block:", &Mblocks[((blocks-1) * 16)], 16);
#endif

		for (x = 0; x < 16; x++)
		{
			Mblocks[((blocks-1) * 16) + x] ^= k2[x];
		}
	}
	else
	{
#ifdef TEST_DISPLAY
		dump("Final block:", &Mblocks[((blocks-1) * 16)], 16);
#endif

		for (x = 0; x < 16; x++)
		{
			Mblocks[((blocks-1) * 16) + x] ^= k1[x];
		}
	}

	memset(&C[0], 0x00, 16);

	AES_set_encrypt_key(key, 16*8, &akey);

	for (i = 0; i < blocks; i++)
	{
		for (x = 0; x < 16; x++)
		{
			temp[x] = C[x] ^ Mblocks[(i * 16) + x];
		}

		AES_ecb_encrypt(temp, &C[0], &akey, AES_ENCRYPT);
	}

	retval = malloc(16);
	if (retval == NULL) 
	{
		FREE(Mblocks);
		return NULL;
	}

	memcpy(retval, &C[0], 16);

#ifdef TEST_DISPLAY
	dump("t:", C, 16);
#endif

	FREE(Mblocks);

	return retval;
}

void AES_counter_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *data, uint16_t data_size,
						 uint8_t **result, uint16_t *res_size)
{
	AES_KEY akey;
	uint8_t counter[16];
	uint8_t buf[16];
	uint8_t temp[16];
	uint8_t *encrypted = NULL;
	uint8_t carry = FALSE;
	int i = 0, x = 0;

	encrypted = malloc(data_size);
	if (encrypted == NULL)
	{
		(*result) = NULL;
		(*res_size) = 0;
	}

	AES_set_encrypt_key(key, 16*8, &akey);

	memcpy(&counter[0], nonce, 16);

	for (i = 0; i < data_size; i+=16)
	{
		AES_ecb_encrypt(&counter[0], &buf[0], &akey, AES_ENCRYPT);
		debug_printf(DEBUG_AUTHTYPES, "Encrypted data : ");
		debug_hex_printf(DEBUG_AUTHTYPES, buf, 16);

		memset(&temp[0], 0x00, 16);
		
		if ((data_size - (i * 16)) >= 16)
		{
			memcpy(&temp[0], &data[(i*16)], 16);

			for (x = 0; x < 16; x++)
			{
				encrypted[(i * 16)+x] = data[(i*16)+x] ^ buf[x];
			}
		}
		else
		{
			memcpy(&temp[0], &data[(i*16)], (data_size - (i * 16)));

			for (x = 0; x < (data_size - (i * 16)); x++)
			{
				encrypted[(i * 16)+x] = data[(i*16)+x] ^ buf[x];
			}
		}

		if  (counter[15] == 0xff) carry = TRUE;
		counter[15]++;

		if (carry == TRUE)
		{
			for (x = 14; x >= 0; x--)
			{
				carry = FALSE;
				if (counter[14] == 0xff) carry = TRUE;

				counter[14]++;

				if (carry == FALSE) break;
			}
		}
	}

	(*result) = encrypted;
	(*res_size) = data_size;
}

int eax_decrypt(unsigned char *key, unsigned char *nonce, unsigned char *header, unsigned char *tag,
				unsigned char *payload, unsigned int payload_size, unsigned char **out,
				unsigned int *out_size)
{
	unsigned char *nonce_mac = NULL;
	unsigned char *hdr_mac = NULL;
	unsigned char *data_mac = NULL;
	unsigned char *decrypted = NULL;
	unsigned char *temp_data = NULL;
	unsigned char ntag[16];
	AES_KEY akey;
	uint16_t res_size;
	int i = 0;

	temp_data = malloc(32);
	if (temp_data == NULL) return 0;

	memset(temp_data, 0x00, 32);
	memcpy(&temp_data[28], nonce, 4);

	nonce_mac = cmac_aes_128(key, temp_data, (32*8));
	free(temp_data);
	temp_data = NULL;

	debug_printf(DEBUG_AUTHTYPES, "Nonce MAC : ");
	debug_hex_printf(DEBUG_AUTHTYPES, nonce_mac, 16);

	temp_data = malloc(16+22);
	if (temp_data == NULL)
	{
		free(nonce_mac);
		return 0;
	}

	memset(temp_data, 0x00, (16+22));
	temp_data[15] = 0x01;
	memcpy(&temp_data[16], header, 22);

	debug_printf(DEBUG_AUTHTYPES, "Header : ");
	debug_hex_printf(DEBUG_AUTHTYPES, temp_data, 16+22);

	hdr_mac = cmac_aes_128(key, temp_data, ((16+22)*8));
	free(temp_data);
	temp_data = NULL;

	debug_printf(DEBUG_AUTHTYPES, "HDR MAC : ");
	debug_hex_printf(DEBUG_AUTHTYPES, hdr_mac, 16);

	temp_data = malloc(payload_size + 16);
	if (temp_data == NULL)
	{
		free(temp_data);
		free(nonce_mac);
		free(hdr_mac);
		return 0;
	}

	memset(temp_data, 0x00, (payload_size+16));
	temp_data[15] = 2;
	memcpy(&temp_data[16], payload, payload_size);
	data_mac = cmac_aes_128(key, temp_data, ((payload_size+16)*8));
	free(temp_data);

	debug_printf(DEBUG_AUTHTYPES, "Data MAC : ");
	debug_hex_printf(DEBUG_AUTHTYPES, data_mac, 16);

	for (i = 0; i < 16; i++)
	{
		ntag[i] = nonce_mac[i] ^ data_mac[i] ^ hdr_mac[i];
	}

	free(data_mac);
	free(hdr_mac);

	debug_printf(DEBUG_AUTHTYPES, "Tag : ");
	debug_hex_printf(DEBUG_AUTHTYPES, tag, 16);

	debug_printf(DEBUG_AUTHTYPES, "NTag : ");
	debug_hex_printf(DEBUG_AUTHTYPES, ntag, 16);

	if (memcmp(&ntag[0], tag, 16) != 0)
	{
		debug_printf(DEBUG_NORMAL, "PSK tags do not match.  Failing authentication.\n");
		return 0;
	}

	AES_counter_encrypt(key, nonce_mac, payload, payload_size, &temp_data, &res_size);

	free(nonce_mac);

	decrypted = malloc(res_size);
	if (decrypted == NULL)
	{
		free(temp_data);
		free(nonce_mac);
		free(hdr_mac);
		return 0;
	}

	memcpy(decrypted, temp_data, res_size);
	free(temp_data);

	(*out_size) = res_size;
	*out = decrypted;

	return 1;
}

int eax_encrypt(unsigned char *key, unsigned char *nonce, unsigned char *header,
				unsigned char *payload, unsigned int payload_size, unsigned char **out,
				unsigned int *out_size, unsigned char *tag)
{
	unsigned char *nonce_mac = NULL;
	unsigned char *hdr_mac = NULL;
	unsigned char *data_mac = NULL;
	unsigned char *encrypted = NULL;
	unsigned char *temp_data = NULL;
	AES_KEY akey;
	int i = 0;
	uint16_t res_size;

	temp_data = malloc(32);
	if (temp_data == NULL) return 0;

	memset(temp_data, 0x00, 32);
	memcpy(&temp_data[28], nonce, 4);

	nonce_mac = cmac_aes_128(key, temp_data, (32*8));
	free(temp_data);
	temp_data = NULL;

	temp_data = malloc(16+22);
	if (temp_data == NULL)
	{
		free(nonce_mac);
		return 0;
	}

	memset(temp_data, 0x00, (16+22));
	temp_data[15] = 0x01;
	memcpy(&temp_data[16], header, 22);
	hdr_mac = cmac_aes_128(key, temp_data, ((16+22)*8));
	free(temp_data);
	temp_data = NULL;

	AES_counter_encrypt(key, nonce_mac, payload, payload_size, &temp_data, &res_size);

	encrypted = malloc(res_size);
	if (encrypted == NULL)
	{
		free(temp_data);
		free(nonce_mac);
		free(hdr_mac);
		return 0;
	}

	memcpy(encrypted, temp_data, res_size);
	free(temp_data);

	temp_data = malloc(res_size + 16);
	if (temp_data == NULL)
	{
		free(temp_data);
		free(nonce_mac);
		free(hdr_mac);
		return 0;
	}

	memset(temp_data, 0x00, (res_size+16));
	temp_data[15] = 2;
	memcpy(&temp_data[16], encrypted, res_size);
	data_mac = cmac_aes_128(key, temp_data, ((res_size+16)*8));
	free(temp_data);

	for (i = 0; i < 16; i++)
	{
		tag[i] = nonce_mac[i] ^ data_mac[i] ^ hdr_mac[i];
	}

	free(nonce_mac);
	free(data_mac);
	free(hdr_mac);

	(*out_size) = res_size;
	*out = encrypted;

	return 1;
}

#endif   // EXPERIMENTAL
