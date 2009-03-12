/**
 * Routines for queueing error messages to be sent to a UI once it connects.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_crypt.c
 *
 * \author chris@open1x.org
 **/

#ifdef WINDOWS

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

#include "src/stdintwin.h"
#include "src/platform/windows/win_impersonate.h"
#include "lib/libxsupconfig/xsupconfig.h"

/**
 * \brief Determine if this OS has password encryption/decryption functions
 *        available.
 *
 * \retval 1 if functions are available
 * \retval 0 if functions are empty stubs.
 **/
int pwcrypt_funcs_available()
{
	return 1;
}

/**
 *
 * Convert an array of uint8_t to a string.
 *
 **/
char *convert_hex_to_str(uint8_t * inhex, uint16_t insize)
{
	uint16_t strsize = 0, i;
	char *retstr = NULL;
	char bytes[3];

	if (inhex == NULL)
		return NULL;

	strsize = (insize * 2) + 1;

	retstr = (char *)malloc(strsize);
	if (retstr == NULL)
		return NULL;

	memset(retstr, 0x00, strsize);

	memset(&bytes, 0x00, 3);

	for (i = 0; i < insize; i++) {
		sprintf(bytes, "%02X", inhex[i]);
		if (Strcat(retstr, strsize, bytes) != 0) {
			fprintf(stderr, "Refusing to overflow string!\n");
			return NULL;
		}
	}

	return retstr;
}

/**
 * \brief Encrypt a string that is passed in.
 *
 * @param[in] toencdata   An array of bytes that are the cleartext version
 *                        of what we want to encrypt.
 * @param[in] toenclen   The length of the bytes that toencdata points to.
 * @param[out] encdata   An array of bytes that make up the encrypted data.
 * @param[out] enclen   The length of the bytes that make up the encrypted data.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int pwcrypt_encrypt(uint8_t config_type, uint8_t * toencdata, uint16_t toenclen,
		    uint8_t ** encdata, uint16_t * enclen)
{
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;

	DataIn.cbData = toenclen;
	DataIn.pbData = toencdata;

	if (config_type == CONFIG_LOAD_GLOBAL) {
		if (CryptProtectData
		    (&DataIn, L"Password String", NULL, NULL, NULL,
		     (CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE),
		     &DataOut)) {
			(*encdata) =
			    convert_hex_to_str(DataOut.pbData, DataOut.cbData);
			(*enclen) = DataOut.cbData;

			LocalFree(DataOut.pbData);

			return 0;
		}

		return -1;	// Encryption failed.
	} else {
		win_impersonate_desktop_user();

		if (CryptProtectData
		    (&DataIn, L"Password String", NULL, NULL, NULL,
		     CRYPTPROTECT_UI_FORBIDDEN, &DataOut)) {
			(*encdata) =
			    convert_hex_to_str(DataOut.pbData, DataOut.cbData);
			(*enclen) = DataOut.cbData;

			LocalFree(DataOut.pbData);

			win_impersonate_back_to_self();
			return 0;
		}

		win_impersonate_back_to_self();
		return -1;	// Encryption failed.
	}

	return -1;
}

char ctonibble1(char cnib)
{
	char retVal = 0x00;
	char testval = 0x00;

	if ((cnib >= '0') && (cnib <= '9')) {
		retVal = cnib - '0';
	} else {
		testval = toupper(cnib);
		if ((testval >= 'A') && (testval <= 'F')) {
			retVal = ((testval - 'A') + 10);
		} else {
			printf
			    ("Error in conversion!  (Check ctonibble1()) -- %02x\n",
			     testval);
		}
	}
	return retVal;
}

// Convert an ASCII hex string to it's binary version.
void str2hex(char *instr, uint8_t ** outstr, int *rsize)
{
	int i;
	int size;
	uint8_t *result = NULL;

	(*rsize) = 0;
	(*outstr) = NULL;
	if (instr == NULL) {
		return;
	}

	size = strlen(instr);

	// Make sure we don't try to convert something that isn't byte aligned.
	if ((size % 2) != 0) {
		printf("Hex string isn't an even number of chars!!!\n");
		return;
	}

	result = malloc(size / 2);
	if (result == NULL) {
		(*outstr) = NULL;
		return;
	}

	for (i = 0; i < (size / 2); i++) {
		if (instr[i * 2] != 0x00) {
			result[i] =
			    (ctonibble1(instr[i * 2]) << 4) +
			    ctonibble1(instr[(i * 2) + 1]);
		}
	}

	(*rsize) = (int)(size / 2);
	(*outstr) = result;
}

/**
 * \brief Decrypt a string that is passed in.
 *
 * @param[in] encdata   An array of bytes that are the encrypted version
 *                        of what we want to decrypt.
 * @param[in] enclen   The length of the bytes that encdata points to.
 * @param[out] decdata   An array of bytes that make up the decrypted data.
 * @param[out] declen   The length of the bytes that make up the decrypted data.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int pwcrypt_decrypt(uint8_t config_type, uint8_t * encdata, uint16_t enclen,
		    uint8_t ** decdata, uint16_t * declen)
{
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	uint8_t *data;
	int size, i;

	str2hex(encdata, &data, &size);

	if (size <= 0)
		return -1;

	DataIn.cbData = size;
	DataIn.pbData = data;

	if (config_type == CONFIG_LOAD_GLOBAL) {
		if (CryptUnprotectData
		    (&DataIn, NULL, NULL, NULL, NULL,
		     (CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE),
		     &DataOut)) {
			free(data);

			(*decdata) = malloc(DataOut.cbData + 3);
			if ((*decdata) == NULL)
				return -1;

			memset((*decdata), 0x00, DataOut.cbData + 3);
			memcpy((*decdata), DataOut.pbData, DataOut.cbData);

			(*declen) = strlen((*decdata));

			LocalFree(DataOut.pbData);

			return 0;
		}

		free(data);
		return -1;
	} else {
		win_impersonate_desktop_user();

		if (CryptUnprotectData
		    (&DataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN,
		     &DataOut)) {
			free(data);

			(*decdata) = malloc(DataOut.cbData + 3);
			if ((*decdata) == NULL)
				return -1;

			memset((*decdata), 0x00, DataOut.cbData + 3);
			memcpy((*decdata), DataOut.pbData, DataOut.cbData);

			(*declen) = strlen((*decdata));

			LocalFree(DataOut.pbData);

			win_impersonate_back_to_self();
			return 0;
		}

		free(data);
		win_impersonate_back_to_self();
		return -1;
	}

	return -1;
}

#endif				// WINDOWS
