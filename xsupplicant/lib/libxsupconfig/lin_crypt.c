/**
 * Routines for queueing error messages to be sent to a UI once it connects.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file lin_crypt.c
 *
 * \author chris@open1x.org
 *
 * $Id: lin_crypt.c,v 1.3 2007/10/20 08:10:07 galimorerpg Exp $
 * $Date: 2007/10/20 08:10:07 $
 **/

#ifndef WINDOWS

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "src/xsup_common.h" 

/**
 * \brief Determine if this OS has password encryption/decryption functions
 *        available.
 *
 * \retval 1 if functions are available
 * \retval 0 if functions are empty stubs.
 **/
int pwcrypt_funcs_available()
{
	return 0;
}

/**
 *
 * Convert an array of uint8_t to a string.
 *
 **/
char *convert_hex_to_str(uint8_t *inhex, uint16_t insize)
{
  uint16_t strsize = 0, i;
  char *retstr = NULL;
  char bytes[3];

  if (inhex == NULL) return NULL;

  strsize = (insize * 2)+1;

  retstr = (char *)malloc(strsize);
  if (retstr == NULL) return NULL;

  memset(retstr, 0x00, strsize);

  memset(&bytes, 0x00, 3);

  for (i=0;i<insize;i++)
    {
      sprintf(bytes, "%02X", inhex[i]);
      if (Strcat(retstr, strsize, bytes) != 0)
		{
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
int pwcrypt_encrypt(uint8_t *toencdata, uint16_t toenclen, uint8_t **encdata, uint16_t *enclen)
{
	return -1;   // Encryption failed.
}

char ctonibble1(char cnib)
{
  char retVal=0x00;
  char testval=0x00;

  if ((cnib>='0') && (cnib<='9'))
    {
      retVal = cnib - '0';
    } else {
      testval = toupper(cnib);
      if ((testval>='A') && (testval<='F'))
	{
	  retVal = ((testval - 'A') +10);
	} else {
	  printf("Error in conversion!  (Check ctonibble()) -- %02x\n",testval);
	}
    }
  return retVal;
}

// Convert an ASCII hex string to it's binary version.
void str2hex(char *instr, uint8_t **outstr, int *rsize)
{
  int i;
  int size;
  uint8_t *result = NULL;

  (*rsize) = 0;

  size = strlen(instr);
	
  // Make sure we don't try to convert something that isn't byte aligned.
  if ((size % 2) != 0)
    {
      printf("Hex string isn't an even number of chars!!!\n");
      return;
    }

  result = malloc(size/2);
  if (result == NULL) 
  {
	  (*outstr) = NULL;
	  return;
  }

  for (i=0;i<(size/2);i++)
    {
      if (instr[i*2] != 0x00)
		{
			result[i] = (ctonibble1(instr[i*2]) << 4) + ctonibble1(instr[(i*2)+1]);
		}
    }

  (*rsize) = (int)(size/2);
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
int pwcrypt_decrypt(uint8_t *encdata, uint16_t enclen, uint8_t **decdata, uint16_t *declen)
{
	return -1;
}


#endif   // WINDOWS
