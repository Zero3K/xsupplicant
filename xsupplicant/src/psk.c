/**
 * WPA-PSK Function implementations for supplicant
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file psk.c
 *
 * \author chris@open1x.org
 *
 **/

#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h> 
#include <assert.h>
#include <string.h>

// For OpenSSL 0.9.8 we need to explicitly include sha.h
#ifndef SHA_DIGEST_LENGTH
#include <openssl/sha.h>
#endif

// If we still don't have SHA_DIGEST_LENGTH defined, then define it ourselves.
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

/*********************************************************************
 *
 * This code taken from 802.11i-D3.0, section F.8.2 reference implementation.
 *
 *********************************************************************/
void psk_wpa_pbkdf2_f(char *password, unsigned char *ssid, int ssidlength,
		      int iterations, int count, unsigned char *output)
{
  unsigned char digest[36], digest1[SHA_DIGEST_LENGTH];
  int i, j, k;

  if (!xsup_assert((password != NULL), "password != NULL", FALSE))
    return;

  if (!xsup_assert((ssid != NULL), "ssid != NULL", FALSE))
    return;

  if (!xsup_assert((output != NULL), "output != NULL", FALSE))
    return;

  for (i=0; i < strlen(password); i++)
    {
      assert((password[i] >= 32) && (password[i] <= 126));
    }

  /* U1 = PRF(P, S || int(i)) */
  memcpy(digest, ssid, ssidlength);
  digest[ssidlength] = (unsigned char)((count>>24) & 0xff);
  digest[ssidlength+1] = (unsigned char)((count>>16) & 0xff);
  digest[ssidlength+2] = (unsigned char)((count>>8) & 0xff);
  digest[ssidlength+3] = (unsigned char)(count & 0xff);

  // OpenSSL takes the parameters in a different order than what is
  // defined in F.8.2, so even though it looks wrong, this is correct. ;)
  HMAC(EVP_sha1(), password, strlen(password), digest, ssidlength+4, 
       digest1, (unsigned int *) &k);

  /* output = U1 */
  memcpy(output, digest1, SHA_DIGEST_LENGTH);

  for (i = 1; i < iterations; i++)
    {
      /* Un = PRF(P, Un-1) */
      HMAC(EVP_sha1(), password, strlen(password), digest1, SHA_DIGEST_LENGTH, 
	   digest, (unsigned int *) &k);
      memcpy(digest1, digest, k);

      /* output = output xor Un */
      for (j = 0; j < SHA_DIGEST_LENGTH; j++)
	{
	  output[j] ^= digest[j];
	}
    }
}

int psk_wpa_pbkdf2(char *password, unsigned char *ssid, int ssidlength,
		   unsigned char *output)
{
  if (!xsup_assert((password != NULL), "password != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((ssid != NULL), "ssid != NULL", FALSE))
    return FALSE;

  if (!xsup_assert((output != NULL), "output != NULL", FALSE))
    return FALSE;

  if ((strlen(password) > 63) || (ssidlength > 32))
    {
		debug_printf(DEBUG_NORMAL, "Invalid WPA-PSK password! (Length : %d)\n", strlen(password));
      return FALSE;
    }

  psk_wpa_pbkdf2_f(password, ssid, ssidlength, 4096, 1, output);
  psk_wpa_pbkdf2_f(password, ssid, ssidlength, 4096, 2, 
		   &output[SHA_DIGEST_LENGTH]);
  return TRUE;
}
