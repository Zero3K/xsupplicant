/**
 * EAPMSCHAPv2 Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file mschapv2.c
 *
 * \author chris@open1x.org
 *
 **/

// This code was taken from the pseudo code in RFC 2759.

#include <openssl/ssl.h>
#include <openssl/des.h>
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#include <stdint.h>
#endif

#include <ctype.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../xsup_err.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

void ChallengeHash(char *PeerChallenge, char *AuthenticatorChallenge,
		   char *UserName, char *Challenge)
{
  EVP_MD_CTX cntx;
  char Digest[30];
  int retLen = 0;

  if (!xsup_assert((PeerChallenge != NULL), "PeerChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((AuthenticatorChallenge != NULL), 
		   "AuthenticatorChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((UserName != NULL), "UserName != NULL", FALSE))
    return;

  if (!xsup_assert((Challenge != NULL), "Challenge != NULL", FALSE))
    return;

  memset(Digest, 0x00, 30);
  EVP_DigestInit(&cntx, EVP_sha1());
  EVP_DigestUpdate(&cntx, PeerChallenge, 16);
  EVP_DigestUpdate(&cntx, AuthenticatorChallenge, 16);
  EVP_DigestUpdate(&cntx, UserName, strlen(UserName));
  EVP_DigestFinal(&cntx, (uint8_t *)&Digest, (unsigned int *) &retLen);

  memcpy(Challenge, Digest, 8);
}

char *to_unicode(char *non_uni)
{
  char *retUni;
  int i;

  if (!xsup_assert((non_uni != NULL), "non_uni != NULL", FALSE))
    return NULL;

  retUni = (char *)Malloc((strlen(non_uni)+1)*2);
  if (retUni == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with MALLOC in to_unicode()!\n");
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  for (i=0; i<strlen(non_uni); i++)
    {
      retUni[(2*i)] = non_uni[i];
    }
  return retUni;
}

void NtPasswordHash(char *Password, char *PasswordHash, int tounicode)
{
  EVP_MD_CTX cntx;
  char retVal[20];
  int i, len;
  char *uniPassword;

  if (!xsup_assert((Password != NULL), "Password != NULL", FALSE))
    return;

  if (!xsup_assert((PasswordHash != NULL), "PasswordHash != NULL", FALSE))
    return;

  memset(retVal, 0x00, 20);

  if (tounicode == 1)
  {
	  uniPassword = to_unicode(Password);
	  len = (strlen(Password))*2;
  }
  else
  {
	  uniPassword = Password;
	  len = wcslen((wchar_t *)uniPassword)*2;
  }

  EVP_DigestInit(&cntx, EVP_md4());
  EVP_DigestUpdate(&cntx, uniPassword, len);
  EVP_DigestFinal(&cntx, (uint8_t *)&retVal, (unsigned int *)&i);
  memcpy(PasswordHash, &retVal, 16);

  if (tounicode == 1) FREE(uniPassword);
}

void HashNtPasswordHash(char *PasswordHash, char *PasswordHashHash)
{
  EVP_MD_CTX cntx;
  int i;

  if (!xsup_assert((PasswordHash != NULL), "PasswordHash != NULL", FALSE))
    return;

  if (!xsup_assert((PasswordHashHash != NULL), "PasswordHashHash != NULL",
		   FALSE)) return;

  EVP_DigestInit(&cntx, EVP_md4());
  EVP_DigestUpdate(&cntx, PasswordHash, 16);
  EVP_DigestFinal(&cntx, (uint8_t *) PasswordHashHash, (unsigned int *) &i);
}

// Shamelessly take from the hostap code written by Jouni Malinen
void des_encrypt(uint8_t *clear, uint8_t *key, uint8_t *cypher)
{
  uint8_t pkey[8], next, tmp;
  int i;
  DES_key_schedule ks;

  if (!xsup_assert((clear != NULL), "clear != NULL", FALSE))
    return;

  if (!xsup_assert((key != NULL), "key != NULL", FALSE))
    return;

  if (!xsup_assert((cypher != NULL), "cypher != NULL", FALSE))
    return;

  /* Add parity bits to key */
  next = 0;
  for (i=0; i<7; i++)
    {
      tmp = key[i];
      pkey[i] = (tmp >> i) | next | 1;
      next = tmp << (7-i);
    }
  pkey[i] = next | 1;

  DES_set_key(&pkey, &ks);
  DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks,
		  DES_ENCRYPT);
}

char ctonibble(char cnib)
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
	  debug_printf(DEBUG_NORMAL, "Error in conversion!  (Check ctonibble()) -- %02x\n",testval);
	}
    }
  return retVal;
}

// Convert an ASCII hex string to it's binary version.
void process_hex(char *instr, int size, char *outstr)
{
  int i;

  if (!xsup_assert((instr != NULL), "instr != NULL", FALSE))
    return;

  if (!xsup_assert((outstr != NULL), "outstr != NULL", FALSE))
    return;

  // Make sure we don't try to convert something that isn't byte aligned.
  if ((size % 2) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Hex string isn't an even number of chars!!!"
		   "\n");
      return;
    }

  for (i=0;i<(size/2);i++)
    {
      if (instr[i*2] != 0x00)
	{
	  outstr[i] = (ctonibble(instr[i*2]) << 4) + ctonibble(instr[(i*2)+1]);
	}
    }
}

void GenerateAuthenticatorResponse(char *Password, char *NTResponse,
				   char *PeerChallenge, 
				   char *AuthenticatorChallenge, char *UserName,
				   char *AuthenticatorResponse, int mode)
{
  char PasswordHash[16];
  char PasswordHashHash[16];
  EVP_MD_CTX context;
  int Digest_len;
  char Digest[20];
  char Challenge[8];

  char Magic1[39] =
    {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
     0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
     0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
     0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};

  char Magic2[41] =
    {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
     0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
     0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
     0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
     0x6E};

  if (!xsup_assert((Password != NULL), "Password != NULL", FALSE))
    return;

  if (!xsup_assert((NTResponse != NULL), "NTResponse != NULL", FALSE))
    return;

  if (!xsup_assert((PeerChallenge != NULL), "PeerChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((AuthenticatorChallenge != NULL),
		   "AuthenticatorChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((UserName != NULL), "UserName != NULL", FALSE))
    return;

  if (!xsup_assert((AuthenticatorResponse != NULL), 
		   "AuthenticatorResponse != NULL", FALSE))
    return;

  if (mode == 0)
    {
      NtPasswordHash(Password, (char *)&PasswordHash, 0);
    } 
  else if (mode == 2)
  {
	  NtPasswordHash(Password, (char *)&PasswordHash, 1);
  }
	else {
      process_hex(Password, strlen(Password), (char *)&PasswordHash);
    }

  HashNtPasswordHash((char *)&PasswordHash, (char *)&PasswordHashHash);

  EVP_DigestInit(&context, EVP_sha1());
  EVP_DigestUpdate(&context, &PasswordHashHash, 16);
  EVP_DigestUpdate(&context, NTResponse, 24);
  EVP_DigestUpdate(&context, Magic1, 39);
  EVP_DigestFinal(&context, (uint8_t *)&Digest, (unsigned int *) &Digest_len);

  ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, Challenge);

  EVP_DigestInit(&context, EVP_sha1());
  EVP_DigestUpdate(&context, &Digest, 20);
  EVP_DigestUpdate(&context, &Challenge, 8);
  EVP_DigestUpdate(&context, Magic2, 41);
  EVP_DigestFinal(&context, (uint8_t *)&Digest, (unsigned int *) &Digest_len);

  memcpy(AuthenticatorResponse, &Digest, Digest_len);
}



void CheckAuthenticatorResponse(char *Password, char *NtResponse,
				char *PeerChallenge, 
				char *AuthenticatorChallenge, char *UserName,
				char *ReceivedResponse, int *ResponseOK,
				int mode)
{
  char MyResponse[20], procResp[20];
  char *stripped;
  int i = 0;

  if (!xsup_assert((Password != NULL), "Password != NULL", FALSE))
    return;

  if (!xsup_assert((NtResponse != NULL), "NtResponse != NULL", FALSE))
    return;

  if (!xsup_assert((PeerChallenge != NULL), "PeerChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((AuthenticatorChallenge != NULL), 
		   "AuthenticatorChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((UserName != NULL), "UserName != NULL", FALSE))
    return;

  if (!xsup_assert((ReceivedResponse != NULL), "ReceivedResponse != NULL",
		   FALSE)) return;

  if (!xsup_assert((ResponseOK != NULL), "ResponseOK != NULL", FALSE))
    return;

  GenerateAuthenticatorResponse(Password, NtResponse, PeerChallenge,
				AuthenticatorChallenge, UserName, 
				(char *)&MyResponse, mode);

  while ((i < strlen(ReceivedResponse)) && (ReceivedResponse[i] != 0x20))
    i++;

  stripped = Malloc(i+1);
  if (stripped == NULL)
  {
	  ipc_events_malloc_failed(NULL);
    *ResponseOK = FALSE;
	return;
  }

  memcpy(stripped, ReceivedResponse, i);
  stripped[i] = 0x00;
  process_hex(stripped, strlen(stripped), (char *)&procResp);

  FREE(stripped);
  stripped = NULL;

  if (memcmp((char *)&MyResponse, (char *)&procResp, 20) == 0)
    {
      *ResponseOK = 1;
    } else {
      *ResponseOK = 0;
    }
}

// Take from hostap code by Jouni Malinen, and modified to work with
// XSupplicant.
void ChallengeResponse(char *Challenge, char *PasswordHash, char *Response)
{
  uint8_t zpwd[7];

  if (!xsup_assert((Challenge != NULL), "Challenge != NULL", FALSE))
    return;

  if (!xsup_assert((PasswordHash != NULL), "PasswordHash != NULL", FALSE))
    return;

  if (!xsup_assert((Response != NULL), "Response != NULL", FALSE))
    return;

  des_encrypt((uint8_t *) Challenge, (uint8_t *) PasswordHash, (uint8_t *) Response);
  des_encrypt((uint8_t *) Challenge, (uint8_t *) PasswordHash + 7, (uint8_t *) Response+8);
  zpwd[0] = PasswordHash[14];
  zpwd[1] = PasswordHash[15];
  memset(zpwd + 2, 0, 5);
  des_encrypt((uint8_t *) Challenge, zpwd, (uint8_t *) Response+16);
}

void NtChallengeResponse(char *Challenge, char *Password, char *Response, 
			 int mode)
{
  char password_hash[16];

  if (!xsup_assert((Challenge != NULL), "Challenge != NULL", FALSE))
    return;

  if (!xsup_assert((Password != NULL), "Password != NULL", FALSE))
    return;

  if (!xsup_assert((Response != NULL), "Response != NULL", FALSE))
    return;

  if (mode == 0)
    {
      NtPasswordHash(Password, (char *)&password_hash, 0);
    } 
  else if (mode == 2)
  {
	  NtPasswordHash(Password, (char *)&password_hash, 1);
  }
  else {
      process_hex(Password, strlen(Password), (char *)&password_hash);
    }

  ChallengeResponse(Challenge, (char *)&password_hash, Response);
}

void GenerateNTResponse(char *AuthenticatorChallenge, char *PeerChallenge,
			char *UserName, char *Password, char *Response, 
			int mode)
{
  char Challenge[8], PasswordHash[16];

  if (!xsup_assert((AuthenticatorChallenge != NULL),
		   "AuthenticatorChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((PeerChallenge != NULL), "PeerChallenge != NULL", FALSE))
    return;

  if (!xsup_assert((UserName != NULL), "UserName != NULL", FALSE))
    return;

  if (!xsup_assert((Password != NULL), "Password != NULL", FALSE))
    return;

  if (!xsup_assert((Response != NULL), "Response != NULL", FALSE))
    return;
  
  ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, (char *)&Challenge);
  debug_printf(DEBUG_AUTHTYPES, "PeerChallenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) PeerChallenge, 8);
  debug_printf(DEBUG_AUTHTYPES, "AuthenticatorChallenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) AuthenticatorChallenge, 8);
  debug_printf(DEBUG_AUTHTYPES, "Username : %s\n",UserName);
  debug_printf(DEBUG_AUTHTYPES, "Challenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) Challenge, 8);

  if (mode == 0)
    {
      NtPasswordHash(Password, (char *)&PasswordHash, 1);
    } 
  else if (mode == 2)
  {
	  NtPasswordHash(Password, (char *)&PasswordHash, 0);
  }
  else
  {
      process_hex(Password, strlen(Password), (char *)&PasswordHash);
    }

  debug_printf(DEBUG_AUTHTYPES, "PasswordHash : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) PasswordHash, 16);
  ChallengeResponse(Challenge, (char *)&PasswordHash, Response);
  debug_printf(DEBUG_AUTHTYPES, "Response : ");
  debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *) Response, 24);
}

void GetMasterKey(char *PasswordHashHash, char *NTResponse, char *MasterKey)
{
  EVP_MD_CTX cntx;
  char Digest[20];
  int retLen;

  char Magic1[27] =
    {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
     0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
     0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79};

  if (!xsup_assert((PasswordHashHash != NULL), "PasswordHashHash != NULL",
		   FALSE))
    return;

  if (!xsup_assert((NTResponse != NULL), "NTResponse != NULL", FALSE))
    return;

  if (!xsup_assert((MasterKey != NULL), "MasterKey != NULL", FALSE))
    return;
  
  memset(&Digest, 0x00, 20);

  EVP_DigestInit(&cntx, EVP_sha1());
  EVP_DigestUpdate(&cntx, PasswordHashHash, 16);
  EVP_DigestUpdate(&cntx, NTResponse, 24);
  EVP_DigestUpdate(&cntx, (char *)&Magic1, 27);
  EVP_DigestFinal(&cntx, (uint8_t *)&Digest, (unsigned int *) &retLen);

  memcpy(MasterKey, &Digest, 16);
}

void GetMasterLEAPKey(char *PasswordHashHash, char *APC, char *APR, char *PC, char *PR, char *MasterKey)
{
  EVP_MD_CTX cntx;
  char Digest[20];
  int retLen;

  if (!xsup_assert((PasswordHashHash != NULL), "PasswordHashHash != NULL",
		   FALSE))
    return;

  if (!xsup_assert((APC != NULL), "APC != NULL", FALSE))
    return;
  
  if (!xsup_assert((APR != NULL), "APR != NULL", FALSE))
    return;

  if (!xsup_assert((PC != NULL), "PC != NULL", FALSE))
    return;

  if (!xsup_assert((PR != NULL), "PR != NULL", FALSE))
    return;

  if (!xsup_assert((MasterKey != NULL), "MasterKey != NULL", FALSE))
    return;

  memset(&Digest, 0x00, 20);

  EVP_DigestInit(&cntx, EVP_md5());
  EVP_DigestUpdate(&cntx, PasswordHashHash, 16);
  EVP_DigestUpdate(&cntx, APC, 8);
  EVP_DigestUpdate(&cntx, APR, 24);
  EVP_DigestUpdate(&cntx, PC, 8);
  EVP_DigestUpdate(&cntx, PR, 24); 
  EVP_DigestFinal(&cntx, (uint8_t *)&Digest, (unsigned int *) &retLen);
  
  memcpy(MasterKey, &Digest, 16);
  
}

void GetAsymetricStartKey(char *MasterKey, char *SessionKey, 
			  int SessionKeyLength, int IsSend, int IsServer)
{
  EVP_MD_CTX cntx;
  char Digest[20];
  char Magic[84];
  int retLen;

  char Magic2[84] =
    {0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
     0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
     0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
     0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
     0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
     0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
     0x6b, 0x65, 0x79, 0x2e};

  char Magic3[84] =
    {0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
     0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
     0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
     0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
     0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
     0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
     0x6b, 0x65, 0x79, 0x2e};

  char SHSpad1[40] =
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  char SHSpad2[40] =
    {0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2};

  if (!xsup_assert((MasterKey != NULL), "MasterKey != NULL", FALSE))
    return;

  if (!xsup_assert((SessionKey != NULL), "SessionKey != NULL", FALSE))
    return;

  memset(&Digest, 0x00, 20);

  if (IsSend) {
    if (IsServer) {
      memcpy(&Magic, &Magic3, 84);
    } else {
      memcpy(&Magic, &Magic2, 84);
    }
  } else {
    if (IsServer) {
      memcpy(&Magic, &Magic2, 84);
    } else {
      memcpy(&Magic, &Magic3, 84);
    }
  }

  EVP_DigestInit(&cntx, EVP_sha1());
  EVP_DigestUpdate(&cntx, MasterKey, 16);
  EVP_DigestUpdate(&cntx, SHSpad1, 40);
  EVP_DigestUpdate(&cntx, (char *)&Magic, 84);
  EVP_DigestUpdate(&cntx, SHSpad2, 40);
  EVP_DigestFinal(&cntx, (uint8_t *)&Digest, (unsigned int *)&retLen);

  memcpy(SessionKey, &Digest, SessionKeyLength);
}

