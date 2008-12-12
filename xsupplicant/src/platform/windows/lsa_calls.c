/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file lsa_calls.c
 *
 * \author chris@open1x.org
 *
 **/

#include <windows.h>
#include <ntsecapi.h>

#include "../../stdintwin.h"
#include "../../xsup_debug.h"

#define STATUS_SUCCESS 0x00000000

typedef DWORD HPOLICY;
typedef DWORD HSECRET;

typedef struct _LSAPR_OBJECT_ATTRIBUTES {
  unsigned long Length;
  unsigned char* RootDirectory;
  void* ObjectName;					// When we use this structure, everything is NULL, so using a void* is okay.
  unsigned long Attributes;
  void* SecurityDescriptor;
  void* SecurityQualityOfService;
} LSAPR_OBJECT_ATTRIBUTES, 
 *PLSAPR_OBJECT_ATTRIBUTES;

typedef struct _RPC_UNICODE_STRING {
  unsigned short Length;
  unsigned short MaximumLength;
  //[size_is(MaximumLength/2), length_is(Length/2)] 
    wchar_t* Buffer;
} RPC_UNICODE_STRING, 
 *PRPC_UNICODE_STRING;

typedef struct _LSAPR_CR_CIPHER_VALUE {
  unsigned long Length;
  unsigned long MaximumLength;
//  [size_is(MaximumLength), length_is(Length)] 
    unsigned char* Buffer;
} LSAPR_CR_CIPHER_VALUE, 
 *PLSAPR_CR_CIPHER_VALUE;

// http://msdn.microsoft.com/en-us/library/cc207149.aspx
//typedef NTSTATUS (WINAPI *LsarOpenPolicy_Proto) (wchar_t *SystemName, PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, LSAPR_HANDLE *PolicyHandle);

typedef NTSTATUS (WINAPI *LsaIOpenPolicyTrusted_Proto) (HPOLICY *);

// http://msdn.microsoft.com/en-us/library/cc234363(PROT.10).aspx
typedef NTSTATUS (WINAPI *LsarOpenSecret_Proto) (HPOLICY PolicyHandle, PLSA_UNICODE_STRING SecretName, ACCESS_MASK DesiredAccess, PLSA_HANDLE SecretHandle);

// http://msdn.microsoft.com/en-us/library/cc234365(PROT.10).aspx
typedef NTSTATUS (WINAPI *LsarQuerySecret_Proto) (HSECRET SecretHandle, PLSAPR_CR_CIPHER_VALUE *EncryptedCurrentValue, PLARGE_INTEGER CurrentValueSetTime, PLSAPR_CR_CIPHER_VALUE *EncryptedOldValue, PLARGE_INTEGER OldValueSetTime);

// http://msdn.microsoft.com/en-us/library/cc207153.aspx
typedef NTSTATUS (WINAPI *LsarClose_Proto) (HPOLICY *ObjectHandle);

/*
HMODULE lsarModule;
LsaIOpenPolicyTrusted_Proto  pLsaIOpenPolicyTrusted;
*/
//LsarOpenPolicy_Proto pLsarOpenPolicy;
LsarOpenSecret_Proto  pLsarOpenSecret;
LsarQuerySecret_Proto  pLsarQuerySecret;
LsarClose_Proto  pLsarClose;

//NTSTATUS NTAPI LsaOpenSecret(LSA_HANDLE PolicyHandle, PLSA_UNICODE_STRING SecretName, ACCESS_MASK DesiredAccess, LSA_HANDLE *SecretHandle);
//NTSTATUS NTAPI LsaQuerySecret(LSA_HANDLE SecretHandle, PLSAPR_CR_CIPHER_VALUE *EncryptedCurrentValue, PLARGE_INTEGER CurrentValueSetTime, PLSAPR_CR_CIPHER_VALUE *EncryptedOldValue, PLARGE_INTEGER OldValueSetTime);

int lsa_calls_init()
{
	/*
	lsarModule = LoadLibraryA("lsasrv.dll");
	if (lsarModule == INVALID_HANDLE_VALUE) return -1;

	pLsaIOpenPolicyTrusted = (LsaIOpenPolicyTrusted_Proto) GetProcAddress(lsarModule, "LsaIOpenPolicyTrusted");
	if (pLsaIOpenPolicyTrusted == NULL) return -2; 
/*	pLsarOpenPolicy = (LsarOpenPolicy_Proto) GetProcAddress(lsarModule, "LsarOpenPolicy");
	if (pLsarOpenPolicy == NULL) return -2;*/
/*
	pLsarOpenSecret = (LsarOpenSecret_Proto) GetProcAddress(lsarModule, "LsarOpenSecret");
	if (pLsarOpenSecret == NULL) return -3;

	pLsarQuerySecret = (LsarQuerySecret_Proto) GetProcAddress(lsarModule, "LsarQuerySecret");
	if (pLsarQuerySecret == NULL) return -4;

	pLsarClose = (LsarClose_Proto) GetProcAddress(lsarModule, "LsarClose");
	if (pLsarClose == NULL) return -5; 
*/
	return 0;
}

void lsa_calls_deinit()
{
//	FreeLibrary(lsarModule);
}

int lsa_calls_decrypt_secret(uint8_t *inData, uint16_t inLen, uint8_t **outData, uint16_t *outLen)
{
	LSA_UNICODE_STRING secretString;
	LSAPR_CR_CIPHER_VALUE decryptedData;
	uint8_t *buffer = NULL;
	HPOLICY *lsarHandle;
	HSECRET secretHandle;
	HMODULE lsarModule;
	LsaIOpenPolicyTrusted_Proto  pLsaIOpenPolicyTrusted;

//	LSA_OBJECT_ATTRIBUTES objAttr;

	lsarHandle = Malloc(1024);

	lsarModule = LoadLibraryA("lsasrv.dll");
	if (lsarModule == INVALID_HANDLE_VALUE) return -1;

	pLsaIOpenPolicyTrusted = (LsaIOpenPolicyTrusted_Proto) GetProcAddress(lsarModule, "LsaIOpenPolicyTrusted");
	if (pLsaIOpenPolicyTrusted == NULL) return -2; 

	if (pLsaIOpenPolicyTrusted(lsarHandle) != STATUS_SUCCESS) 
	{
		debug_printf(DEBUG_AUTHTYPES, "pLsaIOpenPolicyTrusted failed!\n");
		return -1;
	}
	/*
	memset(&objAttr, 0x00, sizeof(objAttr));

	if (LsaOpenPolicy(NULL, (PLSA_OBJECT_ATTRIBUTES)&objAttr, 3, &lsarHandle) != STATUS_SUCCESS)
	{
		debug_printf(DEBUG_AUTHTYPES, "pLsaOpenPolicy2 failed!\n");
		return -1;
	}
*/
	secretString.Buffer = wcsdup(L"$MACHINE.ACC");
	secretString.MaximumLength = wcslen(secretString.Buffer)*2;
	secretString.Length = secretString.MaximumLength;

	if (pLsarOpenSecret(lsarHandle, &secretString, 3, &secretHandle) != STATUS_SUCCESS)
	{
		debug_printf(DEBUG_AUTHTYPES, "pLsarOpenSecret failed!\n");
		free(secretString.Buffer);
		return -2;
	}

	free(secretString.Buffer);

	// We only care about the current secret.
	if (pLsarQuerySecret(secretHandle, (PLSAPR_CR_CIPHER_VALUE *)&decryptedData, NULL, NULL, NULL) != STATUS_SUCCESS)
	{
		debug_printf(DEBUG_AUTHTYPES, "pLsarQuerySecret failed!\n");
		return -3;
	}

	buffer = Malloc(decryptedData.Length);
	if (buffer == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to return the machine secret!!\n");
		return -4;
	}

	memcpy(buffer, decryptedData.Buffer, decryptedData.Length);
	(*outData) = buffer;
	(*outLen) = decryptedData.Length;

	pLsarClose(&lsarHandle);

	FreeLibrary(lsarModule);
	return 0;
}