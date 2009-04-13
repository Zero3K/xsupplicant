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

int lsa_calls_decrypt_secret(uint8_t ** outData, uint16_t * outLen) 
{
	LSA_UNICODE_STRING secretString;
	PLSA_UNICODE_STRING resultData;
	LSA_OBJECT_ATTRIBUTES objAttr;
	uint8_t * buffer = NULL;
	LSA_HANDLE lsarHandle;

	memset(&objAttr, 0x00, sizeof(objAttr));

	if (LsaOpenPolicy(NULL, (PLSA_OBJECT_ATTRIBUTES) & objAttr,
		POLICY_GET_PRIVATE_INFORMATION, &lsarHandle) != STATUS_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain a handle to the policy object needed to read the machine secret!\n");
		return -1;
	}

	secretString.Buffer = wcsdup(L"$MACHINE.ACC");
	secretString.MaximumLength = wcslen(secretString.Buffer) * 2;
	secretString.Length = secretString.MaximumLength;

	if (LsaRetrievePrivateData(lsarHandle, &secretString, &resultData) !=
		STATUS_SUCCESS)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to read machine secret!  (Is this machine a domain member?)\n");
		return -1;
	}

	free(secretString.Buffer);

	buffer = Malloc(resultData->Length + 2);	// Plus 2 for the Unicode NULL at the end.
	if (buffer == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory to return the machine secret!!\n");
		return -4;
	}

	memcpy(buffer, resultData->Buffer, resultData->Length);
	(*outData) = buffer;
	(*outLen) = resultData->Length + 2;

	LocalFree(resultData->Buffer);
	LocalFree(resultData);

	return 0;
}
