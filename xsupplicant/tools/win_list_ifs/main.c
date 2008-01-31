/**
 *
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file main.c
 *
 * \author chris@open1x.org
 *
 * $Id: main.c,v 1.2 2007/09/24 02:12:31 galimorerpg Exp $
 * $Date: 2007/09/24 02:12:31 $
 * $Log: main.c,v $
 * Revision 1.2  2007/09/24 02:12:31  galimorerpg
 * The previous commit didn't take fully.
 *
 * Hopefully this one will.
 *
 * Note: Don't check out head with -r HEAD... it will break things unhappily. ;)
 *
 * Revision 1.1.2.4  2007/02/07 07:17:42  chessing
 * Updated my e-mail address in all source files.  Replaced strcpy() with a safer version.  Updated Strncpy() to be a little safer.
 *
 **/

#include <stdio.h>
#include <winsock2.h>
#include <winioctl.h>

#include <ntddndis.h>
#include "../../vs2005/ndis_proto_driver/nuiouser.h"

#if 0
#include "pcap.h"

void print_if_info(pcap_if_t *ifdata)
{
	printf("Interface Name : %s\n", ifdata->name);
	printf("\tInterface Description : %s\n\n", ifdata->description);
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *cur;
	char errbuf[PCAP_ERRBUF_SIZE+1];

	if (pcap_findalldevs(&alldevs, &errbuf) < 0)
	{
		printf("Error : %s\n", errbuf);
		exit(1);
	}

	cur = alldevs;

	while (cur != NULL)
	{
		print_if_info(cur);
		cur = cur->next;
	}

	pcap_freealldevs(&alldevs);
}
#endif

char  NdisDev[] = "\\\\.\\\\Open1X";

/**
 * Rather than just showing an error code, we want to show a string.
 * This function will return a string to the last error that was
 * generated.  It is up to the caller to LocalFree() the result.
 **/
LPVOID GetLastErrorStr(DWORD error)
{
	LPVOID lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
   				  FORMAT_MESSAGE_FROM_SYSTEM,
				  NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				  (LPTSTR) &lpMsgBuf, 0, NULL );

	return lpMsgBuf;
}

/**
 * Go through a list of indicies showing information about the
 * available devices.  The loop that drives this function is terminated
 * by DeviceIoControl() returning an error code.  The error code needs 
 * to be checked to make sure it is ERROR_NO_MORE_ITEMS.
 **/
void ListDevs(HANDLE devHandle)
{
	PNDISPROT_QUERY_BINDING pQueryBinding;
	DWORD BytesWritten, dw;
	LPVOID lpMsgBuf;

	printf("Interfaces currently known to the Open1X Protocol Handler :\n\n");
	// Allocate enough memory to store the result.
	pQueryBinding = malloc(1024);
	if (pQueryBinding == NULL)
	{
		printf("Couldn't allocate memory to store the binding structure!\n");
		return;
	}

	pQueryBinding->BindingIndex = 0;

	while (DeviceIoControl(devHandle, IOCTL_NDISPROT_QUERY_BINDING,
			pQueryBinding, sizeof(NDISPROT_QUERY_BINDING),
			pQueryBinding, 1024,
			&BytesWritten, NULL) != 0)
	{
		printf("Device Name : %ws\n", (WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceNameOffset));
		printf("\tDevice Description : %ws\n", (WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceDescrOffset));
		printf("\n");

		pQueryBinding->BindingIndex++;
	}

	dw = GetLastError();

	if (dw != ERROR_NO_MORE_ITEMS)
	{
		lpMsgBuf = GetLastErrorStr(dw);
		printf("Error getting interface information!\n");
		printf("  Error was : %s\n", lpMsgBuf);
	}

	free(pQueryBinding);
}

/**
 * Get an handle to the "file" that the Open1X protocol handler
 * presents.
 **/
HANDLE GetHandle(char *devName)
{
		HANDLE retHandle;
		LPVOID lpMsgBuf;

		retHandle = CreateFile(devName, 
							   FILE_READ_DATA | FILE_WRITE_DATA,
							   FILE_SHARE_READ | FILE_SHARE_WRITE,
							   NULL, OPEN_EXISTING, 
							   FILE_ATTRIBUTE_NORMAL,
							   INVALID_HANDLE_VALUE);

		if (retHandle == INVALID_HANDLE_VALUE)
		{
			lpMsgBuf = GetLastErrorStr(GetLastError());

			printf("Couldn't establish a connection to the Open1X "
				"protocol service!\n  Error was : %s", lpMsgBuf);

			LocalFree(lpMsgBuf);
		}

		return retHandle;
}

int main()
{
	HANDLE devHandle;
	LPVOID lpMsgBuf;

	devHandle = GetHandle((char *)&NdisDev);

	if (devHandle == INVALID_HANDLE_VALUE)
		exit(1);

	ListDevs(devHandle);

	if (CloseHandle(devHandle) == 0)
	{
		printf("Couldn't close device handle to Open1X protocol "
				"handler.\n");

		lpMsgBuf = GetLastErrorStr(GetLastError());
		printf("Error was : %s\n", lpMsgBuf);
		LocalFree(lpMsgBuf);
	}
}