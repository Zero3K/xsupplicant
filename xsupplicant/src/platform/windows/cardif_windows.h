/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _CARDIF_WINDOWS_H_
#define _CARDIF_WINDOWS_H_

struct win_sock_data {
	HANDLE devHandle;
	HANDLE hEvent;
	int wmiIntIdx;
	wchar_t *caption;	// The caption for this interface.  Needed to match WMI events to the interface.
	uint8_t *frame;		// Buffer to store a frame for this interface
	DWORD size;		// The size of the frame that was received.
	uint8_t *eventdata;	// Buffer for the event data from the protocol driver.
	DWORD evtSize;		// The size of event data that was received.
	uint8_t osver;		// The OS version this interface is running on.

	uint8_t dhcpOutstanding;	// # of DHCP threads waiting to run.
	HANDLE mutexDhcpRunning;
	HANDLE mutexDhcpOutstanding;
	uint8_t needTerminate;

	uint8_t strays;		// The # of frames that we didn't expect.
};

LPVOID GetLastErrorStr(DWORD);
char *uni_to_ascii(wchar_t * instr);

int devioctl_blk(HANDLE devHandle, DWORD ioctlValue, LPVOID lpInBuf,
		 DWORD nInBufSiz, LPVOID lpOutBuf, DWORD nOutBufSiz,
		 LPDWORD lpBytesReturned);

DWORD devioctl(HANDLE hDevice, DWORD dwIoCtl, LPVOID lpInBuf, DWORD nInBufSiz,
	       LPVOID lpOutBuf, DWORD nOutBufSiz, LPDWORD lpBytesReturned);

char *cardif_windows_find_os_name_from_desc(wchar_t * devdesc);
void cardif_windows_is_dhcp_enabled(context * ctx, int *enabled);
wchar_t *cardif_windows_get_friendly_name(uint8_t *mac);

#endif
