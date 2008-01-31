/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#ifndef _CARDIF_WINDOWS_H_
#define _CARDIF_WINDOWS_H_

struct win_sock_data {
  HANDLE devHandle;
  HANDLE hEvent;
  int wmiIntIdx;
  wchar_t *caption;    // The caption for this interface.  Needed to match WMI events to the interface.
  uint8_t *frame;      // Buffer to store a frame for this interface
  DWORD size;       // The size of the frame that was received.
};

LPVOID GetLastErrorStr(DWORD);

int devioctl_blk(HANDLE devHandle, DWORD ioctlValue, LPVOID lpInBuf, DWORD nInBufSiz,
                LPVOID lpOutBuf,  DWORD nOutBufSiz, LPDWORD lpBytesReturned);

DWORD devioctl(HANDLE hDevice, DWORD dwIoCtl, LPVOID lpInBuf, DWORD nInBufSiz,
                LPVOID lpOutBuf,  DWORD nOutBufSiz, LPDWORD lpBytesReturned);

char *cardif_windows_find_os_name_from_desc(wchar_t *devdesc);

#endif
