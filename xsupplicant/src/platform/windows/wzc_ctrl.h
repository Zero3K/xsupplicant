/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wzc_ctrl.h
 *
 * \author chris@open1x.org
 *
 * $Id: wzc_ctrl.h,v 1.1 2008/01/30 20:46:44 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:44 $
 */

#ifndef __WZC_CTRL_H__
#define __WZC_CTRL_H__

#define INTFCTL_ENABLED 0x8000
#define INTFCTL_VOLATILE 0x1000

typedef struct
{
    DWORD   dwDataLen;
    LPBYTE  pData;
} RAW_DATA, *PRAW_DATA;

typedef struct {
  LPWSTR wszGuid;
} INTF_KEY_ENTRY, 
 *PINTF_KEY_ENTRY;

typedef struct {
  DWORD dwNumIntfs;
  PINTF_KEY_ENTRY pIntfs;
} INTFS_KEY_TABLE, 
 *PINTFS_KEY_TABLE;

typedef struct {
  LPWSTR wszGuid;
  LPWSTR wszDescr;
  ULONG ulMediaState;
  ULONG ulMediaType;
  ULONG ulPhysicalMediaType;
  INT nInfraMode;
  INT nAuthMode;
  INT nWepStatus;
  DWORD bogusData;             // MSDN doesn't show this data, but it is there. ;)
  DWORD dwCtlFlags;
  DWORD dwCapabilities;
  DWORD bogusData2;            // Ditto for this data.
  RAW_DATA rdSSID;
  RAW_DATA rdBSSID;
  RAW_DATA rdBSSIDList;
  RAW_DATA rdStSSIDList;
  RAW_DATA rdCtrlData;
  BOOL bInitialized;
} INTF_ENTRY, 
 *PINTF_ENTRY;

typedef DWORD (WINAPI* WZCEnumInts)(LPWSTR pSvrAddr, INTFS_KEY_TABLE *pIntfs);
typedef DWORD (WINAPI* WZCQueryInts)(LPWSTR pSvrAddr, DWORD dwInFlags, INTF_ENTRY *pIntf, LPDWORD pdwOutFlags);
typedef DWORD (WINAPI* WZCSetInt)(LPWSTR pSvrAddr, DWORD dwInFlags, INTF_ENTRY *pIntf, LPDWORD pdwOutFlags);
typedef DWORD (WINAPI* WZCRefreshInt)(LPWSTR pSvrAddr, DWORD dwInFlags, INTF_ENTRY *pIntf, LPDWORD pdwOutFlags);

int wzc_ctrl_disconnect();
int wzc_ctrl_connect();
int wzc_ctrl_disable_wzc(char *guid);
int wzc_ctrl_enable_wzc(char *guid);

#endif // WZC_CTRL_H