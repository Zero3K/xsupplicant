// 1XGina.h : main header file for the 1XGina DLL
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

#define OPEN1XGINA_API extern "C" __declspec(dllexport)


typedef struct pGinaInfo {
	LPTSTR pathMSGina;
	LPTSTR pathPlugin;
	LPTSTR pathProfile;
	LPTSTR mapPaths;
	LPTSTR Username;
	LPTSTR Password;
	LPTSTR homeDir;
	BOOL isAdmin;
	BOOL disabled;
	int authType;
	HANDLE hUser;
	LPTSTR userGroups;
	LPTSTR userDescription;
	LPTSTR userFullName;
	BOOL allowPassChange;
	LPTSTR errorString;
	LPTSTR defaultDomain;
	BOOL reserved3;
	BOOL reserved4;
} pGinaInfo;

OPEN1XGINA_API BOOL UserLogin(LPTSTR, LPTSTR, pGinaInfo *);
OPEN1XGINA_API BOOL ChangeUserPassword(LPTSTR, LPTSTR, LPTSTR);
OPEN1XGINA_API LPCTSTR AboutPlugin(void);
OPEN1XGINA_API void ChangePluginSettings(void);
OPEN1XGINA_API void LoginHook(pGinaInfo *);
OPEN1XGINA_API void LogoutHook(pGinaInfo *);
OPEN1XGINA_API BOOL IsRequired(void);

// CMy1XGinaApp
// See 1XGina.cpp for the implementation of this class
//

class CMy1XGinaApp : public CWinApp
{
public:
	CMy1XGinaApp();

// Overrides
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
