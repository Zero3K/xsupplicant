// 1XGina.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "1XGina.h"

extern "C" {
#include <xsupgui.h>
#include <xsupgui_request.h>
};

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO: If this DLL is dynamically linked against the MFC DLLs,
//		any functions exported from this DLL which call into
//		MFC must have the AFX_MANAGE_STATE macro added at the
//		very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the 
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//


// CMy1XGinaApp

BEGIN_MESSAGE_MAP(CMy1XGinaApp, CWinApp)
END_MESSAGE_MAP()


// CMy1XGinaApp construction

CMy1XGinaApp::CMy1XGinaApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CMy1XGinaApp object

CMy1XGinaApp theApp;


// CMy1XGinaApp initialization

BOOL CMy1XGinaApp::InitInstance()
{
	int i = 0;

	CWinApp::InitInstance();

	for (i=0; i < 30; i++)
	{
		if (xsupgui_connect() != REQUEST_SUCCESS)
		{
			Sleep(1);
		}
		else
		{
			break;
		}
	}

	return TRUE;
}

OPEN1XGINA_API BOOL UserLogin(LPTSTR Username, LPTSTR Password, pGinaInfo *settingsInfo)
{
	char username[1024];
	char password[1024];

	// Set the username and password in the supplicant and tell it to connect.
	WideCharToMultiByte(CP_ACP, 0, Username, wcslen(Username), (char *)&username, 1024, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, Password, wcslen(Password), (char *)&password, 1024, NULL, NULL);

	if (xsupgui_request_set_logon_upw(username, password) != REQUEST_SUCCESS) return false;

	return true;
}

OPEN1XGINA_API BOOL ChangeUserPassword(LPTSTR Username, LPTSTR OldPassword, LPTSTR NewPassword)
{
	// Don't let the user change passwords through pGina when using this plugin.
	return false;
}

OPEN1XGINA_API LPCTSTR AboutPlugin(void)
{
	LPCTSTR resultText;
	char *myVer = NULL;
	wchar_t longVersion[256];

	if (xsupgui_request_version_string(&myVer) != REQUEST_SUCCESS)
	{
		return TEXT("XSupplicant seems to be unavailable.");
	}
	
	resultText = (LPCTSTR)malloc(1024);
	if (resultText == NULL)
	{
		return TEXT("pGINA plugin failed to allocate memory");
	}

	memset((void *)&longVersion, 0x00, 256);
	MultiByteToWideChar(CP_ACP, 0, myVer, strlen(myVer), (wchar_t *)&longVersion, 128);

	swprintf((wchar_t *)resultText, 1024, L"%ws", longVersion);
	free(myVer);

	return resultText;
}

OPEN1XGINA_API void ChangePluginSettings(void)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	/*CConfigDialog *myDialog = new CCConfigDialog();
	myDialog->DoModal();*/
}

OPEN1XGINA_API void LoginHook(pGinaInfo *settingsInfo)
{
}

OPEN1XGINA_API void LogoutHook(pGinaInfo *settingInfo)
{
}

OPEN1XGINA_API BOOL IsRequired(void)
{
	// Don't require this plugin, and allow normal users to
	// bypass it for local account logon.
	return false;
}