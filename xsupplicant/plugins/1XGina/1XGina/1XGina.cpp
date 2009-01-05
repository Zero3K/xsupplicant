// 1XGina.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "1XGina.h"

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
	CWinApp::InitInstance();

	return TRUE;
}

OPEN1XGINA_API BOOL UserLogin(LPTSTR Username, LPTSTR Password, pGinaInfo *settingsInfo)
{
	// Set the username and password in the supplicant and tell it to connect.
	//return false;
	return true;
}

OPEN1XGINA_API BOOL ChangeUserPassword(LPTSTR Username, LPTSTR OldPassword, LPTSTR NewPassword)
{
	// Don't let the user change passwords through pGina when using this plugin.
	return false;
}

OPEN1XGINA_API LPCTSTR AboutPlugin(void)
{
	return TEXT("This is the Open1X GINA Plugin.");
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