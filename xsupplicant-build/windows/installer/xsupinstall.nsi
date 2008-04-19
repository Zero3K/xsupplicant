;------------------------
; Vista Tweaks:
RequestExecutionLevel user

;------------------------
; Include Modern UI

   !include "MUI.nsh"

;------------------------
; Include our "do special stuff" code.

   !include "xsupextras.nsi"


InstallDirRegKey HKLM "Software\XSupplicant" "Install_Dir"

;-----------------------
; Pages

  !insertmacro MUI_PAGE_LICENSE "win-LICENSE"
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES

  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES

;-----------------------
; Languages

  !insertmacro MUI_LANGUAGE "English"

;-----------------------
; Functions
Function .onInit

UAC_Elevate:
  UAC::RunElevated
  StrCmp 1223 $0 UAC_ElevationAborted ; UAC dialog aborted by user?
  StrCmp 0 $0 0 UAC_Err ; Error?
  StrCmp 1 $1 0 UAC_Success ; Are we the real deal or just the wrapper?
  Quit

UAC_Err:
  MessageBox mb_iconstop "Unable to elevate, error $0"
  Abort

UAC_ElevationAborted: 
  # elevation was aborted, run as normal?
  MessageBox mb_iconstop "User needs to have administrator rights in order to install application, aborting!"
  Abort

UAC_Success:
  StrCmp 1 $3 +4 ; Admin?
  StrCmp 3 $1 0 UAC_ElevationAborted ; Try again?
  MessageBox mb_iconstop "User needs to have administrator rights in order to install application, abortin!"
  goto UAC_Elevate
 
  ReadRegStr $R0 HKLM \
  "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" \
  "UninstallString"
  StrCmp $R0 "" done
 
  MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
  "XSupplicant and XSupplicant UI is already installed. $\n$\nClick `OK` to remove the \
  previous version or `Cancel` to cancel this upgrade." \
  IDOK uninst
  Abort
  
;Run the uninstaller
uninst:
  ClearErrors
  ExecWait '$R0 _?=$INSTDIR' ;Do not copy the uninstaller to a temp file
 
  IfErrors no_remove_uninstaller
    ;You can either use Delete /REBOOTOK in the uninstaller or add some code
    ;here to remove the uninstaller. Use a registry key to check
    ;whether the user has chosen to uninstall. If you are using an uninstaller
    ;components page, make sure all sections are uninstalled.
  no_remove_uninstaller:
  
done:
 
FunctionEnd

Function .OnInstSuccess
  UAC::Unload ; Must call unload!
FunctionEnd

Function .OnInstFailed
  UAC::Unload ; Must call unload!
FunctionEnd


;Function CheckSups
;        File "..\check_other_supplicants\libchecksups\checksups\Release\checksuppsapp.exe"
;	File "qtcore4.dll"
;	File "qtgui4.dll"
;        File "qtxml4.dll"

;        DetailPrint "Checking for other supplicants..."
;        nsExec::Exec '"$INSTDIR\checksuppsapp.exe" -Q'  ; If there are no other supplicants, be quiet about it. ;)
;	Pop $0
;        DetailPrint "  Checksuppsapp return value : $0"

;        IntCmp $0 4 done
;        IntCmp $0 1 abort
;        IntCmp $0 2 abort
;        IntCmp $0 3 reboot_needed
;        IntCmp $0 5 done         ; No others were found, so move along.

; abort:
;	MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 \
;  		"Other supplicants or wireless managers were discovered, but not disabled or removed. $\nThis could cause \
;  		XSupplicant to be unable to work properly.  (In some cases, it can cause drivers to blue screen.) $\n \
;		Would you like to continue anyway?" \
;	IDYES done

;        DetailPrint "One or more problems prevented us from installing.  Please correct the problems and try again."
;        Abort  ; We can't continue.

; reboot_needed:
        ; Set a flag so that we know not to start the UI and service at the end
        ; as well as asking the user to reboot at the end.
;	SetRebootFlag true

; done:

;FunctionEnd  ;CheckSups

Function CheckAdmin

        ClearErrors
        UserInfo::GetName
        IfErrors Win9x
        Pop $0
        UserInfo::GetAccountType
        Pop $1
        UserInfo::GetOriginalAccountType
        Pop $2

        StrCmp $1 "Admin" +3 0
                MessageBox MB_OK 'You must have administrator rights to install this program.'
                Abort

        Goto done

    Win9x:
        MessageBox MB_OK 'This program will not operate on this version of Windows!'
        Goto done

    done:


FunctionEnd   ; CheckAdmin

Function CheckWinVer

	ClearErrors
	GetVersion::WindowsName
	Pop $R0

	Strcmp $R0 "XP" move_along

	MessageBox MB_YESNO|MB_ICONSTOP "This version of Windows has not been tested.  It is likely that the supplicant will not work.$\n \
		Do you want to continue?" IDYES move_along

	Abort

move_along:

FunctionEnd   ; CheckWinVer

;-----------------------
; Installer Sections

Section "XSupplicant (required)"

	Call CheckWinVer

        Call CheckAdmin

	SetOutPath $INSTDIR

	; Make sure the redist is installed before going forward.
	; 
	File "C:\Program Files\Microsoft Visual Studio 8\SDK\v2.0\BootStrapper\Packages\vcredist_x86\vcredist_x86.exe"
	DetailPrint "Installing Microsoft Runtime."
	nsExec::Exec '"$INSTDIR\vcredist_x86.exe"'
	Pop $0
	DetailPrint "  VCRedist return value : $0"
	Delete $INSTDIR\vcredist_x86.exe

        ; Call CheckSups

        Call CallFirst

        SetOutPath $INSTDIR    ; Make sure we are in the right place still.

        File "..\..\..\xsupplicant\vs2005\build-release\XSupplicant_service.exe"
        File "..\..\..\xsupplicant-ui\build-release\XSupplicantUI.exe"
        File "..\..\..\XSupplicant\vs2005\ndis_proto_driver\open1x.sys"
        File "..\..\..\xsupplicant\vs2005\ndis_proto_driver\open1x.inf"
        ;File "..\..\..\..\vendor\ProtInstall\build-release\ProtInstall.exe"

	SetOutPath "$INSTDIR\Modules"
	File "..\..\..\xsupplicant\plugins\vs2005\release\BirdDog.dll"

        SetOutPath "$INSTDIR\Docs"

        File "xsupphelp.html"

        SetOutPath "$INSTDIR\Skins\Default"

        File "..\..\..\xsupplicant-ui\Skins\Default\AboutWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\ConfigWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\HelpWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\LogWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\LoginWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\SelectTrustedServerWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\ViewLogWindow.ui"
        File "..\..\..\xsupplicant-ui\Skins\Default\WirelessPriorityWindow.ui"

        SetOutPath "$INSTDIR\Skins\Default\images"

        File "..\..\..\xsupplicant-ui\Skins\Default\images\banner_left_short.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\images\banner_right_short.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\images\banner_right.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\images\banner_left.png"

        SetOutPath "$INSTDIR\Skins\Default\icons"

        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_advanced.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_trustedservers.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_trustedserver.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_connections.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_connection.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_globals.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_internals.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\key.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\lock.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\lockedstate.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_logging.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\prod_color.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\prod_red.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_profiles.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_profile.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\tree_settings.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\signal_0.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\signal_1.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\signal_2.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\signal_3.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\signal_4.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\unlockedstate.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\wired.png"
        File "..\..\..\xsupplicant-ui\Skins\Default\icons\wireless.png"

        SetOutPath $INSTDIR

	; Start the UI when Windows starts.
        WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Run" "XSupplicantUI" "$INSTDIR\XSupplicantUI.exe"

        ; Set the Open1X Protocol Handler to start on startup.
        WriteRegDWORD HKEY_LOCAL_MACHINE "SYSTEM\CurrentControlSet\Services\Open1X" "Start" 0x00000000
        WriteRegDWORD HKEY_LOCAL_MACHINE "SYSTEM\CurrentControlSet\Services\Open1X" "Tag"   0x00000014

        Call CallLast   ; Make this call before we turn everything on.

        ; Then, install the protocol driver.
        DetailPrint "Installing the protocol driver.."
        nsExec::Exec '"$INSTDIR\ProtInstall.exe" /Install /hide open1x.inf'

        ; Get the windows version and determine how to install the service.
        ; The service won't start on Vista if we try to depend on wzc.
	  ClearErrors
	  GetVersion::WindowsName
	  Pop $R0

	  Strcmp $R0 "Vista" vista_service_install
        
        Goto default_service_install

default_service_install:
        nsExec::Exec '"$WINDIR\system32\sc.exe" create XSupplicant binPath= "$INSTDIR\xsupplicant_service.exe" DisplayName= XSupplicant start= auto depend= open1x/SENS/wzcsvc'
        Goto finish_service_install

vista_service_install:
        nsExec::Exec '"$WINDIR\system32\sc.exe" create XSupplicant binPath= "$INSTDIR\xsupplicant_service.exe" DisplayName= XSupplicant start= auto depend= open1x/SENS'

finish_service_install:

        ; Create a description for the supplicant.
        WriteRegStr  HKLM SYSTEM\CurrentControlSet\Services\XSupplicant "Description" "802.1X Authentication Service"

	; Create some start menu programs
	SetShellVarContext All
	CreateDirectory "$SMPROGRAMS\${TARGET}"
        CreateShortCut "$SMPROGRAMS\${TARGET}\XSupplicant Tray Application.lnk" $INSTDIR\XSupplicantUI.exe "-l"
	CreateShortCut "$SMPROGRAMS\${TARGET}\Check for other supplicants.lnk" $INSTDIR\checksuppsapp.exe

	; If we need to reboot, then don't start stuff it would be bad.
	IfRebootFlag dont_start_app

        nsExec::Exec '"$WINDIR\system32\net.exe" start open1x'

	; Start the supplicant service.
	DetailPrint "Starting XSupplicant"
        nsExec::Exec '"$WINDIR\system32\net.exe" start XSupplicant'

	; Start the supplicant UI.
	DetailPrint "Starting the XSupplicant UI"
        Exec '"$INSTDIR\XSupplicantUI.exe"'

dont_start_app:
	WriteRegStr  HKLM SOFTWARE\XSupplicant "Install_Dir" "$INSTDIR"
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "DisplayName" "XSupplicant"
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "UninstallString" '"$INSTDIR\uninstall.exe"'
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "NoRepair" 1
        WriteUninstaller "uninstall.exe"    

	IfRebootFlag 0 noreboot
		MessageBox MB_YESNO "A reboot is required to finish the installation.  Do you wish to reboot now?" IDNO noreboot
			Reboot

noreboot:

SectionEnd

Section "Uninstall"

        Call un.CallFirst

        DetailPrint "Killing the tray icon.."
        push "XSupplicantUI.exe"
        processwork::KillProcess
        Sleep 2000

	DetailPrint "Stopping the service.."
        nsExec::Exec '"$WINDIR\system32\net.exe" stop XSupplicant'

        DetailPrint "Remove the service.."
        nsExec::Exec '"$WINDIR\system32\sc.exe" delete XSupplicant'

        DetailPrint "Uninstalling the protocol driver.."
        nsExec::Exec '"$INSTDIR\ProtInstall.exe" /Uninstall /hide open1x.inf'

	DetailPrint "Removing program files..."
	Delete $INSTDIR\xsupplicant_service.exe
	Delete $INSTDIR\qtcore4.dll
        Delete $INSTDIR\qtgui4.dll 
        Delete $INSTDIR\qtxml4.dll
        Delete $INSTDIR\XSupplicantUI.exe
        Delete $INSTDIR\ProtInstall.exe
        Delete $INSTDIR\open1x.inf
        Delete $INSTDIR\open1x.sys
	Delete $INSTDIR\uninstall.exe
	Delete $INSTDIR\checksuppsapp.exe

	Delete $INSTDIR\Modules\BirdDog.dll

        Delete $INSTDIR\Skins\Default\AbtDlg.ui
        Delete $INSTDIR\Skins\Default\ConfigDlg.ui
        Delete $INSTDIR\Skins\Default\HelpDlg.ui
        Delete $INSTDIR\Skins\Default\LogDlg.ui
        Delete $INSTDIR\Skins\Default\LoginDlg.ui
        Delete $INSTDIR\Skins\Default\SelectTrustedServerDlg.ui
        Delete $INSTDIR\Skins\Default\ViewLogDlg.ui

        Delete $INSTDIR\Skins\Default\images\banner_left_short.png
        Delete $INSTDIR\Skins\Default\images\banner_right_short.png
        Delete $INSTDIR\Skins\Default\images\banner_right.png
        Delete $INSTDIR\Skins\Default\images\banner_left.png

        SetOutPath "$INSTDIR\Skins\Default\icons"

        Delete $INSTDIR\Skins\Default\icons\tree_advanced.png
        Delete $INSTDIR\Skins\Default\icons\tree_trustedservers.png
        Delete $INSTDIR\Skins\Default\icons\tree_trustedserver.png
        Delete $INSTDIR\Skins\Default\icons\tree_connections.png
        Delete $INSTDIR\Skins\Default\icons\tree_connection.png
        Delete $INSTDIR\Skins\Default\icons\tree_globals.png
        Delete $INSTDIR\Skins\Default\icons\tree_internals.png
        Delete $INSTDIR\Skins\Default\icons\key.png
        Delete $INSTDIR\Skins\Default\icons\lock.png
        Delete $INSTDIR\Skins\Default\icons\lockedstate.png
        Delete $INSTDIR\Skins\Default\icons\tree_logging.png
        Delete $INSTDIR\Skins\Default\icons\prod_color.png
        Delete $INSTDIR\Skins\Default\icons\prod_red.png
        Delete $INSTDIR\Skins\Default\icons\tree_profiles.png
        Delete $INSTDIR\Skins\Default\icons\tree_profile.png
        Delete $INSTDIR\Skins\Default\icons\tree_settings.png
        Delete $INSTDIR\Skins\Default\icons\signal_0.png
        Delete $INSTDIR\Skins\Default\icons\signal_1.png
        Delete $INSTDIR\Skins\Default\icons\signal_2.png
        Delete $INSTDIR\Skins\Default\icons\signal_3.png
        Delete $INSTDIR\Skins\Default\icons\signal_4.png
        Delete $INSTDIR\Skins\Default\icons\unlockedstate.png
        Delete $INSTDIR\Skins\Default\icons\wired.png
        Delete $INSTDIR\Skins\Default\icons\wireless.png

	SetOutPath $INSTDIR

        RMDir /r "$INSTDIR\Skins\Default\icons"
        RMDir /r "$INSTDIR\Skins\Default"
        RMDir /r "$INSTDIR\Skins"
        RMDir /r "$INSTDIR\Skins"
	RMDir /r "$INSTDIR\Modules"

        Delete $INSTDIR\Docs\xsupphelp.html
        RMDir "$INSTDIR\Docs"

        Call un.CallLast

	DetailPrint "Removing Start Menu links..."
	; Delete start menu programs
	SetShellVarContext All
        Delete "$SMPROGRAMS\XSupplicant\XSupplicant Tray Application.lnk"
        Delete "$SMPROGRAMS\XSupplicant\Check for other supplicants.lnk"
	RMDir $SMPROGRAMS\XSupplicant
        Delete "$SMPROGRAMS\Identity Engines\XSupplicant Tray Application.lnk"
        Delete "$SMPROGRAMS\Identity Engines\Check for other supplicants.lnk"
	RMDir "$SMPROGRAMS\Identity Engines"

	; Clean up registry keys.
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant"
	DeleteRegKey HKLM SOFTWARE\XSupplicant
        DeleteRegValue HKLM SOFTWARE\Microsoft\Windows\CurrentVersion\Run "XSupplicantUI"
        DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\XSupplicant

	SetOutPath "$INSTDIR\.."

	RMDir "$INSTDIR"

SectionEnd
