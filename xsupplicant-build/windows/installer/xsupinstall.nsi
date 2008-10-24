;------------------------
; Set sane defaults for environment variables:
;

; The more relative the better.  It's more portable. ;)
; 
; 
; Variables:
;
; The following variables can be passed to the nullsoft command line (Use /D<VARIABLE>=<VALUE>):
;
;
; QTDIR     - 	The root directory for Qt (i.e. C:\Qt\qt-win-opensource-src-4.3.4)
;
; SRCDIR    - 	The directory containing the Open1X source tree (i.e. C:\OpenSEA\SeaAnt)
;
; VENDORDIR - 	The directory containing the Open1X vendor source tree (i.e. C:\OpenSEA\vendor)
;
; SKINROOT  - 	The directory containing the skins directories (i.e. C:\OpenSEA\SeaAnt\xsupplicant-ui\Skins)
;			This option *MUST* be defined relative to SRCDIR! (i.e. xsupplicant-ui\Skins)
;
; SKINDIR   - 	The directory containing the actual skin files (i.e. C:\OpenSEA\SeaAnt\xsupplicant-ui\Skins\Default)
;			This option *MUST* be defined relative to SKINROOT!  (i.e. Default )
;
; Invocation:
; C:\>"C:\Program Files\NSIS\makensis.exe" /D<VARIABLE>=<VALUE> C:\OpenSEA\SeaAnt\xsupplicant-build\windows\installer\xsupinstall.nsi
;

!define PROTOCOL_DRIVER_REV     4     ; If the protocol driver is updated, this needs to be incremented to get it upgraded on user's systems.

!ifndef QTDIR
	!define QTDIR C:\Qt\qt-win-opensource-src-4.3.5
!endif

!ifndef SRCDIR
	!define SRCDIR ..\..\..
!endif 

!ifndef VENDORDIR
	!define VENDORDIR ..\..\..\..\vendor
!endif

!ifndef SKINROOT
	!define SKINROOT xsupplicant-ui\Skins
!endif

!ifndef SKINDIR
	!define SKINDIR Default
!endif

!ifndef DOCDIR
	!define DOCDIR .
!endif 

; Define a global to determine if we need to install the protocol driver.
Var InstallProtDriver

;------------------------
; Set our default compressor

SetCompressor /SOLID lzma

;------------------------
; Vista Tweaks:
RequestExecutionLevel user

;------------------------
; Include Modern UI

   !include "MUI.nsh"

;------------------------
; Include our "do special stuff" code.

   !include "xsupextras.nsi"

;-----------------------
; Interface Settings
; Don't edit directly.
; Define the necessary variables in xsupextras.nsi
   !define MUI_HEADERIMAGE
   !define MUI_HEADERIMAGE_BITMAP ${OPEN1X_MUI_HEADERIMAGE_BITMAP}
   !define MUI_ICON ${OPEN1X_MUI_ICON}
   !define MUI_UNICON ${OPEN1X_MUI_UNICON}
   !define MUI_ABORTWARNING

InstallDirRegKey HKLM "Software\XSupplicant" "Install_Dir"

;-----------------------
; Pages

  !insertmacro MUI_PAGE_LICENSE ${SOFTWARE_LICENSE_FILE}
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES

  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES

;-----------------------
; Languages

  !insertmacro MUI_LANGUAGE "English"

;-----------------------
; Functions
Function SetUpgradeEnv
	ClearErrors
	ReadRegDWORD $R1 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "ProtocolRev"
	IfErrors do_prot_upgrade

	; If the value stored in the registry is less than what we have, then we want to do an upgrade.
	IntCmp $R1 ${PROTOCOL_DRIVER_REV} dont_prot_upgrade do_prot_upgrade do_prot_upgrade

	; Depending on if we want to reinstall the protocol driver, we need to set (or unset) two different
	; things.  We need to set a temporary registry key to let the uninstaller know that we don't want it
	; to remove the driver.  And we need to store a variable for ourselves to let us know to skip installing
	; it.  We need the variable because the uninstaller will delete the registry key when it is done.
dont_prot_upgrade:
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "UpgradeFlags" 1
	StrCpy $InstallProtDriver "NO"
	goto prot_done

do_prot_upgrade:
        DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "UpgradeFlags"
	StrCpy $InstallProtDriver "YES"

prot_done:
FunctionEnd  ; SetUpgradeEnv

Function .onInit

;------------- Begin Vista Bits ----------------

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

;------------- End Vista Bits ----------------
 
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
  Call SetUpgradeEnv
  ExecWait '$R0 _?=$INSTDIR' ;Do not copy the uninstaller to a temp file
 
  IfErrors no_remove_uninstaller
    ;You can either use Delete /REBOOTOK in the uninstaller or add some code
    ;here to remove the uninstaller. Use a registry key to check
    ;whether the user has chosen to uninstall. If you are using an uninstaller
    ;components page, make sure all sections are uninstalled.
  no_remove_uninstaller:
  
done:
 
FunctionEnd

;------------- Begin Vista Bits ----------------

Function .OnInstSuccess
  UAC::Unload ; Must call unload!
FunctionEnd

Function .OnInstFailed
  UAC::Unload ; Must call unload!
FunctionEnd

;------------- End Vista Bits ----------------

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

Function un.CheckAdmin

        ClearErrors
        UserInfo::GetName
        IfErrors Win9x
        Pop $0
        UserInfo::GetAccountType
        Pop $1
        UserInfo::GetOriginalAccountType
        Pop $2

        StrCmp $1 "Admin" +3 0
                MessageBox MB_OK 'You must have administrator rights to uninstall this program.'
                Abort

        Goto done

    Win9x:
        MessageBox MB_OK 'This program will not operate on this version of Windows!'
        Goto done

    done:


FunctionEnd   ; un.CheckAdmin

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
	DetailPrint "Installing Microsoft Runtimes."
	nsExec::Exec '"$INSTDIR\vcredist_x86.exe"'
	Pop $0
	DetailPrint "  VCRedist return value : $0"
	Delete $INSTDIR\vcredist_x86.exe
	;File "C:\Program Files\Microsoft Visual Studio 8\VC\redist\x86\Microsoft.VC80.CRT\msvcr80.dll"

	File "${QTDIR}\bin\QtCore4.dll"
	File "${QTDIR}\bin\QtGui4.dll"
        File "${QTDIR}\bin\QtXml4.dll"

        Call ExtrasPreInstall

        SetOutPath $INSTDIR    ; Make sure we are in the right place still.

        File "${SRCDIR}\xsupplicant\vs2005\build-release\XSupplicant_service.exe"
        File "${SRCDIR}\xsupplicant-ui\build-release\XSupplicantUI.exe"
        File "${SRCDIR}\xsupplicant\vs2005\ndis_proto_driver\open1x.sys"
        File "${SRCDIR}\xsupplicant\vs2005\ndis_proto_driver\open1x.inf"
        File "${VENDORDIR}\ProtInstall\build-release\ProtInstall.exe"

        SetOutPath "$INSTDIR\Docs"

        File "${DOCDIR}\xsupphelp.html"

        SetOutPath "$INSTDIR\Skins\Default"

        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\AboutWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ConfigWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ConnectionInfoWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ConnectionManagerWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ConnectionPromptWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ConnectionWizardWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ConnectWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\GTCWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\HelpWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\LogWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\PINWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\PSKWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\SelectTrustedServerWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\SSIDListWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\UPWWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\ViewLogWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\WEPWindow.ui"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\WirelessPriorityWindow.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\WirelessScanDialog.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageAdapter.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageDot1XCert.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageDot1XInnerProtocol.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageDot1XProtocol.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageFASTInnerProtocol.ui
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageFinished.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageIPOptions.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageNetworkType.ui"
      File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageSIMReader.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageStaticIP.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageWiredSecurity.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageWirelessInfo.ui"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\wizardPageWirelessNetwork.ui"


        SetOutPath "$INSTDIR\Skins\Default\images"

        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner_left.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner_left_short.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner_right.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner_right_short.png"

	SetOutPath "$INSTDIR\Skins\Default\images\banner"

	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner\banner_center.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner\banner_left.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner\banner_left_bg.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner\banner_right.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\images\banner\banner_right_bg.png"


        SetOutPath "$INSTDIR\Skins\Default\icons"
        
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_a.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_ab.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_abg.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_abgn.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_abn.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_ag.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_agn.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_an.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_b.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_bg.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_bgn.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_bn.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_g.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_gn.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\802_11_n.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\arrow_down.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\arrow_left.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\arrow_right.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\arrow_up.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\key.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\lock.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\lockedstate.png"
	File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\lockedstate_bw.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\prod_color.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\prod_eng_connected.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\prod_green.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\prod_no_engine.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\prod_red.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\prod_yellow.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\signal_0.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\signal_1.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\signal_2.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\signal_3.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\signal_4.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tnc_allowed.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tnc_isolated.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tnc_none.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_advanced.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_connections.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_connection.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_globals.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_internals.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_logging.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_profile.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_profiles.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_settings.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_trustedserver.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\tree_trustedservers.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\unlockedstate.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\wired.png"
        File "${SRCDIR}\${SKINROOT}\${SKINDIR}\icons\wireless.png"

        SetOutPath $INSTDIR

	; Start the UI when Windows starts.
        WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Run" "XSupplicantUI" "$INSTDIR\XSupplicantUI.exe"

        ; Set the Open1X Protocol Handler to start on startup.
        WriteRegDWORD HKEY_LOCAL_MACHINE "SYSTEM\CurrentControlSet\Services\Open1X" "Start" 0x00000000
        WriteRegDWORD HKEY_LOCAL_MACHINE "SYSTEM\CurrentControlSet\Services\Open1X" "Tag"   0x00000014

        Call ExtrasPostInstall   ; Make this call before we turn everything on.

	StrCmpS $InstallProtDriver "NO" continue_service_install

        ; Then, install the protocol driver.
        DetailPrint "Installing the protocol driver.."
        nsExec::Exec '"$INSTDIR\ProtInstall.exe" /Install /hide open1x.inf'
	Pop $0
	DetailPrint "  Protocol driver installer return value : $0"
	IntCmp $0 0 continue_service_install
	
	DetailPrint "Unable to install the Open1X.sys protocol driver."
	abort

continue_service_install:
        SetOutPath $INSTDIR

        ; Get the windows version and determine how to install the service.
        ; The service won't start on Vista if we try to depend on wzc.
	  ClearErrors
	  GetVersion::WindowsName
	  Pop $R0

	  Strcmp $R0 "Vista" vista_service_install
        
        Goto default_service_install

default_service_install:
        nsExec::Exec '"$WINDIR\system32\sc.exe" create XSupplicant binPath= "$INSTDIR\XSupplicant_service.exe" DisplayName= XSupplicant start= auto depend= open1x/SENS/wzcsvc'
        Goto finish_service_install

vista_service_install:
        nsExec::Exec '"$WINDIR\system32\sc.exe" create XSupplicant binPath= "$INSTDIR\XSupplicant_service.exe" DisplayName= XSupplicant start= auto depend= open1x/SENS'

finish_service_install:

        ; Create a description for the supplicant.
        WriteRegStr  HKLM SYSTEM\CurrentControlSet\Services\XSupplicant "Description" "802.1X Authentication Service"

	; Set the service to restart up to 2 times if it terminates abnormally
	WriteRegBin  HKLM SYSTEM\CurrentControlSet\Services\XSupplicant "FailureActions" 80510100000000000000000003000000490044000100000060ea00000100000060ea00000000000000000000

	; Create some start menu programs
	SetShellVarContext All
	CreateDirectory "$SMPROGRAMS\${TARGET}"
        CreateShortCut "$SMPROGRAMS\${TARGET}\XSupplicant.lnk" $INSTDIR\XSupplicantUI.exe "-l"
	CreateShortCut "$SMPROGRAMS\${TARGET}\Check for other supplicants.lnk" $INSTDIR\checksuppsapp.exe

	; If we need to reboot, then don't start stuff it would be bad.
	IfRebootFlag dont_start_app

        nsExec::Exec '"$WINDIR\system32\net.exe" start open1x'

	; Start the supplicant service.
        SetOutPath $INSTDIR
	DetailPrint "Starting XSupplicant"
        nsExec::Exec '"$WINDIR\system32\net.exe" start XSupplicant'

	; Start the supplicant UI.
	DetailPrint "Starting the XSupplicant UI"
        Exec '"$INSTDIR\XSupplicantUI.exe"'

dont_start_app:
        DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "UpgradeFlags"
	WriteRegStr  HKLM SOFTWARE\XSupplicant "Install_Dir" "$INSTDIR"
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "DisplayName" "XSupplicant"
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "DisplayVersion" '${VERSION}'
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "URLInfoAbout" "http://www.open1x.org"
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "URLUpdateInfo" "http://www.open1x.org"
	WriteRegStr  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "UninstallString" '"$INSTDIR\uninstall.exe"'
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "NoRepair" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "ProtocolRev" ${PROTOCOL_DRIVER_REV}
        WriteUninstaller "uninstall.exe"    

	IfRebootFlag 0 noreboot
		MessageBox MB_YESNO "A reboot is required to finish the installation.  Do you wish to reboot now?" IDNO noreboot
			Reboot

noreboot:

SectionEnd

Section "Uninstall"

	Call un.CheckAdmin
        Call un.ExtrasPreInstall

        DetailPrint "Shutting down the XSupplicant UI..."
        push "XSupplicantUI.exe"
        processwork::KillProcess
        Sleep 2000

	DetailPrint "Stopping XSupplicant..."
        nsExec::Exec '"$WINDIR\system32\net.exe" stop XSupplicant'

        DetailPrint "Unregistering XSupplicant..."
        nsExec::Exec '"$WINDIR\system32\sc.exe" delete XSupplicant'

	ReadRegDWORD $R0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant" "UpgradeFlags"
	IntCmp $R0 1 no_prot_uninstall

        DetailPrint "Uninstalling the protocol driver..."
        nsExec::Exec '"$INSTDIR\ProtInstall.exe" /Uninstall /hide open1x.inf'
	goto remove_program_files

no_prot_uninstall:
	DetailPrint "Doing an upgrade where the protocol driver doesn't need to be replaced."
	; Fall through

remove_program_files:
	DetailPrint "Removing program files..."
	Delete $INSTDIR\XSupplicant_service.exe
	Delete $INSTDIR\QtCore4.dll
        Delete $INSTDIR\QtGui4.dll
        Delete $INSTDIR\QtXml4.dll
        Delete $INSTDIR\XSupplicantUI.exe
        Delete $INSTDIR\ProtInstall.exe
        Delete $INSTDIR\open1x.inf
        Delete $INSTDIR\open1x.sys
	Delete $INSTDIR\uninstall.exe
	;Delete $INSTDIR\msvcr80.dll

        Delete $INSTDIR\Skins\Default\AboutWindow.ui
        Delete $INSTDIR\Skins\Default\ConfigWindow.ui
	Delete $INSTDIR\Skins\Default\ConnectionInfoWindow.ui
	Delete $INSTDIR\Skins\Default\ConnectionManagerWindow.ui
	Delete $INSTDIR\Skins\Default\ConnectionPromptWindow.ui
	Delete $INSTDIR\Skins\Default\ConnectionWizardWindow.ui
	Delete $INSTDIR\Skins\Default\ConnectWindow.ui
	Delete $INSTDIR\Skins\Default\GTCWindow.ui
        Delete $INSTDIR\Skins\Default\HelpWindow.ui
        Delete $INSTDIR\Skins\Default\LogWindow.ui
	Delete $INSTDIR\Skins\Default\PINWindow.ui
	Delete $INSTDIR\Skins\Default\PSKWindow.ui
        Delete $INSTDIR\Skins\Default\SelectTrustedServerWindow.ui
	Delete $INSTDIR\Skins\Default\SSIDListWindow.ui
	Delete $INSTDIR\Skins\Default\UPWWindow.ui
        Delete $INSTDIR\Skins\Default\ViewLogWindow.ui
	Delete $INSTDIR\Skins\Default\WEPWindow.ui
	Delete $INSTDIR\Skins\Default\WirelessPriorityWindow.ui
	Delete $INSTDIR\Skins\Default\WirelessScanDialog.ui
	Delete $INSTDIR\Skins\Default\wizardPageAdapter.ui
	Delete $INSTDIR\Skins\Default\wizardPageDot1XCert.ui
	Delete $INSTDIR\Skins\Default\wizardPageDot1XInnerProtocol.ui
	Delete $INSTDIR\Skins\Default\wizardPageDot1XProtocol.ui
	Delete $INSTDIR\Skins\Default\wizardPageFASTInnerProtocol.ui
	Delete $INSTDIR\Skins\Default\wizardPageFinished.ui
	Delete $INSTDIR\Skins\Default\wizardPageIPOptions.ui
	Delete $INSTDIR\Skins\Default\wizardPageNetworkType.ui
      Delete $INSTDIR\Skins\Default\wizardPageSIMReader.ui
	Delete $INSTDIR\Skins\Default\wizardPageStaticIP.ui
	Delete $INSTDIR\Skins\Default\wizardPageWiredSecurity.ui
	Delete $INSTDIR\Skins\Default\wizardPageWirelessInfo.ui
	Delete $INSTDIR\Skins\Default\wizardPageWirelessNetwork.ui
	
	Delete $INSTDIR\Skins\Default\images\banner\banner_center.png
	Delete $INSTDIR\Skins\Default\images\banner\banner_left.png
	Delete $INSTDIR\Skins\Default\images\banner\banner_left_bg.png
	Delete $INSTDIR\Skins\Default\images\banner\banner_right.png
	Delete $INSTDIR\Skins\Default\images\banner\banner_right_bg.png

        Delete $INSTDIR\Skins\Default\images\banner_left_short.png
        Delete $INSTDIR\Skins\Default\images\banner_right_short.png
        Delete $INSTDIR\Skins\Default\images\banner_right.png
        Delete $INSTDIR\Skins\Default\images\banner_left.png

        SetOutPath "$INSTDIR\Skins\Default\icons"

	Delete $INSTDIR\Skins\Default\icons\802_11_a.png
	Delete $INSTDIR\Skins\Default\icons\802_11_ab.png
	Delete $INSTDIR\Skins\Default\icons\802_11_abg.png
	Delete $INSTDIR\Skins\Default\icons\802_11_abgn.png
	Delete $INSTDIR\Skins\Default\icons\802_11_abn.png
	Delete $INSTDIR\Skins\Default\icons\802_11_ag.png
	Delete $INSTDIR\Skins\Default\icons\802_11_agn.png
	Delete $INSTDIR\Skins\Default\icons\802_11_an.png
	Delete $INSTDIR\Skins\Default\icons\802_11_b.png
	Delete $INSTDIR\Skins\Default\icons\802_11_bg.png
	Delete $INSTDIR\Skins\Default\icons\802_11_bgn.png
	Delete $INSTDIR\Skins\Default\icons\802_11_bn.png
	Delete $INSTDIR\Skins\Default\icons\802_11_g.png
	Delete $INSTDIR\Skins\Default\icons\802_11_gn.png
	Delete $INSTDIR\Skins\Default\icons\802_11_n.png
        Delete $INSTDIR\Skins\Default\icons\arrow_down.png
        Delete $INSTDIR\Skins\Default\icons\arrow_left.png
        Delete $INSTDIR\Skins\Default\icons\arrow_right.png
        Delete $INSTDIR\Skins\Default\icons\arrow_up.png
        Delete $INSTDIR\Skins\Default\icons\lock.png
        Delete $INSTDIR\Skins\Default\icons\lockedstate.png
	Delete $INSTDIR\Skins\Default\icons\lockedstate_bw.png
        Delete $INSTDIR\Skins\Default\icons\key.png
        Delete $INSTDIR\Skins\Default\icons\prod_color.png
        Delete $INSTDIR\Skins\Default\icons\prod_eng_connected.png
        Delete $INSTDIR\Skins\Default\icons\prod_green.png
        Delete $INSTDIR\Skins\Default\icons\prod_no_engine.png
        Delete $INSTDIR\Skins\Default\icons\prod_red.png
        Delete $INSTDIR\Skins\Default\icons\prod_yellow.png
        Delete $INSTDIR\Skins\Default\icons\signal_0.png
        Delete $INSTDIR\Skins\Default\icons\signal_1.png
        Delete $INSTDIR\Skins\Default\icons\signal_2.png
        Delete $INSTDIR\Skins\Default\icons\signal_3.png
        Delete $INSTDIR\Skins\Default\icons\signal_4.png
        Delete $INSTDIR\Skins\Default\icons\tnc_allowed.png
        Delete $INSTDIR\Skins\Default\icons\tnc_isolated.png
        Delete $INSTDIR\Skins\Default\icons\tnc_none.png
        Delete $INSTDIR\Skins\Default\icons\tree_advanced.png
        Delete $INSTDIR\Skins\Default\icons\tree_connections.png
        Delete $INSTDIR\Skins\Default\icons\tree_connection.png
        Delete $INSTDIR\Skins\Default\icons\tree_globals.png
        Delete $INSTDIR\Skins\Default\icons\tree_internals.png
        Delete $INSTDIR\Skins\Default\icons\tree_logging.png
        Delete $INSTDIR\Skins\Default\icons\tree_profiles.png
        Delete $INSTDIR\Skins\Default\icons\tree_profile.png
        Delete $INSTDIR\Skins\Default\icons\tree_settings.png
        Delete $INSTDIR\Skins\Default\icons\tree_trustedservers.png
        Delete $INSTDIR\Skins\Default\icons\tree_trustedserver.png
        Delete $INSTDIR\Skins\Default\icons\unlockedstate.png
        Delete $INSTDIR\Skins\Default\icons\wired.png
        Delete $INSTDIR\Skins\Default\icons\wireless.png


	SetOutPath $INSTDIR

        RMDir /r "$INSTDIR\Skins\Default\icons"
	RMDir /r "$INSTDIR\Skins\Default\images"
        RMDir /r "$INSTDIR\Skins\Default"
        RMDir /r "$INSTDIR\Skins"
	RMDir /r "$INSTDIR\Modules"

        Delete $INSTDIR\Docs\xsupphelp.html
        RMDir /r "$INSTDIR\Docs"

        Call un.ExtrasPostInstall

	DetailPrint "Removing Start Menu links..."
	; Delete start menu programs
	SetShellVarContext All
        Delete "$SMPROGRAMS\${TARGET}\XSupplicant Tray Application.lnk"
	RMDir $SMPROGRAMS\${TARGET}

	; remove Open1X.sys from the System Drivers directory
	;Delete %SYSTEMROOT%\system32\drivers\Open1X.sys

	; Clean up registry keys.
	DetailPrint "Cleaning up registry keys..."
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\XSupplicant"
	DeleteRegKey HKLM SOFTWARE\XSupplicant
        DeleteRegValue HKLM SOFTWARE\Microsoft\Windows\CurrentVersion\Run "XSupplicantUI"
        DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\XSupplicant

	SetOutPath "$INSTDIR\.."

	RMDir "$INSTDIR"

SectionEnd
