; This variable can be overridden by passing /DVERSION=<whatever> to the nullsoft compiler.
!ifndef VERSION
	!define VERSION 2.1.1.080610
!endif

; For official Open1X builds, the IDE supplicant checker is included.
; Comment out "!define THIRDPARTYADDITIONS" to turn this off.
; if you need to create an installer for your own purposes.
; 
!define THIRDPARTYADDITIONS

; This script packages up the .pdb debug files for easier
; debugability of the supplicant in the event of crashes.
; Comment out "!define DEBUGFILES" to turn this off.
;
;!define DEBUGFILES


;------------------------
; Target Directory for Start Menu

!define TARGET "XSupplicant"

;------------------------
; General

Name "XSupplicant"

OutFile "xsupinst-v${VERSION}.exe"

InstallDir "$PROGRAMFILES\XSupplicant"

;-----------------------
; Interface Settings
   !define MUI_HEADERIMAGE
   !define MUI_HEADERIMAGE_BITMAP "opensea-header.bmp"
   !define MUI_ICON "opensea.ico"
   !define MUI_UNICON "opensea-bw.ico"
   !define MUI_ABORTWARNING

;-------------------------
;  This file is called to allow people to put their own extra bits in the
;   installer package without changing the base installation.
;
; There are two functions that will get called out of this file.  (For Install
; and two for uninstall.)
;
; 1. ExtrasPreInstall --  This function will be called after the installer verifies
;                   it is running with admin rights, but before anything
;                   else is done.
;
;    un.ExtrasPreInstall -- Same as above, but is called during uninstall.
;
; 2. ExtrasPostInstall -- This function will be called right before the installer
;                   enables the services and the tray app.
;
;    un.ExtrasPostInstall -- Same as above, but is called during uninstall.

Function ExtrasPreInstall
!ifdef THIRDPARTYADDITIONS
	; Called from thirdparty.nsi
 	Call ThirdPartyPreInstall
!endif ;THIRDPARTYDDITIONS

!ifdef DEBUGFILES
	; Called from open1xdebug.nsi
	Call DebugFilesInstall
!endif ;DEBUGFILES
FunctionEnd

Function un.ExtrasPreInstall

!ifdef THIRDPARTYADDITIONS
	; Called from thirdparty.nsi
	Call un.ThirdPartyPreInstall
!endif ;THIRDPARTYADDITIONS

!ifdef DEBUGFILES
	; Called from open1xdebug.nsi
	Call un.DebugFilesInstall
!endif ;DEBUGFILES
FunctionEnd

Function ExtrasPostInstall
	
FunctionEnd

Function un.ExtrasPostInstall
	
FunctionEnd


; -------- Start 3rd Party Functions --------
; Third party tweaks go here.


!ifdef THIRDPARTYADDITIONS

!define THIRDPARTY ..\..\..\..\thirdparty

; Do pre-installation stuff here
Function ThirdPartyPreInstall
	Call InstallSupplicantChecker
FunctionEnd ;ThirdPartyPreInstall

; Do post-installation stuff here.
Function un.ThirdPartyPreInstall
	Call un.InstallSupplicantChecker
FunctionEnd ;ThirdPartyPostInstall

Function InstallSupplicantChecker
        File "${THIRDPARTY}\checksuppsapp.exe"

        DetailPrint "Checking for other supplicants..."
        nsExec::Exec '"$INSTDIR\checksuppsapp.exe" -Q'  ; If there are no other supplicants, be quiet about it. ;)
	Pop $0
        DetailPrint "  Checksuppsapp return value : $0"

        IntCmp $0 4 done
        IntCmp $0 1 abort
        IntCmp $0 2 abort
        IntCmp $0 3 reboot_needed
        IntCmp $0 5 done         ; No others were found, so move along.

 abort:
	MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 \
  		"Other supplicants or wireless managers were discovered, but not disabled or removed. $\nThis could cause \
  		XSupplicant to be unable to work properly.  (In some cases, it can cause drivers to blue screen.) $\n \
		Would you like to continue anyway?" \
	IDYES done

        DetailPrint "One or more problems prevented us from installing.  Please correct the problems and try again."
        Abort  ; We can't continue.

 reboot_needed:
        ; Set a flag so that we know not to start the UI and service at the end
        ; as well as asking the user to reboot at the end.
	SetRebootFlag true

 done:

FunctionEnd  ;InstallSupplicantChecker

Function un.InstallSupplicantChecker
	Delete $INSTDIR\checksuppsapp.exe

        Delete "$SMPROGRAMS\XSupplicant\Check for other supplicants.lnk"
FunctionEnd ;un.InstallSupplicantChecker
!endif ;THIRDPARTY
; -------- End 3rd Party Functions --------

; -------- Start Debug Functions --------
!ifdef DEBUGFILES 
Function DebugFilesInstall
	DetailPrint "Installing Open1X Debug Files..."

        SetOutPath $INSTDIR    

	; Install the main executable PDB files.
        File "${SRCDIR}\xsupplicant\vs2005\build-release\XSupplicant_service.pdb"
        File "${SRCDIR}\xsupplicant-ui\build-release\XSupplicantUI.pdb"
        File "${VENDORDIR}\ProtInstall\build-release\ProtInstall.pdb"

	; Install the engine plugin PDB files.
	SetOutPath "$INSTDIR\Modules"
	File "${SRCDIR}\xsupplicant\plugins\vs2005\release\BirdDog.pdb"

FunctionEnd ;DebugFilesInstall

Function un.DebugFilesInstall
	DetailPrint "Removing Open1X Debug Files..."

	; Delete the main executable PDB files.
	Delete $INSTDIR\XSupplicant_service.pdb
	Delete $INSTDIR\XSupplicantUI.pdb
        Delete $INSTDIR\ProtInstall.pdb

	; Delete the engine plugin PDB files.
	Delete $INSTDIR\Modules\BirdDog.pdb

FunctionEnd ;un.DebugFilesInstall
!endif ;DEBUGFILES
; -------- End Debug Functions --------