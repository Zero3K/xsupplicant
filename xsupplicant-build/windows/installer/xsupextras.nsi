; This variable can be overridden by passing /DVERSION=<whatever> to the nullsoft compiler.
!ifndef VERSION
	!define VERSION 2.1.1.080610
!endif

; This variable defines the license file to be presented when the installer is launched
; This variable can be overridden by passing /DSOFTWARE_LICENSE_FILE=<whatever> to the nullsoft compiler.
; Defaults to "win-LICENSE"
!ifndef SOFTWARE_LICENSE_FILE 
     !define SOFTWARE_LICENSE_FILE "win-LICENSE"
!endif ;SOFTWARE_LICENSE_FILE

; This variable can be overridden by passing /DINSTALLER_NAME_PREFIX=<whatever> to the nullsoft compiler.
!ifndef INSTALLER_NAME_PREFIX
	!define INSTALLER_NAME_PREFIX xsupplicant-setup-v
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
; i.e. "XSupplicant"  (C:\Program Files\XSupplicant)
!define TARGET "XSupplicant"

; This defines a third-party root directory for installing
; skinned files over the top (or in addition) to the normal
; OpenSEA provided skin files.
;!ifndef THIRDPARTYSKINROOT
;	!define THIRDPARTYSKINROOT <path to your skin root>
;!endif ;THIRDPARTYSKINROOT

; This is a relative path from the skin root where
; the skin files can be located, keeping in mind that
; any skin files that need to replace existing
; files in the OpenSEA builds need to be set up in the
; same file structure
;
; Example:  
; ${THIRDPARTYSKINROOT}\${THIRDPARTYSKINDIR}\<whatever>.ui
; ${THIRDPARTYSKINROOT}\${THIRDPARTYSKINDIR}\icons\<whatever>
; ${THIRDPARTYSKINROOT}\${THIRDPARTYSKINDIR}\images\<whatever>
;
;!ifndef THIRDPARTYSKINDIR
;	!define THIRDPARTYSKINDIR .
;!endif ;THIRDPARTYSKINDIR

; The documentation directory for any third party-overrides or 
; new documentation that you wish to add.
;!ifndef THIRDPARTYDOCDIR
;	!define THIRDPARTYDOCDIR ${SRCDIR}\${THIRDPARTYSKINROOT}\${THIRDPARTYSKINDIR}\Doc
;!endif ;THIRDPARTYDOCDIR

;------------------------
; General
; i.e. "XSupplicant"
Name "XSupplicant"

OutFile "${INSTALLER_NAME_PREFIX}${VERSION}.exe"

InstallDir "$PROGRAMFILES\${TARGET}"

; The installer bitmap/icons.
; For instance:
; !define OPEN1X_MUI_HEADERIMAGE_BITMAP "opensea-header.bmp"
; !define OPEN1X_MUI_ICON "opensea.ico"
; !define OPEN1X_MUI_UNICON "opensea-bw.ico"
; Either replace the respective images/icons with your own or
; change these values to reflect the location of your images.
; These files are loaded relative to the xsupextras.nsi file.
!define OPEN1X_MUI_HEADERIMAGE_BITMAP "opensea-header.bmp"
!define OPEN1X_MUI_ICON "opensea.ico"
!define OPEN1X_MUI_UNICON "opensea-bw.ico"

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
;    un.ExtrasPreInstall -- Same as above, but is called during uninstall before the supplicant termintates.
;
; 2. ExtrasPostInstall -- This function will be called right before the installer
;                   enables the services and the tray app.
;
;    un.ExtrasPostInstall -- Same as above, but is called during uninstall after the supplicant termintates.

Function ExtrasPreInstall

     ; Install the OpenSEA Plugins
     ; Current Plugins: BirdDog
     Call InstallOpenSEAPlugins

     ; Install any 3rd party additions if THIRDPARTYADDITIONS is defined.
     !ifdef THIRDPARTYADDITIONS
     	Call ThirdPartyPreInstall
     !endif ;THIRDPARTYDDITIONS

     ; Install the PDB files with the build if DEBUGFILES is defined.
     !ifdef DEBUGFILES
     	Call DebugFilesInstall
     !endif ;DEBUGFILES

FunctionEnd

; NB: Use un.ExtrasPostInstall if you need to remove something
; after XSupplicant has shutdown.
Function un.ExtrasPreInstall

     ; Remove any 3rd party additions if necessary
     !ifdef THIRDPARTYADDITIONS
     	Call un.ThirdPartyPreInstall
     !endif ;THIRDPARTYADDITIONS

     ; Remove any PDB files if necessary
     !ifdef DEBUGFILES
     	Call un.DebugFilesInstall
     !endif ;DEBUGFILES

FunctionEnd ;un.ExtrasPreInstall

Function ExtrasPostInstall

     ; Install any 3rd party additions if THIRDPARTYADDITIONS is defined.
     !ifdef THIRDPARTYADDITIONS
     	Call ThirdPartyPostInstall
     !endif ;THIRDPARTYADDITIONS

FunctionEnd ;ExtrasPostInstall

Function un.ExtrasPostInstall 

     ; Remove any 3rd party additions if necessary
     !ifdef THIRDPARTYADDITIONS
     	Call un.ThirdPartyPostInstall
     !endif ;THIRDPARTYADDITIONS

     ; Remove the OpenSEA Plugins
     Call un.InstallOpenSEAPlugins

FunctionEnd ;un.ExtrasPostInstall

; -------- Start 3rd Party Functions --------
; Third party tweaks go here.

;---------------------------------------
; Install OpenSEA/Open1X Plugins
; 
; NB: Just installing the plugins isn't enough.
; There isn't currently a plugin loader in 
; XSupplicant, so some code changes will be needed
; to make your code be loaded into the engine/UI.
Function InstallOpenSEAPlugins

     DetailPrint "Installing OpenSEA Plugins..."

     SetOutPath $INSTDIR\Modules

     File "${SRCDIR}\xsupplicant\plugins\vs2005\release\BirdDog.dll"

     DetailPrint "Adding BirdDog to the configuration file..."
     nsExec::Exec '$INSTDIR\xsupplicant_plugin_installer -n "BirdDog" -p "BirdDog.dll" -d "BirdDog monitors all log data and writes it to a log file when a trouble ticket is created."'

FunctionEnd ;InstallOpenSEAPlugins

;---------------------------------------
; Remove OpenSEA/Open1X Plugins
;
Function un.InstallOpenSEAPlugins 
     Delete "$INSTDIR\Modules\BirdDog.dll"

     RMDir "$INSTDIR\Modules"
FunctionEnd ;un.InstallOpenSEAPlugins

!ifdef THIRDPARTYADDITIONS

!define THIRDPARTY ..\..\..\..\thirdparty

; Do pre-installation stuff here
Function ThirdPartyPreInstall
	Call InstallSupplicantChecker
FunctionEnd ;ThirdPartyPreInstall

; Do pre-uninstallation stuff here.
Function un.ThirdPartyPreInstall
	Call un.InstallSupplicantChecker
FunctionEnd ;ThirdPartyPostInstall

; Do post-installation stuff here
Function ThirdPartyPostInstall
	Call ThirdPartySkinInstall
FunctionEnd ;ThirdPartyPostInstall

; Do post-uninstallation stuff here.
Function un.ThirdPartyPostInstall
	; Call this last, in case any plugins/etc are using any skin files.
	Call un.ThirdPartySkinInstall
FunctionEnd ;un.ThirdPartyPostInstall

Function InstallSupplicantChecker
	SetOutPath "$INSTDIR"

        File "${THIRDPARTY}\checksuppsapp.exe"

	SetShellVarContext All
	CreateDirectory "$SMPROGRAMS\${TARGET}"
	CreateShortCut "$SMPROGRAMS\${TARGET}\Check for other supplicants.lnk" $INSTDIR\checksuppsapp.exe

        DetailPrint "Checking for other supplicants..."
        nsExec::Exec '"$INSTDIR\checksuppsapp.exe" -Q -L'  ; If there are no other supplicants, be quiet about it. ;)
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

	SetShellVarContext All
        Delete "$SMPROGRAMS\${TARGET}\Check for other supplicants.lnk"
FunctionEnd ;un.InstallSupplicantChecker

;-----------------------------------
; Install any third-party skins/docs
Function ThirdPartySkinInstall
FunctionEnd 

;-------------------------------------
; Uninstall any third-party skins/docs
Function un.ThirdPartySkinInstall
FunctionEnd

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