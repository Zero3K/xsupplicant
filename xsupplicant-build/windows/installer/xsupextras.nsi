; This variable can be overridden by passing /DVERSION=<whatever> to the nullsoft compiler.
!ifndef VERSION
	!define VERSION 2.1.1.080419
!endif

; Third party tweaks go here.
; For official Open1X builds, the IDE supplicant checker is included.
; Comment out "!define THIRDPARTYADDITIONS" to turn this off.
; if you need to create an installer for your own purposes.
; 
!define THIRDPARTYADDITIONS
!ifdef THIRDPARTYADDITIONS
	!include thirdparty.nsi
!endif

; This script packages up the .pdb debug files for easier
; debugability of the supplicant in the event of crashes.
; Comment out "!define DEBUGFILES" to turn this off.
!define DEBUGFILES
!ifdef DEBUGFILES
!include open1xdebug.nsi
!endif ;DEBUGFILES

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
