;------------------------
; XSupplicant version # used in this installer
   !include version.nsi
   !include thirdparty.nsi

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
; 2. ExtrasPostInstall -- This function will be called right before the installer
;                   enables the services and the tray app.

Function ExtrasPreInstall
 	Call ThirdPartyPreInstall
FunctionEnd



Function ExtrasPostInstall
	
FunctionEnd




;--------------------------
; These are the calls for the installer.

Function un.ExtrasPreInstall
	Call un.ThirdPartyPreInstall
FunctionEnd

Function un.ExtrasPostInstall

FunctionEnd
