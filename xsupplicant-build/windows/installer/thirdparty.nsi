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

	Delete "$SMPROGRAMS\Identity Engines\XSupplicant Tray Application.lnk"
 
	RMDir "$SMPROGRAMS\Identity Engines"

	Delete "$SMPROGRAMS\Identity Engines\Check for other supplicants.lnk"	
FunctionEnd ;un.InstallSupplicantChecker
