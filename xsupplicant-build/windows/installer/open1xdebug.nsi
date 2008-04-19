;
; This script packages up the Visual Studio PDB files for a given release.
;

; This file is included by xsupextras.nsi

; 
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
