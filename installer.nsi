; ByeByeDPI NSIS Installer
; Requires: NSIS 3.x with MUI2

!include "MUI2.nsh"

; ─── General ───────────────────────────────────────────────────────────────
Name "ByeByeDPI"
OutFile "ByeByeDPI-Setup.exe"
InstallDir "$PROGRAMFILES\ByeByeDPI"
InstallDirRegKey HKLM "Software\ByeByeDPI" "InstallDir"
RequestExecutionLevel admin
Unicode True

; ─── Version Info ──────────────────────────────────────────────────────────
VIProductVersion "0.1.0.0"
VIAddVersionKey "ProductName" "ByeByeDPI"
VIAddVersionKey "FileDescription" "DPI Bypass Service"
VIAddVersionKey "LegalCopyright" "ByeByeDPI Team"
VIAddVersionKey "FileVersion" "0.1.0"

; ─── Interface ─────────────────────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON "data\icon.ico"
!define MUI_UNICON "data\icon.ico"

; ─── Pages ─────────────────────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ─── Languages ─────────────────────────────────────────────────────────────
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

; ─── Sections ──────────────────────────────────────────────────────────────
Section "ByeByeDPI (required)" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"

    ; Install files
    File "target\release\byebyedpi-service.exe"
    File "target\release\byebyedpi-ui.exe"

    ; Install WinDivert
    SetOutPath "$INSTDIR\WinDivert"
    File "vendor\WinDivert\WinDivert.dll"
    File "vendor\WinDivert\WinDivert.lib"
    File "vendor\WinDivert\WinDivert64.sys"

    ; Install config
    SetOutPath "$INSTDIR"
    File /oname=config.toml "config.toml.example"

    ; Create data directory
    CreateDirectory "$INSTDIR\data"

    ; Store install path
    WriteRegStr HKLM "Software\ByeByeDPI" "InstallDir" "$INSTDIR"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Add to Programs menu
    CreateDirectory "$SMPROGRAMS\ByeByeDPI"
    CreateShortCut "$SMPROGRAMS\ByeByeDPI\ByeByeDPI UI.lnk" "$INSTDIR\byebyedpi-ui.exe"
    CreateShortCut "$SMPROGRAMS\ByeByeDPI\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; Add to Windows Firewall
    ExecWait 'netsh advfirewall firewall add rule name="ByeByeDPI Service" dir=in action=allow program="$INSTDIR\byebyedpi-service.exe" enable=yes'
    ExecWait 'netsh advfirewall firewall add rule name="ByeByeDPI API" dir=in action=allow program="$INSTDIR\byebyedpi-service.exe" enable=yes localport=11337 protocol=tcp'

SectionEnd

Section "Install Service" SecService
    ; Install as Windows Service
    ExecWait '"$INSTDIR\byebyedpi-service.exe" --install'
SectionEnd

Section "Create Firewall Rules" SecFirewall
    ExecWait 'netsh advfirewall firewall add rule name="ByeByeDPI WinDivert" dir=in action=allow program="$INSTDIR\WinDivert\WinDivert.dll" enable=yes'
SectionEnd

; ─── Descriptions ──────────────────────────────────────────────────────────
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Core files: service, UI, WinDivert"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Install ByeByeDPI as Windows Service"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecFirewall} "Add Windows Firewall rules for WinDivert"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ─── Uninstaller ───────────────────────────────────────────────────────────
Section "Uninstall"
    ; Stop service if running
    ExecWait 'net stop ByeByeDPI'

    ; Remove firewall rules
    ExecWait 'netsh advfirewall firewall delete rule name="ByeByeDPI Service"'
    ExecWait 'netsh advfirewall firewall delete rule name="ByeByeDPI API"'
    ExecWait 'netsh advfirewall firewall delete rule name="ByeByeDPI WinDivert"'

    ; Remove files
    Delete "$INSTDIR\byebyedpi-service.exe"
    Delete "$INSTDIR\byebyedpi-ui.exe"
    Delete "$INSTDIR\config.toml"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR\WinDivert"
    RMDir /r "$INSTDIR\data"
    RMDir "$INSTDIR"

    ; Remove shortcuts
    RMDir /r "$SMPROGRAMS\ByeByeDPI"

    ; Remove registry
    DeleteRegKey HKLM "Software\ByeByeDPI"
SectionEnd
