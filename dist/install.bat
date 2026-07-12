@echo off
setlocal enabledelayedexpansion
title FreeDPI Installer

echo ============================================
echo         FreeDPI ? DPI Bypass Service
echo ============================================
echo.

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This installer requires Administrator rights.
    echo     Please right-click and select "Run as Administrator".
    pause
    exit /b 1
)

set "INSTDIR=%ProgramFiles%\FreeDPI"

echo [*] Installing to %INSTDIR%...
if not exist "%INSTDIR%" mkdir "%INSTDIR%"
if not exist "%INSTDIR%\WinDivert" mkdir "%INSTDIR%\WinDivert"
if not exist "%INSTDIR%\data" mkdir "%INSTDIR%\data"

:: Copy files
echo [*] Copying service binary...
copy /Y "%~dp0freedpi-service.exe" "%INSTDIR%\" >nul

echo [*] Copying UI binary...
copy /Y "%~dp0freedpi-ui.exe" "%INSTDIR%\" >nul

echo [*] Copying WinDivert driver...
copy /Y "%~dp0WinDivert64.sys" "%INSTDIR%\WinDivert\" >nul

echo [*] Copying config...
if not exist "%INSTDIR%\config.toml" (
    copy /Y "%~dp0config.toml.example" "%INSTDIR%\config.toml" >nul
) else (
    echo [.] Config already exists, preserving...
)

:: Firewall rules
echo [*] Adding firewall rules...
netsh advfirewall firewall add rule name="FreeDPI Service" dir=in action=allow program="%INSTDIR%\freedpi-service.exe" enable=yes >nul 2>&1

:: Shortcuts
echo [*] Creating shortcuts...
if not exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\FreeDPI" mkdir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\FreeDPI"
if not exist "%USERPROFILE%\Desktop\FreeDPI.lnk" (
    :: Create desktop shortcut via PowerShell
    powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%USERPROFILE%\Desktop\FreeDPI.lnk'); $SC.TargetPath = '%INSTDIR%\freedpi-ui.exe'; $SC.WorkingDirectory = '%INSTDIR%'; $SC.Save()" >nul 2>&1
)
:: Start Menu shortcut
powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\FreeDPI\FreeDPI.lnk'); $SC.TargetPath = '%INSTDIR%\freedpi-ui.exe'; $SC.WorkingDirectory = '%INSTDIR%'; $SC.Save()" >nul 2>&1

:: Register service
echo [*] Registering Windows service...
"%INSTDIR%\freedpi-service.exe" --install >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Service registered successfully.
    echo [*] Starting service...
    net start FreeDPI >nul 2>&1
    if !errorlevel! equ 0 (
        echo [+] Service started.
    ) else (
        echo [!] Could not start service. Start manually: net start FreeDPI
    )
) else (
    echo [!] Service registration failed. Run as Administrator.
)

echo.
echo ============================================
echo  Installation complete!
echo ============================================
echo  Service:   %INSTDIR%\freedpi-service.exe
echo  UI:        %INSTDIR%\freedpi-ui.exe
echo  Config:    %INSTDIR%\config.toml
echo  API:       http://127.0.0.1:11337
echo.
pause
