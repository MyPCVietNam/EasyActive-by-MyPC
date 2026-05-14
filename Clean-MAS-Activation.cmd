@echo off
setlocal EnableExtensions

set "TOOL_NAME=DeActive by MyPC"
set "TOOL_VERSION=1.2.0"

title %TOOL_NAME%

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%Clean-MAS-Activation.ps1"
set "POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" (
    set "POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
)

if not exist "%POWERSHELL%" (
    echo.
    echo ERROR: Windows PowerShell was not found:
    echo        %POWERSHELL%
    echo.
    pause
    exit /b 2
)

if not exist "%PS1%" (
    echo.
    echo ERROR: Cannot find PowerShell script:
    echo        %PS1%
    echo.
    pause
    exit /b 2
)

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo.
    echo Administrator rights are required.
    echo Requesting UAC elevation...
    echo.
    "%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%ComSpec%' -ArgumentList '/d /c ""%~f0"" %*' -Verb RunAs"
    if not "%errorlevel%"=="0" (
        echo.
        echo UAC elevation was cancelled or failed.
        pause
        exit /b 1
    )
    exit /b 0
)

if not "%~1"=="" (
    call :RunPowerShell %*
    goto :Done
)

:Menu
cls
echo ================================================================
echo %TOOL_NAME% %TOOL_VERSION%
echo ================================================================
echo.
echo PowerShell script:
echo %PS1%
echo.
echo Choose an option:
echo.
echo   1. Dry-run only ^(simulate cleanup, no changes^)
echo   2. Clean Office and Windows activation keys/configuration
echo   3. Clean Office activation keys/configuration only
echo   4. Clean Windows activation keys/configuration only
echo.
echo Close this window to exit.
echo.
set /p "CHOICE=Enter choice [1-4]: "

if "%CHOICE%"=="1" (
    call :RunPowerShell -DryRun -CreateRestorePoint -VerboseLog -ExportReport
    goto :Done
)
if "%CHOICE%"=="2" (
    call :ConfirmOfficeAppsClosed
    if errorlevel 1 goto :Menu
    call :ConfirmWindowsKeyRemoval
    if errorlevel 1 goto :Menu
    call :RunPowerShell -CreateRestorePoint -ForceWindowsProductKeyRemoval -VerboseLog -ExportReport
    goto :Done
)
if "%CHOICE%"=="3" (
    call :ConfirmOfficeAppsClosed
    if errorlevel 1 goto :Menu
    call :RunPowerShell -CreateRestorePoint -SkipWindows -VerboseLog -ExportReport
    goto :Done
)
if "%CHOICE%"=="4" (
    call :ConfirmWindowsKeyRemoval
    if errorlevel 1 goto :Menu
    call :RunPowerShell -CreateRestorePoint -SkipOffice -ForceWindowsProductKeyRemoval -VerboseLog -ExportReport
    goto :Done
)

echo.
echo Invalid choice.
pause
goto :Menu

:ConfirmOfficeAppsClosed
echo.
echo WARNING: Close all Microsoft Office apps before continuing.
echo Close Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher, Project,
echo Visio, and any Office setup/repair or open Office document windows.
echo.
set /p "CONFIRM_CLOSE_OFFICE=Have you closed all Office apps? Type Y to continue: "
if /I "%CONFIRM_CLOSE_OFFICE%"=="Y" exit /b 0
echo.
echo Cancelled by user.
pause
exit /b 1

:ConfirmWindowsKeyRemoval
echo.
echo WARNING: This option will remove the installed Windows product key from the local licensing store.
echo It does not remove a valid digital license, but Windows may show as needing activation until
echo you sign in, enter a valid key, or the digital license is refreshed.
echo.
set /p "CONFIRM_REMOVE_WINKEY=Continue with Windows product key cleanup? Type Y to continue: "
if /I "%CONFIRM_REMOVE_WINKEY%"=="Y" exit /b 0
echo.
echo Cancelled by user.
pause
exit /b 1

:RunPowerShell
echo.
echo Running:
echo "%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
echo.
"%POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "SCRIPT_EXIT=%errorlevel%"
echo.
echo PowerShell script exit code: %SCRIPT_EXIT%
exit /b %SCRIPT_EXIT%

:Done
set "FINAL_EXIT=%errorlevel%"
echo.
echo Done. This window will stay open so you can read the result.
echo.
echo Exit code meaning:
echo   0 = success
echo   1 = not admin
echo   2 = fatal error
echo   3 = completed with warnings
echo.
echo Logs and reports are under:
echo   C:\ProgramData\LegitActivationCleaner
echo.
pause
exit /b %FINAL_EXIT%
