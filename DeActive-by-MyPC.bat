@echo off
setlocal EnableExtensions

set "CMD_LAUNCHER=%~dp0Clean-MAS-Activation.cmd"

if not exist "%CMD_LAUNCHER%" (
    echo ERROR: Cannot find launcher:
    echo %CMD_LAUNCHER%
    pause
    exit /b 2
)

call "%CMD_LAUNCHER%" %*
exit /b %errorlevel%
