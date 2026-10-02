@echo off
setlocal
chcp 65001 > nul
title SysCare - Personal Windows Care

:: Check for Administrator privileges
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [SysCare] Administrator privileges required. Requesting elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)

:: Launch interactive menu with Administrator privileges
python "%~dp0main.py" %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo An error occurred while running SysCare.
    pause
)
endlocal
