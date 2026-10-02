@echo off
setlocal
chcp 65001 > nul
title Build SysCare Standalone Executable

echo ============================================================
echo   Building SysCare Portable Standalone .exe
echo ============================================================
echo.

:: Check for PyInstaller
python -m PyInstaller --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [SysCare] PyInstaller not detected. Installing PyInstaller...
    python -m pip install pyinstaller
)

echo [SysCare] Compiling SysCare.exe via PyInstaller...
python -m PyInstaller --name "SysCare" --onefile --console --clean main.py

if %ERRORLEVEL% EQU 0 (
    copy /y "dist\SysCare.exe" ".\SysCare.exe" > nul
    echo.
    echo ============================================================
    echo   [SUCCESS] Standalone portable executable created!
    echo   File: %~dp0SysCare.exe
    echo ============================================================
) else (
    echo.
    echo [ERROR] Build failed. Please check the logs above.
)

echo.
pause
endlocal
