@echo off
:: Check if the script is being run as administrator
openfiles >nul 2>nul
if errorlevel 1 (
    echo This script needs to be run as Administrator.
    pause
    exit /b
)

cd /d "%~dp0"

:: Ask the user for the interface
set /p interface="Enter network interface (leave blank for 'Wi-Fi'): "

:: If the input is blank, default to "Wi-Fi"
if "%interface%"=="" set interface=Wi-Fi

:: Run main.py with the provided or default interface
start "" python -u .\main.py %interface%

:: Pause to keep the window open after execution
exit
