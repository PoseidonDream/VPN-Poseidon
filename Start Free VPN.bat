@echo off
rem Starts Free VPN. Windows will ask for permission ("Yes") because a VPN
rem has to change how your PC routes internet traffic.
cd /d "%~dp0"

where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3 "%~dp0FreeVPN.pyw"
    exit /b 0
)
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0FreeVPN.pyw"
    exit /b 0
)

echo.
echo  Python is not installed on this PC.
echo.
echo  Free VPN needs Python (free). Your browser will now open the download page.
echo  Download "Python for Windows", run the installer, then start Free VPN again.
echo.
start "" https://www.python.org/downloads/windows/
pause
