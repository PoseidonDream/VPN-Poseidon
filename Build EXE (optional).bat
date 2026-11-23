@echo off
rem Optional: turns FreeVPN.pyw into a single FreeVPN.exe you can pin to the
rem taskbar or copy to another PC. You need Python installed to build it.
cd /d "%~dp0"

echo Installing the PyInstaller build tool...
py -3 -m pip install --upgrade pyinstaller
if errorlevel 1 goto failed

echo Building FreeVPN.exe...
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name FreeVPN FreeVPN.pyw
if errorlevel 1 goto failed

echo.
echo Done! Your app is here: %~dp0dist\FreeVPN.exe
echo (OpenVPN still needs to be installed on any PC you run it on.)
echo.
explorer "%~dp0dist"
pause
exit /b 0

:failed
echo.
echo The build failed. Scroll up to see why.
pause
exit /b 1
