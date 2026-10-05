@echo off
REM Buduje przenośny WSBPasskey.exe (folder dist\). Uruchom na SWOIM komputerze.
cd /d "%~dp0"
python -m pip install -r requirements.txt || goto :err
python -m PyInstaller --noconfirm --clean --onefile --windowed --name WSBPasskey wsb_passkey.py || goto :err
echo.
echo Gotowe: dist\WSBPasskey.exe  ^(skopiuj na pendrive^)
pause
exit /b 0
:err
echo BLAD budowania.
pause
exit /b 1
