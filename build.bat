@echo off
rem Builds dist\DeadlockRegionChanger.exe, which needs no Python installed.
cd /d "%~dp0"
py -m pip install --upgrade pyinstaller || exit /b 1
py -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
    --icon icon.ico --add-data "icon.ico;." ^
    --name DeadlockRegionChanger deadlock_region_changer.py
