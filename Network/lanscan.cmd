@echo off
start "" /D "%~dp0" pythonw.exe "%~dp0lan_scanner_gui.py" %*
exit /b