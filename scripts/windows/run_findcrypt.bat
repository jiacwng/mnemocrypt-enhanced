@echo off
REM Run Findcrypt in batch on all tool IDA databases (requires findcrypt3.py in IDA plugins).
cd /d "%~dp0..\.."
"C:\Program Files\Git\bin\bash.exe" ./tool/plugin_batch.sh findcrypt
pause
