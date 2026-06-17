@echo off
REM Create IDA databases from training binaries via Git Bash.
cd /d "%~dp0..\.."
"C:\Program Files\Git\bin\bash.exe" ./common/building_wrapper.sh databases training
pause
