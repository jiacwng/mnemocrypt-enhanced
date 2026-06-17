@echo off
REM Create IDA databases from evaluation binaries (tool dataset) via Git Bash.
cd /d "%~dp0..\.."
echo Running IDA database creation...
"C:\Program Files\Git\bin\bash.exe" ./common/building_wrapper.sh databases
pause
