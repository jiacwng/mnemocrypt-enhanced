@echo off
REM Compute feature CSVs from training/ida_databases/ via Git Bash.
cd /d "%~dp0..\.."
"C:\Program Files\Git\bin\bash.exe" ./common/building_wrapper.sh features training
pause
