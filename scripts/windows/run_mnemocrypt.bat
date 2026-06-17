@echo off
REM Run Mnemocrypt in batch and write tool/mnemocrypt_predictions.csv.
cd /d "%~dp0..\.."
"C:\Program Files\Git\bin\bash.exe" ./tool/plugin_batch.sh mnemocrypt
pause
