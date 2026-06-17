@echo off
REM Retrain Mnemocrypt (random forest) from training/computed_features/ CSVs.
cd /d "%~dp0..\.."
set LOKY_MAX_CPU_COUNT=8
python training/train_mnemocrypt.py
pause
