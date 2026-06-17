@echo off
REM Build IDA databases then compute features for the full training set (two-step pipeline).
cd /d "%~dp0..\.."
echo ========================================
echo Step 1/2: Creating IDA databases (training)
echo ========================================
"C:\Program Files\Git\bin\bash.exe" ./common/building_wrapper.sh databases training
if %ERRORLEVEL% neq 0 (
    echo Step 1 failed. Set IDAT_PATH or edit idat_path in common/building_wrapper.sh
    pause
    exit /b 1
)

echo.
echo ========================================
echo Step 2/2: Computing features (training)
echo ========================================
"C:\Program Files\Git\bin\bash.exe" ./common/building_wrapper.sh features training
if %ERRORLEVEL% neq 0 (
    echo Step 2 failed.
    pause
    exit /b 1
)

echo.
echo Done. Check training/computed_features/ for new CSVs, then run: python training/train_mnemocrypt.py
pause
