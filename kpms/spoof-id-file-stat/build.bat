@echo off
setlocal EnableDelayedExpansion

REM Check ADB availability and device connection first
set ADB_OK=0
where adb >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    adb devices | find "device" >nul
    if !ERRORLEVEL! EQU 0 (
        echo ADB available and device found
        set ADB_OK=1
    ) else (
        echo No device found, will skip ADB push
    )
) else (
    echo ADB not found, will skip ADB push
)

REM Create backup directory if it doesn't exist
if not exist "backup" mkdir backup

REM Backup existing KPM if it exists
if exist "spoofSTAT.kpm" (
    echo Backing up existing spoofSTAT.kpm...
    for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (
        for /f "tokens=1-2 delims=: " %%x in ('time /t') do (
            copy "spoofSTAT.kpm" "backup\spoofSTAT_%%c-%%a-%%b_%%x%%y.kpm" >nul
        )
    )
    del "spoofSTAT.kpm"
    echo Backup created and old file removed
)

REM Set compiler and build
set TARGET_COMPILE=aarch64-none-elf-
echo Building with: %TARGET_COMPILE%gcc

REM Clean old object files to force full recompilation
echo Cleaning old object files...
del /Q *.o 2>nul
del /Q *.kpm 2>nul

make
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

REM If build succeeded and ADB is OK, handle device operations
if !ADB_OK! EQU 1 (
    if exist "spoofSTAT.kpm" (
        echo Checking for existing KPM on device...
        adb shell "if [ -f /sdcard/spoofSTAT.kpm ]; then rm /sdcard/spoofSTAT.kpm && echo Removed old KPM from device; fi"
        
        echo Creating directory and pushing new KPM...
        adb shell mkdir -p /sdcard/
        adb push spoofSTAT.kpm /sdcard/
        
        if !ERRORLEVEL! EQU 0 (
            echo Successfully pushed new KPM to device
        ) else (
            echo Failed to push KPM to device
        )
    ) else (
        echo Build succeeded but KPM file not found
    )
)

endlocal