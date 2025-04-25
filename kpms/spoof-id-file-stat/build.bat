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
if exist "syscallhook.kpm" (
    echo Backing up existing syscallhook.kpm...
    for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (
        for /f "tokens=1-2 delims=: " %%x in ('time /t') do (
            copy "syscallhook.kpm" "backup\syscallhook_%%c-%%a-%%b_%%x%%y.kpm" >nul
        )
    )
    del "syscallhook.kpm"
    echo Backup created and old file removed
)

REM Set compiler and build
set TARGET_COMPILE=aarch64-none-elf-
echo Building with: %TARGET_COMPILE%gcc
make
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

REM If build succeeded and ADB is OK, handle device operations
if !ADB_OK! EQU 1 (
    if exist "syscallhook.kpm" (
        echo Checking for existing KPM on device...
        adb shell "if [ -f /sdcard/kk/KPM/syscallhook.kpm ]; then rm /sdcard/kk/KPM/syscallhook.kpm && echo Removed old KPM from device; fi"
        
        echo Creating directory and pushing new KPM...
        adb shell mkdir -p /sdcard/kk/KPM/
        adb push syscallhook.kpm /sdcard/kk/KPM/
        
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