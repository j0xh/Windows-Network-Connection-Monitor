@echo off
echo Building Network Monitor...

:: Check if cl.exe is available
where cl >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: MSVC compiler (cl.exe) not found in PATH.
    echo Please run this script from the "Developer Command Prompt for VS".
    pause
    exit /b 1
)

cl core.cpp /EHsc /link iphlpapi.lib ws2_32.lib /out:NetMonitor.exe
if %ERRORLEVEL% EQU 0 (
    echo Build Successful! Run NetMonitor.exe directly or as Administrator.
) else (
    echo Build Failed.
)
pause
