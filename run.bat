@echo off
REM RAKSHAK-AI is NOT supported on native Windows in this version.
REM The plugin runner uses Linux process controls (process groups, resource limits, user switching)
REM and the firewall enforcers use iptables / nftables. None of this has been tested on Windows.
echo.
echo   RAKSHAK-AI runs on Linux (tested on Ubuntu 24.04).
echo   On a Windows computer, use WSL2 (Ubuntu) or a Linux virtual machine, then run:  ./run.sh
echo.
pause
