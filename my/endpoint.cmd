@echo off

SETLOCAL ENABLEEXTENSIONS
SET me=%~n0
SET parent=%~dp0

SET testing=true

SET exe_path=%1
SET time=%2

>nttrace_log.txt (start "" /B "C:\Endpoint\NtTrace\NtTrace.exe" "-pid" "-nl" "-time" %exe_path%)
PING -n %time% 127.0.0.1>nul
taskkill /im %exe_path% /F
