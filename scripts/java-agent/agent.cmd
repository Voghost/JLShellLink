@echo off
setlocal
chcp 65001 >nul
"%~dp0runtime\bin\java.exe" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -jar "%~dp0link-agent.jar" %*
if errorlevel 1 pause
endlocal
