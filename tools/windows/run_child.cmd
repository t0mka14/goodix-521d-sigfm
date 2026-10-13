@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0unseal_psk.ps1" -Child -Tag %1 > "%~dp0child_%1.log" 2>&1
