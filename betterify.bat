@echo off
title Windows Betterify by Windows Better Team
echo Check for admin...
openfiles > NUL 2>&1
if %errorlevel%==0 (
        echo Admin found. Thank you for using Windows Betterify.
        echo Version 11.2205-01a
        echo Warning: This action is irreversable!
        echo If you do not want this, press the red x NOW. Otherwise...
        pause
        echo ARE YOU SURE?
        echo I forgot to also warn you this software is in prepetual Alpha!
        echo This means this software is in alpha forever.
        echo Also, speaking of which, we are not responsible for any bad things that might happen.
        echo This includes, but is not limited to, data loss, as well as any destruction, physical, mental, software, or any other damage is not our fault!
        echo TLDR, this script comes without any warranty. 
        echo Remember, press the RED X to close this Window, otherwise...
        pause
) else (
        echo Please run as admin.
        pause
        exit
)

cls

PowerShell -command "Set-ExecutionPolicy Bypass –Scope LocalMachine"
curl "https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/betterify.ps1" -O betterify.ps1
PowerShell -command "./betterify.ps1"
PowerShell -command "Set-ExecutionPolicy Restricted –Scope LocalMachine"

echo Done! Enjoy the rest of your day.
pause
