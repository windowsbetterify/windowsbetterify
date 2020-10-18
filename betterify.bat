:: Bringing back F8 menu
echo Bringing back the F8 menu...
bcdedit /set {default} bootmenupolicy legacy

:: Disable Cortana
echo Disabling Cortana and Search
taskkill /F /IM SearchUI.exe
rename "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak" > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1

:: Disabling Oklomsy Brrr mark
echo Disabling Windows Watermark
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d 0 /f > NUL 2>&1
sc config sppsvc start=disabled

::Add UTC Time
echo Change to UTC time
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f > NUL 2>&1

:: Disable crap services and SMBv1
echo Disable crap services and SMBv1, therefore lowering chance people on this PC would get an EternalBlue virus.
sc config diagtrack start=disabled
sc config RetailDemo start=disabled
PowerShell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
sc config lanmanworkstation depend=bowser/mrxsmb20/nsi
sc config mrxsmb10 start=disabled

:: Disable + Delete Tasks
echo Disabling tasks and Windows Updates...
schtasks /delete /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f > NUL 2>&1
net stop wuauserv
sc config wuauserv start=disabled

:: Installing alternative apps
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin
@powershell -NoProfile -ExecutionPolicy Bypass -Command "choco install -y --force --allow-empty-checksums vlc 7zip open-shell jpegview vcredist-all directx firefox obs onlyoffice"

:: Disable Telemetry
echo Disabling Telemetry...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1

:: RegEdits
echo Applying Registry Edits
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f > NUL 2>&1
echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1

:: Editing HOSTS
echo Editing HOSTS
echo. > %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0001.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0002.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0003.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0004.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0005.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0006.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0007.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0008.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0009.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.mopub.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.msn.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.msn.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.msn.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	telemetry.microsoft.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	akamaiedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	feedback.windows.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	feedback.search.microsoft.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	feedback.microsoft-hohm.com >> %WINDIR%\System32\drivers\etc\hosts

:: Deleting all apps except store
echo Deleting all apps except store
PowerShell -Command "Get-AppxPackage -AllUsers | where-object {$_.name –notlike '*store*'} | Remove-AppxPackage"
