title Windows Betterify by Windows Better Team
cls

echo Bringing back the F8 menu...
bcdedit /set {default} bootmenupolicy legacy

echo Disabling Cortana and Search
taskkill /F /IM SearchUI.exe
rename 'C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy' 'C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak' > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'SearchboxTaskbarMode' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowCortana' /t REG_DWORD /d 0 /f > NUL 2>&1

echo Disabling Watermark
sc config sppsvc start=disabled
reg add 'HKEY_CURRENT_USER\Control Panel\Desktop' /v 'PaintDesktopVersion' /t REG_DWORD /d 0 /f > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Clip\License Validation' /f > NUL 2>&1

echo Disable crap services and SMBv1, therefore lowering chance people on this PC would get an EternalBlue virus.
sc config diagtrack start=disabled
sc config RetailDemo start=disabled
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
sc config lanmanworkstation depend=bowser/mrxsmb20/nsi
sc config TrkWks start=disabled
sc config WbioSrvc start=disabled
sc config WMPNetworkSvc start=disabled
sc config wscsvc start=disabled
sc config mrxsmb10 start=disabled
sc config MapsBroker start=disabled
sc config RetailDemo start=disabled
sc config DiagTrack start=disabled
sc config RemoteAccess start=disabled
sc config RemoteRegistry start=disabled
sc config lanmanworkstation depend=bowser/mrxsmb20/nsi
sc config mrxsmb10 start=disabled

reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t REG_DWORD /d 0 /f > NUL 2>&1

echo Disabling task...
schtasks /change /TN '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' /DISABLE > NUL 2>&1
schtasks /change /TN '\Microsoft\Windows\Application Experience\ProgramDataUpdater' /DISABLE > NUL 2>&1
schtasks /change /TN '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator' /DISABLE > NUL 2>&1
schtasks /change /TN '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask' /DISABLE > NUL 2>&1
schtasks /change /TN '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' /DISABLE > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Application Experience\ProgramDataUpdater' /f > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Application Experience\StartupAppTask' /f > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Application Experience\ProgramDataUpdater' /f > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Application Experience\StartupAppTask' /f > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' /f > NUL 2>&1
schtasks /delete /TN '\Microsoft\Windows\Maps\MapsToastTask' /f > NUL 2>&1

echo Disabling Telemetry...
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'AllowBuildPreview' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP' -Name 'CEIPEnable' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'AITEnable' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput' -Name 'AllowLinguisticDataCollection' -Type DWord -Value 0
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' | Out-Null

echo Applying Registry Edits
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' /v DontSendAdditionalData /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowCortana /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v HideSCAHealth /t REG_DWORD /d 0x1 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v DisableWebSearch /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell' /v UseActionCenterExperience /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f > NUL 2>&1
echo '' > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener' /v 'Start' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v DisableWebSearch /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' /v value /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' /v value /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v Enabled /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener' /v 'Start' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger' /v 'Start' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' /v DontSendAdditionalData /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v SettingsPageVisibility /t REG_SZ /d 'showonly:defaultapps;display;nightlight;sound;powersleep;batterysaver;batterysaver-usagedetails;batterysaver-settings;multitasking;about;bluetooth;connecteddevices;printers;mousetouchpad;devices-touchpad;typing;pen;autoplay;usb;network-status;network-cellular;network-wifi;network-wificalling;network-wifisettings;network-ethernet;network-dialup;netowrk-vpn;network-airplanemode;network-mobilehotspot;datausage;network-proxy;personalization-background;colors;lockscreen;themes;taskbar;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;dateandtime;notifications;maps;appsforwebsites' /f > NUL 2>&1
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' /f > NUL 2>&1
timeout /t 2 /nobreak
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' /v 'BingSearchEnabled' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences' /v 'VoiceActivationDefaultOn' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences' /v 'VoiceActivationEnableAboveLockscreen' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences' /v 'ModelDownloadAllowed' /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v 'DisableVoice' /t REG_DWORD /d 1 /f > NUL 2>&1

echo Disabling all updates except security updates...
curl 'https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/security-updates-only.reg' -o security-updates-only.reg
regedit /s security-updates-only.reg

echo Better UX by neolectron
curl 'https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/improved-experience-neolectron.reg' -o security-updates-only.re
regedit /s improved-experience-neolectron.reg

echo Editing HOSTS
attrib -R %WINDIR%\System32\drivers\etc\hosts
echo. > %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.msn.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.msn.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.msn.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	telemetry.microsoft.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	akamaiedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0005.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0006.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0007.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	feedback.search.microsoft.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	feedback.microsoft-hohm.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	footprintpredict.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	statsfe2.update.microsoft.com.akadns.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	fe2.update.microsoft.com.akadns.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0001.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0002.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0003.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0004.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	feedback.windows.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	pre.footprintpredict.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0008.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	a-0009.a-msedge.net >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	ads.mopub.com >> %WINDIR%\System32\drivers\etc\hosts
echo 0.0.0.0	sls.update.microsoft.com.akadns.net >> %WINDIR%\System32\drivers\etc\hosts
takeown /f '%WINDIR%\System32\drivers\etc\hosts'
attrib +R %WINDIR%\System32\drivers\etc\hosts

powercfg /h off

echo Deleting all bad apps except store and XBOX
Get-AppxPackage -AllUsers | where-object {$_.name -notlike "*Microsoft.WindowsStore*"} | where-object {$_.name -notlike "*Microsoft.WindowsCalculator*"} | where-object {$_.name -notlike "*Microsoft.Windows.Photos*"}  | where-object {$_.name -notlike "*xbox*"} | Remove-AppxPackage

echo Disabling app suggestions
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353698Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord -Value 0

echo Disable tailored experiences
reg add 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f > NUL 2>&1

echo Disabling SmartScreen etc.
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v SmartScreenEnabled /t REG_SZ /d 'Off' /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' /v ContentEvaluation /t REG_DWORD /d 0 /f > NUL 2>&1
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v 'SecurityHealth' /f > NUL 2>&1
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' /v 'SecurityHealth' /f
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v SaveZoneInformation /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' /v SaveZoneInformation /t REG_DWORD /d 1 /f > NUL 2>&1

echo Setting up explorer
reg delete 'HKEY_CLASSES_ROOT\CABFolder\CLSID' /f > NUL 2>&1
reg delete 'HKEY_CLASSES_ROOT\SystemFileAssociations\.cab\CLSID' /f > NUL 2>&1
reg delete 'HKEY_CLASSES_ROOT\CompressedFolder\CLSID' /f > NUL 2>&1
reg delete 'HKEY_CLASSES_ROOT\SystemFileAssociations\.zip\CLSID' /f > NUL 2>&1
reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'DisallowShaking' /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'NavPaneShowAllFolders' /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v LaunchTo /t REG_DWORD /d 1 /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f > NUL 2>&1
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f > NUL 2>&1

echo 'Running ShutUp10++'
curl 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe' -o OOSU10.exe
curl 'https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/ooshutup10.cfg' -o ooshutup10.cfg
./OOSU10.exe ooshutup10.cfg /quiet

echo Changing TTL for limitless tethering on an unlimited plan...
netsh int ipv4 set glob defaultcurhoplimit=65
netsh int ipv6 set glob defaultcurhoplimit=65

echo Done! Enjoy the rest of your day.
pause
