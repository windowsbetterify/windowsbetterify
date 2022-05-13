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


:: Bringing back F8 menu
echo Bringing back the F8 menu...
bcdedit /set {default} bootmenupolicy legacy

:: Disable Cortana
echo Disabling Cortana and Search
taskkill /F /IM SearchUI.exe
rename "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak" > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1

:: Disabling Mr Brrr mark
echo Disabling Watermark
sc config sppsvc start=disabled
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d 0 /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Clip\License Validation" /f > NUL 2>&1

:: Disable crap services and SMBv1
echo Disable crap services and SMBv1, therefore lowering chance people on this PC would get an EternalBlue virus.
sc config diagtrack start=disabled
sc config RetailDemo start=disabled
PowerShell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
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

:: Disable Timeline
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f > NUL 2>&1

:: Disable + Delete Tasks
echo Disabling task...
schtasks /change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Maps\MapsToastTask" /f > NUL 2>&1

:: Disable Telemetry
echo Disabling Telemetry...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' | Out-Null"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'AllowBuildPreview' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP' -Name 'CEIPEnable' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'AITEnable' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1"
PowerShell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput' -Name 'AllowLinguisticDataCollection' -Type DWord -Value 0"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' | Out-Null"
PowerShell -Command "Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' | Out-Null"

:: RegEdits
echo Applying Registry Edits
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 0x1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v UseActionCenterExperience /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f > NUL 2>&1
echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "showonly:defaultapps;display;nightlight;sound;powersleep;batterysaver;batterysaver-usagedetails;batterysaver-settings;multitasking;about;bluetooth;connecteddevices;printers;mousetouchpad;devices-touchpad;typing;pen;autoplay;usb;network-status;network-cellular;network-wifi;network-wificalling;network-wifisettings;network-ethernet;network-dialup;netowrk-vpn;network-airplanemode;network-mobilehotspot;datausage;network-proxy;personalization-background;colors;lockscreen;themes;taskbar;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;dateandtime;notifications;maps;appsforwebsites" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f > NUL 2>&1
timeout /t 2 /nobreak
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d 1 /f > NUL 2>&1

:: Only use security updates
echo Disabling all updates except security updates...
curl "https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/security-updates-only.reg" -O security-updates-only.reg
regedit /s security-updates-only.reg

:: Better UX
echo Better UX by neolectron
curl "https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/improved-experience-neolectron.reg" -O security-updates-only.re
regedit /s improved-experience-neolectron.reg


:: Editing HOSTS
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
takeown /f "%WINDIR%\System32\drivers\etc\hosts"
attrib +R %WINDIR%\System32\drivers\etc\hosts

:: Disable Hibernation, to make NTFS available in other OSes
powercfg /h off

:: Deleting all apps except store and XBOX
echo Deleting all bad apps except store and XBOX
PowerShell -Command "Get-AppxPackage -AllUsers | where-object {$_.name –notlike '*store*'} | where-object {$_.name –notlike '*xbox*'} | where-object {$_.name –notlike '*edge*'}  | where-object {$_.name –notlike '*packageman*'} | Remove-AppxPackage"



:: Reinforcements
PowerShell -Command "Get-AppxPackage -allusers Microsoft.549981C3F5F10* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.BingWeather* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.DesktopAppInstaller* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.MixedReality.Portal* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.MSPaint* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Office.OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.People* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Print3D* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.ScreenSketch* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.VP9VideoExtensions* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Wallet* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WebMediaExtensions* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WebpImageExtension* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Windows.Photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WindowsCalculator* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers microsoft.windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.YourPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.ZuneMusic* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.ZuneVideo* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *ActiproSoftwareLLC* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers Microsoft.BingNews* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *Duolingo* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *EclipseManager* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *Facebook* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *king.com.FarmHeroesSaga* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *Flipboard* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *HiddenCityMysteryofShadows* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *Plex* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -AllUsers *Wunderlist* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *FeedbackHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MixedRealityPortal* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Caclulator* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *AppInstaller* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"

:: Disable app suggestions
echo Disabling app suggestions
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353698Enabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Type DWord -Value 0"
PowerShell -Command "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord -Value 0"

:: Disable tailored experience
echo Disable tailored experiences
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f > NUL 2>&1

:: Disable SmartScreen etc (imo its scareware, because it falsely detects some apps!)
echo Disabling SmartScreen etc.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v ContentEvaluation /t REG_DWORD /d 0 /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f > NUL 2>&1

:: Clean up control panel
echo Cleaning control panel...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "showonly:display;nightlight;sound;notifications;quiethours;powersleep;batterysaver;tabletmode;multitasking;clipboard;remote-desktop;about;bluetooth;connecteddevices;printers;mousetouchpad;devices-touchpad;typing;pen;autoplay;usb;network-status;network-cellular;network-wifi;network-wificalling;network-wifisettings;network-ethernet;network-dialup;network-vpn;network-airplanemode;network-mobilehotspot;datausage;network-proxy;personalization-background;personalization-start;fonts;colors;lockscreen;themes;taskbar;defaultapps;videoplayback;startupapps;dateandtime;regionlanguage;regionformatting;gaming;gaming-gamemode;gaming-broadcasting;gaming-gamedvr;easeofaccess-display;easeofaccess-colorfilter;easeofaccess-audio;easeofaccess-easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;yourinfo;emailandaccounts;workplace;signinoptions;speech;easeofaccess-speechrecognition;easeofaccess-eyecontrol;easeofaccess-keyboard;easeofaccess-mouse;cortana-windowssearch;search-moredetails;windowsupdate;windowsupdate-action;windowsupdate-history;windowsupdate-restartoptions;windowsupdate-options;windowsdefender;recovery;activation;holographic;holographic-audio;privacy;privacy-location;privacy-webcam;privacy-microphone;privacy-notifications;privacy-speechtyping;privacy-accountinfo;privacy-contacts;privacy-calandar;privacy-callhistory;privacy-email;privacy-tasks;privacy-messaging;privacy-radios;privacy-customdevices;privacy-feedback;privacy-backgroundapps;privacy-appdiagnostics;otherusers;sync;optionalfeatures;appsfeatures" /f > NUL 2>&1

:: Set up explorer
echo Setting up explorer
reg delete "HKEY_CLASSES_ROOT\CABFolder\CLSID" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.cab\CLSID" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\CompressedFolder\CLSID" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\.zip\CLSID" /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f > NUL 2>&1

::Run O&O ShutUp 10
echo "Running ShutUp10++"
curl "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -O OOSU10.exe
curl "https://raw.githubusercontent.com/windowsbetterify/windowsbetterify/main/ooshutup10.cfg" -O ooshutup10.cfg
OOSU10.exe ooshutup10.cfg /quiet

echo Done! Enjoy the rest of your day.
pause
