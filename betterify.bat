@echo off
title Windows Betterify by Windows Better Team
echo Check for admin...
openfiles > NUL 2>&1
if %errorlevel%==0 (
        echo Admin found. Thank you for using Windows Betterify.
        echo Version 11.2107-2a
        echo Warning: This action is irreversable!
        echo This will destroy stuff most people might want, including Edge.
        echo And also, this will install FOSS alternatives.
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

:: Disabling Oklomsy Brrr mark
echo Disabling Watermark
sc config sppsvc start=disabled
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d 0 /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Clip\License Validation" /f > NUL 2>&1

::Add UTC Time
echo Change to UTC time
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f > NUL 2>&1

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
schtasks /delete /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /f > NUL 2>&1
schtasks /delete /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /f > NUL 2>&1

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
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "showonly:defaultapps;display;nightlight;sound;powersleep;batterysaver;batterysaver-usagedetails;batterysaver-settings;multitasking;about;bluetooth;connecteddevices;printers;mousetouchpad;devices-touchpad;typing;pen;autoplay;usb;network-status;network-cellular;network-wifi;network-wificalling;network-wifisettings;network-ethernet;network-dialup;netowrk-vpn;network-airplanemode;network-mobilehotspot;datausage;network-proxy;personalization-background;colors;lockscreen;themes;taskbar;easeofaccess-narrator;easeofaccess-magnifier;easeofaccess-highcontrast;easeofaccess-closedcaptioning;easeofaccess-keyboard;easeofaccess-mouse;easeofaccess-otheroptions;dateandtime;notifications" /f > NUL 2>&1

:: Only use security updates
echo Disabling all updates except security updates...
Invoke-WebRequest -Uri https://raw.githubusercontent.com/windows10better/windows-betterify/main/security-updates-only.reg -OutFile security-updates-only.reg
regedit /s security-updates-only.reg

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
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *AppInstaller* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"


:: Reinforcements for 20H1 and above
PowerShell -Command "Get-AppxPackage -allusers Microsoft.549981C3F5F10* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.BingWeather* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.DesktopAppInstaller* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage -allusers Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage"
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

:: Remove Microsoft Edge
echo Removing Edge...
PowerShell -Command "cd 'C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer\'; .\setup.exe --uninstall --force-uninstall --system-level"

:: Installing LibreWolf and 7zip
echo Installing LibreWolf and 7zip, great FOSS alternative to Edge, and Microsoft Default Unzipper or WinRAR.
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin
@powershell -NoProfile -ExecutionPolicy Bypass -Command "choco install -y --force --allow-empty-checksums 7zip librewolf"

:: Reinstall app store due to bug
echo Reinstall Microsoft Store due to Bug...
Powershell -Command 'Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}'

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

:: Disable SmartScreen (imo its scareware, because it falsely detects some apps!)
echo Disabling SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v ContentEvaluation /t REG_DWORD /d 0 /f > NUL 2>&1

echo Done! Enjoy the rest of your day.
pause
